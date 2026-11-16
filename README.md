# 双身份提供方 SSO 回调绑定实验系统（本地 / Windows / 纯标准库）

两个身份提供方（IdP A / IdP B）+ 一个业务站点（RP），只实现授权码 + PKCE(S256) +
HS256 ID Token 这一条链路，重点演示并验证：

* 并行登录时回调不串线（没有"最后一次 state"这种东西）；
* 身份提供方混淆（用 A 的码/issuer/密钥冒充 B，或反之）被拒绝；
* 回调与授权码重放、并发重复回调不会多建会话；
* RP 以 **多个独立进程共享一个 SQLite** 运行，可在两个同步点被真实杀死后重启，
  重启不会绕过 state 绑定，也不会补建会话。

全部为本地测试数据；不使用 Docker、真实第三方账号、现成 OAuth/OIDC 客户端或任何
第三方依赖，仅 Windows 原生 Python 3.12 标准库（`http.server` / `sqlite3` /
`hmac` / `hashlib` / `urllib` / `multiprocessing` / `ctypes`）。

---

## 1. 快速开始

在仓库根目录（本文件所在目录）打开 cmd / PowerShell：

```bat
REM 1) 启动三个本地服务（RP 2 个 worker 进程 + IdP A + IdP B）
python scripts\run_lab.py

REM 2) 浏览器里打开（两个身份提供方分别在不同回环地址，Cookie 天然隔离）
REM    http://127.0.0.1:8800/                业务站点
REM    http://127.0.0.1:8800/login?issuer=A  用 A 登录
REM    http://127.0.0.1:8800/login?issuer=B  用 B 登录
REM    http://127.0.0.1:8800/me              JSON 形式的当前身份
```

`Ctrl-C` 结束 `run_lab.py` 会连带结束 RP 的 supervisor 与 worker、两个 IdP。

运行完整自动化测试（约 90 秒，含真实进程启动/杀死）：

```bat
python scripts\run_tests.py
python scripts\run_tests.py -v
python scripts\run_tests.py unit binding      REM 只跑部分分组
```

跑一遍端到端演示（自动起停，打印每一步的观测结果）：

```bat
python scripts\demo.py
```

单浏览器会话模拟器（真实 HTTP，不写数据库）：

```bat
python -m sso_lab.browser --rp http://127.0.0.1:8800 --issuer A --user alice
```

端口/路径可通过参数或环境变量覆盖：`SSO_RP_PORT`、`SSO_IDP_A_PORT`、
`SSO_IDP_B_PORT`、`SSO_RUNTIME_DIR`、`SSO_CODE_TTL`、`SSO_RP_WORKERS`、
`SSO_CLOCK_OFFSET_SECONDS`；`run_lab.py` 另有 `--rp-port/--idp-a-port/--idp-b-port/
--workers/--runtime-dir/--code-ttl/--no-test-hooks`。

### 目录

```
sso_lab/            实现
  config.py         受信配置：issuer / 授权端点 / 令牌端点 / client / 密钥 / 回调 URL 全部预置
  jwt.py            HS256 JWS 生成与严格校验（重复成员、alg、jku、类型、时间窗）
  tokens.py         随机标识符与 PKCE S256
  idp.py            身份提供方（同一份代码，A/B 各起一个进程）
  rp.py             业务站点（回调绑定、原子认领、会话提交）
  rp_worker.py      RP supervisor：绑定一次监听套接字，交给 N 个 worker 进程
  browser.py        浏览器会话模拟器（独立 CookieJar + 真实 HTTP + 回调拦截）
  harness.py        测试用启停编排（真实子进程）
  procs.py          Windows 进程树查询/硬杀（ctypes）
  faults.py         故意发坏令牌的 IdP 变体（仅测试启用）
  testhooks.py      SSO_TEST_HOOKS=1 才生效的同步点/崩溃点
  schema.py, db.py  SQLite 模式与事务封装
tests/              自动化测试（unittest，无第三方依赖）
scripts/            run_lab.py / run_tests.py / demo.py
runtime/            运行期数据（数据库、日志、报告；已在 .gitignore 中）
```

---

## 2. 拓扑与信任关系

```
浏览器(模拟器)
   │  ①GET /login?issuer=A          ┌──────────────┐
   ├────────────────────────────────►│ RP 127.0.0.1 │  2 个 worker 进程共享 1 个 SQLite
   │  ②302 到 A 的 /authorize        └──────┬───────┘
   ▼                                        │ ④服务端 POST /token（HTTP Basic 客户端认证）
┌───────────────────────┐                   │    只用事务行里预置的 A 令牌端点
│ IdP A 127.0.0.2:8801  │◄──────────────────┘
│ issuer …/issuer/A     │
│ 独立 SQLite + 独立密钥 │  ③302 → RP 回调 ?issuer=A&code=…&state=…
└───────────────────────┘
┌───────────────────────┐
│ IdP B 127.0.0.3:8802  │  B 的 issuer / 端点 / 密钥 / 库全部独立
└───────────────────────┘
```

* 三个服务绑定 **三个不同的回环地址**（127.0.0.1 / .2 / .3）。浏览器 Cookie 按主机名
  隔离，因此 RP 的 Cookie 对两个 IdP 不可见，模拟器也不需要伪造这一点。
* RP 对每个 IdP 的认知全部来自 `sso_lab/config.py`（受信配置）：issuer、授权端点、
  令牌端点、client_id、client_secret、HS256 共享密钥、aud、以及**精确到查询串**的
  回调 URL（`/callback?issuer=A` 与 `/callback?issuer=B` 是两个不同的注册值）。
* RP 从不下载密钥：令牌头里出现 `jku/jwks/x5u/x5c/jwk/x5t` 直接拒绝；payload 里的
  `jwks_uri` 之类只是被忽略的未知声明。测试用本地监听器证明 RP 从不向这些 URL 发请求。

---

## 3. 协议细节与安全不变量

### 3.1 授权码（IdP 侧）

| 绑定项 | 说明 |
|---|---|
| issuer | 码行里存 issuer，兑换时比对（跨库复制的码也无效） |
| client_id | 与令牌端点的 HTTP Basic 客户端比对 |
| redirect_uri | 与授权时**完全相同**的值比对（含 `?issuer=`） |
| 用户 / nonce / state | 存入码行，用于后续 ID Token |
| PKCE | 只接受 `S256`；挑战必须是 43 个 base64url 字符 |
| 有效期 | 60 秒（`SSO_CODE_TTL` 可调），`expires_at` 在签发时固定 |
| 单次使用 | 兑换成功时 `UPDATE … WHERE consumed_at IS NULL`，并发兑换只有一个成功 |

失败路径（错 verifier / 错 client / 错 redirect_uri / 过期 / 未知码）**不消费**有效码：
条件更新只在所有校验通过后才执行。`tests/test_idp_codes.py` 逐个断言"失败后原码仍可兑换"。

授权端点对 `redirect_uri` 不匹配时**不重定向**（避免开放重定向），直接在提供方页面报错。
查询串重复参数（如两个 `state`）直接 400，不做"后者覆盖"。

ID Token 固定 `HS256`，`header={"alg":"HS256","typ":"JWT"}`，claims 含
`iss/sub/aud/nonce/iat/exp`（另带展示用 `email/name`），有效期 120 秒。

### 3.2 登录事务（RP 侧）

每次 `/login` 都插入一行 `login_txns`，主键就是随机 32 字节的 `state`，行内固定：
浏览器 `rp_sid`、issuer 键（A/B）、issuer 字符串、授权端点、令牌端点、client_id、
**回调 URL**、nonce、PKCE verifier 与 challenge、创建/过期时间。

* 没有任何"最后一次 state"变量或槽位。同一浏览器同时发起 A、B、A 三次登录就是三行，
  互不覆盖（`test_three_parallel_logins_all_complete`、`test_out_of_order_callbacks_same_browser`）。
* 回调处理顺序：**按 state 查事务 → 校验浏览器 Cookie → 校验回调 issuer → 校验回调 URL
  与预置值一致 → 校验事务仍 pending/未过期 → 校验端点仍与配置一致 → 原子认领**。
  任何一步失败都不触碰其他事务。
* 只向该事务行里存的 `token_endpoint` 兑换，客户端凭据也来自该 issuer 的预置配置；
  回调参数/令牌内容都不能改变兑换目标。
* 令牌校验：MAC（`hmac.compare_digest`）→ 声明存在性与类型 → `iss` 必须等于事务 issuer
  → `aud` 必须含预置 client_id → `nonce` 必须等于事务 nonce → `iat ≤ now+skew`、
  `exp+skew ≥ now`、`exp > iat`。`bool` 不被当作整数接受。
* 身份键是 `(issuer, subject)`；`login_sessions` 的唯一约束是
  `(browser_sid, issuer, subject)`，email 只用于显示，不参与任何唯一性判断。
* 会话插入与事务置 `done` 在**同一个事务、同一次 COMMIT** 内完成；失败路径会
  `UPDATE … SET status='failed'`，不留半成品会话。

### 3.3 重放与并发

* 回调开始时先写一行 `callback_attempts` 审计记录。
* 认领是 `UPDATE … SET status='consuming', claim_pid=?, claimed_at=? WHERE state=? AND
  status='pending' AND expires_at>?`：只有一个进程的 `rowcount==1`。
* 已完成 → 409 `replayed_callback`；正在被别的请求处理 → 409；
  被已死进程认领（超过 1 秒宽限且 pid 不存活，或认领超过 120 秒）→ 关闭事务并 400
  `invalid_transaction`（提示重新登录），**不会**恢复该事务。
* 实测：8 个并发同回调 = 1×200 + 7×409，会话数 1。

### 3.4 多进程

`python -m sso_lab.rp_worker --workers 2`：supervisor 绑定一次监听套接字，用
`multiprocessing`(spawn) 把继承的套接字交给每个 worker，worker 各自 `serve_forever`
同一个套接字（Windows 上由 Winsock 分发）。worker 死亡时 supervisor 自动补一个。
测试断言 `/healthz` 由 ≥2 个不同 pid 回答、会话在两个 worker 上都可见。

---

## 4. 可控同步点与真实进程终止

仅当进程环境变量 `SSO_TEST_HOOKS=1` 时，RP 才识别以下请求头（`run_lab.py` 默认开启，
`--no-test-hooks` 关闭；正常部署请关闭）：

| 头 | 含义 |
|---|---|
| `X-Lab-Delay: <秒>` | 兑换令牌前等待（≤5 s），放大并发窗口 |
| `X-Lab-Crash: after-verify` | 令牌已验证、本地未提交时 `os._exit(70)` |
| `X-Lab-Crash: after-commit` | 会话已提交、响应未发出时 `os._exit(70)` |
| `X-Lab-Hold: after-verify\|after-commit` | 停在同一位置并写标记文件（含 pid），等外部硬杀 |

两种方式都覆盖：
* `X-Lab-Crash`：RP 自己终止自己（无 `finally`、无清理）；
* `X-Lab-Hold`：**测试进程**用 `TerminateProcess` 硬杀该 worker（`sso_lab/procs.py`），
  与"进程被外部杀死"完全等价。

`after-verify` 之后重启的结论（`tests/test_crash.py`）：
无会话行；事务停在 `consuming`；原回调重放 → 409/400，**不建会话**；宽限期后事务被关闭；
换个浏览器拿同一个 state 也无法使用；必须重新登录，重新登录正常。
授权码此时已在提供方被消费——按题目允许"要求重新登录"，不做跨服务事务。

`after-commit` 之后重启的结论：会话**恰好一行**（数据库里有），事务 `done`；
浏览器后续请求（新连接、可能是另一个 worker）能看到该会话；同一回调重放 → 409，
会话数不变。

---

## 5. 自动化测试覆盖（全部真实 HTTP / 真实进程）

| 要求 | 测试 |
|---|---|
| 同浏览器乱序回调 | `test_out_of_order_callbacks_same_browser`、`test_three_parallel_logins_all_complete` |
| 跨浏览器交换 state | `test_cross_browser_state_exchange_is_rejected_without_burning_it`、`test_callback_with_foreign_cookie_only_is_rejected` |
| A/B 授权码互换 | `test_code_from_a_redeemed_at_b_is_rejected_and_a_still_works`、`test_b_token_endpoint_rejects_a_client_credentials` |
| A/B issuer 互换（回调参数 / 事务 / 令牌 iss） | `test_callback_issuer_swap_is_rejected`、`test_issuer_in_id_token_must_match_transaction`、`test_callback_without_issuer_is_rejected` |
| 相同 sub、不同 issuer | `test_same_sub_at_two_issuers_are_two_identities`、`test_login_with_provider_b_same_email_different_identity` |
| 错误 nonce / aud / 签名 | `test_wrong_nonce`、`test_wrong_audience`、`test_wrong_signing_key`、`test_other_provider_key_is_rejected` |
| alg=none / 重复 JSON / 非法类型 / jku | `test_alg_none`、`test_duplicate_json_member`、`test_bad_sub_type`、`test_jku_header_is_never_used`、`test_token_supplied_urls_are_never_fetched` |
| 过期边界 | `test_authorization_code_expiry_at_provider`（59 s 成功）、`test_authorization_code_expired_at_provider`（61 s 失败后恢复正常登录）、`test_id_token_expiry_boundary_at_rp` |
| 码兑换失败后正常兑换 | `test_bad_code_fails_then_valid_login_succeeds`、`test_provider_unreachable_is_reported_as_failure` |
| 同回调并发 | `test_concurrent_identical_callbacks_create_one_session`、`test_concurrent_callbacks_from_two_browsers_both_succeed` |
| 重复回调 | `test_replayed_callback_creates_no_second_session` |
| 多进程共享库 | `tests/test_multi_process.py`（5 项，含杀死一个 worker 后服务仍可用） |
| 两个崩溃点 | `tests/test_crash.py`（6 项：自终止 & 外部硬杀 × 两个点 + 全量重启 + 认领回收） |
| 令牌级严格性 | `tests/test_jwt.py`（34 项）、`tests/test_idp_codes.py`（14 项） |
| 模拟器自身 | `tests/test_simulator.py`（独立 CookieJar、只走 HTTP、不回写库） |

运行方式：`python scripts\run_tests.py`（见第 6 节实际结果）。

---

## 6. 实际测试结果

环境：Windows 11 Pro 10.0.26200，Python 3.12.8，CPU only，本机回环。

`python scripts\run_tests.py`（2026-11-17 本机多次实跑，取最后一次，输出节选）：

```
$ python -m unittest test_jwt test_idp_codes test_rp_binding test_crash test_multi_process test_simulator
...................................................................................................
----------------------------------------------------------------------
Ran 100 tests in 91.7s

OK
exit=0 elapsed=92.0s
```

重复运行均为 `Ran 100 tests ... OK`；总耗时 86–93 s，随机器负载浮动。

分组（同一命令分模块实跑）：

| 模块 | 用例数 | 结果 | 用时 |
|---|---|---|---|
| test_jwt（令牌/JSON/PKCE 严格性） | 34 | OK | 0.003 s |
| test_idp_codes（授权码语义 + 并发兑换，进程内真实 socket） | 14 | OK | 0.5–1.0 s |
| test_rp_binding（绑定/混淆/重放/并发/故障注入） | 35 | OK | 44–46 s |
| test_crash（两个崩溃点、外部硬杀） | 6 | OK | 13–14 s |
| test_multi_process（双 worker 共享端口与库） | 5 | OK | 24–26 s |
| test_simulator（模拟器行为） | 6 | OK | 3–4 s |
| **合计** | **100** | **OK** | **≈92 s** |

`python scripts\demo.py` 关键输出（一次实跑，PID/端口随运行变化）：

```
1. 同一浏览器先发 A 再发 B，先交付 B 的回调
   deliver B -> HTTP 200 ; deliver A -> HTTP 200
   session issuer=B subject=user-2002 ; session issuer=A subject=user-1001
2. 跨浏览器偷 state
   thief -> HTTP 400 / invalid_callback (browser_mismatch) ; thief /me -> None
   victim 随后交付同一回调 -> HTTP 200, victim /me -> same-sub-7 @ A
3. 回调 issuer 互换
   ?issuer=B 用于 A 的 state -> HTTP 400: issuer_mismatch ; 原 A 回调仍 -> 200
4. 两个 issuer 下相同 sub
   A: sub=same-sub-7 ; B: sub=same-sub-7 ; 该浏览器会话数 = 2
5. 已完成回调重放
   first -> 200 ; replay -> 409, sessions=1
6. 8 个并发同回调
   statuses=[200,409,409,409,409,409,409,409], sessions=1
7a. 令牌已验证、未提交时外部硬杀 worker
   客户端连接被重置；重启后 /me -> None
   立即重放 -> 409（认领仍在飞行中）；宽限期后重放 -> 400 invalid_transaction
   重新登录 -> 200
7b. 会话已提交、响应未发出时外部硬杀 worker
   客户端连接被重置；重启后 /me -> user-2002 @ B
   重放 -> 409, sessions=1
summary {'attempts': 24, 'sessions': 10, 'txn_status': {'done': 10, 'failed': 1}}
lab stopped; all 5 started pids gone: True []
```

`RUNTIME.txt` 里指定的解释器（`D:/CC_Codex_FeedBack/runtimes/cc005-csv-python312/python.exe`）
即上表所用的 Python 3.12.8；`python` 若不在 PATH，把上面命令里的 `python` 换成该完整路径。

---

## 7. 已知限制 / 未完成项

1. **不是完整 OIDC**：没有 discovery、JWKS、`userinfo`、refresh token、logout 传播、
   `at_hash`/`c_hash`、多 audience 语义、`azp`，也没有 RS256/ES256。题目只要求本条链路。
2. **HS256 只是演示**：A/B 各自预共享密钥，RP 端按 issuer 查表；生产应使用非对称签名
   + 预置 JWKS（仍然不按令牌内 URL 下载）。`client_secret` 也是本地明文测试数据。
3. **IdP 是单进程**：只有 RP 按题目要求多进程；IdP 的并发兑换安全依赖其 SQLite 条件更新
   （已在单元测试覆盖单进程并发语义），没有做 IdP 多进程/高可用。
4. **SQLite 单机文件**：回调并发靠 `BEGIN IMMEDIATE` + 写锁串行化；跨机器部署需换成
   真正的共享存储，且"认领 + 会话提交"需要相应的事务隔离方案。
5. **崩溃恢复策略是"失败即关闭"**：`after-verify` 崩溃后，即使授权码已被消费，RP 也
   不会尝试恢复该事务（题面允许要求重新登录）。没有跨服务补偿/分布式事务。
6. **认领回收依赖 pid 存活判断**：宽限期 1 秒 + `OpenProcess/WaitForSingleObject`；另有
   120 秒绝对上限来兜底 pid 复用；极端情况下（pid 被立即复用且原认领 <120 秒）回收会推迟，
   期间表现为 409 而非 400——但两种都不会建立会话。
7. **测试钩子**：`/lab/*` 端点、`X-Lab-*` 头、`SSO_TEST_HOOKS`、`SSO_CLOCK_OFFSET_SECONDS`
   都是测试脚手架，必须在生产部署中关闭/移除；关闭后这些端点返回 404、请求头被忽略。
8. **Cookie 安全属性**：本地 HTTP 实验，Cookie 只有 `HttpOnly`+`SameSite=Lax`，没有
   `Secure`、没有 CSRF token（`state` 本身承担了 CSRF 作用）；RP 也不做会话轮换/固定防护。
9. **无 TLS**：三个服务都是明文 HTTP，仅限 127.0.0.0/8。
10. **日志与审计**：`rp_events`/`callback_attempts`/`idp_events` 只用于实验观察，没有
    轮转、保留策略或结构化导出；没有对接外部日志系统。
