"""The user directory the two IdPs share.

The point of the shared directory is the "same e-mail, same raw sub, different
issuer" case: both providers hold accounts that *look* identical by e-mail, and
one account even reuses the exact ``sub`` string used at the other provider.
The RP must still keep them apart, because a subject is only unique within its
issuer -- which is why ``sub`` alone is never a key anywhere in the RP schema.

No passwords: this lab models a pre-authenticated local account, and the login
form is just "pick who you are at this IdP".
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InputError


@dataclass(frozen=True)
class IdpUser:
    issuer_name: str  # "A" or "B" -- internal provider selector
    username: str  # what the login form posts
    sub: str  # claim value; NOT globally unique
    email: str  # deliberately collides across providers
    display_name: str


_DIRECTORY: dict[str, dict[str, IdpUser]] = {
    "A": {
        "alice": IdpUser(
            "A", "alice", "user-1001", "alice@example.test", "Alice at A"
        ),
        "shared": IdpUser(
            "A", "shared", "same-sub-7", "shared@example.test", "Shared identity at A"
        ),
    },
    "B": {
        "alice": IdpUser(
            # Same e-mail as A/alice, different raw sub.
            "B", "alice", "user-2002", "alice@example.test", "Alice at B"
        ),
        "shared": IdpUser(
            # Same raw sub *and* same e-mail as A/shared -> must not merge.
            "B", "shared", "same-sub-7", "shared@example.test", "Shared identity at B"
        ),
    },
}


def list_users(issuer_name: str) -> list[IdpUser]:
    try:
        users = _DIRECTORY[issuer_name]
    except KeyError:
        raise InputError(f"unknown provider {issuer_name!r}")
    return [users[key] for key in sorted(users)]


def lookup(issuer_name: str, username: str) -> IdpUser:
    try:
        users = _DIRECTORY[issuer_name]
    except KeyError:
        raise InputError(f"unknown provider {issuer_name!r}")
    user = users.get(username)
    if user is None:
        raise InputError(f"unknown user {username!r} at provider {issuer_name}")
    return user
