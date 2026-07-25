"""Identity correlation helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .models import Employee


def correlate_identities(
    accounts: Iterable[str], employees: Mapping[str, Employee]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Split accounts into known, unknown, and privileged identity groups."""

    normalised = sorted({account.casefold() for account in accounts})
    known = tuple(account for account in normalised if account in employees)
    unknown = tuple(account for account in normalised if account not in employees)
    privileged = tuple(account for account in known if employees[account].privileged)
    return known, unknown, privileged
