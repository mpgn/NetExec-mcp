"""Safety guardrails enforced before any nxc command runs.

Three independent controls, plus an audit trail:

  * **Scope allowlist** -- every target must fall inside `NXC_SCOPE`. This is
    fail-closed: if a command has targets but no scope is configured, it is
    rejected. CIDR targets must be *subnets* of an allowed network (you cannot
    scan a /16 when only a /24 is allowed).
  * **Offensive gate** -- tools marked offensive require `NXC_MODE=full`.
  * **Target cap** -- no more than `NXC_MAX_TARGETS` target tokens per call.
  * **Audit log** -- every command (executed, dry-run, or rejected) is appended
    as one JSON object to `NXC_AUDIT_LOG`.

These are pure functions over primitives so they're trivial to unit-test and have
no dependency on the executor.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone


class GuardrailError(RuntimeError):
    """Base class for a blocked command. Nothing runs when this is raised."""


class ScopeError(GuardrailError):
    """A target is not inside the configured scope allowlist."""


class OffensiveBlocked(GuardrailError):
    """An offensive action was attempted without NXC_MODE=full."""


class TooManyTargets(GuardrailError):
    """More target tokens than NXC_MAX_TARGETS were supplied."""


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

def _as_network(token: str):
    """Interpret a token as an IP or CIDR -> ip_network, else None."""
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def _expand_range(token: str):
    """Parse nxc range syntax (`10.0.0.1-10` or `10.0.0.1-10.0.0.20`).

    Returns (first, last) ip_address pair, or (None, None) if not a range.
    """
    left, sep, right = token.partition("-")
    if not sep:
        return None, None
    try:
        start = ipaddress.ip_address(left.strip())
    except ValueError:
        return None, None

    right = right.strip()
    try:
        end = ipaddress.ip_address(right)
    except ValueError:
        # last-octet shorthand: 10.0.0.1-10
        if right.isdigit() and start.version == 4:
            octets = str(start).split(".")
            octets[-1] = right
            try:
                end = ipaddress.ip_address(".".join(octets))
            except ValueError:
                return None, None
        else:
            return None, None
    return start, end


@dataclass
class Scope:
    networks: list = field(default_factory=list)   # ip_network objects
    hostnames: list[str] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.networks and not self.hostnames


def parse_scope(entries: list[str]) -> Scope:
    networks, hostnames = [], []
    for entry in entries:
        net = _as_network(entry)
        if net is not None:
            networks.append(net)
        else:
            hostnames.append(entry.strip().lower().lstrip("."))
    return Scope(networks=networks, hostnames=hostnames, raw=list(entries))


def _target_in_scope(target: str, scope: Scope, resolve=None) -> bool:
    t = target.strip()

    first, last = _expand_range(t)
    if first is not None:
        # whole range must sit inside a single allowed network
        return any(
            first.version == n.version == last.version and first in n and last in n
            for n in scope.networks
        )

    net = _as_network(t)
    if net is not None:
        if net.num_addresses == 1:
            ip = net.network_address
            return any(ip.version == n.version and ip in n for n in scope.networks)
        # CIDR target must be a subnet of an allowed network
        return any(net.version == n.version and net.subnet_of(n) for n in scope.networks)

    # hostname: an exact match / subdomain of an allowed scope hostname ...
    host = t.lower()
    if any(host == e or host.endswith("." + e) for e in scope.hostnames):
        return True
    # ... or it RESOLVES to address(es) that all sit inside an allowed network. `resolve`
    # (the same OS resolver nxc uses on this box) is injected by the executor; resolving here
    # and checking the result keeps the scope check sound for hostname targets -- we verify
    # the address nxc will actually connect to -- without moving the boundary. Every resolved
    # address of a family the scope covers must be in-scope, so DNS round-robin can't slip an
    # out-of-scope answer through.
    if resolve is not None and scope.networks:
        versions = {n.version for n in scope.networks}
        ips = [ip for ip in resolve(t) if ip.version in versions]
        if ips and all(any(ip in n for n in scope.networks if n.version == ip.version)
                       for ip in ips):
            return True
    return False


def check_scope(targets: list[str], scope: Scope, resolve=None) -> None:
    """Raise ScopeError unless every target is inside the allowlist. A hostname target passes
    if it matches an allowed scope hostname OR (via `resolve`) maps to in-scope IP(s)."""
    if not targets:
        return  # commands with no target (e.g. module listing) need no scope
    if scope.is_empty:
        raise ScopeError(
            "NXC_SCOPE is empty -- refusing to target anything. Set NXC_SCOPE to an "
            "allowlist (e.g. \"192.168.56.0/24\")."
        )
    rejected = [t for t in targets if not _target_in_scope(t, scope, resolve)]
    if rejected:
        msg = (f"target(s) out of scope: {', '.join(rejected)} "
               f"(allowed: {', '.join(scope.raw)})")
        if any(_as_network(t) is None and _expand_range(t)[0] is None for t in rejected):
            msg += (". A hostname is allowed only if it resolves to an in-scope IP -- check it "
                    "resolves (e.g. `ping <host>`), or pass the IP directly.")
        raise ScopeError(msg)


# --------------------------------------------------------------------------- #
# Offensive gate & target cap
# --------------------------------------------------------------------------- #

def check_offensive(
    allow_offensive: bool,
    offensive: bool,
    *,
    dump: bool = False,
    allow_loot: bool = False,
) -> None:
    """Enforce the recon < loot < full gate for a single action.

    `offensive` marks anything beyond read-only enumeration. `dump` narrows that to
    read-only *credential-dumping* (sam/lsa/ntds/gpp/roasting) -- no state change,
    so `loot` mode (allow_loot) permits it while `recon` does not. Everything else
    offensive (exec/write/spray/exploit) requires `full` (allow_offensive).
    """
    if not offensive or allow_offensive:
        return
    if dump and allow_loot:
        return
    if dump:
        raise OffensiveBlocked(
            "this action dumps credential material (read-only, but it harvests "
            "secrets) and is blocked in the current mode. Set NXC_MODE=loot to "
            "permit credential collection (or full for everything). Plain read-only "
            "enumeration is not gated -- a dedicated smb_*/ldap_* tool likely exists."
        )
    raise OffensiveBlocked(
        "this action is offensive (exec/write/spray/exploit) and is blocked. "
        "If you only need standard read-only enumeration, a dedicated, "
        "non-gated tool likely already exists (e.g. the smb_* tools, or "
        "nxc_search_tools to find one) -- use it instead. To genuinely "
        "permit a state-changing action, set NXC_MODE=full."
    )


def check_target_cap(targets: list[str], max_targets: int) -> None:
    if len(targets) > max_targets:
        raise TooManyTargets(
            f"{len(targets)} target tokens exceeds NXC_MAX_TARGETS={max_targets}."
        )


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_audit(path: str | None, record: dict) -> None:
    """Append one JSON object to the audit log. No-op if no path configured."""
    if not path:
        return
    target = os.path.expanduser(path)
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    entry = {"ts": _now_iso(), **record}
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
