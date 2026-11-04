"""Discovery + escape-hatch meta-tools for nxc's `-M` module long tail.

These sit *alongside* the per-protocol static tools (PLAN.md), covering modules
that don't have a dedicated tool:

  * ``nxc_list_modules`` / ``nxc_search_tools`` -- pure **recon/discovery**: ask
    nxc what `-M` modules exist for a protocol and search them. No targets, never
    offensive.
  * ``nxc_run_module`` / ``nxc_raw_command`` -- actually execute a module or an
    arbitrary nxc invocation (``nxc_raw_command`` is the deliberately
    awkwardly-named last-resort escape hatch, so agents don't reach for it on
    routine recon). These are **offensive-gated** (``offensive=True``): they are
    refused unless ``NXC_MODE=full``, keeping the default surface
    recon-only. Every call still goes through ``execute()`` (scope/cap/audit).
"""

from __future__ import annotations

import asyncio
import json
import re
from functools import lru_cache
from pathlib import Path

from .auth import build_auth_flags
from .executor import execute

# A module line in `nxc <proto> -L` output (after ANSI strip):
#   [*] enum_av                   Gathers information on ...
_MODULE_RE = re.compile(r"^\[\*\]\s+(?P<name>\S+)\s+(?P<desc>.*)$")
# Privilege banner: "LOW PRIVILEGE MODULES" / "HIGH PRIVILEGE MODULES". nxc appends a
# parenthetical to the HIGH one ("... (requires admin privs)"), so the pattern must NOT be
# anchored at the end: it was, and the banner therefore never matched -- every module, up to
# and including `ntdsutil` and `lsassy`, was served to the model as `privilege: low`.
_PRIV_RE = re.compile(r"^(?P<level>LOW|HIGH) PRIVILEGE MODULES\b", re.IGNORECASE)


_REMOVED_TAG = "[REMOVED]"

# Where each retired module went. nxc still LISTS them in `-L` (tagged `[REMOVED]`) but only
# two carry the replacement in their description; the other nine reveal it at run time, in a
# `context.log.fail("[REMOVED] ...")` reached only with valid credentials on a live target --
# i.e. never, in practice. Filtering them out silently (what we do, and should keep doing:
# offering a dead module wastes a turn) leaves a list that LOOKS complete with the capability
# missing and no word about it. So we filter them out of `modules` and serve them, with the
# pointer, in `removed`.
#
# These notes are COPIED FROM UPSTREAM, not invented: each one restates the module's own
# `[REMOVED]` fail message in terms of the tool that now does the job. When bumping nxc, run
# tests/test_meta.py::test_removed_module_table_matches_nxc_sources to catch drift.
_REMOVED_GENERIC_NOTE = "removed from nxc: this module can no longer run."
REMOVED_MODULE_NOTES = {
    # ldap
    "enum_trusts": (
        "removed from nxc, which redirects to the `--dc-list` LDAP flag: use `ldap_dc_list`, "
        "whose stdout prints every trusted domain ALREADY DECODED "
        "(`north.example.local -> Bidirectional -> Within Forest`). That line needs the trusted "
        "domain's DCs to resolve over DNS; when they do not, read the attributes directly with "
        "`ldap_query` on `(objectClass=trustedDomain)`."
    ),
    "group-mem": (
        'removed from nxc, which redirects to the `--groups "<group>"` LDAP flag: call '
        "`ldap_groups` with a group name to list its members."
    ),
    "ldap-checker": (
        "removed from nxc: LDAP signing and channel binding are now reported natively in the "
        "host banner, i.e. in the output of `ldap_enum_hosts`."
    ),
    "pso": "removed from nxc, which redirects to the core `--pso` option: use `ldap_pso`.",
    # smb
    "petitpotam": "removed from nxc, which redirects to the `coerce_plus` module: use `smb_coerce_plus`.",
    "printerbug": "removed from nxc, which redirects to the `coerce_plus` module: use `smb_coerce_plus`.",
    "shadowcoerce": "removed from nxc, which redirects to the `coerce_plus` module: use `smb_coerce_plus`.",
    "dfscoerce": "removed from nxc, which redirects to the `coerce_plus` module: use `smb_coerce_plus`.",
    "efsr_spray": (
        "removed from nxc: EFS is now activated automatically by `coerce_plus`, so use "
        "`smb_coerce_plus`."
    ),
    "firefox": "removed from nxc, which redirects to the `--dpapi` flag: use `smb_dpapi`.",
    "ntlm_reflection": (
        "removed from nxc: integrated into the `enum_cve` module, reachable with "
        'nxc_run_module(module="enum_cve").'
    ),
}


def removed_module_note(name: str) -> str:
    """The redirect for a retired module, or a generic 'it cannot run' when unknown."""
    return REMOVED_MODULE_NOTES.get(name, _REMOVED_GENERIC_NOTE)


def _scan_modules(text: str):
    """Yield ``(record, is_removed)`` for every module line in `nxc <proto> -L` stdout.

    Category headers (e.g. ENUMERATION) and privilege banners are tracked as we scan and
    attached to the modules beneath them.
    """
    privilege: str | None = None
    category: str | None = None

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        m = _MODULE_RE.match(line)
        if m:
            desc = m["desc"].strip()
            removed = _REMOVED_TAG in desc
            if removed:                       # the tag is noise once the field says so
                desc = desc.replace(_REMOVED_TAG, "").strip()
            yield (
                {
                    "name": m["name"],
                    "description": desc,
                    "category": category,
                    "privilege": privilege,
                },
                removed,
            )
            continue

        priv = _PRIV_RE.match(line)
        if priv:
            privilege = priv["level"].lower()
            category = None
            continue

        # A short all-caps line with no marker is a sub-category header.
        if (
            not line.startswith("[")
            and line == line.upper()
            and len(line.split()) <= 4
            and any(c.isalpha() for c in line)
        ):
            category = line


def parse_module_list(text: str) -> list[dict]:
    """Parse `nxc <proto> -L` stdout into structured records for the RUNNABLE modules.

    Each record: ``{name, description, category, privilege}``. Modules tagged ``[REMOVED]``
    are excluded -- deliberately, and they must stay excluded: this list also feeds
    :func:`_module_categories`, i.e. the recon/loot/full gate, so a retired module leaking in
    would be classified and offered as runnable. Read them with :func:`parse_removed_modules`.
    """
    return [rec for rec, removed in _scan_modules(text) if not removed]


def parse_removed_modules(text: str) -> list[dict]:
    """Parse the ``[REMOVED]`` modules out of `nxc <proto> -L` into ``{name, description, note}``.

    Deliberately a SEPARATE list from :func:`parse_module_list`, never a flag on the same
    records: these must never reach the category cache that gates execution.
    """
    return [
        {"name": rec["name"], "description": rec["description"], "note": removed_module_note(rec["name"])}
        for rec, removed in _scan_modules(text)
        if removed
    ]


def _matches(module: dict, query: str) -> bool:
    q = query.lower()
    return q in module["name"].lower() or q in (module["description"] or "").lower()


# Category-aware gating for nxc_run_module: ENUMERATION modules are read-only recon
# and may run in recon mode; everything else (CREDENTIAL_DUMPING, PRIVILEGE_ESCALATION,
# or unknown) is treated as offensive and gated behind NXC_MODE=full.
_RECON_CATEGORY = "ENUMERATION"
# CREDENTIAL_DUMPING modules are offensive but read-only -> permitted from loot mode
# up (dump=True). PRIVILEGE_ESCALATION / unknown stay full-only (dump=False).
_DUMP_CATEGORY = "CREDENTIAL_DUMPING"
# Session cache of {protocol: {module_name: category}} so we don't re-run `-L` per call.
_MODULE_CATEGORY_CACHE: dict[str, dict[str, str]] = {}


async def _module_categories(get_config, protocol: str) -> dict[str, str]:
    """Return {module_name: category} for a protocol, caching the parsed `-L` output."""
    cached = _MODULE_CATEGORY_CACHE.get(protocol)
    if cached:
        return cached
    outcome = await execute(get_config(), protocol, [], ["-L"], offensive=False)
    cat_map = {m["name"]: m["category"] for m in parse_module_list(outcome.stdout)}
    if cat_map:  # don't cache an empty/failed listing
        _MODULE_CATEGORY_CACHE[protocol] = cat_map
    return cat_map


async def collect_module_catalog(get_config, protocols) -> list[dict]:
    """Flat list of RUNNABLE nxc `-M` modules across the ENABLED protocols for the dynamic
    find_tool index, each record tagged with its `protocol`. parse_module_list already drops
    retired ([REMOVED]) modules, so they never enter discovery or the gate. Best-effort: a
    protocol whose `-L` fails/empties is skipped; total failure returns []. A module supported
    by several protocols appears once per protocol (each independently runnable via
    nxc_run_module with that protocol). Runs at startup; cheap and cached per protocol.
    """
    async def _one(proto):
        try:
            # per-protocol timeout so one hung `-L` can't block server startup forever
            outcome = await asyncio.wait_for(
                execute(get_config(), proto, [], ["-L"], offensive=False), timeout=30)
            return proto, parse_module_list(outcome.stdout)
        except Exception:  # noqa: BLE001 -- one protocol's -L failing/hanging must not sink discovery
            return proto, []

    # Run the -L probes CONCURRENTLY (not 10 serial nxc spawns) to keep boot latency bounded.
    results = await asyncio.gather(*[_one(p) for p in protocols])
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for proto, mods in results:
        for m in mods:
            name = m.get("name")
            if not name or (proto, name) in seen:
                continue
            seen.add((proto, name))
            out.append({**m, "protocol": proto})
    return out


STATIC_CATALOG = Path(__file__).parent / "data" / "nxc_modules.json"


def static_module_catalog(protocols, installed_version: str | None = None) -> tuple[list[dict] | None, str]:
    """The `-M` module catalog shipped with the MCP (NXC_MODULE_CATALOG=static, the default).

    Written by scripts/gen_module_catalog.py with the very collector above, from a given nxc, so
    the dynamic index is built without starting a single nxc process (the live build took ~20 s
    under `uv run`, 2026-11-01) and is the same on every start. It only feeds DISCOVERY
    (nxc_find_tool, nxc_describe_tool): nxc_run_module's recon/loot/full gate still reads the
    module's category from the installed nxc (`_module_categories`), so a stale or edited file
    cannot change what a mode allows. Modules the file does not list (custom ones in
    NXC_PATH/modules, an nxc newer than the file) stay invisible to discovery: that is what
    NXC_MODULE_CATALOG=live is for. Records come back in `protocols` order, as live discovery
    yields them. Returns (None, reason) when the file is missing or unreadable, so the caller can
    fall back to live discovery."""
    try:
        data = json.loads(STATIC_CATALOG.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"static catalog unreadable ({type(exc).__name__}), fell back to live discovery"
    order = {p: i for i, p in enumerate(protocols)}
    mods = sorted((dict(m) for m in data.get("modules", []) if m.get("protocol") in order),
                  key=lambda m: order[m["protocol"]])
    built_for = data.get("nxc_version") or "?"
    note = f"static, generated for nxc {built_for}"
    if installed_version and built_for != "?" and installed_version.strip() != built_for.strip():
        note += (f" -- the installed nxc reports {installed_version.strip()!r}: regenerate it "
                 "(scripts/gen_module_catalog.py) or set NXC_MODULE_CATALOG=live")
    return mods, note


@lru_cache(maxsize=1)
def _catalog_index() -> dict[str, frozenset]:
    """{module: the protocols the shipped catalog lists it under}; {} if the file is unreadable."""
    try:
        data = json.loads(STATIC_CATALOG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    index: dict[str, set] = {}
    for m in data.get("modules", []):
        if m.get("name") and m.get("protocol"):
            index.setdefault(m["name"], set()).add(m["protocol"])
    return {name: frozenset(protos) for name, protos in index.items()}


async def _find_module_protocols(get_config, module: str, requested: str) -> set[str]:
    """Every protocol nxc lists `module` under, for nxc_run_module's wrong-protocol error: the
    shipped catalog first (no nxc process); for a module it does not know (a custom module, an
    nxc newer than the file), the live `-L` of the other enabled protocols, as the gate reads it."""
    known = _catalog_index().get(module)
    if known:
        return set(known)

    async def _lists(proto):
        try:
            return proto if module in await _module_categories(get_config, proto) else None
        except Exception:  # noqa: BLE001 -- a protocol whose -L fails just answers "not here"
            return None

    others = [p for p in get_config().protocols if p != requested]
    return {p for p in await asyncio.gather(*[_lists(p) for p in others]) if p}


def _wrong_protocol_error(module: str, protocol: str, supported: set[str], enabled: list[str]) -> str:
    """nxc_run_module on a protocol that does not list the module: name the right one, never
    switch to it silently, never point at a protocol NXC_PROTOCOLS leaves out."""
    on = [p for p in enabled if p in supported]
    off = sorted(supported - set(enabled))
    if on:
        msg = (f"{module!r} is not an nxc {protocol} module: nxc lists it for {', '.join(on)}. "
               f"Nothing ran; re-run with protocol={on[0]!r}.")
        if off:
            msg += f" It also exists for {', '.join(off)}, which NXC_PROTOCOLS does not enable."
        return msg
    if off:
        return (f"{module!r} is an nxc {', '.join(off)} module, and NXC_PROTOCOLS="
                f"{','.join(enabled)} does not enable {'it' if len(off) == 1 else 'them'}. Nothing "
                "ran; the operator has to enable the protocol to run it.")
    return (f"unknown module {module!r}: nxc lists no such -M module for {protocol} or any enabled "
            "protocol. Nothing ran; find the module's name with nxc_find_tool (dynamic mode) or "
            "nxc_search_tools.")


def register(mcp, get_config) -> None:
    """Attach the discovery + (offensive-gated) escape-hatch meta-tools."""

    @mcp.tool()
    async def nxc_list_modules(protocol: str = "smb", verbose: bool = False) -> dict:
        """List the nxc `-M` modules available for a protocol (recon/discovery).

        Runs `nxc <protocol> -L`. TERSE by default: each module is {name, category,
        privilege} (the full `-L` listing is ~16KB and the description rarely changes the
        decision). Pass `verbose=true` for full descriptions plus the `removed` (retired)
        list. No targets, never offensive.
        """
        outcome = await execute(get_config(), protocol, [], ["-L"], offensive=False)
        modules = parse_module_list(outcome.stdout)
        # `count` stays the number of RUNNABLE modules, so it keeps matching len(modules).
        if verbose:
            # `removed` is what nxc still lists but retired: without it the response looks
            # complete while the capability is simply absent (reads as "nxc cannot do this").
            return {
                "protocol": protocol,
                "count": len(modules),
                "modules": modules,
                "removed": parse_removed_modules(outcome.stdout),
            }
        terse = [{"name": m.get("name"), "category": m.get("category"),
                  "privilege": m.get("privilege")} for m in modules]
        return {
            "protocol": protocol,
            "count": len(terse),
            "modules": terse,
            "note": "terse view; pass verbose=true for descriptions and the retired-module list.",
        }

    @mcp.tool()
    async def nxc_search_tools(query: str, protocol: str = "smb") -> dict:
        """Search a protocol's `-M` modules by keyword (recon/discovery).

        Case-insensitive substring match over module name and description.
        """
        outcome = await execute(get_config(), protocol, [], ["-L"], offensive=False)
        modules = [m for m in parse_module_list(outcome.stdout) if _matches(m, query)]
        # Retired modules are filtered on the query too: an unfiltered `removed` would answer
        # every search with the same 4-7 dead names, trading a bad result for pure noise.
        removed = [m for m in parse_removed_modules(outcome.stdout) if _matches(m, query)]
        return {
            "protocol": protocol,
            "query": query,
            "count": len(modules),
            "modules": modules,
            "removed": removed,
        }

    @mcp.tool()
    async def nxc_run_module(
        protocol: str,
        targets: list[str],
        module: str,
        module_options: dict[str, str] | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
    ) -> dict:
        """Run an nxc `-M` module against targets (`nxc <proto> <targets> -M <module> -o K=V`).

        For standard recon a dedicated `smb_*`/`ldap_*` tool is usually better; this is
        for the `-M` module long tail. Discover modules first with
        `nxc_list_modules`/`nxc_search_tools` (read-only, run nothing).

        Gating is **category-aware** (from the module's `-L` category): `ENUMERATION`
        modules run in `recon`; `CREDENTIAL_DUMPING` (read-only credential harvest) needs
        `NXC_MODE=loot`; `PRIVILEGE_ESCALATION`/unknown need `NXC_MODE=full`. If the
        category can't be determined, it is gated as full-only offensive (conservative).

        Modules are protocol-specific (`raisechild` exists only for ldap, `nanodump` for smb
        and mssql): nxc_find_tool's suggested_call carries the right protocol, and a protocol
        that does not list the module gets an error naming the right one; nothing runs.
        """
        # A retired module is refused HERE, from a constant, before anything else. Two reasons
        # it cannot be derived from a live `-L`: `_module_categories` needs an execution, which
        # dry_run/suggest mode does not perform (so the set would be empty exactly where the
        # preview matters), and without this guard the call falls through to the conservative
        # gate below and is refused as an "offensive, state-changing action requiring
        # NXC_MODE=full" -- a wrong reason that invites the model to ask for mode elevation for
        # a module that no longer exists.
        if module in REMOVED_MODULE_NOTES:
            raise ValueError(f"module {module!r} no longer exists: {removed_module_note(module)}")

        cfg = get_config()
        offensive = True   # conservative default
        dump = False       # unknown -> full-only, not loot
        # Suggest mode previews regardless: classify only when executing, and only on an enabled
        # protocol (execute() refuses the others, once in the audit).
        if not cfg.dry_run and protocol in cfg.protocols:
            try:
                cats = await _module_categories(get_config, protocol)
            except Exception:  # noqa: BLE001 -- couldn't classify -> gate it
                cats = {}
            # A module this protocol does not list used to fall through to the full-only gate:
            # "requires NXC_MODE=full" in recon/loot (the wrong reason), an nxc error in full.
            # An EMPTY map is a failed -L, not an absent module: the conservative gate stays.
            if cats and module not in cats:
                supported = await _find_module_protocols(get_config, module, protocol)
                raise ValueError(_wrong_protocol_error(module, protocol, supported, cfg.protocols))
            category = cats.get(module)
            offensive = category != _RECON_CATEGORY
            dump = category == _DUMP_CATEGORY  # loot-permitted credential dumping

        auth = build_auth_flags(
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id,
        )
        extra = ["-M", module]
        if module_options:
            extra.append("-o")
            extra += [f"{k}={v}" for k, v in module_options.items()]
        outcome = await execute(cfg, protocol, targets, auth + extra, offensive=offensive, dump=dump)
        return outcome.to_dict()

    @mcp.tool()
    async def nxc_raw_command(
        protocol: str,
        targets: list[str],
        args: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
    ) -> dict:
        """Escape hatch / LAST RESORT: run an arbitrary nxc invocation.

        PREFER A DEDICATED TOOL. Standard SMB recon is already covered by, e.g.,
        `smb_enum_hosts` (host fingerprint + auth/guest/null check), `smb_shares`,
        `smb_users`, `smb_groups`, `smb_sessions`, `smb_pass_pol`, `smb_rid_brute`.
        Use `nxc_search_tools`/`nxc_list_modules` to discover capabilities. Only use
        this for flags no dedicated tool exposes.

        `args` is a list of raw argv tokens (e.g. ["--smb-timeout", "5"]); nothing is
        shell-interpreted. Auth params are prepended for convenience.
        OFFENSIVE-GATED: refused unless NXC_MODE=full.
        """
        auth = build_auth_flags(
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id,
        )
        outcome = await execute(get_config(), protocol, targets, auth + list(args), offensive=True)
        return outcome.to_dict()
