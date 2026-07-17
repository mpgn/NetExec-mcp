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

import re

from .auth import build_auth_flags
from .executor import execute

# A module line in `nxc <proto> -L` output (after ANSI strip):
#   [*] enum_av                   Gathers information on ...
_MODULE_RE = re.compile(r"^\[\*\]\s+(?P<name>\S+)\s+(?P<desc>.*)$")
# Privilege banner: "LOW PRIVILEGE MODULES" / "HIGH PRIVILEGE MODULES".
_PRIV_RE = re.compile(r"^(?P<level>LOW|HIGH) PRIVILEGE MODULES$", re.IGNORECASE)


def parse_module_list(text: str) -> list[dict]:
    """Parse `nxc <proto> -L` stdout into structured module records.

    Each record: ``{name, description, category, privilege}``. Category headers
    (e.g. ENUMERATION) and privilege banners are tracked as we scan and attached
    to the modules beneath them. Modules tagged ``[REMOVED]`` are skipped.
    """
    modules: list[dict] = []
    privilege: str | None = None
    category: str | None = None

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        m = _MODULE_RE.match(line)
        if m:
            desc = m["desc"].strip()
            if "[REMOVED]" in desc:
                continue
            modules.append(
                {
                    "name": m["name"],
                    "description": desc,
                    "category": category,
                    "privilege": privilege,
                }
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

    return modules


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


def register(mcp, get_config) -> None:
    """Attach the discovery + (offensive-gated) escape-hatch meta-tools."""

    @mcp.tool()
    async def nxc_list_modules(protocol: str = "smb") -> dict:
        """List the nxc `-M` modules available for a protocol (recon/discovery).

        Runs `nxc <protocol> -L` and returns structured records
        (name, description, category, privilege). No targets, never offensive.
        """
        outcome = await execute(get_config(), protocol, [], ["-L"], offensive=False)
        modules = parse_module_list(outcome.stdout)
        return {"protocol": protocol, "count": len(modules), "modules": modules}

    @mcp.tool()
    async def nxc_search_tools(query: str, protocol: str = "smb") -> dict:
        """Search a protocol's `-M` modules by keyword (recon/discovery).

        Case-insensitive substring match over module name and description.
        """
        outcome = await execute(get_config(), protocol, [], ["-L"], offensive=False)
        modules = [m for m in parse_module_list(outcome.stdout) if _matches(m, query)]
        return {"protocol": protocol, "query": query, "count": len(modules), "modules": modules}

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
        """
        cfg = get_config()
        offensive = True   # conservative default
        dump = False       # unknown -> full-only, not loot
        if not cfg.dry_run:  # suggest mode previews regardless; classify only when executing
            try:
                cats = await _module_categories(get_config, protocol)
                category = cats.get(module)
                offensive = category != _RECON_CATEGORY
                dump = category == _DUMP_CATEGORY  # loot-permitted credential dumping
            except Exception:
                offensive = True  # couldn't classify -> gate it

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
