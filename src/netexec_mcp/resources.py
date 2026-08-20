"""MCP resources: cheatsheets/guides the client can read for context.

These surface the server's operating model (modes, auth, safety) and a live tool
catalog as MCP resources, so an agent can ground itself without trial and error.
"""

from __future__ import annotations

_OPERATING_MODES = """# Operating modes (`NXC_MODE`)

Four escalating levels controlling how much the server may *do*. The recon < loot <
full split mirrors nxc's own module taxonomy (ENUMERATION < CREDENTIAL_DUMPING <
PRIVILEGE_ESCALATION):

- **suggest** — nothing executes; tools return the resolved nxc command for a human
  (the auditor) to run. Scope is still enforced; offensive commands can be previewed.
- **recon** *(default)* — read-only enumeration executes; everything beyond it is refused.
- **loot** — additionally permits **read-only credential dumping** (sam / lsa / ntds /
  gpp / roasting / gMSA): no state change on the target, but it harvests secrets.
  State-changing actions (exec / write / spray / exploit) are still refused.
- **full** — everything executes, including state-changing / privilege-escalation actions.

Set via `NXC_MODE`; defaults to `recon` when unset.

A tool's gating is fixed by what it does: enumeration tools are recon; credential
dumping is loot; exec / file writes / spray / exploits are full. `nxc_run_module` is
**category-aware** — `ENUMERATION` → recon, `CREDENTIAL_DUMPING` → loot, everything
else → full.
"""

_AUTH = """# Authentication model

All tools share the same credential parameters (omit them for a null/anonymous bind
where allowed):

- `username` / `password` — basic creds. For a **guest** check, pass `username="guest"`
  only — the server adds the empty password automatically (`-u guest -p ''`).
- `ntlm_hash` — pass-the-hash (`-H`). Mutually exclusive with `password`.
- `domain` — `-d`. Omit (or use `local_auth=true`, SMB only) for local accounts.
- `local_auth` *(SMB only)* — authenticate locally to each target.
- `kerberos` / `use_kcache` — Kerberos auth (`-k` / from ccache).
- `cred_id` — use a credential already stored in nxc's DB (`-id`).
- `laps` — read the target's LAPS-managed local-admin password from AD and use it
  (pass the account name, e.g. `"administrator"`).

Spraying (SMB `smb_spray`): `usernames`/`passwords`/`ntlm_hashes` accept lists or
wordlist-file paths; `no_bruteforce` pairs them 1:1.

## Auth success vs. privilege
A `[+]` marker means the credentials **authenticated** — this is nxc's hardcoded
status marker, not configurable, so it's a reliable signal. nxc *additionally*
appends its **privilege label** when the account is admin/privileged on the target.
That label is operator-configurable (`pwn3d_label` in `nxc.conf`, default `Pwn3d!`).
This server's configured label is: **`{pwn3d_label}`** — match that, not a hardcoded
string. For an authoritative, config-independent "who is admin where", prefer
`workspace_admins` (reads the `admin_relations` table).
"""

_WORKFLOWS = """# Common workflows

**Verify access, then enumerate**
1. `smb_enum_hosts` (or `ldap_enum_hosts`) with creds → `[+]` confirms auth; nxc's
   privilege label (default `(Pwn3d!)`, configurable — see the auth guide) marks admin.
2. `smb_shares` / `smb_users` / `ldap_groups` / `ldap_computers` for recon.

**Dump credentials, then replay** *(full mode)*
1. `smb_sam` / `smb_lsa` / `smb_ntds` → each returns structured `secrets`/`credentials`.
2. Take an account + `nt` hash and replay: any tool with
   `username="ACCOUNT$"`, `ntlm_hash="<nt>"`.

**gMSA chain (cross-protocol)** *(full mode)*
1. `smb_lsa` → extract a `gmsa_id` and/or `_SC_GMSA_…` blob from its `secrets`.
2. `ldap_gmsa_convert_id` with the `gmsa_id` → resolves the account name (e.g. `gmsa-robin$`).
3. `ldap_gmsa_decrypt_lsa` with the blob → recovers the gMSA password.
4. Replay with `username="gmsa-robin$"` + the recovered hash/password.

**Module long tail**: discover with `nxc_list_modules` / `nxc_search_tools`, run with
`nxc_run_module` (ENUMERATION → recon; CREDENTIAL_DUMPING → loot; others need full).

**Reading a result**: `records`/`counts` summarise only the lines nxc tagged `[*]`/`[+]`/
`[-]`/`[!]`. Findings are often printed untagged, so those fields can read as "nothing
found" over a `stdout` full of results. `unparsed_lines` is the count of untagged
non-empty lines: when it is > 0, the summary is incomplete and `stdout` holds the payload.
Tools that document a structured list (`shares`, `secrets`, `hashes`, …) have already
extracted theirs.

**Recall vs. re-scan**: before re-running enumeration, check what's already collected.
`workspace_admins` / `workspace_loggedin` / `workspace_hosts` (pass `protocol=`) read
nxc's local workspace DB (no target, no creds), and `workspace_cred_reach` correlates an
account across all protocols. See guide `netexec://guide/workspace`. Use the live `*_*`
tools when you need fresh data.
"""

_WORKSPACE = """# Workspace DB (cached recall vs. live)

NetExec persists what it finds to per-protocol SQLite files under
`~/.nxc/workspaces/<workspace>/`. The `workspace_*` tools READ those files: no
target is contacted, no creds are needed, nothing executes -- they recall what
earlier live runs collected. `NXC_WORKSPACE` selects the store (default
`"default"`); override per call with the `workspace` argument. All tools take a
`protocol` arg (smb, ldap, mssql, winrm, ssh) except `workspace_cred_reach`,
which spans them all.

The collected data is ALSO browsable directly as resources (no tool call needed):
`netexec://workspace/credentials`, `netexec://workspace/admins`,
`netexec://workspace/loggedin`, `netexec://workspace/hosts`. Use those to read what's
stored; use the tools below when you need filtering (by username/host) or a specific protocol.

## Live vs. workspace -- which to call
- Haven't enumerated yet, or you need fresh ground truth -> **live** (`<proto>_*`).
- Want a relation stdout can't give -- who-is-admin-where, who-is-logged-in-where,
  the host vuln inventory -- or want to AVOID re-touching a target -> **workspace**.
- Want to recall something already collected this engagement -> **workspace**
  (free, offline).

## The tools
- `workspace_hosts(protocol)`      -- host inventory; smb adds zerologon/petitpotam/
  signing flags, ldap adds signing_required, ssh has host/banner.
- `workspace_admins(protocol)`     -- who-is-admin-where (admin_relations).
- `workspace_loggedin(protocol)`   -- who-is-logged-in-where (loggedin_relations).
- `workspace_creds(protocol)`      -- credentials collected; secret returned in every mode
  (local read, not a target action). Reuse via username + secret (+ domain) passed to a tool.
- `workspace_cred_reach(username?)` -- **cross-protocol**: one account's admin /
  session / known-credential reach across smb+ldap+mssql+winrm+ssh at once.

ldap records hosts + users only (no relations) -> its admins/loggedin views are
empty by design. ssh keys its principals on the `credentials` table (no domain).

## Caveats
- **Partial view** -- only what nxc chose to write (kerberoast/bloodhound don't
  fill the users table). Complements live enumeration, never replaces it.
- **Staleness** -- every result carries `collected_at` (the DB file mtime);
  refresh live if it's old. `available: false` means the DB isn't populated yet.
- Running the live `<proto>_*` tools is what KEEPS these DBs fresh (they write as a
  side effect). Live = act+record; workspace = recall.
"""

_SAFETY = """# Safety & guardrails

Enforced in a single choke point before any command runs:

- **Scope allowlist** (`NXC_SCOPE`) — every target must be in scope. **Fail-closed**:
  targets with no scope configured are rejected.
- **Mode gating** (`NXC_MODE`) — credential dumping needs `loot`; state-changing
  actions (exec/write/spray/exploit) need `full`; both refused in `recon`.
- **Target cap** (`NXC_MAX_TARGETS`) and per-call **timeout** (`NXC_TIMEOUT`).
- **Audit log** (`NXC_AUDIT_LOG`) — every command (executed, dry-run, or rejected)
  appended as one JSON line.
- **No shell** — nxc is invoked as an argv list; command/args are never shell-interpreted.

For **authorized** security testing only.
"""

_GUIDES = {
    "operating-modes": ("Operating modes (suggest/recon/loot/full)", _OPERATING_MODES),
    "auth": ("Authentication model", _AUTH),
    "workflows": ("Common workflows (incl. the gMSA chain)", _WORKFLOWS),
    "workspace": ("Workspace DB: cached recall vs. live", _WORKSPACE),
    "safety": ("Safety & guardrails", _SAFETY),
}


def register(mcp, get_config) -> None:
    """Attach cheatsheet + catalog resources to the FastMCP app."""

    def _make_guide(text: str):
        def guide() -> str:
            # Fill the configured privilege label at read time so the guide reflects
            # this server's nxc.conf, not a hardcoded string. `.replace` (not
            # `.format`) leaves any literal braces in the guides untouched.
            if "{pwn3d_label}" in text:
                cfg = get_config()
                label = getattr(cfg, "pwn3d_label", None) or "Pwn3d!"
                return text.replace("{pwn3d_label}", label)
            return text
        return guide

    for slug, (title, text) in _GUIDES.items():
        fn = _make_guide(text)
        fn.__name__ = f"guide_{slug.replace('-', '_')}"
        mcp.resource(
            f"netexec://guide/{slug}",
            name=title,
            mime_type="text/markdown",
        )(fn)

    @mcp.resource(
        "netexec://catalog/tools",
        name="Tool catalog",
        mime_type="text/markdown",
    )
    async def tool_catalog() -> str:
        """A live catalog of the registered tools, grouped by protocol/meta."""
        tools = await mcp.list_tools()
        groups: dict[str, list] = {}
        for t in sorted(tools, key=lambda x: x.name):
            prefix = t.name.split("_", 1)[0] if "_" in t.name else "other"
            groups.setdefault(prefix, []).append(t)
        lines = ["# Tool catalog", ""]
        for prefix in sorted(groups):
            lines.append(f"## {prefix} ({len(groups[prefix])})")
            for t in groups[prefix]:
                desc = (t.description or "").strip().splitlines()[0] if t.description else ""
                lines.append(f"- **{t.name}** — {desc}")
            lines.append("")
        return "\n".join(lines)

    # --- Workspace DATA as resources (not just the guide) -------------------------
    # A model asked for "credentials in the nxcdb" tends to browse RESOURCES (data)
    # rather than discover the workspace_* TOOLS -- and, finding only doc guides,
    # wrongly concludes there are none (observed: opencode + qwen3:14b). Surface the
    # collected data as readable resources too, so browsing finds it. Same data as the
    # tools (local read, no target contacted); the tools remain for filtered access.

    def _ws(cfg):
        from .modules import workspace
        return workspace, workspace.resolve_workspace(cfg)

    @mcp.resource("netexec://workspace/credentials",
                  name="Collected credentials (workspace DB)", mime_type="text/markdown")
    def workspace_credentials() -> str:
        ws, name = _ws(get_config())
        out = ["# Collected credentials (workspace DB)", "",
               f"Workspace `{name}`. Credentials nxc already stored (local read, no target "
               "contacted). Reuse an account by passing its `username` + secret to a tool "
               "(`password=`, or `ntlm_hash=` when credtype is `hash`) with its `domain`. For "
               "filtered access use the `workspace_creds` tool.", ""]
        found = False
        for proto in sorted(ws._BINDINGS):
            path = ws.db_path(name, proto)
            if not path.exists():
                continue
            rows = ws.read_creds(path, proto, reveal=True)
            if not rows:
                continue
            found = True
            out.append(f"## {proto} ({len(rows)})")
            for r in rows:
                dom = f"{r['domain']}\\" if r.get("domain") else ""
                out.append(f"- `{dom}{r['username']}` ({r.get('credtype')}) — `{r.get('secret')}`")
            out.append("")
        if not found:
            out.append(f"_No credentials stored yet in workspace `{name}`. Run the live tools "
                       "(e.g. `smb_enum_hosts` with creds) to populate it._")
        return "\n".join(out)

    @mcp.resource("netexec://workspace/admins",
                  name="Who-is-admin-where (workspace DB)", mime_type="text/markdown")
    def workspace_admins_resource() -> str:
        ws, name = _ws(get_config())
        out = ["# Who-is-admin-where (workspace DB)", "",
               f"Workspace `{name}`. Stored `admin_relations`: which account is admin on "
               "which host (local read). For filters use the `workspace_admins` tool.", ""]
        found = False
        for proto in sorted(ws._BINDINGS):
            path = ws.db_path(name, proto)
            if not path.exists():
                continue
            rows = ws.read_relation(path, proto, "admin")
            if not rows:
                continue
            found = True
            out.append(f"## {proto} ({len(rows)})")
            for r in rows:
                dom = f"{r['domain']}\\" if r.get("domain") else ""
                host = r.get("hostname") or r.get("ip") or r.get("host") or "?"
                out.append(f"- `{dom}{r.get('username')}` → **{host}**")
            out.append("")
        if not found:
            out.append("_No admin relations recorded yet (ldap records none by design)._")
        return "\n".join(out)

    @mcp.resource("netexec://workspace/loggedin",
                  name="Who-is-logged-in-where (workspace DB)", mime_type="text/markdown")
    def workspace_loggedin_resource() -> str:
        ws, name = _ws(get_config())
        out = ["# Who-is-logged-in-where (workspace DB)", "",
               f"Workspace `{name}`. Stored `loggedin_relations`: which account has a session "
               "on which host (local read) -- lateral-movement targeting. For filters use the "
               "`workspace_loggedin` tool.", ""]
        found = False
        for proto in sorted(ws._BINDINGS):
            path = ws.db_path(name, proto)
            if not path.exists():
                continue
            rows = ws.read_relation(path, proto, "loggedin")
            if not rows:
                continue
            found = True
            out.append(f"## {proto} ({len(rows)})")
            for r in rows:
                dom = f"{r['domain']}\\" if r.get("domain") else ""
                host = r.get("hostname") or r.get("ip") or r.get("host") or "?"
                shell = " (shell)" if r.get("shell") else ""
                out.append(f"- `{dom}{r.get('username')}` → **{host}**{shell}")
            out.append("")
        if not found:
            out.append("_No login sessions recorded yet._")
        return "\n".join(out)

    @mcp.resource("netexec://workspace/hosts",
                  name="Host inventory (workspace DB)", mime_type="text/markdown")
    def workspace_hosts_resource() -> str:
        ws, name = _ws(get_config())
        out = ["# Host inventory (workspace DB)", "",
               f"Workspace `{name}`. Hosts nxc has recorded (local read). For per-protocol "
               "columns use the `workspace_hosts` tool.", ""]
        found = False
        for proto in ("smb", "ldap", "mssql", "winrm", "rdp", "ssh", "nfs"):
            path = ws.db_path(name, proto)
            if not path.exists():
                continue
            rows = ws.read_hosts(path)
            if not rows:
                continue
            found = True
            out.append(f"## {proto} ({len(rows)})")
            for r in rows:
                label = r.get("hostname") or r.get("host") or "?"
                ip = r.get("ip") or r.get("host") or ""
                extra = " · ".join(x for x in (r.get("os"), r.get("domain")) if x)
                out.append(f"- **{label}** {ip}{(' · ' + extra) if extra else ''}".rstrip())
            out.append("")
        if not found:
            out.append("_No hosts recorded yet._")
        return "\n".join(out)
