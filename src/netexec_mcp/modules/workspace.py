"""Workspace-DB reads -- offline recall of what nxc already collected.

NetExec persists results to per-protocol SQLite files at
``~/.nxc/workspaces/<workspace>/<proto>.db``. These ``workspace_*`` tools READ
those files: no target is contacted, no credentials are needed, nothing is
executed. They surface data that stdout parsing structurally cannot reconstruct
-- the relational tables (who-is-admin-where, who-is-logged-in-where) -- plus a
cumulative host inventory, and they correlate one account's reach across every
protocol.

Registered unconditionally as a meta capability (like :mod:`meta`/:mod:`resources`),
not via the protocol REGISTRARS, because reading a local file is independent of
whether a protocol is enabled.

**Schema-adaptive by design.** The per-protocol schemas drift, so the readers
introspect the columns/tables actually present rather than hardcoding them:
  * The principal (credential) table is ``users`` for smb/ldap/mssql/winrm but
    ``credentials`` for ssh, and the relation FK is ``userid`` vs ``credid`` --
    captured in ``_BINDINGS``.
  * ``ssh`` has no ``domain`` on its principals, uses ``host``/``banner`` instead
    of ``ip``/``hostname``, and carries a ``shell`` flag on logins.
  * ``ldap`` has no relation tables at all (hosts + users only).
  * ``hosts`` columns differ per protocol (smb's vuln flags, ldap's
    signing_required/channel_binding, mssql's instances, winrm's port) -- so
    host reads select ``*`` and adapt.
A missing table (schema churn -- nxc has force-reinitialised winrm.db/rdp.db
before) is treated as "no data", never a crash.

``workspace_creds`` returns the stored secret in EVERY mode: reading nxc's own
workspace DB is a local file read, not an action against a target, so the
recon<loot<full gate (which governs target-side actions) does not apply. Deferred to
a later slice: ``shares`` (its ``hostid`` stores a hostname string, not an int FK),
``groups``/``group_relations``, and ssh ``keys``.
"""

from __future__ import annotations

import datetime
import sqlite3
from pathlib import Path

from ..config import nxc_workspace_dir

# Base dir for nxc workspaces, resolved via nxc's own NXC_PATH/~/.nxc logic so our
# reads track wherever nxc writes (see config.nxc_home). Module-level so tests can
# repoint it at a fixture; NXC_PATH is read once here at import, mirroring
# nxc/paths.py (the process env is fixed at launch).
_WORKSPACES_ROOT = nxc_workspace_dir()

# The only true structural drift for joins: (principal table, relation FK column).
_BINDINGS = {
    "smb": ("users", "userid"),
    "ldap": ("users", "userid"),
    "mssql": ("users", "userid"),
    "winrm": ("users", "userid"),
    "ssh": ("credentials", "credid"),
}

# Columns nxc stores as BOOLEAN (0/1/NULL) across the various schemas (smb vuln
# flags, ldap signing_required, ssh shell, mssql encryptionReq, nfs root_escape).
_BOOL_COLS = {"dc", "smbv1", "signing", "spooler", "zerologon", "petitpotam",
              "signing_required", "shell", "encryptionReq", "root_escape"}

# Principal identity surfaced on a relation row (host's own `domain` is dropped to
# avoid a name clash -- the principal's domain is the meaningful one).
_PRINCIPAL_ID_ADMIN = ["domain", "username", "credtype"]
_PRINCIPAL_ID_SESSION = ["domain", "username"]
_HOST_ID = ["ip", "hostname", "host", "os"]


def resolve_workspace(config, override: str | None = None) -> str:
    """Effective workspace name: explicit arg > NXC_WORKSPACE > "default"."""
    if override and override.strip():
        return override.strip()
    configured = getattr(config, "workspace", None)
    if configured and configured.strip():
        return configured.strip()
    return "default"


def db_path(workspace: str, proto: str) -> Path:
    """Resolve ``~/.nxc/workspaces/<workspace>/<proto>.db`` (no I/O)."""
    return _WORKSPACES_ROOT / workspace / f"{proto}.db"


def _collected_at(path: Path) -> str | None:
    """The DB file's mtime as ISO -- a coarse 'last collected' signal."""
    try:
        ts = path.stat().st_mtime
    except OSError:
        return None
    return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")


def _open(path: Path) -> sqlite3.Connection:
    """Open the DB read-only (mode=ro URI) -- we can never mutate nxc's state."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _cols(con: sqlite3.Connection, table: str) -> set[str]:
    """Column names of a table; empty set if the table is absent."""
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def _as_bool(value):
    """SQLite stores BOOLEAN as 0/1/NULL; keep NULL as None (= 'not checked')."""
    return None if value is None else bool(value)


def _host_label(row: dict) -> str:
    return row.get("hostname") or row.get("ip") or row.get("host") or "?"


# --- readers (take a concrete db path -> trivially unit-testable) --------------

def read_hosts(path: Path) -> list[dict]:
    """Every host row, sans id, with known BOOLEAN columns coerced. Adapts to
    whatever columns the protocol's `hosts` table has."""
    con = _open(path)
    try:
        cols = _cols(con, "hosts")
        if not cols:
            return []
        sel = [c for c in cols if c != "id"]
        rows = [dict(r) for r in con.execute(
            f"SELECT {', '.join(sel)} FROM hosts ORDER BY id").fetchall()]
        for r in rows:
            for c in list(r):
                if c in _BOOL_COLS:
                    r[c] = _as_bool(r[c])
        return rows
    finally:
        con.close()


def read_creds(path: Path, proto: str, reveal: bool) -> list[dict]:
    """Principal/credential rows `{domain?, username, credtype, secret}`. `secret` (the
    stored password/hash) is revealed only when `reveal`; otherwise nulled with
    `redacted: true`. The DB row id is NOT surfaced: nxc's ``-id`` is per-protocol, so an
    id would name a different account under another protocol -- reuse goes by
    username + secret (+ domain) instead."""
    if proto not in _BINDINGS:
        return []
    table, _ = _BINDINGS[proto]
    con = _open(path)
    try:
        cols = _cols(con, table)
        if not cols:
            return []
        sel = [c for c in cols if c not in {"id", "pillaged_from_hostid"}]
        rows = [dict(r) for r in con.execute(
            f"SELECT {', '.join(sel)} FROM {table} ORDER BY username").fetchall()]
        for r in rows:
            if "password" in r:
                r["secret"] = r.pop("password")
            r["redacted"] = not reveal
            if not reveal and "secret" in r:
                r["secret"] = None
        return rows
    finally:
        con.close()


def read_relation(path: Path, proto: str, kind: str,
                  username: str | None = None, host: str | None = None) -> list[dict]:
    """who-is-admin-where (`kind="admin"`) / logged-in-where (`kind="loggedin"`).

    Joins ``<kind>_relations`` x principal x hosts, selecting only the identity
    columns that exist for this protocol. Returns ``[]`` if any required table is
    missing (e.g. ldap, which records no relations)."""
    if proto not in _BINDINGS:
        return []
    ptable, fk = _BINDINGS[proto]
    rel = f"{kind}_relations"
    con = _open(path)
    try:
        rcols = _cols(con, rel)
        pcols = _cols(con, ptable)
        hcols = _cols(con, "hosts")
        if not (rcols and pcols and hcols):
            return []
        want_p = _PRINCIPAL_ID_ADMIN if kind == "admin" else _PRINCIPAL_ID_SESSION
        psel = [c for c in want_p if c in pcols]
        hsel = [c for c in _HOST_ID if c in hcols]
        select = [f"p.{c} AS {c}" for c in psel] + [f"h.{c} AS {c}" for c in hsel]
        if kind == "loggedin" and "shell" in rcols:
            select.append("r.shell AS shell")
        sql = (f"SELECT {', '.join(select)} FROM {rel} r "
               f"JOIN {ptable} p ON p.id = r.{fk} "
               f"JOIN hosts h ON h.id = r.hostid WHERE 1=1")
        params: list = []
        if username and username.strip() and "username" in psel:
            sql += " AND UPPER(p.username) = UPPER(?)"
            params.append(username.strip())
        if host and host.strip():
            host_cols = [c for c in ("ip", "hostname", "host") if c in hcols]
            if host_cols:
                sql += " AND (" + " OR ".join(f"UPPER(h.{c}) = UPPER(?)" for c in host_cols) + ")"
                params += [host.strip()] * len(host_cols)
        order = (["p.username"] if "username" in psel else []) + \
                [f"h.{c}" for c in ("ip", "hostname", "host") if c in hsel]
        if order:
            sql += " ORDER BY " + ", ".join(order)
        rows = [dict(r) for r in con.execute(sql, tuple(params)).fetchall()]
        if kind == "loggedin":
            for r in rows:
                if "shell" in r:
                    r["shell"] = _as_bool(r["shell"])
        return rows
    finally:
        con.close()


def cred_reach(workspace: str, username: str | None = None) -> tuple[list[str], list[dict]]:
    """Cross-protocol correlation: where each account is admin / logged-in / known.

    Scans every protocol DB present in the workspace and groups by bare username
    (case-insensitive). Returns ``(protocols_scanned, accounts)`` where each
    account is ``{username, domains, cred_protocols, reach:[{protocol, relation,
    host}]}``. No secrets -- it reports *where* a credential is known, not its
    value, so it stays recon-safe."""
    accounts: dict[str, dict] = {}
    scanned: list[str] = []
    want = username.strip().lower() if username and username.strip() else None

    def _acct(uname: str) -> dict:
        return accounts.setdefault(uname.lower(), {
            "username": uname, "domains": set(), "reach": [], "cred_protocols": set()})

    for proto in _BINDINGS:
        path = db_path(workspace, proto)
        if not path.exists():
            continue
        scanned.append(proto)
        for kind, label in (("admin", "admin"), ("loggedin", "session")):
            for row in read_relation(path, proto, kind, username=username):
                uname = row.get("username")
                if not uname:
                    continue
                acct = _acct(uname)
                if row.get("domain"):
                    acct["domains"].add(row["domain"])
                acct["reach"].append({"protocol": proto, "relation": label,
                                      "host": _host_label(row)})
        for row in read_creds(path, proto, reveal=False):
            uname = row.get("username")
            if not uname or (want and uname.lower() != want):
                continue
            acct = _acct(uname)
            if row.get("domain"):
                acct["domains"].add(row["domain"])
            acct["cred_protocols"].add(proto)

    out = [{
        "username": a["username"],
        "domains": sorted(a["domains"]),
        "cred_protocols": sorted(a["cred_protocols"]),
        "reach": a["reach"],
    } for a in accounts.values()]
    out.sort(key=lambda a: (-len(a["reach"]), a["username"].lower()))
    return scanned, out


def match_stored_cred(config, proto: str, username: str) -> list[dict]:
    """Stored credentials for `username` in ONE protocol's workspace DB (secret revealed).

    Used by the executor's auth-nudge: when a tool is called with a named account but no
    secret, this finds a reusable credential nxc already holds -- so the caller retries with
    real auth instead of a doomed guest bind. PROTOCOL-SCOPED (ids/domains are per-DB, so a
    match here is only valid for this protocol's tools). Returns [] when the protocol keeps
    no principal table, the DB is absent, or the user isn't stored."""
    if proto not in _BINDINGS or not (username and username.strip()):
        return []
    path = db_path(resolve_workspace(config), proto)
    if not path.exists():
        return []
    want = username.strip().lower()
    return [c for c in read_creds(path, proto, reveal=True)
            if (c.get("username") or "").lower() == want]


# --- tool envelope + registration ---------------------------------------------

def _table_exists(path: Path, table: str) -> bool:
    con = _open(path)
    try:
        return bool(_cols(con, table))
    finally:
        con.close()


def _invalid_protocol(protocol: str) -> dict | None:
    if protocol not in _BINDINGS:
        return {"error": f"unknown protocol {protocol!r}",
                "valid_protocols": sorted(_BINDINGS)}
    return None


def _envelope(config, ws_override, proto, key, reader, *, rel_table=None) -> dict:
    """Resolve the DB path, build the standard response, handle a missing DB/table.

    ``reader`` is ``callable(path) -> list``, invoked only when the DB exists."""
    ws = resolve_workspace(config, ws_override)
    path = db_path(ws, proto)
    base = {"workspace": ws, "protocol": proto, "source": str(path)}
    if not path.exists():
        return {**base, "available": False, "collected_at": None, "count": 0, key: [],
                "note": f"{proto}.db not found in workspace {ws!r}; run the live "
                        f"{proto}_* tools to populate it."}
    data = reader(path)
    result = {**base, "available": True, "collected_at": _collected_at(path),
              "count": len(data), key: data}
    if not data and rel_table and not _table_exists(path, rel_table):
        result["note"] = (f"{proto}.db has no {rel_table} table -- this protocol "
                          f"records no {key}.")
    return result


def register(mcp, get_config) -> None:
    """Attach the read-only workspace-DB recall + correlation tools.

    `protocol` is one of: smb, ldap, mssql, winrm, ssh. Relation views
    (admins/loggedin) exist for all but ldap, which records hosts + users only.
    """

    @mcp.tool()
    async def workspace_hosts(protocol: str = "smb", workspace: str | None = None) -> dict:
        """Host inventory from a protocol's nxc workspace DB -- NO target contacted.

        Returns the hosts earlier `<protocol>_*` runs recorded, with whatever
        columns that protocol stores: smb adds dc/smbv1/signing/spooler/zerologon/
        petitpotam vuln flags (a flag of `null` = not checked); ldap adds
        signing_required/channel_binding; ssh has host/banner. May be stale (see
        `collected_at`); `available: false` means the DB isn't populated yet.
        """
        if (err := _invalid_protocol(protocol)):
            return err
        return _envelope(get_config(), workspace, protocol, "hosts", read_hosts)

    @mcp.tool()
    async def workspace_admins(
        protocol: str = "smb",
        workspace: str | None = None,
        username: str | None = None,
        host: str | None = None,
    ) -> dict:
        """WHO-IS-ADMIN-WHERE from a protocol's workspace DB (no target contacted).

        Joins `admin_relations` x principal x hosts: each row is a stored
        credential with admin on a host. This relation is never in stdout -- it
        only exists in the DB. Optional `username` (exact, case-insensitive) /
        `host` (matches ip/hostname/host) filters. ldap records no relations.
        """
        if (err := _invalid_protocol(protocol)):
            return err
        return _envelope(
            get_config(), workspace, protocol, "admins",
            lambda p: read_relation(p, protocol, "admin", username, host),
            rel_table="admin_relations",
        )

    @mcp.tool()
    async def workspace_loggedin(
        protocol: str = "smb",
        workspace: str | None = None,
        username: str | None = None,
        host: str | None = None,
    ) -> dict:
        """WHO-IS-LOGGED-IN-WHERE from a protocol's workspace DB (no target).

        Joins `loggedin_relations` x principal x hosts into a session map for
        lateral-movement targeting (ssh rows also carry a `shell` flag). Same
        optional `username`/`host` filters as `workspace_admins`.
        """
        if (err := _invalid_protocol(protocol)):
            return err
        return _envelope(
            get_config(), workspace, protocol, "sessions",
            lambda p: read_relation(p, protocol, "loggedin", username, host),
            rel_table="loggedin_relations",
        )

    @mcp.tool()
    async def workspace_creds(protocol: str = "smb", workspace: str | None = None) -> dict:
        """Credentials already collected into a protocol's workspace DB (no target).

        Reads the principal table (`users`, or `credentials` for ssh):
        `{domain?, username, credtype, secret}`. The stored `secret` (password or hash) is
        returned in EVERY mode: reading nxc's own workspace DB is a LOCAL file read, not an
        action against a target, so the recon<loot<full gate (which governs target-side
        actions -- dumping/exec) does not apply. Reuse a listed account by passing its
        `username` + `secret` to a tool (as `password=`, or `ntlm_hash=` when
        `credtype == "hash"`) together with its `domain`. If a tool is called with a username
        but no secret and one is stored here, the server auto-suggests it (`auth_suggestion`).
        """
        if (err := _invalid_protocol(protocol)):
            return err
        cfg = get_config()
        # A LOCAL DB read is not a target action, so it is NOT gated by recon<loot<full
        # (that ladder governs what nxc does TO a target). Always return the stored secret
        # -- it is often one the caller supplied, and the file is locally readable anyway.
        result = _envelope(cfg, workspace, protocol, "credentials",
                           lambda p: read_creds(p, protocol, reveal=True))
        result["revealed"] = True
        return result

    @mcp.tool()
    async def workspace_cred_reach(workspace: str | None = None, username: str | None = None) -> dict:
        """CROSS-PROTOCOL CORRELATION -- one account's reach across all DBs (no target).

        Scans every protocol workspace DB (smb/ldap/mssql/winrm/ssh) and groups by
        username: where each account is admin, where it has a live session, and
        which protocols hold a credential for it. Answers "what does account X own
        across the whole estate" -- the thing no single stdout parse can. Optional
        `username` filter. Reports *where* creds are known, not their value
        (recon-safe). `available: false`-style emptiness shows as `protocols_scanned`.
        """
        cfg = get_config()
        ws = resolve_workspace(cfg, workspace)
        scanned, accounts = cred_reach(ws, username)
        return {
            "workspace": ws,
            "username_filter": username,
            "protocols_scanned": scanned,
            "count": len(accounts),
            "accounts": accounts,
            "note": None if scanned else
                    f"no protocol DBs found in workspace {ws!r}; run the live tools first.",
        }
