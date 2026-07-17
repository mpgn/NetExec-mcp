"""MSSQL protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. MSSQL (TDS, port 1433) is a frequent
AD foothold -- auth maps to SQL logins / Windows auth, and `sysadmin` grants
``xp_cmdshell``-style RCE. The tools span:

  * **Read-only** (``offensive=False``) -- auth check / fingerprint, database &
    table listing, and RID brute-forcing (SID enumeration).
  * **Offensive** (``offensive=True``, only under ``NXC_MODE=full``) -- arbitrary
    T-SQL queries (write-capable), command execution (cmd / PowerShell, needs
    sysadmin), credential dumping (sam/lsa), and file get/put.

**Auth model.** Unlike WinRM, nxc's MSSQL connection implements a real
``kerberos_login`` (and ``pfx_auth`` routes certificate auth through it), so MSSQL
honours the **full** credential model: user/pass, ``-H`` PtH, Kerberos
(``-k``/``--use-kcache``/``--aesKey``/``--kdcHost``/ccache), certificate
(pfx/pem), ``-d`` domain, ``--local-auth``, and stored ``cred_id``. It does **not**
have ``--laps`` (that flag is smb/winrm-only), so LAPS is omitted here. The
MSSQL-specific transport knobs ``--port`` (default 1433) and ``--mssql-timeout``
are exposed on every tool.

Note: ``mssql_query`` runs **arbitrary T-SQL** (a write-capable primitive), so it
is offensive-gated rather than treated as read-only recon. Use ``mssql_database``
/ ``mssql_rid_brute`` for read-only enumeration in recon mode.
"""

from __future__ import annotations

from ..auth import build_auth_flags
from ..executor import execute
from ..results import (
    parse_lsa_secrets,
    parse_mssql_databases,
    parse_mssql_impersonate,
    parse_mssql_links,
    parse_mssql_logins,
    parse_mssql_tables,
    parse_rid_brute,
    parse_secretsdump,
)


async def _mssql_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    dump: bool = False,
    extra_flags: list[str] | None = None,
    port=None,
    mssql_timeout=None,
    username=None,
    password=None,
    ntlm_hash=None,
    domain=None,
    local_auth=False,
    kerberos=False,
    use_kcache=False,
    cred_id=None,
    kdc_host=None,
    aes_key=None,
    ccache=None,
    pfx_cert=None,
    pfx_base64=None,
    pfx_pass=None,
    pem_cert=None,
    pem_key=None,
) -> dict:
    """Build auth + transport + action flags and run against the mssql protocol.

    MSSQL supports the full auth model except ``--laps`` (see module docstring).
    """
    auth = build_auth_flags(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        local_auth=local_auth,
        kerberos=kerberos,
        use_kcache=use_kcache,
        cred_id=cred_id,
        kdc_host=kdc_host,
        aes_key=aes_key,
        ccache=ccache,
        pfx_cert=pfx_cert,
        pfx_base64=pfx_base64,
        pfx_pass=pfx_pass,
        pem_cert=pem_cert,
        pem_key=pem_key,
    )
    transport: list[str] = []
    if port is not None:
        transport += ["--port", str(port)]
    if mssql_timeout is not None:
        transport += ["--mssql-timeout", str(mssql_timeout)]
    extra = auth + transport + list(action_flags) + list(extra_flags or [])
    outcome = await execute(get_config(), "mssql", targets, extra,
                            offensive=offensive, dump=dump, ccache=ccache)
    return outcome.to_dict()


async def _mssql_module(get_config, module, targets, *, offensive=False, dump=False, options=None, **kw) -> dict:
    """Run a promoted `-M <module>` (with `-o KEY=val` options) on the mssql protocol."""
    flags = ["-M", module]
    kv = [f"{k}={v}" for k, v in (options or {}).items() if v is not None and v != ""]
    if kv:
        flags += ["-o", *kv]
    return await _mssql_run(get_config, flags, targets, offensive=offensive, dump=dump, **kw)


def register(mcp, get_config) -> None:
    """Attach the MSSQL tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def mssql_enum_hosts(
        targets: list[str],
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Fingerprint MSSQL and verify authentication (bare `nxc mssql <targets>`).

        Reports SQL Server edition/version, instance count, NTLM support and encryption,
        plus the auth result (`[+]`, with `Pwn3d!` when the login holds the `sysadmin`
        role). Pass credentials to authenticate, or none to fingerprint the service.
        `port` overrides 1433; `mssql_timeout` the connection timeout.
        """
        return await _mssql_run(
            get_config, [], targets, port=port, mssql_timeout=mssql_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache,
            cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache,
            pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert,
            pem_key=pem_key,
        )

    @mcp.tool()
    async def mssql_database(
        targets: list[str],
        name: str | None = None,
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """List databases, or tables within one (`--database [name]`). Read-only.

        Omit `name` to enumerate all databases (structured `databases` list of
        `{host, name, owner}`); pass a database `name` to list its user tables (structured
        `tables` list of `{host, name, modified}`). Read-only metadata enumeration.
        """
        # --database is nargs="?" const=True: bare flag lists DBs, a value lists tables.
        flags = ["--database"] + ([name] if name else [])
        result = await _mssql_run(
            get_config, flags, targets, port=port, mssql_timeout=mssql_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache,
            cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache,
            pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert,
            pem_key=pem_key,
        )
        if name:
            result["tables"] = parse_mssql_tables(result["stdout"])
        else:
            result["databases"] = parse_mssql_databases(result["stdout"])
        return result

    @mcp.tool()
    async def mssql_rid_brute(
        targets: list[str],
        max_rid: int | None = None,
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate domain users by brute-forcing RIDs via the SQL server (`--rid-brute [max]`).

        Uses `SUSER_SNAME(SID_BINARY(...))` to resolve RIDs to account names (default max
        RID 4000; override with `max_rid`). Read-only; needs a valid login but not sysadmin.
        Only works when the server is domain-joined.

        Includes a structured `accounts` list: `{host, rid, domain, account, sid_type}`
        per resolved SID (users, groups, and machine accounts alike; `sid_type` is
        `None` for mssql).
        """
        flags = ["--rid-brute"] + ([str(max_rid)] if max_rid is not None else [])
        result = await _mssql_run(
            get_config, flags, targets, port=port, mssql_timeout=mssql_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache,
            cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache,
            pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert,
            pem_key=pem_key,
        )
        result["accounts"] = parse_rid_brute(result["stdout"])
        return result

    # ---- Offensive (loot for read-only credential/file harvest; full for write/exec) ---- #

    @mcp.tool()
    async def mssql_query(
        targets: list[str],
        query: str,
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Execute an arbitrary T-SQL query against the server (`-q <query>`).

        OFFENSIVE-GATED (NXC_MODE=full): `-q` runs **any** T-SQL -- including writes,
        config changes (e.g. enabling `xp_cmdshell`) and stored-proc calls -- so it is not
        treated as read-only recon. For read-only enumeration use `mssql_database` /
        `mssql_rid_brute`. The query is passed as a single argv token.
        """
        if not query or not query.strip():
            raise ValueError("query is required for mssql_query")
        return await _mssql_run(
            get_config, ["-q", query], targets, offensive=True, port=port,
            mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def mssql_exec(
        targets: list[str],
        command: str,
        use_powershell: bool = False,
        no_output: bool = False,
        force_ps32: bool = False,
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Run a command on the target via MSSQL (`-x`, or `-X` for PowerShell).

        Executes through mssqlexec (xp_cmdshell / sp_OACreate style). Set `use_powershell`
        to run `command` as PowerShell (`-X`); `no_output` to skip output retrieval;
        `force_ps32` to run PowerShell in a 32-bit process (`--force-ps32`). The command is
        a single argv token. OFFENSIVE-GATED (NXC_MODE=full): also requires the login to
        hold `sysadmin` (nxc enforces `@requires_admin`).
        """
        if not command or not command.strip():
            raise ValueError("command is required for mssql_exec")
        flags = (["-X", command] if use_powershell else ["-x", command])
        if no_output:
            flags.append("--no-output")
        if force_ps32:
            flags.append("--force-ps32")
        return await _mssql_run(
            get_config, flags, targets, offensive=True, port=port,
            mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def mssql_sam(
        targets: list[str],
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Dump local SAM password hashes via MSSQL (`--sam`).

        Dumps SAM/SYSTEM hives through command execution. Returns a structured
        `credentials` list (account:rid:lm:nt). OFFENSIVE-GATED (NXC_MODE=full): requires
        the login to hold `sysadmin` (nxc enforces `@requires_admin`).
        """
        result = await _mssql_run(
            get_config, ["--sam"], targets, offensive=True, dump=True, port=port,
            mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )
        result["credentials"] = parse_secretsdump(result["stdout"])
        return result

    @mcp.tool()
    async def mssql_lsa(
        targets: list[str],
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Dump LSA secrets via MSSQL (`--lsa`).

        Returns a structured `secrets` list (machine/user NTLM, kerberos keys, DCC2 cached
        logons, DPAPI keys, gMSA blobs) -- the same classification as `smb_lsa`, so the
        gMSA chain applies. OFFENSIVE-GATED (NXC_MODE=full): requires the login to hold
        `sysadmin` (nxc enforces `@requires_admin`).
        """
        result = await _mssql_run(
            get_config, ["--lsa"], targets, offensive=True, dump=True, port=port,
            mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )
        result["secrets"] = parse_lsa_secrets(result["stdout"])
        return result

    @mcp.tool()
    async def mssql_get_file(
        targets: list[str],
        remote_path: str,
        local_path: str,
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Download a file from the target via MSSQL (`--get-file <remote> <local>`).

        `remote_path` is the path on the target; `local_path` where to save it on the nxc
        host. LOOT-GATED (NXC_MODE=loot): read-only retrieval (no state change); requires
        the login to hold `sysadmin` (nxc enforces `@requires_admin`).
        """
        if not remote_path or not local_path:
            raise ValueError("remote_path and local_path are required for mssql_get_file")
        return await _mssql_run(
            get_config, ["--get-file", remote_path, local_path], targets, offensive=True, dump=True,
            port=port, mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def mssql_put_file(
        targets: list[str],
        local_path: str,
        remote_path: str,
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Upload a file to the target via MSSQL (`--put-file <local> <remote>`).

        `local_path` is the file on the nxc host; `remote_path` the destination on the
        target. OFFENSIVE-GATED (NXC_MODE=full): requires the login to hold `sysadmin`
        (nxc enforces `@requires_admin`); writes to the remote filesystem.
        """
        if not local_path or not remote_path:
            raise ValueError("local_path and remote_path are required for mssql_put_file")
        return await _mssql_run(
            get_config, ["--put-file", local_path, remote_path], targets, offensive=True,
            port=port, mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )

    # ---- Promoted `-M` modules (first-class tools for high-value mssql modules) ---- #
    # All read-only enumeration (recon): the modules hook `on_login` (no sysadmin needed)
    # and take no options.

    @mcp.tool()
    async def mssql_enum_logins(
        targets: list[str],
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate SQL Server logins -- SQL, Domain, and Local users (`-M enum_logins`). Read-only.

        Returns a structured `logins` list (`{host, login_name, type, status}`). Useful for
        spotting other principals (incl. sysadmin candidates) reachable from this login.
        """
        result = await _mssql_module(
            get_config, "enum_logins", targets, offensive=False, port=port,
            mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )
        result["logins"] = parse_mssql_logins(result["stdout"])
        return result

    @mcp.tool()
    async def mssql_enum_impersonate(
        targets: list[str],
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate principals this login can impersonate (`-M enum_impersonate`). Read-only.

        Surfaces `EXECUTE AS` / IMPERSONATE grants -- a common MSSQL privilege-escalation
        path (e.g. impersonate a sysadmin login). Includes a structured `impersonation`
        list: `{host, principal}` per impersonable login.
        """
        result = await _mssql_module(
            get_config, "enum_impersonate", targets, offensive=False, port=port,
            mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )
        result["impersonation"] = parse_mssql_impersonate(result["stdout"])
        return result

    @mcp.tool()
    async def mssql_enum_links(
        targets: list[str],
        port: int | None = None,
        mssql_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate linked SQL Servers and their login configs (`-M enum_links`). Read-only.

        Lists linked servers (`sp_helplinkedsrvlogin`) and their local/remote login mappings
        -- the classic MSSQL lateral-movement path (`OPENQUERY` / RPC into a linked instance,
        often running with higher privileges). Includes a structured `links` list:
        `{host, linked_server}`.
        """
        result = await _mssql_module(
            get_config, "enum_links", targets, offensive=False, port=port,
            mssql_timeout=mssql_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )
        result["links"] = parse_mssql_links(result["stdout"])
        return result
