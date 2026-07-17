"""WMI protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. WMI (DCOM over RPC, port 135) is used
for auth validation, read-only WQL enumeration, VSS-snapshot listing, and command
execution. The tools span:

  * **Read-only** (``offensive=False``) -- auth check / fingerprint, WQL queries
    (``--wmi-query``, SELECT-style and read-only by nature), and VSS-snapshot
    listing.
  * **Offensive** (``offensive=True``, only under ``NXC_MODE=full``) -- command
    execution (cmd / PowerShell) via ``wmiexec`` / ``wmiexec-event``.

**Auth model.** Like MSSQL/RDP, nxc's WMI connection implements a real
``kerberos_login`` (and ``pfx_auth`` routes certificate auth through it), so WMI
honours the **full** credential model: user/pass, ``-H`` PtH, Kerberos
(``-k``/``--use-kcache``/``--aesKey``/``--kdcHost``/ccache), certificate (pfx/pem),
``-d`` domain, ``--local-auth``, and stored ``cred_id``. No ``--laps`` (smb/winrm-only).
The WMI port is fixed at 135 (nxc only allows that), so only ``--rpc-timeout`` is
exposed as a transport knob.
"""

from __future__ import annotations

from ..auth import build_auth_flags
from ..executor import execute
from ..results import parse_wmi


async def _wmi_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    extra_flags: list[str] | None = None,
    rpc_timeout=None,
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
    """Build auth + transport + action flags and run against the wmi protocol.

    WMI supports the full auth model except ``--laps`` (see module docstring).
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
    if rpc_timeout is not None:
        transport += ["--rpc-timeout", str(rpc_timeout)]
    extra = auth + transport + list(action_flags) + list(extra_flags or [])
    outcome = await execute(get_config(), "wmi", targets, extra, offensive=offensive, ccache=ccache)
    return outcome.to_dict()


def register(mcp, get_config) -> None:
    """Attach the WMI tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def wmi_enum_hosts(
        targets: list[str],
        rpc_timeout: int | None = None,
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
        """Fingerprint WMI and verify authentication (bare `nxc wmi <targets>`).

        Reports OS/hostname/domain and the auth result (`[+]`, with `Pwn3d!` when the
        account is a local admin). Pass credentials to authenticate, or none to fingerprint
        the DCOM/RPC service. `rpc_timeout` sets the RPC/DCOM connection timeout.
        """
        return await _wmi_run(
            get_config, [], targets, rpc_timeout=rpc_timeout, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host,
            aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64,
            pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def wmi_query(
        targets: list[str],
        query: str,
        namespace: str | None = None,
        rpc_timeout: int | None = None,
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
        """Run a WQL query against the target (`--wmi-query <wql>`). Read-only.

        `query` is a WQL statement (e.g. "SELECT * FROM Win32_OperatingSystem"); `namespace`
        overrides the WMI namespace (`--wmi-namespace`, default `root\\cimv2`). Returns a
        structured `rows` list (`{host, key, value}`). WQL is SELECT-style and read-only, so
        this runs in recon mode.
        """
        if not query or not query.strip():
            raise ValueError("query is required for wmi_query")
        extra = ["--wmi-namespace", namespace] if namespace else []
        result = await _wmi_run(
            get_config, ["--wmi-query", query], targets, extra_flags=extra,
            rpc_timeout=rpc_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host, aes_key=aes_key,
            ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass,
            pem_cert=pem_cert, pem_key=pem_key,
        )
        result["rows"] = parse_wmi(result["stdout"])
        return result

    @mcp.tool()
    async def wmi_list_snapshots(
        targets: list[str],
        share: str | None = None,
        rpc_timeout: int | None = None,
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
        """List VSS (Volume Shadow Copy) snapshots over WMI (`--list-snapshots`). Read-only.

        `share` overrides the share to inspect (default `ADMIN$`). Read-only enumeration,
        though it typically requires local admin on the target.
        """
        flags = ["--list-snapshots"] + ([share] if share else [])
        return await _wmi_run(
            get_config, flags, targets, rpc_timeout=rpc_timeout, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host,
            aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64,
            pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    # ---- Offensive (NXC_MODE=full only) ---- #

    @mcp.tool()
    async def wmi_exec(
        targets: list[str],
        command: str,
        use_powershell: bool = False,
        exec_method: str | None = None,
        exec_timeout: int | None = None,
        no_output: bool = False,
        codec: str | None = None,
        rpc_timeout: int | None = None,
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
        """Run a command on the target over WMI (`-x`, or `-X` for PowerShell).

        Set `use_powershell` to spawn PowerShell (`-X`) instead of cmd (`-x`). `exec_method`
        is "wmiexec" (default; results via registry) or "wmiexec-event" (T1546.003, less
        stable). `exec_timeout` bounds command execution; `no_output` skips output retrieval;
        `codec` sets the output encoding. The command is a single argv token. OFFENSIVE-GATED
        (NXC_MODE=full): typically requires local admin.
        """
        if not command or not command.strip():
            raise ValueError("command is required for wmi_exec")
        flags = (["-X", command] if use_powershell else ["-x", command])
        if exec_method:
            flags += ["--exec-method", exec_method]
        if exec_timeout is not None:
            flags += ["--exec-timeout", str(exec_timeout)]
        if no_output:
            flags.append("--no-output")
        if codec:
            flags += ["--codec", codec]
        return await _wmi_run(
            get_config, flags, targets, offensive=True, rpc_timeout=rpc_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id,
            kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert,
            pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
