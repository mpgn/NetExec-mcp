"""RDP protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. RDP (port 3389) is used for auth
validation, NLA fingerprinting, screen capture, and command execution. The tools
span:

  * **Read-only** (``offensive=False``) -- auth check / fingerprint (OS, hostname,
    domain, NLA status, ``Pwn3d!``), desktop screenshot on successful login, and
    login-prompt screenshot when NLA is disabled (no creds needed).
  * **Offensive** (``offensive=True``, only under ``NXC_MODE=full``) -- command
    execution (cmd / PowerShell) driven through the RDP session.

**Auth model.** Like MSSQL, nxc's RDP connection implements a real ``kerberos_login``
(and ``pfx_auth`` routes certificate auth through it), so RDP honours the **full**
credential model: user/pass, ``-H`` PtH, Kerberos
(``-k``/``--use-kcache``/``--aesKey``/``--kdcHost``/ccache), certificate (pfx/pem),
``-d`` domain, ``--local-auth``, and stored ``cred_id``. It has no ``--laps``
(smb/winrm-only), so LAPS is omitted. Transport knobs ``--port`` (3389) /
``--rdp-timeout`` are exposed on every tool.

Screenshots are treated as **recon**: they capture the display read-only and don't
modify the target (the image is saved on the nxc host, under ``~/.nxc/screenshots``).
"""

from __future__ import annotations

from ..auth import build_auth_flags
from ..executor import execute


async def _rdp_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    extra_flags: list[str] | None = None,
    port=None,
    rdp_timeout=None,
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
    """Build auth + transport + action flags and run against the rdp protocol.

    RDP supports the full auth model except ``--laps`` (see module docstring).
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
    if rdp_timeout is not None:
        transport += ["--rdp-timeout", str(rdp_timeout)]
    extra = auth + transport + list(action_flags) + list(extra_flags or [])
    outcome = await execute(get_config(), "rdp", targets, extra, offensive=offensive, ccache=ccache)
    return outcome.to_dict()


def register(mcp, get_config) -> None:
    """Attach the RDP tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def rdp_enum_hosts(
        targets: list[str],
        port: int | None = None,
        rdp_timeout: int | None = None,
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
        """Fingerprint RDP and verify authentication (bare `nxc rdp <targets>`).

        Reports OS/hostname/domain and the NLA (Network Level Authentication) status, plus
        the auth result (`[+]`, with `Pwn3d!` when the account can log in). Pass credentials
        to authenticate, or none to fingerprint the service / NLA support. `port` overrides
        3389; `rdp_timeout` the socket timeout.
        """
        return await _rdp_run(
            get_config, [], targets, port=port, rdp_timeout=rdp_timeout, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host,
            aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64,
            pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def rdp_screenshot(
        targets: list[str],
        screentime: int | None = None,
        res: str | None = None,
        port: int | None = None,
        rdp_timeout: int | None = None,
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
        """Screenshot the RDP desktop after a successful login (`--screenshot`). Read-only.

        `screentime` is how long to wait for the desktop image (`--screentime`, default 10s);
        `res` sets the capture resolution `WIDTHxHEIGHT` (`--res`, default 1024x768). The PNG
        is saved on the nxc host (`~/.nxc/screenshots`); the output reports its path.
        """
        flags = ["--screenshot"]
        if screentime is not None:
            flags += ["--screentime", str(screentime)]
        if res:
            flags += ["--res", res]
        return await _rdp_run(
            get_config, flags, targets, port=port, rdp_timeout=rdp_timeout, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, kdc_host=kdc_host,
            aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64,
            pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def rdp_nla_screenshot(
        targets: list[str],
        port: int | None = None,
        rdp_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
    ) -> dict:
        """Screenshot the RDP login prompt when NLA is disabled (`--nla-screenshot`). Read-only.

        Captures the pre-auth logon screen, so it needs **no credentials** (only works when
        the target has NLA off). The PNG is saved on the nxc host. Credential params are
        accepted but unnecessary.
        """
        return await _rdp_run(
            get_config, ["--nla-screenshot"], targets, port=port, rdp_timeout=rdp_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, cred_id=cred_id,
        )

    # ---- Offensive (NXC_MODE=full only) ---- #

    @mcp.tool()
    async def rdp_exec(
        targets: list[str],
        command: str,
        use_powershell: bool = False,
        no_output: bool = False,
        cmd_delay: int | None = None,
        clipboard_delay: int | None = None,
        port: int | None = None,
        rdp_timeout: int | None = None,
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
        """Run a command on the target via the RDP session (`-x`, or `-X` for PowerShell).

        nxc drives the command through the RDP session (clipboard/run dialog), so it's
        slower and less reliable than SMB/WinRM exec. Set `use_powershell` for `-X`;
        `no_output` to skip output retrieval; `cmd_delay` (`--cmd-delay`) the sleep before
        executing; `clipboard_delay` (`--clipboard-delay`) the clipboard-init wait. The
        command is a single argv token. OFFENSIVE-GATED (NXC_MODE=full).
        """
        if not command or not command.strip():
            raise ValueError("command is required for rdp_exec")
        flags = (["-X", command] if use_powershell else ["-x", command])
        if no_output:
            flags.append("--no-output")
        if cmd_delay is not None:
            flags += ["--cmd-delay", str(cmd_delay)]
        if clipboard_delay is not None:
            flags += ["--clipboard-delay", str(clipboard_delay)]
        return await _rdp_run(
            get_config, flags, targets, offensive=True, port=port, rdp_timeout=rdp_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id,
            kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert,
            pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
