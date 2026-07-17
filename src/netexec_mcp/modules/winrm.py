"""WinRM protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. WinRM (Windows Remote Management,
ports 5985/5986) is the post-credential exec/pivot surface. The tools span:

  * **Read-only** (``offensive=False``) -- auth check / fingerprint and remote
    directory listing.
  * **Offensive** (``offensive=True``, only under ``NXC_MODE=full``) -- remote
    command execution (cmd / PowerShell), credential dumping (sam/lsa/dpapi), and
    file get/put.

**Auth model -- NTLM only.** Unlike SMB/LDAP, nxc's WinRM connection implements
only ``plaintext_login`` and ``hash_login`` (the handler explicitly notes "nxc
winrm only support NTLM currently"; the base ``kerberos_login`` is a no-op for
this protocol). So these tools intentionally expose **only** the credential
parameters WinRM can honour -- user/pass, ``-H`` NTLM hash (pass-the-hash),
``-d`` domain, ``--local-auth``, ``--laps``, and stored ``cred_id`` -- and omit
Kerberos / aesKey / ccache / certificate (those flags are accepted by argparse
but silently ignored by the WinRM handler). The WinRM-specific transport knobs
``--port`` / ``--check-proto`` / ``--http-timeout`` are exposed for non-default
deployments.
"""

from __future__ import annotations

from ..auth import build_auth_flags
from ..executor import execute
from ..results import parse_lsa_secrets, parse_secretsdump


async def _winrm_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    dump: bool = False,
    extra_flags: list[str] | None = None,
    port=None,
    check_proto=None,
    http_timeout=None,
    username=None,
    password=None,
    ntlm_hash=None,
    domain=None,
    local_auth=False,
    cred_id=None,
    laps=None,
) -> dict:
    """Build auth + transport + action flags and run against the winrm protocol.

    WinRM is NTLM-only, so the auth surface here is deliberately the SMB set minus
    Kerberos/cert (see module docstring).
    """
    auth = build_auth_flags(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        local_auth=local_auth,
        cred_id=cred_id,
        laps=laps,
    )
    transport: list[str] = []
    if port is not None:
        transport += ["--port", str(port)]
    if check_proto:
        transport += ["--check-proto", str(check_proto)]
    if http_timeout is not None:
        transport += ["--http-timeout", str(http_timeout)]
    extra = auth + transport + list(action_flags) + list(extra_flags or [])
    outcome = await execute(get_config(), "winrm", targets, extra, offensive=offensive, dump=dump)
    return outcome.to_dict()


def register(mcp, get_config) -> None:
    """Attach the WinRM tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def winrm_enum_hosts(
        targets: list[str],
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """Fingerprint WinRM and verify authentication (bare `nxc winrm <targets>`).

        Reports OS/domain and the auth result (`[+]`, with `Pwn3d!` when the account can
        open a remote shell). Pass credentials to authenticate, or none to probe whether
        WinRM is enabled. `port`/`check_proto` override the default 5985/5986 + http/https
        probe; `http_timeout` the per-connection HTTP timeout. WinRM auth is NTLM-only
        (user/pass or `ntlm_hash`).
        """
        return await _winrm_run(
            get_config, [], targets, port=port, check_proto=check_proto,
            http_timeout=http_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, cred_id=cred_id,
            laps=laps,
        )

    @mcp.tool()
    async def winrm_dir(
        targets: list[str],
        path: str | None = None,
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """List the contents of a remote path over WinRM (`--dir [path]`). Read-only.

        Omit `path` for the default working directory. Runs `dir <path>` in a remote shell,
        so it requires an account that can open one.
        """
        # --dir takes an optional value; only append it when a path is given.
        flags = ["--dir"] + ([path] if path else [])
        return await _winrm_run(
            get_config, flags, targets, port=port, check_proto=check_proto,
            http_timeout=http_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, cred_id=cred_id,
            laps=laps,
        )

    # ---- Offensive (loot for read-only credential/file harvest; full for write/exec) ---- #

    @mcp.tool()
    async def winrm_exec(
        targets: list[str],
        command: str,
        use_powershell: bool = False,
        no_output: bool = False,
        codec: str | None = None,
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """Run a command on the target over WinRM (`-x`, or `-X` for PowerShell).

        Set `use_powershell` to execute `command` as PowerShell (`-X`) instead of cmd
        (`-x`). `no_output` skips retrieving output; `codec` sets the output encoding
        (default 437) for garbled-output cases. The command is passed as a single argv
        token (no shell interpolation on the nxc side). OFFENSIVE-GATED (NXC_MODE=full).
        """
        if not command or not command.strip():
            raise ValueError("command is required for winrm_exec")
        flags = (["-X", command] if use_powershell else ["-x", command])
        if no_output:
            flags.append("--no-output")
        if codec:
            flags += ["--codec", codec]
        return await _winrm_run(
            get_config, flags, targets, offensive=True, port=port, check_proto=check_proto,
            http_timeout=http_timeout, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth, cred_id=cred_id,
            laps=laps,
        )

    @mcp.tool()
    async def winrm_sam(
        targets: list[str],
        dump_method: str | None = None,
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """Dump local SAM password hashes over WinRM (`--sam`).

        `dump_method` selects the shell used for the dump: "cmd" (default) or "powershell"
        (`--dump-method`). Returns a structured `credentials` list (account:rid:lm:nt).
        OFFENSIVE-GATED (NXC_MODE=full): requires local admin on the target.
        """
        extra = ["--dump-method", dump_method] if dump_method else []
        result = await _winrm_run(
            get_config, ["--sam"], targets, offensive=True, dump=True, extra_flags=extra, port=port,
            check_proto=check_proto, http_timeout=http_timeout, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            cred_id=cred_id, laps=laps,
        )
        result["credentials"] = parse_secretsdump(result["stdout"])
        return result

    @mcp.tool()
    async def winrm_lsa(
        targets: list[str],
        dump_method: str | None = None,
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """Dump LSA secrets over WinRM (`--lsa`).

        `dump_method` selects "cmd" (default) or "powershell" (`--dump-method`). Returns a
        structured `secrets` list (machine/user NTLM, kerberos keys, DCC2 cached logons,
        DPAPI keys, gMSA blobs) -- the same classification as `smb_lsa`, so the gMSA chain
        applies. OFFENSIVE-GATED (NXC_MODE=full): requires local admin on the target.
        """
        extra = ["--dump-method", dump_method] if dump_method else []
        result = await _winrm_run(
            get_config, ["--lsa"], targets, offensive=True, dump=True, extra_flags=extra, port=port,
            check_proto=check_proto, http_timeout=http_timeout, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            cred_id=cred_id, laps=laps,
        )
        result["secrets"] = parse_lsa_secrets(result["stdout"])
        return result

    @mcp.tool()
    async def winrm_dpapi(
        targets: list[str],
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """Dump the user's Credential Manager / DPAPI secrets over WinRM (`--dpapi`).

        OFFENSIVE-GATED (NXC_MODE=full): retrieves stored credential material. Decrypts
        masterkeys with the supplied password, so it needs plaintext creds for the user
        whose secrets are looted.
        """
        return await _winrm_run(
            get_config, ["--dpapi"], targets, offensive=True, dump=True, port=port,
            check_proto=check_proto, http_timeout=http_timeout, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            cred_id=cred_id, laps=laps,
        )

    @mcp.tool()
    async def winrm_get_file(
        targets: list[str],
        remote_path: str,
        local_path: str,
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """Download a file from the target over WinRM (`--get-file <remote> <local>`).

        `remote_path` is the path on the target; `local_path` where to save it on the nxc
        host. LOOT-GATED (NXC_MODE=loot): read-only retrieval (no state change).
        """
        if not remote_path or not local_path:
            raise ValueError("remote_path and local_path are required for winrm_get_file")
        return await _winrm_run(
            get_config, ["--get-file", remote_path, local_path], targets, offensive=True, dump=True,
            port=port, check_proto=check_proto, http_timeout=http_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, cred_id=cred_id, laps=laps,
        )

    @mcp.tool()
    async def winrm_put_file(
        targets: list[str],
        local_path: str,
        remote_path: str,
        port: int | None = None,
        check_proto: str | None = None,
        http_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
    ) -> dict:
        """Upload a file to the target over WinRM (`--put-file <local> <remote>`).

        `local_path` is the file on the nxc host; `remote_path` the destination on the
        target. OFFENSIVE-GATED (NXC_MODE=full): writes to the remote filesystem.
        """
        if not local_path or not remote_path:
            raise ValueError("local_path and remote_path are required for winrm_put_file")
        return await _winrm_run(
            get_config, ["--put-file", local_path, remote_path], targets, offensive=True,
            port=port, check_proto=check_proto, http_timeout=http_timeout,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, cred_id=cred_id, laps=laps,
        )
