"""SSH protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. SSH is structurally different from
the Windows protocols:

  * **Read-only** (``offensive=False``) -- ``ssh_enum_hosts`` authenticates, grabs
    the SSH banner, detects the platform (Linux / Windows / network device), and
    does a *non-intrusive* privilege check (``id; sudo -ln``), reporting
    ``Shell access!`` and ``Pwn3d!`` for root/admin.
  * **Offensive** (``offensive=True``, only under ``NXC_MODE=full``) -- command
    execution (``-x``), SFTP file get/put, and the *intrusive* ``--sudo-check``
    (runs sudo and copies ``/etc/shadow`` to verify the user can reach root).

**Auth model -- SSH only.** nxc's SSH connection implements just ``plaintext_login``:
username + **password**, *or* ``--key-file`` (the password is then the key's
**passphrase**), plus stored ``cred_id``. There is no domain, NTLM hash, Kerberos,
certificate, or ``--local-auth`` here, so this module builds the auth flags inline
rather than via the Windows-oriented :func:`auth.build_auth_flags`. Transport knobs
``--port`` (22) / ``--ssh-timeout`` are exposed on every tool.
"""

from __future__ import annotations

from ..executor import execute


def _ssh_auth_flags(username=None, password=None, key_file=None, cred_id=None) -> list[str]:
    """SSH credential flags. ``cred_id`` (stored cred) is mutually exclusive with
    inline creds. With ``key_file`` set, ``password`` is the key passphrase."""
    if cred_id is not None:
        return ["-id", str(cred_id)]
    flags: list[str] = []
    if username:
        flags += ["-u", username]
    if key_file:
        flags += ["--key-file", key_file]
    if password is not None:
        flags += ["-p", password]
    return flags


async def _ssh_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    dump: bool = False,
    extra_flags: list[str] | None = None,
    port=None,
    ssh_timeout=None,
    username=None,
    password=None,
    key_file=None,
    cred_id=None,
) -> dict:
    """Build auth + transport + action flags and run against the ssh protocol."""
    auth = _ssh_auth_flags(username=username, password=password, key_file=key_file, cred_id=cred_id)
    transport: list[str] = []
    if port is not None:
        transport += ["--port", str(port)]
    if ssh_timeout is not None:
        transport += ["--ssh-timeout", str(ssh_timeout)]
    extra = auth + transport + list(action_flags) + list(extra_flags or [])
    outcome = await execute(get_config(), "ssh", targets, extra, offensive=offensive, dump=dump)
    return outcome.to_dict()


def register(mcp, get_config) -> None:
    """Attach the SSH tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def ssh_enum_hosts(
        targets: list[str],
        port: int | None = None,
        ssh_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        key_file: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Authenticate over SSH and fingerprint the host (bare `nxc ssh <targets>`).

        Reports the SSH banner/version, platform (Linux / Windows / network device),
        whether the account gets `Shell access!`, and `Pwn3d!` if it's root/admin (via a
        non-intrusive `id; sudo -ln` check). Authenticate with `username`+`password`, or a
        `key_file` (then `password` is the key's passphrase). Pass none to just grab the
        banner.
        """
        return await _ssh_run(
            get_config, [], targets, port=port, ssh_timeout=ssh_timeout,
            username=username, password=password, key_file=key_file, cred_id=cred_id,
        )

    # ---- Offensive (loot for read-only file harvest; full for write/exec) ---- #

    @mcp.tool()
    async def ssh_exec(
        targets: list[str],
        command: str,
        no_output: bool = False,
        codec: str | None = None,
        port: int | None = None,
        ssh_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        key_file: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Run a command on the target over SSH (`-x <command>`).

        The command runs in a remote shell (nxc appends `2>&1`, so stderr is included).
        `no_output` skips output retrieval; `codec` sets the output encoding (default
        utf-8). OFFENSIVE-GATED (NXC_MODE=full).
        """
        if not command or not command.strip():
            raise ValueError("command is required for ssh_exec")
        flags = ["-x", command]
        if no_output:
            flags.append("--no-output")
        if codec:
            flags += ["--codec", codec]
        return await _ssh_run(
            get_config, flags, targets, offensive=True, port=port, ssh_timeout=ssh_timeout,
            username=username, password=password, key_file=key_file, cred_id=cred_id,
        )

    @mcp.tool()
    async def ssh_get_file(
        targets: list[str],
        remote_path: str,
        local_path: str,
        port: int | None = None,
        ssh_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        key_file: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Download a file from the target over SFTP (`--get-file <remote> <local>`).

        `remote_path` is the path on the target; `local_path` where to save it on the nxc
        host. LOOT-GATED (NXC_MODE=loot): read-only retrieval (no state change).
        """
        if not remote_path or not local_path:
            raise ValueError("remote_path and local_path are required for ssh_get_file")
        return await _ssh_run(
            get_config, ["--get-file", remote_path, local_path], targets, offensive=True, dump=True,
            port=port, ssh_timeout=ssh_timeout, username=username, password=password,
            key_file=key_file, cred_id=cred_id,
        )

    @mcp.tool()
    async def ssh_put_file(
        targets: list[str],
        local_path: str,
        remote_path: str,
        port: int | None = None,
        ssh_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        key_file: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Upload a file to the target over SFTP (`--put-file <local> <remote>`).

        `local_path` is the file on the nxc host; `remote_path` the destination on the
        target. OFFENSIVE-GATED (NXC_MODE=full): writes to the remote filesystem.
        """
        if not local_path or not remote_path:
            raise ValueError("local_path and remote_path are required for ssh_put_file")
        return await _ssh_run(
            get_config, ["--put-file", local_path, remote_path], targets, offensive=True,
            port=port, ssh_timeout=ssh_timeout, username=username, password=password,
            key_file=key_file, cred_id=cred_id,
        )

    @mcp.tool()
    async def ssh_sudo_check(
        targets: list[str],
        method: str | None = None,
        get_output_tries: int | None = None,
        port: int | None = None,
        ssh_timeout: int | None = None,
        username: str | None = None,
        password: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Actively verify the user can escalate to root via sudo (`--sudo-check`).

        Unlike the passive check in `ssh_enum_hosts`, this *runs* sudo and copies
        `/etc/shadow` to a temp file to confirm root access. `method` is "sudo-stdin"
        (default) or "mkfifo" (`--sudo-check-method`); `get_output_tries` bounds the result
        polling (`--get-output-tries`). Requires a `password` (sudo can't use a key here).
        OFFENSIVE-GATED (NXC_MODE=full): executes privileged commands and touches
        `/etc/shadow` on the target.
        """
        flags = ["--sudo-check"]
        if method:
            flags += ["--sudo-check-method", method]
        if get_output_tries is not None:
            flags += ["--get-output-tries", str(get_output_tries)]
        return await _ssh_run(
            get_config, flags, targets, offensive=True, port=port, ssh_timeout=ssh_timeout,
            username=username, password=password, cred_id=cred_id,
        )
