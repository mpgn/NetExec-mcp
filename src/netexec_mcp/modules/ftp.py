"""FTP protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. FTP (port 21) is used for auth
validation (incl. anonymous) and file listing / transfer:

  * **Read-only** (``offensive=False``) -- auth check and directory listing.
  * **Offensive** (``offensive=True``, only under ``NXC_MODE=full``) -- file
    download / upload.

**Auth model.** nxc's FTP connection implements only ``plaintext_login`` -- username
+ password, with anonymous handling (``anonymous``/empty username). No domain, NTLM
hash, Kerberos, certificate, or ``--local-auth``. It reuses the credential subset of
:func:`auth.build_auth_flags` (user/pass + stored ``cred_id``), which also yields the
``-u <user> -p ''`` anonymous case from a username alone -- so MCP clients never have
to serialise an empty password. ``--port`` overrides 21.

*(No live lab was available for FTP/NFS/VNC; these are source-verified against
``proto_args.py`` + handlers and unit-tested, but not yet validated end-to-end.)*
"""

from __future__ import annotations

from ..auth import build_auth_flags
from ..executor import execute


async def _ftp_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    port=None,
    username=None,
    password=None,
    cred_id=None,
) -> dict:
    """Build auth + transport + action flags and run against the ftp protocol."""
    auth = build_auth_flags(username=username, password=password, cred_id=cred_id)
    transport = ["--port", str(port)] if port is not None else []
    extra = auth + transport + list(action_flags)
    outcome = await execute(get_config(), "ftp", targets, extra, offensive=offensive)
    return outcome.to_dict()


def register(mcp, get_config) -> None:
    """Attach the FTP tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def ftp_enum_hosts(
        targets: list[str],
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Verify FTP authentication / grab the banner (bare `nxc ftp <targets>`).

        Pass `username`+`password` to authenticate, `username="anonymous"` for an anonymous
        login (the empty password is supplied automatically), or nothing to fingerprint the
        service. `port` overrides 21.
        """
        return await _ftp_run(
            get_config, [], targets, port=port, username=username, password=password,
            cred_id=cred_id,
        )

    @mcp.tool()
    async def ftp_ls(
        targets: list[str],
        directory: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """List files (including hidden) in an FTP directory (`--ls [directory]`). Read-only.

        Omit `directory` to list the current directory (`.`).
        """
        flags = ["--ls"] + ([directory] if directory else [])
        return await _ftp_run(
            get_config, flags, targets, port=port, username=username, password=password,
            cred_id=cred_id,
        )

    # ---- Offensive (NXC_MODE=full only) ---- #

    @mcp.tool()
    async def ftp_get(
        targets: list[str],
        remote_file: str,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Download a file from the FTP server (`--get <file>`).

        `remote_file` is the path on the server; nxc saves it locally (basename, in the
        working directory). OFFENSIVE-GATED (NXC_MODE=full).
        """
        if not remote_file or not remote_file.strip():
            raise ValueError("remote_file is required for ftp_get")
        return await _ftp_run(
            get_config, ["--get", remote_file], targets, offensive=True, port=port,
            username=username, password=password, cred_id=cred_id,
        )

    @mcp.tool()
    async def ftp_put(
        targets: list[str],
        local_file: str,
        remote_file: str,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Upload a file to the FTP server (`--put <local> <remote>`).

        `local_file` is the file on the nxc host; `remote_file` the destination on the
        server. OFFENSIVE-GATED (NXC_MODE=full): writes to the remote filesystem.
        """
        if not local_file or not remote_file:
            raise ValueError("local_file and remote_file are required for ftp_put")
        return await _ftp_run(
            get_config, ["--put", local_file, remote_file], targets, offensive=True,
            port=port, username=username, password=password, cred_id=cred_id,
        )
