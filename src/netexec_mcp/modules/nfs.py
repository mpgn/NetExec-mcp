"""NFS protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. NFS (portmapper on 111) is used for
share enumeration and file transfer:

  * **Read-only** (``offensive=False``) -- portmapper fingerprint, share listing,
    recursive share enumeration (with access perms), and directory listing.
  * **Offensive** (``offensive=True``, only under ``NXC_MODE=full``) -- file
    download / upload (upload is chmod 777) and ``chmod`` of remote files.

**Auth model -- none.** nxc's NFS connection has no ``plaintext_login``: NFS uses
AUTH_SYS (uid/gid, auto-detected by nxc), not username/password. So these tools take
**no credential parameters** -- only ``--port`` (111) / ``--nfs-timeout`` and the
operation flags. ``--share`` selects the share for ``--ls`` / ``--get-file`` /
``--put-file``.

*(No live lab was available; source-verified against ``proto_args.py`` + handler and
unit-tested, but not validated end-to-end.)*
"""

from __future__ import annotations

from ..executor import execute


async def _nfs_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    dump: bool = False,
    share=None,
    port=None,
    nfs_timeout=None,
) -> dict:
    """Build transport + action flags and run against the nfs protocol (no auth)."""
    transport: list[str] = []
    if port is not None:
        transport += ["--port", str(port)]
    if nfs_timeout is not None:
        transport += ["--nfs-timeout", str(nfs_timeout)]
    share_flag = ["--share", share] if share else []
    extra = transport + share_flag + list(action_flags)
    outcome = await execute(get_config(), "nfs", targets, extra, offensive=offensive, dump=dump)
    return outcome.to_dict()


def register(mcp, get_config) -> None:
    """Attach the NFS tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def nfs_enum_hosts(
        targets: list[str],
        port: int | None = None,
        nfs_timeout: int | None = None,
    ) -> dict:
        """Fingerprint the NFS portmapper (bare `nxc nfs <targets>`). Read-only.

        Confirms NFS is reachable and reports the portmapper/mountd info. `port` overrides
        111; `nfs_timeout` the connection timeout. NFS needs no credentials (AUTH_SYS).
        """
        return await _nfs_run(get_config, [], targets, port=port, nfs_timeout=nfs_timeout)

    @mcp.tool()
    async def nfs_shares(
        targets: list[str],
        port: int | None = None,
        nfs_timeout: int | None = None,
    ) -> dict:
        """List exported NFS shares (`--shares`). Read-only."""
        return await _nfs_run(get_config, ["--shares"], targets, port=port, nfs_timeout=nfs_timeout)

    @mcp.tool()
    async def nfs_enum_shares(
        targets: list[str],
        depth: int | None = None,
        port: int | None = None,
        nfs_timeout: int | None = None,
    ) -> dict:
        """Enumerate exposed shares recursively with access perms (`--enum-shares [depth]`). Read-only.

        `depth` is the recursion depth (default 3). Reports UID / read-write-execute perms /
        storage usage / share / access list for each export.
        """
        flags = ["--enum-shares"] + ([str(depth)] if depth is not None else [])
        return await _nfs_run(get_config, flags, targets, port=port, nfs_timeout=nfs_timeout)

    @mcp.tool()
    async def nfs_ls(
        targets: list[str],
        path: str | None = None,
        share: str | None = None,
        port: int | None = None,
        nfs_timeout: int | None = None,
    ) -> dict:
        """List files in an NFS share/path (`--ls [path]`). Read-only.

        `path` defaults to `/`; `share` selects the export to browse (`--share`).
        """
        flags = ["--ls"] + ([path] if path else [])
        return await _nfs_run(
            get_config, flags, targets, share=share, port=port, nfs_timeout=nfs_timeout
        )

    # ---- Offensive (loot for read-only file harvest; full for write) ---- #

    @mcp.tool()
    async def nfs_get_file(
        targets: list[str],
        remote_file: str,
        local_file: str,
        share: str | None = None,
        port: int | None = None,
        nfs_timeout: int | None = None,
    ) -> dict:
        """Download a file from an NFS share (`--get-file <remote> <local>`).

        `remote_file` is the path on the share; `local_file` where to save it on the nxc
        host. `share` selects the export. LOOT-GATED (NXC_MODE=loot): read-only
        retrieval (no state change).
        """
        if not remote_file or not local_file:
            raise ValueError("remote_file and local_file are required for nfs_get_file")
        return await _nfs_run(
            get_config, ["--get-file", remote_file, local_file], targets, offensive=True, dump=True,
            share=share, port=port, nfs_timeout=nfs_timeout,
        )

    @mcp.tool()
    async def nfs_put_file(
        targets: list[str],
        local_file: str,
        remote_file: str,
        share: str | None = None,
        port: int | None = None,
        nfs_timeout: int | None = None,
    ) -> dict:
        """Upload a file to an NFS share (`--put-file <local> <remote>`).

        `local_file` is the file on the nxc host; `remote_file` the destination on the
        share (written with chmod 777). `share` selects the export. OFFENSIVE-GATED
        (NXC_MODE=full): writes to the remote filesystem.
        """
        if not local_file or not remote_file:
            raise ValueError("local_file and remote_file are required for nfs_put_file")
        return await _nfs_run(
            get_config, ["--put-file", local_file, remote_file], targets, offensive=True,
            share=share, port=port, nfs_timeout=nfs_timeout,
        )

    @mcp.tool()
    async def nfs_chmod(
        targets: list[str],
        permissions: str,
        remote_file: str,
        share: str | None = None,
        port: int | None = None,
        nfs_timeout: int | None = None,
    ) -> dict:
        """Change permissions of a remote NFS file (`--chmod <perms> <file>`).

        `permissions` is an octal mode (e.g. "777"); `remote_file` the target path. `share`
        selects the export. OFFENSIVE-GATED (NXC_MODE=full): modifies the remote filesystem.
        """
        if not permissions or not remote_file:
            raise ValueError("permissions and remote_file are required for nfs_chmod")
        return await _nfs_run(
            get_config, ["--chmod", permissions, remote_file], targets, offensive=True,
            share=share, port=port, nfs_timeout=nfs_timeout,
        )
