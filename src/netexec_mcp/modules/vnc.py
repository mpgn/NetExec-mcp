"""VNC protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. VNC (port 5900) is used for auth
validation and screen capture -- both read-only:

  * **Read-only** (``offensive=False``) -- auth check (``Pwn3d!`` on a successful
    connection) and desktop screenshot.

**Auth model -- password only.** nxc's VNC connection implements ``plaintext_login``
but VNC has **no username** -- only a password (the handler ignores the username and
uses NONE auth when the password is empty). So these tools take only ``password``
(plus stored ``cred_id``); there is no domain/hash/Kerberos/certificate. Transport
knobs ``--port`` (5900) / ``--vnc-sleep`` (rate-limit avoidance) / ``--vnc-timeout``
(socket + RFB-handshake deadline, default 5s) are exposed.

*(No live lab was available; source-verified against ``proto_args.py`` + handler and
unit-tested, but not validated end-to-end.)*
"""

from __future__ import annotations

from ..executor import execute


async def _vnc_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    port=None,
    vnc_sleep=None,
    vnc_timeout=None,
    password=None,
    cred_id=None,
) -> dict:
    """Build auth (password-only) + transport + action flags and run against vnc."""
    auth: list[str] = []
    if cred_id is not None:
        auth += ["-id", str(cred_id)]
    elif password is not None:
        auth += ["-p", password]
    transport: list[str] = []
    if port is not None:
        transport += ["--port", str(port)]
    if vnc_sleep is not None:
        transport += ["--vnc-sleep", str(vnc_sleep)]
    if vnc_timeout is not None:
        transport += ["--vnc-timeout", str(vnc_timeout)]
    extra = auth + transport + list(action_flags)
    outcome = await execute(get_config(), "vnc", targets, extra, offensive=offensive)
    return outcome.to_dict()


def register(mcp, get_config) -> None:
    """Attach the VNC tools to the FastMCP app."""

    # ---- Read-only (recon mode) ---- #

    @mcp.tool()
    async def vnc_enum_hosts(
        targets: list[str],
        password: str | None = None,
        port: int | None = None,
        vnc_sleep: int | None = None,
        vnc_timeout: int | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Verify VNC authentication (bare `nxc vnc <targets>`).

        VNC has no username -- pass just the `password` (reports `Pwn3d!` on a successful
        connection), or a stored `cred_id`. `port` overrides 5900; `vnc_sleep` adds a delay
        on connect to avoid server rate-limiting; `vnc_timeout` bounds the connection
        (default 5s) -- raise it for a slow server, since a host that answers the TCP
        connect and then stalls in the RFB handshake is reported as a timeout, not as a
        rejected password.
        """
        return await _vnc_run(
            get_config, [], targets, password=password, port=port, vnc_sleep=vnc_sleep,
            vnc_timeout=vnc_timeout, cred_id=cred_id,
        )

    @mcp.tool()
    async def vnc_screenshot(
        targets: list[str],
        screentime: int | None = None,
        password: str | None = None,
        port: int | None = None,
        vnc_sleep: int | None = None,
        vnc_timeout: int | None = None,
        cred_id: int | None = None,
    ) -> dict:
        """Screenshot the VNC desktop on a successful connection (`--screenshot`). Read-only.

        `screentime` is how long to wait for the desktop image (`--screentime`, default 5s).
        The PNG is saved on the nxc host (`~/.nxc/screenshots`); the output reports its path.
        `vnc_timeout` bounds the connection (default 5s).
        """
        flags = ["--screenshot"]
        if screentime is not None:
            flags += ["--screentime", str(screentime)]
        return await _vnc_run(
            get_config, flags, targets, password=password, port=port, vnc_sleep=vnc_sleep,
            vnc_timeout=vnc_timeout, cred_id=cred_id,
        )
