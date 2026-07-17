"""Protocol-module tool groups.

Each submodule exposes a ``register(mcp, get_config)`` function that attaches its
tools to the FastMCP app. ``server.main()`` calls the registrars for the
protocols enabled via ``NXC_PROTOCOLS``.
"""

from __future__ import annotations

from . import ftp, ldap, mssql, nfs, rdp, smb, ssh, vnc, winrm, wmi

# Maps a protocol name (as used in NXC_PROTOCOLS) to its registrar.
REGISTRARS = {
    "smb": smb.register,
    "ldap": ldap.register,
    "winrm": winrm.register,
    "mssql": mssql.register,
    "ssh": ssh.register,
    "rdp": rdp.register,
    "wmi": wmi.register,
    "ftp": ftp.register,
    "nfs": nfs.register,
    "vnc": vnc.register,
}


def register_enabled(mcp, get_config, protocols) -> list[str]:
    """Register every enabled protocol that has an implemented module.

    Returns the list of protocol names actually registered (skips enabled
    protocols whose module isn't built yet).
    """
    registered = []
    for proto in protocols:
        registrar = REGISTRARS.get(proto)
        if registrar is not None:
            registrar(mcp, get_config)
            registered.append(proto)
    return registered
