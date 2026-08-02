"""SMB protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. The surface spans:

  * **Read-only enumeration** (``offensive=False``) -- host fingerprint/auth check,
    shares, users, groups, sessions, password policy, rid-brute, file spidering.
  * **Offensive actions** (``offensive=True``, only run under ``NXC_MODE=full``) --
    password spraying, credential dumping (sam/lsa/ntds/dpapi), remote command
    execution, and file get/put.

The tools share the credential parameters defined in :mod:`auth`; pass them to
authenticate, or omit them for a null/guest session where the target allows it.
"""

from __future__ import annotations

import os

from ..auth import build_auth_flags
from ..executor import execute
from ..results import (
    parse_dir,
    parse_hosts_file,
    parse_lsa_secrets,
    parse_pass_pol,
    parse_rid_brute,
    parse_secretsdump,
    parse_shares,
    parse_smb_hosts,
    parse_users,
    parse_wmi,
)

# action flag -> nothing; documented inline per tool. Centralised here so the
# set of read-only enum actions is visible in one place.
_ENUM_FLAGS = {
    "hosts": [],                       # bare smb scan: OS / domain / signing
    "shares": ["--shares"],
    "sessions": ["--qwinsta"],         # nxc removed --smb-sessions; --qwinsta is the replacement
    "disks": ["--disks"],
    "loggedon_users": ["--loggedon-users"],
    "users": ["--users"],
    "local_groups": ["--local-groups"],
    "pass_pol": ["--pass-pol"],
    "rid_brute": ["--rid-brute"],
    # NB: --groups and --computers were moved to the LDAP protocol upstream
    # (nxc 1.5.x) -- they belong to the ldap module, not here.
}


async def _enum(
    get_config,
    action: str,
    targets: list[str],
    *,
    username=None,
    password=None,
    ntlm_hash=None,
    domain=None,
    local_auth=False,
    kerberos=False,
    use_kcache=False,
    cred_id=None,
    laps=None,
    kdc_host=None,
    aes_key=None,
    ccache=None,
    pfx_cert=None,
    pfx_base64=None,
    pfx_pass=None,
    pem_cert=None,
    pem_key=None,
) -> dict:
    """Run one read-only SMB enum action and return the parsed outcome dict."""
    auth = build_auth_flags(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        local_auth=local_auth,
        kerberos=kerberos,
        use_kcache=use_kcache,
        cred_id=cred_id,
        laps=laps,
        kdc_host=kdc_host,
        aes_key=aes_key,
        ccache=ccache,
        pfx_cert=pfx_cert,
        pfx_base64=pfx_base64,
        pfx_pass=pfx_pass,
        pem_cert=pem_cert,
        pem_key=pem_key,
    )
    extra = auth + _ENUM_FLAGS[action]
    outcome = await execute(get_config(), "smb", targets, extra, offensive=False, ccache=ccache)
    return outcome.to_dict()


async def _action_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool,
    dump: bool = False,
    extra_flags: list[str] | None = None,
    username=None,
    password=None,
    ntlm_hash=None,
    domain=None,
    local_auth=False,
    kerberos=False,
    use_kcache=False,
    cred_id=None,
    laps=None,
    kdc_host=None,
    aes_key=None,
    ccache=None,
    pfx_cert=None,
    pfx_base64=None,
    pfx_pass=None,
    pem_cert=None,
    pem_key=None,
) -> dict:
    """Build auth+action flags and run, marking the call recon or offensive."""
    auth = build_auth_flags(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        local_auth=local_auth,
        kerberos=kerberos,
        use_kcache=use_kcache,
        cred_id=cred_id,
        laps=laps,
        kdc_host=kdc_host,
        aes_key=aes_key,
        ccache=ccache,
        pfx_cert=pfx_cert,
        pfx_base64=pfx_base64,
        pfx_pass=pfx_pass,
        pem_cert=pem_cert,
        pem_key=pem_key,
    )
    extra = auth + list(action_flags) + list(extra_flags or [])
    outcome = await execute(get_config(), "smb", targets, extra,
                            offensive=offensive, dump=dump, ccache=ccache)
    return outcome.to_dict()


async def _offensive_run(get_config, action_flags, targets, **kw) -> dict:
    """Run a state-changing SMB action -- exec/write/exploit (`offensive`, full mode only)."""
    return await _action_run(get_config, action_flags, targets, offensive=True, **kw)


async def _loot_run(get_config, action_flags, targets, **kw) -> dict:
    """Run a read-only *credential-dumping* SMB action (sam/lsa/ntds/gpp): offensive but
    state-preserving, so it is permitted from `loot` mode upward, not just `full`."""
    return await _action_run(get_config, action_flags, targets, offensive=True, dump=True, **kw)


async def _recon_run(get_config, action_flags, targets, **kw) -> dict:
    """Run a read-only SMB action with dynamic flags (`offensive=False`, recon mode)."""
    return await _action_run(get_config, action_flags, targets, offensive=False, **kw)


async def _run_module(get_config, module, targets, *, offensive, dump=False, options=None, **kw) -> dict:
    """Run a promoted `-M <module>` (with `-o KEY=val` options) at a fixed gating level."""
    flags = ["-M", module]
    kv = [f"{k}={v}" for k, v in (options or {}).items() if v is not None and v != ""]
    if kv:
        flags += ["-o", *kv]
    return await _action_run(get_config, flags, targets, offensive=offensive, dump=dump, **kw)


def register(mcp, get_config) -> None:
    """Attach the read-only SMB enumeration tools to the FastMCP app."""

    @mcp.tool()
    async def smb_enum_hosts(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Fingerprint SMB hosts AND verify authentication (null / guest / credentialed).

        Use this to **test whether credentials work** (or whether null/guest auth is
        allowed) and to fingerprint OS, hostname, domain, signing, and SMBv1 -- it is
        the bare `nxc smb <targets>` scan and reports the auth result directly (`[+]`
        success / `[-]` failure). For a guest check pass `username="guest"` only; for
        a null session pass no credentials at all.

        Includes a structured `hosts` list: `{host, port, hostname, os, name, domain,
        signing, smbv1, is_dc}` per fingerprinted host (`is_dc` is `True` when nxc tags
        the host as a domain controller, else `None`).
        """
        result = await _enum(
            get_config, "hosts", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["hosts"] = parse_smb_hosts(result["stdout"])
        return result

    @mcp.tool()
    async def smb_shares(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """List SMB shares and the calling account's READ/WRITE access (`--shares`).

        In addition to the raw records, the result includes a structured `shares`
        list: `{host, share, permissions: [READ/WRITE...], remark}` per share.
        """
        result = await _enum(
            get_config, "shares", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["shares"] = parse_shares(result["stdout"])
        return result

    @mcp.tool()
    async def smb_sessions(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """List interactive user sessions on the target (`--qwinsta`).

        (nxc removed the old `--smb-sessions`; this uses `--qwinsta`, its replacement.)
        """
        return await _enum(
            get_config, "sessions", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_disks(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate disks/drives exposed on the target (`--disks`)."""
        return await _enum(
            get_config, "disks", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_loggedon_users(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """List users currently logged on to the target (`--loggedon-users`)."""
        return await _enum(
            get_config, "loggedon_users", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_users(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate domain users via SAMR/LSA (`--users`).

        Includes a structured `users` list: `{host, username, last_pw_set,
        bad_pw_count, description}` per account.
        """
        result = await _enum(
            get_config, "users", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["users"] = parse_users(result["stdout"])
        return result

    @mcp.tool()
    async def smb_local_groups(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate local groups on the target (`--local-groups`)."""
        return await _enum(
            get_config, "local_groups", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_pass_pol(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Retrieve the domain/host password policy (`--pass-pol`).

        Includes a structured `policy` list: `{host, domain, settings: {key: value}}`
        (e.g. minimum length, lockout threshold, complexity flags).
        """
        result = await _enum(
            get_config, "pass_pol", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["policy"] = parse_pass_pol(result["stdout"])
        return result

    @mcp.tool()
    async def smb_spray(
        targets: list[str],
        usernames: list[str],
        passwords: list[str] | None = None,
        ntlm_hashes: list[str] | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        continue_on_success: bool = False,
        no_bruteforce: bool = False,
    ) -> dict:
        """Password-spray / validate SMB credentials across targets and accounts.

        Tries `usernames` against `passwords` (or `ntlm_hashes`) and reports which
        authenticate (`[+]`) vs fail (`[-]`). Each entry may be a literal value OR a
        path to a wordlist file on the nxc host (nxc auto-detects files). By default
        nxc tries every user against every password (bruteforce); set
        `no_bruteforce=true` to pair them 1:1 by line. `continue_on_success=true`
        keeps spraying after the first valid credential instead of stopping per host.

        OFFENSIVE-GATED (requires NXC_MODE=full): spraying makes active authentication
        attempts and **can lock out accounts**, so it is refused in recon mode. To
        validate a single known credential without spraying, use `smb_enum_hosts`.
        """
        auth = build_auth_flags(
            username=usernames, password=passwords, ntlm_hash=ntlm_hashes,
            domain=domain, local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache,
        )
        extra = list(auth)
        if continue_on_success:
            extra.append("--continue-on-success")
        if no_bruteforce:
            extra.append("--no-bruteforce")
        outcome = await execute(get_config(), "smb", targets, extra, offensive=True)
        return outcome.to_dict()

    @mcp.tool()
    async def smb_rid_brute(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate domain principals by RID cycling over a null/guest session (`--rid-brute`).

        Read-only enumeration (no authentication brute force); useful when SAMR
        user enumeration is restricted but RID lookups still succeed.

        Includes a structured `accounts` list: `{host, rid, domain, account, sid_type}`
        per resolved SID (users, groups, and machine accounts).
        """
        result = await _enum(
            get_config, "rid_brute", targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["accounts"] = parse_rid_brute(result["stdout"])
        return result

    # ---- Credential dumping (offensive but read-only; NXC_MODE=loot or full) ---- #

    @mcp.tool()
    async def smb_sam(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Dump local SAM password hashes (`--sam`). Requires local admin.

        Returns a structured `credentials` list (`{account, account_type, rid, lm, nt}`)
        ready for pass-the-hash. CREDENTIAL-DUMPING (NXC_MODE=loot or full): read-only, but harvests credential material.
        """
        result = await _loot_run(
            get_config, ["--sam"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["credentials"] = parse_secretsdump(result["stdout"])
        return result

    @mcp.tool()
    async def smb_lsa(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Dump LSA secrets (cached creds, service/machine accounts, gMSA) (`--lsa`). Requires admin.

        Returns a structured `secrets` list classifying each dumped item -- machine/user
        NTLM hashes, Kerberos keys, plaintext, DCC2 cached logons, DPAPI keys, and gMSA
        artifacts (`gmsa_id`+`ntlm`, `_SC_GMSA_…` blobs). An agent can extract these and
        chain them (e.g. feed a `gmsa_id` to ldap `--gmsa-convert-id`, or pass-the-hash a
        machine account). CREDENTIAL-DUMPING (NXC_MODE=loot or full): read-only, but harvests credential material.
        """
        result = await _loot_run(
            get_config, ["--lsa"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["secrets"] = parse_lsa_secrets(result["stdout"])
        return result

    @mcp.tool()
    async def smb_ntds(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
        method: str | None = None,
        include_history: bool = False,
        enabled_only: bool = False,
        kerberos_keys: bool = False,
        only_user: str | None = None,
    ) -> dict:
        """Dump the domain NTDS.dit hashes from a DC (`--ntds`). Requires domain admin.

        `method` selects the extraction technique: `drsuapi` (default, over the wire)
        or `vss` (volume shadow copy). `include_history` adds `--history` (password
        history); `enabled_only` adds `--enabled` (skip disabled accounts);
        `kerberos_keys` adds `--kerberos-keys` (also dump AES/DES keys); `only_user`
        dumps just that account (`--user <name>`).

        Returns a structured `credentials` list (`{account, account_type, rid, lm, nt,
        ...}`; `kerberos_key` entries when `kerberos_keys=true`) ready for replay.
        CREDENTIAL-DUMPING (NXC_MODE=loot or full): read-only, but dumps every domain
        credential -- run only against a DC you are authorized to compromise.
        """
        flags = ["--ntds"]
        if method is not None:
            if method not in ("drsuapi", "vss"):
                raise ValueError("method must be 'drsuapi' or 'vss'")
            flags.append(method)
        extra: list[str] = []
        if include_history:
            extra.append("--history")
        if enabled_only:
            extra.append("--enabled")
        if kerberos_keys:
            extra.append("--kerberos-keys")
        if only_user:
            extra += ["--user", only_user]
        result = await _loot_run(
            get_config, flags, targets, extra_flags=extra, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["credentials"] = parse_secretsdump(result["stdout"])
        return result

    @mcp.tool()
    async def smb_dpapi(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
        modes: list[str] | None = None,
    ) -> dict:
        """Dump DPAPI-protected secrets (saved browser/RDP/Wi-Fi creds) (`--dpapi`). Requires admin.

        `modes` is an optional list of nxc `--dpapi` values: `cookies` (also dump
        browser cookies) and/or `nosystem` (skip SYSTEM DPAPI). Omit for the default.

        CREDENTIAL-DUMPING (NXC_MODE=loot or full): read-only, but harvests credential material.
        """
        flags = ["--dpapi"]
        if modes:
            for m in modes:
                if m not in ("cookies", "nosystem"):
                    raise ValueError("dpapi modes must be 'cookies' and/or 'nosystem'")
            flags += modes
        return await _loot_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    # ---- Remote command execution (offensive=True; NXC_MODE=full only) ---- #

    @mcp.tool()
    async def smb_exec(
        targets: list[str],
        command: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
        use_powershell: bool = False,
        exec_method: str | None = None,
        no_output: bool = False,
    ) -> dict:
        """Execute a command on the target over SMB (`-x` cmd / `-X` PowerShell). Requires admin.

        `command` is the command line to run. Set `use_powershell=true` to run it via
        PowerShell (`-X`) instead of cmd.exe (`-x`). `exec_method` selects the technique
        (`wmiexec`, `atexec`, `smbexec`, `mmcexec`); omit to let nxc choose. `no_output=true`
        adds `--no-output` (fire-and-forget, don't retrieve stdout).

        OFFENSIVE-GATED (NXC_MODE=full): this is remote code execution -- run only
        against hosts you are explicitly authorized to compromise. The command is
        passed as a single argv token (no shell interpretation on this side).
        """
        if not command or not command.strip():
            raise ValueError("command is required for smb_exec")
        flags: list[str] = []
        if exec_method is not None:
            if exec_method not in ("wmiexec", "atexec", "smbexec", "mmcexec"):
                raise ValueError(
                    "exec_method must be one of wmiexec, atexec, smbexec, mmcexec"
                )
            flags += ["--exec-method", exec_method]
        flags += (["-X"] if use_powershell else ["-x"]) + [command]
        if no_output:
            flags.append("--no-output")
        return await _offensive_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    # ---- File operations ---- #

    @mcp.tool()
    async def smb_spider(
        targets: list[str],
        share: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
        folder: str | None = None,
        pattern: list[str] | None = None,
        regex: list[str] | None = None,
        content: bool = False,
        depth: int | None = None,
    ) -> dict:
        """Recursively list/search files on an SMB share (`--spider`). Read-only.

        `share` is the share to crawl (e.g. "SYSVOL", "C$"). `folder` sets a base
        sub-folder. `pattern`/`regex` filter by filename (or by file content when
        `content=true`) -- they are mutually exclusive. `depth` caps recursion. This
        only *reads* directory listings and (optionally) file content, so it runs in
        recon mode -- it is not gated.
        """
        if not share or not share.strip():
            raise ValueError("share is required for smb_spider")
        if pattern and regex:
            raise ValueError("pattern and regex are mutually exclusive; pass only one")
        auth = build_auth_flags(
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        flags = ["--spider", share]
        if folder:
            flags += ["--spider-folder", folder]
        if pattern:
            flags += ["--pattern", *pattern]
        if regex:
            flags += ["--regex", *regex]
        if content:
            flags.append("--content")
        if depth is not None:
            flags += ["--depth", str(depth)]
        outcome = await execute(get_config(), "smb", targets, auth + flags, offensive=False)
        return outcome.to_dict()

    @mcp.tool()
    async def smb_get_file(
        targets: list[str],
        share: str,
        remote_path: str,
        local_path: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Download a file from an SMB share (`--share <share> --get-file <remote> <local>`).

        `remote_path` is relative to `share`; the file is written to `local_path` on
        the nxc host. LOOT-GATED (NXC_MODE=loot): read-only retrieval that harvests
        data from the target (no state change).
        """
        flags = ["--share", share, "--get-file", remote_path, local_path]
        return await _loot_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_put_file(
        targets: list[str],
        share: str,
        local_path: str,
        remote_path: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Upload a file to an SMB share (`--share <share> --put-file <local> <remote>`).

        `local_path` is read from the nxc host and written to `remote_path` (relative
        to `share`) on the target. OFFENSIVE-GATED (NXC_MODE=full): writes/plants a
        file on the target.
        """
        flags = ["--share", share, "--put-file", local_path, remote_path]
        return await _offensive_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    # ---- Additional read-only enumeration ---- #

    @mcp.tool()
    async def smb_dir(
        targets: list[str],
        share: str = "C$",
        path: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """List the contents of a path on a share (`--share <share> --dir [path]`). Read-only.

        `path` is relative to `share` (default share C$, default path = share root).
        """
        flags = ["--share", share, "--dir"]
        if path is not None:
            flags.append(path)
        result = await _recon_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["entries"] = parse_dir(result["stdout"])
        return result

    @mcp.tool()
    async def smb_interfaces(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate the target's network interfaces (`--interfaces`). Read-only."""
        return await _recon_run(
            get_config, ["--interfaces"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_tasklist(
        targets: list[str],
        process_filter: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate running processes (`--tasklist`). Read-only.

        `process_filter` (optional) limits output to processes matching that name.
        """
        flags = ["--tasklist"]
        if process_filter is not None:
            flags.append(process_filter)
        return await _recon_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_wmi_query(
        targets: list[str],
        query: str,
        namespace: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Run a WMI query against the target (`--wmi-query <query>`). Read-only.

        `namespace` overrides the WMI namespace (default root\\cimv2).
        """
        if not query or not query.strip():
            raise ValueError("query is required for smb_wmi_query")
        flags = ["--wmi-query", query]
        if namespace:
            flags += ["--wmi-namespace", namespace]
        result = await _recon_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["rows"] = parse_wmi(result["stdout"])
        return result

    @mcp.tool()
    async def smb_gen_relay_list(
        targets: list[str],
        output_file: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Write hosts that don't require SMB signing to a file (`--gen-relay-list <file>`).

        Read-only recon: identifies NTLM-relay targets. `output_file` is written on
        the nxc host.
        """
        return await _recon_run(
            get_config, ["--gen-relay-list", output_file], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_generate_hosts_file(
        targets: list[str],
        output_file: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Build an /etc/hosts mapping (IP -> FQDN) from the targets (`--generate-hosts-file <file>`).

        Read-only recon. Useful when the testing host has **no DNS for the AD domain**:
        Kerberos/FQDN-based tools need name resolution. The result includes the parsed
        `hosts_entries` and `instructions` to apply them. In `suggest` mode it returns the
        command for you to run yourself; in `recon`/`full` it writes `output_file` on the
        nxc host. Applying it (review first!) typically: `sudo sh -c 'cat <file> >> /etc/hosts'`.
        """
        result = await _recon_run(
            get_config, ["--generate-hosts-file", output_file], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["hosts_file"] = output_file
        if result["dry_run"]:
            result["instructions"] = (
                f"[suggest] Run the shown command to generate the hosts file, then review it "
                f"and append to /etc/hosts to enable FQDN/Kerberos resolution: "
                f"sudo sh -c 'cat {output_file} >> /etc/hosts'"
            )
        else:
            try:
                with open(os.path.expanduser(output_file), encoding="utf-8") as fh:
                    result["hosts_entries"] = parse_hosts_file(fh.read())
            except OSError:
                result["hosts_entries"] = []
            n = len(result["hosts_entries"])
            result["instructions"] = (
                f"Wrote {n} host entr{'y' if n == 1 else 'ies'} to {output_file} (on the nxc host). "
                f"Review it, then append to /etc/hosts to resolve these FQDNs without DNS: "
                f"sudo sh -c 'cat {output_file} >> /etc/hosts'"
            )
        return result

    @mcp.tool()
    async def smb_generate_krb5_file(
        targets: list[str],
        output_file: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Generate a `krb5.conf` for the target's realm (`--generate-krb5-file <file>`). Read-only.

        Companion to `smb_generate_hosts_file` for the Kerberos config side: when the
        testing host lacks a krb5 config, this writes one (realm, KDC, domain_realm) so
        `-k`/`--aesKey` auth works. The result includes the generated `krb5_conf` and
        `instructions`. Apply with: `export KRB5_CONFIG=<file>` (or copy to /etc/krb5.conf).
        In `suggest` mode it returns the command for you to run yourself.
        """
        result = await _recon_run(
            get_config, ["--generate-krb5-file", output_file], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["krb5_file"] = output_file
        if result["dry_run"]:
            result["instructions"] = (
                f"[suggest] Run the shown command to generate the krb5.conf, then use it with: "
                f"export KRB5_CONFIG={output_file}"
            )
        else:
            try:
                with open(os.path.expanduser(output_file), encoding="utf-8") as fh:
                    result["krb5_conf"] = fh.read()
            except OSError:
                result["krb5_conf"] = ""
            result["instructions"] = (
                f"Wrote krb5.conf to {output_file} (on the nxc host). Use it for Kerberos auth "
                f"with: export KRB5_CONFIG={output_file}  (or copy it to /etc/krb5.conf)."
            )
        return result

    @mcp.tool()
    async def smb_generate_tgt(
        targets: list[str],
        output_file: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Request a Kerberos TGT and save it to a ccache file (`--generate-tgt <file>`).

        Authenticates with the supplied creds (password / `ntlm_hash` / `aes_key`) and
        writes a ccache to `output_file`. Then reuse it WITHOUT re-authenticating: pass
        `ccache="<output_file>"` to any tool here (it sets KRB5CCNAME for that call and
        adds `--use-kcache`), or `export KRB5CCNAME=<output_file>` in your own shell.
        Read-only (it requests your own ticket).
        """
        result = await _recon_run(
            get_config, ["--generate-tgt", output_file], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps,
            kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
        result["ccache_file"] = output_file
        if result["dry_run"]:
            result["instructions"] = (
                f"[suggest] Run the shown command to write the TGT, then reuse it with "
                f"ccache=\"{output_file}\" on any tool (or export KRB5CCNAME={output_file})."
            )
        else:
            result["instructions"] = (
                f"TGT written to {output_file}. Reuse it without re-auth: pass "
                f"ccache=\"{output_file}\" to any tool here, or export KRB5CCNAME={output_file}."
            )
        return result

    @mcp.tool()
    async def smb_list_snapshots(
        targets: list[str],
        share: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """List VSS (Volume Shadow Copy) snapshots on the target (`--list-snapshots`). Requires admin.

        Read-only: useful as a precursor to snapshot-based credential dumping.
        `share` overrides the default (ADMIN$).
        """
        flags = ["--list-snapshots"]
        if share:
            flags.append(share)
        return await _recon_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    # ---- Additional offensive actions (offensive=True; NXC_MODE=full only) ---- #

    @mcp.tool()
    async def smb_sccm(
        targets: list[str],
        method: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Dump SCCM secrets from the target (`--sccm`). Requires admin.

        `method` is `disk` (default) or `wmi`. OFFENSIVE-GATED (NXC_MODE=full):
        extracts credential material.
        """
        flags = ["--sccm"]
        if method is not None:
            if method not in ("disk", "wmi"):
                raise ValueError("method must be 'disk' or 'wmi'")
            flags.append(method)
        return await _offensive_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_taskkill(
        targets: list[str],
        process: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Kill a process on the target by PID or name (`--taskkill <pid|name>`). Requires admin.

        OFFENSIVE-GATED (NXC_MODE=full): terminates a process on the target.
        """
        if not process or not process.strip():
            raise ValueError("process (PID or name) is required for smb_taskkill")
        return await _offensive_run(
            get_config, ["--taskkill", process], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_delegate(
        targets: list[str],
        impersonate_user: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
        local_auth: bool = False,
        kerberos: bool = False,
        use_kcache: bool = False,
        cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
        self_only: bool = False,
        u2u: bool = False,
        spn: str | None = None,
        store_ticket: str | None = None,
    ) -> dict:
        """Abuse S4U delegation to impersonate a user (`--delegate <user>`). Requires delegation rights.

        Does S4U2Self + S4U2Proxy to obtain a service ticket as `impersonate_user`.
        `self_only=true` does only S4U2Self (`--self`); `u2u=true` uses User-to-User
        (`--u2u`); `spn` overrides the S4U2Proxy SPN (`--spn`); `store_ticket`
        saves the ticket to a file (`--generate-st`).

        OFFENSIVE-GATED (NXC_MODE=full): credential/ticket abuse technique.
        """
        flags = ["--delegate", impersonate_user]
        if self_only:
            flags.append("--self")
        if u2u:
            flags.append("--u2u")
        if spn:
            flags += ["--spn", spn]
        if store_ticket:
            flags += ["--generate-st", store_ticket]
        return await _offensive_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    # ---- Promoted `-M` modules (first-class tools for high-value modules) ---- #
    # Detection/enum modules run in recon mode; credential-gathering ones are offensive.

    @mcp.tool()
    async def smb_zerologon(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Check if a DC is vulnerable to Zerologon / CVE-2020-1472 (`-M zerologon`). Read-only check.

        Detection only -- does NOT reset the machine account password.
        """
        return await _run_module(
            get_config, "zerologon", targets, offensive=False, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_nopac(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Check if a DC is vulnerable to noPac / CVE-2021-42278 & 42287 (`-M nopac`). Read-only check."""
        return await _run_module(
            get_config, "nopac", targets, offensive=False, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_printnightmare(
        targets: list[str],
        port: int | None = None,
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Check if a host is vulnerable to PrintNightmare (`-M printnightmare`). Read-only check.

        `port` overrides the RPC port (default 445).
        """
        return await _run_module(
            get_config, "printnightmare", targets, offensive=False,
            options={"PORT": port}, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_sccm_recon6(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Detect if the target is an SCCM Distribution Point / Primary Site Server (`-M sccm-recon6`). Read-only."""
        return await _run_module(
            get_config, "sccm-recon6", targets, offensive=False, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_ntlmv1(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Check whether NTLMv1 is allowed on the target (`-M ntlmv1`). Read-only. **Requires admin** (reads the registry)."""
        return await _run_module(
            get_config, "ntlmv1", targets, offensive=False, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_webdav(
        targets: list[str],
        message: str | None = None,
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Check whether the WebClient (WebDAV) service is running (`-M webdav`). Read-only.

        `message` overrides the info string (the module's `MSG` option; '{}' = target).
        """
        return await _run_module(
            get_config, "webdav", targets, offensive=False, options={"MSG": message},
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache,
            cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_spooler(
        targets: list[str],
        port: int | None = None,
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Check whether the print spooler service is enabled (`-M spooler`). Read-only.

        `port` overrides the RPC port (default 135).
        """
        return await _run_module(
            get_config, "spooler", targets, offensive=False, options={"PORT": port},
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache,
            cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_enum_ca(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Hunt for ADCS Certificate Authorities over RPC (`-M enum_ca`). Read-only enumeration."""
        return await _run_module(
            get_config, "enum_ca", targets, offensive=False, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_enum_av(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Enumerate installed endpoint-protection / AV solutions (`-M enum_av`). Read-only."""
        return await _run_module(
            get_config, "enum_av", targets, offensive=False, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_coerce_plus(
        targets: list[str],
        listener: str | None = None,
        method: str | None = None,
        always: bool = False,
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Check for / trigger authentication-coercion vulns (`-M coerce_plus`).

        With no `listener` the coercion targets localhost (harmless) -- a vulnerability
        **check**, so it runs in recon mode. Supplying a real `listener` IP makes the
        target authenticate to you (relay/coercion attack) -- that is **offensive** and
        requires NXC_MODE=full. `method` selects the technique (Petitpotam, DFSCoerce,
        ShadowCoerce, Printerbug, MSEven, All; default All); `always` tries all methods.
        """
        offensive = listener is not None
        options = {"LISTENER": listener, "METHOD": method}
        if always:
            options["ALWAYS"] = "True"
        return await _run_module(
            get_config, "coerce_plus", targets, offensive=offensive, options=options,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            local_auth=local_auth, kerberos=kerberos, use_kcache=use_kcache,
            cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_gpp_password(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Recover GPP cPassword cleartext creds from SYSVOL (`-M gpp_password`).

        CREDENTIAL-DUMPING (NXC_MODE=loot or full): read-only, but harvests credential material.
        """
        return await _run_module(
            get_config, "gpp_password", targets, offensive=True, dump=True, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )

    @mcp.tool()
    async def smb_gpp_autologin(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None, local_auth: bool = False,
        kerberos: bool = False, use_kcache: bool = False, cred_id: int | None = None,
        laps: str | None = None,
        kdc_host: str | None = None,
        aes_key: str | None = None,
        ccache: str | None = None,
        pfx_cert: str | None = None,
        pfx_base64: str | None = None,
        pfx_pass: str | None = None,
        pem_cert: str | None = None,
        pem_key: str | None = None,
    ) -> dict:
        """Recover autologon credentials from SYSVOL registry.xml (`-M gpp_autologin`).

        CREDENTIAL-DUMPING (NXC_MODE=loot or full): read-only, but harvests credential material.
        """
        return await _run_module(
            get_config, "gpp_autologin", targets, offensive=True, dump=True, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, local_auth=local_auth,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key,
        )
