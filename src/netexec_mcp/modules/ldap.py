"""LDAP protocol module.

Every tool funnels through :func:`executor.execute`, so scope/cap/offensive
guardrails and the audit log apply uniformly. The surface spans:

  * **Read-only enumeration** (``offensive=False``) -- auth check, users/groups/
    OUs/computers, DC list, domain SID, password policy/PSO, AD attack-path recon
    (delegation, PASSWD_NOTREQD, adminCount), custom LDAP query, BloodHound
    collection, and gMSA id->name resolution.
  * **Credential-gathering / offensive** (``offensive=True``, only under
    ``NXC_MODE=full``) -- asreproast, kerberoast (+targeted), gMSA password
    retrieval, and gMSA-from-LSA decryption.

LDAP is always domain authentication, so these tools omit ``--local-auth``. They
share the rest of the credential model from :mod:`auth` (user/pass, ``-H`` hash,
Kerberos, ``-d`` domain, stored ``cred_id``, ``laps``). Every tool also exposes the
``ldap_timeout`` transport knob (nxc ``--ldap-timeout``, default 3s) -- raise it for
slow or high-latency DCs where the aggressive default trips a false connection error.
"""

from __future__ import annotations

import re

from ..auth import build_auth_flags
from ..executor import execute
from ..results import (
    decode_attributes,
    parse_dc_list,
    parse_domain_sid,
    parse_ldap_computers,
    parse_ldap_delegation,
    parse_ldap_group_members,
    parse_ldap_gmsa,
    parse_ldap_gmsa_id,
    parse_ldap_groups,
    parse_ldap_ou_users,
    parse_ldap_ous,
    parse_ldap_principals,
    parse_pass_pol,
    parse_ldap_query,
    parse_password_not_required,
    parse_roast_hashes,
    parse_users,
)

_ATTR_SPLIT_RE = re.compile(r"[,;\s]+")


def _normalize_attributes(attributes: list[str] | str | None) -> list[str]:
    """Accept every spelling a model produces and return a clean attribute list.

    nxc wants ONE space-separated argv element; a comma- or semicolon-separated list
    is silently dropped (DN returned, zero attributes, exit 0), which gives the caller
    no signal at all. Models write commas (they mirror the docstring's prose or JSON
    habits), so normalize instead of failing quietly. A list is taken as-is, a string
    is split on commas, semicolons and whitespace; blanks are dropped.
    """
    if attributes is None:
        return []
    items = attributes if isinstance(attributes, list) else _ATTR_SPLIT_RE.split(attributes)
    return [a.strip() for a in items if a and a.strip()]


async def _ldap_run(
    get_config,
    action_flags: list[str],
    targets: list[str],
    *,
    offensive: bool = False,
    dump: bool = False,
    extra_flags: list[str] | None = None,
    username=None,
    password=None,
    ntlm_hash=None,
    domain=None,
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
    ldap_timeout=None,
) -> dict:
    """Build auth+action flags and run against the ldap protocol."""
    auth = build_auth_flags(
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
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
    transport: list[str] = []
    if ldap_timeout is not None:
        transport += ["--ldap-timeout", str(ldap_timeout)]
    extra = auth + transport + list(action_flags) + list(extra_flags or [])
    outcome = await execute(get_config(), "ldap", targets, extra,
                            offensive=offensive, dump=dump, ccache=ccache)
    return outcome.to_dict()


async def _ldap_module(get_config, module, targets, *, offensive=False, dump=False, options=None, **kw) -> dict:
    """Run a promoted `-M <module>` (with `-o KEY=val` options) on the ldap protocol."""
    flags = ["-M", module]
    kv = [f"{k}={v}" for k, v in (options or {}).items() if v is not None and v != ""]
    if kv:
        flags += ["-o", *kv]
    return await _ldap_run(get_config, flags, targets, offensive=offensive, dump=dump, **kw)


def register(mcp, get_config) -> None:
    """Attach the LDAP tools to the FastMCP app."""

    # ---- Read-only enumeration (recon mode) ---- #

    @mcp.tool()
    async def ldap_enum_hosts(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Fingerprint the DC over LDAP and verify authentication (bare `nxc ldap <targets>`).

        Reports OS/domain and the auth result (`[+]`/`[-]`). Pass credentials to bind,
        or none for an anonymous bind where allowed.
        """
        return await _ldap_run(
            get_config, [], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )

    @mcp.tool()
    async def ldap_users(
        targets: list[str],
        users: list[str] | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Enumerate domain users (`--users`). Pass `users` to query specific accounts.

        Includes a structured `users` list (`{host, username, last_pw_set, bad_pw_count,
        description}`), same shape as `smb_users`.
        """
        result = await _ldap_run(
            get_config, ["--users", *(users or [])], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["users"] = parse_users(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_active_users(
        targets: list[str],
        users: list[str] | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Enumerate only active (non-disabled) domain user accounts (`--active-users`)."""
        result = await _ldap_run(
            get_config, ["--active-users", *(users or [])], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["users"] = parse_users(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_groups(
        targets: list[str],
        group: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Enumerate domain groups (`--groups`); pass `group` to list its members.

        (This is the `--groups` capability nxc moved from the smb protocol to ldap.)

        Without `group`, nxc prints a table -> parsed into `groups`
        (`{group, members (int), description}`). With `group`, nxc prints bare
        member names -> parsed into `members` (`{host, member}`).
        """
        flags = ["--groups"] + ([group] if group else [])
        result = await _ldap_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        if group:
            result["members"] = parse_ldap_group_members(result["stdout"])
        else:
            result["groups"] = parse_ldap_groups(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_ous(
        targets: list[str],
        ou: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Enumerate organizational units (`--ous`); pass `ou` to list the users inside one.

        Without `ou`, nxc prints the OU inventory -> parsed into `ous`
        (`{host, ou, distinguished_name}`). The DN is the useful half: it is the
        `base_dn` to hand to `ldap_query` to scope a search to that OU.

        With `ou` (the OU's *name*, not its DN), the search is scoped to that OU's
        baseDN and the users are parsed into `users` (`{host, username, cn}`).
        Useful for mapping delegation boundaries: which accounts live under an OU
        tells you who a GPO or an OU-level ACL applies to.
        """
        flags = ["--ous"] + ([ou] if ou else [])
        result = await _ldap_run(
            get_config, flags, targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        if ou:
            result["users"] = parse_ldap_ou_users(result["stdout"])
        else:
            result["ous"] = parse_ldap_ous(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_computers(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Enumerate domain computer accounts (`--computers`).

        (This is the `--computers` capability nxc moved from the smb protocol to ldap.)
        Includes a structured `computers` list (`{host, computer}`).
        """
        result = await _ldap_run(
            get_config, ["--computers"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["computers"] = parse_ldap_computers(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_dc_list(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Enumerate the domain controllers and the forest's domain trusts (`--dc-list`).

        Includes a structured `dcs` list: `{host, dc, ip}`. nxc additionally prints every
        trusted domain ALREADY DECODED in `stdout`
        (`north.example.local -> Bidirectional -> Within Forest`), which makes this the
        fastest way to characterize a trust. That line is only emitted when the trusted
        domain's DCs resolve over DNS (SRV `_ldap._tcp.dc._msdcs.<trust>`); when they do
        not, read the raw attributes with `ldap_query` on `(objectClass=trustedDomain)`.
        """
        result = await _ldap_run(
            get_config, ["--dc-list"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["dcs"] = parse_dc_list(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_get_sid(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Get the domain SID (`--get-sid`)."""
        result = await _ldap_run(
            get_config, ["--get-sid"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["domain_sid"] = parse_domain_sid(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_pass_pol(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Dump the domain password policy via LDAP (`--pass-pol`)."""
        result = await _ldap_run(
            get_config, ["--pass-pol"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["policy"] = parse_pass_pol(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_pso(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Get fine-grained password policies / PSOs (`--pso`)."""
        return await _ldap_run(
            get_config, ["--pso"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )

    @mcp.tool()
    async def ldap_find_delegation(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Find delegation relationships in the domain (`--find-delegation`)."""
        result = await _ldap_run(
            get_config, ["--find-delegation"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["delegations"] = parse_ldap_delegation(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_trusted_for_delegation(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """List principals flagged TRUSTED_FOR_DELEGATION (`--trusted-for-delegation`)."""
        result = await _ldap_run(
            get_config, ["--trusted-for-delegation"], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["principals"] = parse_ldap_principals(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_password_not_required(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """List users with the PASSWD_NOTREQD flag (`--password-not-required`).

        Includes a structured `accounts` list: `{host, account, status}`.
        """
        result = await _ldap_run(
            get_config, ["--password-not-required"], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["accounts"] = parse_password_not_required(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_admin_count(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """List principals with adminCount=1 (protected/privileged) (`--admin-count`)."""
        result = await _ldap_run(
            get_config, ["--admin-count"], targets, username=username, password=password,
            ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["principals"] = parse_ldap_principals(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_query(
        targets: list[str],
        ldap_filter: str,
        attributes: list[str] | str,
        base_dn: str | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Run a custom LDAP query (`--query <filter> <attributes>`), e.g. for domain trusts.

        The escape hatch for anything the dedicated `ldap_*` tools do not cover, e.g.
        `(objectClass=trustedDomain)` with `trustPartner trustDirection trustAttributes`
        to read a domain trust from the directory itself (`ldap_dc_list` shows the same
        trust already decoded, but only when DNS cooperates).

        `ldap_filter` is an LDAP search filter (e.g. "(objectClass=user)"). `attributes`
        is the attribute list, either a real list (["sAMAccountName", "description"]) or
        a string; commas, semicolons and spaces all work as separators. `base_dn`
        overrides the search base. Results come back parsed in `entries`
        (`[{host, dn, attrs}]`); an entry whose `attrs` is empty means the object was
        found but the attribute list yielded nothing (see the `warning` field).

        An entry also carries `decoded` when it holds an attribute whose value is a raw
        number: `userAccountControl`, `trustDirection`, `trustType`, `trustAttributes` are
        returned both raw (in `attrs`) and read out (in `decoded`), e.g.
        `{"value": 4194816, "flags": ["NORMAL_ACCOUNT", "DONT_REQUIRE_PREAUTH"]}`.
        """
        if not ldap_filter or not ldap_filter.strip():
            raise ValueError("ldap_filter is required for ldap_query")
        # nxc takes ONE space-separated argv element. A comma- or semicolon-separated
        # list is silently ignored by nxc (it returns the DN and no attribute at all),
        # so normalize every spelling here rather than leave a silent dead end.
        attr_list = _normalize_attributes(attributes)
        extra = ["--base-dn", base_dn] if base_dn else []
        result = await _ldap_run(
            get_config, ["--query", ldap_filter, " ".join(attr_list)], targets, extra_flags=extra,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["entries"] = parse_ldap_query(result["stdout"])
        # Numeric AD attributes get their reading NEXT TO the raw value, never instead of it:
        # `trustDirection: "3"` stays, and a `decoded` sibling says "Bidirectional". The key is
        # omitted when nothing is decodable, so an enumeration of plain string attributes pays
        # nothing for this.
        for entry in result["entries"]:
            if decoded := decode_attributes(entry["attrs"]):
                entry["decoded"] = decoded
        # Qualify an empty result instead of relaying bare silence: the model cannot
        # otherwise tell "no such object" from "my attribute list was unusable".
        # A dry-run preview has no output by construction -- never warn on it.
        if result.get("dry_run"):
            return result
        if attr_list and result["entries"] and not any(e["attrs"] for e in result["entries"]):
            result["warning"] = (
                f"{len(result['entries'])} object(s) matched but NO attribute value was "
                f"returned for {attr_list}. Check the attribute names exist on these "
                "objects; pass them as a list or space-separated string."
            )
        elif not result["entries"] and not (result["stdout"] or "").strip():
            result["warning"] = (
                "no output at all: the filter matched nothing, or the target was not "
                "reached. Verify the target is up before assuming an empty directory."
            )
        return result

    @mcp.tool()
    async def ldap_gmsa_convert_id(
        targets: list[str],
        gmsa_id: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Resolve a gMSA ID to its account name (`--gmsa-convert-id <id>`). Read-only.

        Feed a `gmsa_id` recovered from `smb_lsa` here to learn the managed-service
        account name (e.g. `gmsa-robin$`).
        """
        if not gmsa_id or not gmsa_id.strip():
            raise ValueError("gmsa_id is required for ldap_gmsa_convert_id")
        result = await _ldap_run(
            get_config, ["--gmsa-convert-id", gmsa_id], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["gmsa_ids"] = parse_ldap_gmsa_id(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_bloodhound(
        targets: list[str],
        collection: str = "Default",
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Run a BloodHound collection against the domain (`--bloodhound -c <collection>`).

        `collection` is one or more (comma-separated) of: Group, LocalAdmin, Session,
        Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps,
        ACL, ADCS, All. Read-only: collects AD data to a local zip on the nxc host.
        The default collector is BloodHound CE (nxc build >= 595); legacy-format output
        is selected via nxc's config file, not a flag.
        """
        return await _ldap_run(
            get_config, ["--bloodhound", "-c", collection], targets, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )

    # ---- Credential gathering / offensive (NXC_MODE=full only) ---- #

    @mcp.tool()
    async def ldap_asreproast(
        targets: list[str],
        output_file: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """AS-REP roast: collect crackable hashes for users without Kerberos pre-auth (`--asreproast <file>`).

        Hashes are written to `output_file` (on the nxc host) and printed. OFFENSIVE-GATED
        (NXC_MODE=full): gathers crackable credential material.
        """
        result = await _ldap_run(
            get_config, ["--asreproast", output_file], targets, offensive=True, dump=True,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["hashes"] = parse_roast_hashes(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_kerberoast(
        targets: list[str],
        output_file: str,
        accounts: list[str] | None = None,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Kerberoast: collect crackable TGS hashes for SPN accounts (`--kerberoasting <file>`).

        Pass `accounts` to target specific sAMAccountNames (`--kerberoast-account`).
        Hashes are written to `output_file`. OFFENSIVE-GATED (NXC_MODE=full): gathers
        crackable credential material.
        """
        extra = ["--kerberoast-account", *accounts] if accounts else []
        result = await _ldap_run(
            get_config, ["--kerberoasting", output_file], targets, offensive=True, dump=True,
            extra_flags=extra, username=username, password=password, ntlm_hash=ntlm_hash,
            domain=domain, kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["hashes"] = parse_roast_hashes(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_targeted_kerberoast(
        targets: list[str],
        accounts: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Targeted kerberoast: temporarily add an SPN to accounts, request a ST, then remove it (`--targeted-kerberoast`).

        OFFENSIVE-GATED (NXC_MODE=full): this **modifies the directory** (adds/removes an
        SPN on `accounts`) and gathers crackable hashes -- requires write rights on the targets.
        """
        if not accounts:
            raise ValueError("accounts is required for ldap_targeted_kerberoast")
        result = await _ldap_run(
            get_config, ["--targeted-kerberoast", *accounts], targets, offensive=True, dump=True,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["hashes"] = parse_roast_hashes(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_gmsa(
        targets: list[str],
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Retrieve gMSA managed passwords readable by the account (`--gmsa`).

        OFFENSIVE-GATED (NXC_MODE=full): retrieves credential material (the gMSA NTLM/hash).
        """
        result = await _ldap_run(
            get_config, ["--gmsa"], targets, offensive=True, dump=True, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
        result["gmsa"] = parse_ldap_gmsa(result["stdout"])
        return result

    @mcp.tool()
    async def ldap_gmsa_decrypt_lsa(
        targets: list[str],
        blob: str,
        username: str | None = None,
        password: str | None = None,
        ntlm_hash: str | None = None,
        domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Decrypt a gMSA `_SC_GMSA_…` blob recovered from an LSA dump (`--gmsa-decrypt-lsa <blob>`).

        Feed a `gmsa_lsa_blob` value from `smb_lsa` here to recover the gMSA password.
        OFFENSIVE-GATED (NXC_MODE=full): yields credential material.
        """
        if not blob or not blob.strip():
            raise ValueError("blob is required for ldap_gmsa_decrypt_lsa")
        return await _ldap_run(
            get_config, ["--gmsa-decrypt-lsa", blob], targets, offensive=True, dump=True,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )

    # ---- Promoted `-M` modules (first-class tools for high-value ldap modules) ---- #
    # All read-only enumeration (recon). NB: `enum_trusts` and the `pso` module are
    # [REMOVED] upstream -> use ldap_dc_list / ldap_pso instead.

    @mcp.tool()
    async def ldap_adcs(
        targets: list[str],
        server: str | None = None,
        base_dn: str | None = None,
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Find ADCS PKI Enrollment Services and certificate template names (`-M adcs`). Read-only.

        `server` limits enumeration to a specific PKI Enrollment Server (CN); `base_dn`
        overrides the LDAP search base.
        """
        return await _ldap_module(
            get_config, "adcs", targets, offensive=False,
            options={"SERVER": server, "BASE_DN": base_dn},
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )

    @mcp.tool()
    async def ldap_entra_id(
        targets: list[str],
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Find the Entra ID (Azure AD) sync server in the domain (`-M entra-id`). Read-only."""
        return await _ldap_module(
            get_config, "entra-id", targets, offensive=False, username=username,
            password=password, ntlm_hash=ntlm_hash, domain=domain, kerberos=kerberos,
            use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )

    @mcp.tool()
    async def ldap_sccm(
        targets: list[str],
        base_dn: str | None = None,
        recursive_resolve: bool = False,
        username: str | None = None, password: str | None = None,
        ntlm_hash: str | None = None, domain: str | None = None,
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
        ldap_timeout: int | None = None,
    ) -> dict:
        """Find SCCM infrastructure published in Active Directory (`-M sccm`). Read-only.

        `base_dn` overrides the LDAP search base; `recursive_resolve` resolves group
        members recursively (the module's `REC_RESOLVE` option).
        """
        options = {"BASE_DN": base_dn}
        if recursive_resolve:
            options["REC_RESOLVE"] = "True"
        return await _ldap_module(
            get_config, "sccm", targets, offensive=False, options=options,
            username=username, password=password, ntlm_hash=ntlm_hash, domain=domain,
            kerberos=kerberos, use_kcache=use_kcache, cred_id=cred_id, laps=laps, kdc_host=kdc_host, aes_key=aes_key, ccache=ccache, pfx_cert=pfx_cert, pfx_base64=pfx_base64, pfx_pass=pfx_pass, pem_cert=pem_cert, pem_key=pem_key, ldap_timeout=ldap_timeout,
        )
