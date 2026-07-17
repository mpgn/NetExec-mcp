"""Shared authentication model -> nxc flags.

Every protocol module accepts the same credential parameters; this module turns
them into the argv flags nxc expects, with light validation of nonsensical
combinations. It builds *only* the auth-related flags -- targets and per-tool
action flags (e.g. ``--shares``) are added by the caller.

Mapping (per PLAN.md "Shared auth model -> flags"):
  username      -> -u
  password      -> -p
  ntlm_hash     -> -H   (pass-the-hash)
  domain        -> -d
  local_auth    -> --local-auth
  kerberos      -> -k
  use_kcache    -> --use-kcache  (implies kerberos)
  cred_id       -> -id  (use a credential already stored in nxc's DB)
"""

from __future__ import annotations


class AuthError(ValueError):
    """Raised for contradictory credential parameters (nothing runs)."""


def _as_list(value) -> list[str]:
    """Normalise a str | list[str] | None credential field to a list of tokens."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


# The blank/empty-LM hash. nxc's DB stores a pass-the-hash secret as `<LM>:<NT>`, and for a
# modern account the LM half is this constant. Passing the full `<blankLM>:<NT>` can fail
# auth (observed live: NTDS dump -> STATUS_LOGON_FAILURE on a DC that refuses LM) while the
# bare NT hash succeeds -- so reduce a blank-LM pair to just the NT half.
_BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"


def _nt_only(h: str) -> str:
    """Reduce a `LM:NT` hash whose LM half is the blank-LM value (or empty) to the bare NT
    hash. A real (non-blank) LM half, a plain NT hash, and a non-hash token (e.g. a wordlist
    path) are returned unchanged -- only an exact blank-LM prefix is stripped."""
    lm, sep, nt = h.partition(":")
    if sep and nt and (lm.lower() == _BLANK_LM or lm == ""):
        return nt
    return h


def build_auth_flags(
    username: "str | list[str] | None" = None,
    password: "str | list[str] | None" = None,
    ntlm_hash: "str | list[str] | None" = None,
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
) -> list[str]:
    """Translate credential parameters into an nxc auth flag list.

    username/password/ntlm_hash accept either a single value or a list (for
    password spraying); each list entry may be a literal value or a path to a
    wordlist file that nxc reads. `laps` enables LAPS auth (`--laps <account>`):
    nxc reads the target's LAPS-managed local-admin password from AD using the
    supplied creds, then authenticates with it -- pass the account name (use
    "administrator" for the nxc default). Raises AuthError on contradictory
    combinations so a bad call is rejected before any command is built.
    """
    usernames = _as_list(username)
    passwords = _as_list(password)
    hashes = _as_list(ntlm_hash)
    cert_auth = bool(pfx_cert or pfx_base64 or pem_cert)

    if passwords and hashes:
        raise AuthError("provide either password(s) or NTLM hash(es), not both.")
    if local_auth and domain:
        raise AuthError("--local-auth authenticates locally; do not also set a domain.")
    if cred_id is not None and (usernames or passwords or hashes or domain or local_auth):
        raise AuthError(
            "cred_id uses a credential stored in nxc's DB; do not also pass "
            "username/password/hash/domain/local_auth."
        )
    if cert_auth and not usernames:
        raise AuthError("certificate authentication requires a username.")
    if bool(pem_cert) != bool(pem_key):
        raise AuthError("PEM certificate auth needs both pem_cert and pem_key.")

    flags: list[str] = []

    if cred_id is not None:
        flags += ["-id", str(cred_id)]
    else:
        if domain:
            flags += ["-d", domain]
        for user in usernames:
            flags += ["-u", user]
        for pw in passwords:
            flags += ["-p", pw]
        if usernames and not passwords and not hashes and not (kerberos or use_kcache or aes_key or ccache or cert_auth):
            # Username(s) with no secret = empty-password (guest/null) bind. nxc
            # needs an explicit `-p ''`; emitting it here makes guest auth reliable
            # without an agent having to serialise an empty string (which MCP
            # clients routinely mangle). `-u guest` -> `-u guest -p ''`.
            flags += ["-p", ""]
        for h in hashes:
            flags += ["-H", _nt_only(h)]
        if local_auth:
            flags.append("--local-auth")

    # Certificate authentication (PKINIT / ADCS) -- a distinct method (requires a
    # username, checked above). Provide a pfx (file or base64, optional --pfx-pass)
    # OR a PEM cert+key pair.
    if pfx_cert:
        flags += ["--pfx-cert", pfx_cert]
    if pfx_base64:
        flags += ["--pfx-base64", pfx_base64]
    if pfx_pass:
        flags += ["--pfx-pass", pfx_pass]
    if pem_cert:
        flags += ["--pem-cert", pem_cert]
    if pem_key:
        flags += ["--pem-key", pem_key]

    if laps:
        flags += ["--laps", laps]

    # Kerberos options. `--aesKey` is itself a Kerberos secret (overpass-the-key;
    # pairs with the aes256/aes128 keys recovered by smb_lsa/smb_ntds) -- nxc treats
    # its presence as enabling Kerberos, so no separate -k is needed. `--kdcHost`
    # names the KDC and is often required for `-k` to resolve the DC.
    if aes_key:
        flags += ["--aesKey", aes_key]
    if kdc_host:
        flags += ["--kdcHost", kdc_host]

    # Kerberos can layer on top of either path (e.g. -k with a username, or
    # --use-kcache with a stored ticket). A `ccache` path implies --use-kcache
    # (the executor points KRB5CCNAME at it; nxc has no ccache flag).
    if use_kcache or ccache:
        flags.append("--use-kcache")
    elif kerberos:
        flags.append("-k")

    return flags
