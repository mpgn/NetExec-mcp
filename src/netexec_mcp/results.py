"""Parse nxc stdout into structured status records.

nxc prints one result per line in a fixed column layout, ending in a status
marker and a message, e.g. (after ANSI stripping):

    SMB   10.0.0.5   445  DC01   [*] Windows Server 2022 (name:DC01) (domain:CORP)
    SMB   10.0.0.5   445  DC01   [+] CORP\\admin:Passw0rd! (Pwn3d!)
    SMB   10.0.0.5   445  DC01   [-] CORP\\bob:badpass STATUS_LOGON_FAILURE

We extract protocol/host/port/hostname plus the marker and message. Lines that
carry a marker but don't match the full column layout still yield a record with
those fields left as None. Reading the nxc SQLite workspace DB for richer data is
a later, optional addition (PLAN.md open question).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

# Full nxc result line: PROTO HOST PORT NAME [marker] message
# `proto` allows `_`/`-`/`.` so promoted `-M` module labels parse like base protocols —
# including nxc's truncated form for long names (e.g. ENUM_IMPERSONATE -> `ENUM_IMP...`).
_LINE_RE = re.compile(
    r"^(?P<proto>[A-Za-z0-9_.-]+)\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+"
    r"\[(?P<marker>[-+*!])\]\s*(?P<message>.*)$"
)
# Column prefix only (no marker): PROTO HOST PORT NAME <rest...>
_PREFIX_RE = re.compile(
    r"^(?P<proto>[A-Za-z0-9_.-]+)\s+(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+"
)
_MARKER_ANYWHERE_RE = re.compile(r"\[[-+*!]\]")
# Fallback: any line carrying a status marker.
_MARKER_RE = re.compile(r"\[(?P<marker>[-+*!])\]\s*(?P<message>.*)$")

_STATUS = {"+": "success", "-": "failure", "*": "info", "!": "error"}


@dataclass
class StatusRecord:
    status: str            # success | failure | info | error
    marker: str            # one of + - * !
    message: str
    protocol: str | None = None
    host: str | None = None
    port: int | None = None
    hostname: str | None = None
    # On `[+]` auth lines only: "pwned" (privilege label), "guest_fallback" ((Guest) -- the
    # credential is INVALID, the server granted a guest/null session), or "valid". None else.
    auth: str | None = None
    # On `[-]`/`[!]` lines carrying a known TERMINAL signature (a ticket/credential that will
    # never work as-is): "auth_error" | "op_error". None otherwise.
    error_class: str | None = None
    terminal: bool = False


# Trailing "(...)" privilege qualifier on an auth line, e.g. "(Pwn3d!)" / "(Guest)".
_TRAILING_QUAL_RE = re.compile(r"\(([^)]+)\)\s*$")
# A real auth line starts with `user:` (AD form `DOMAIN\user:`, or a bare `user:` for SSH/FTP/
# VNC). The leading `[^:\s]+:` (no space before the colon) still excludes non-auth `[+]` lines
# like "[+] Response for object:" (space before the colon) and "[+] Dumping ...". Two `[-]`
# lines have that shape without being auth lines: impacket's T-SQL error "ERROR(HOST\INSTANCE):
# Line 1: ..." (hence no parentheses) and an exec method's "WMIEXEC: Could not retrieve output
# file" (hence no `<METHOD>EXEC:`). Each added a phantom account to auth_failed, 41 times over
# the bench references.
_AUTH_CRED_RE = re.compile(r"^(?![A-Z]+EXEC:)[^:\s()]+:")
# A login with no secret to print has no `user:` prefix, so _AUTH_CRED_RE misses it. nxc writes
# `DOMAIN\user from certificate` (Schannel), `DOMAIN\user from ccache` (a Kerberos ticket cache)
# and `DOMAIN\target through S4U[+U2U] with X [(w/ SPN ...)]` (delegation), on success and
# failure lines alike, optionally followed by ` (Pwn3d!)` or an error. Only the certificate form
# was matched, so a non-admin ticket login read as no login at all (klist lab test, 2026-11-12).
# Anchored, the user before the suffix: nxc before 97b31bf1 printed the mssql failure as
# `DOMAIN\user: from ccache <error>`, which _AUTH_CRED_RE reads instead.
_NO_SECRET_AUTH_RE = re.compile(
    r"^(?P<who>[^\s:()]+)\s+(?:from (?:certificate|ccache)"
    r"|through S4U(?:\+U2U)? with \S+(?: \(w/ SPN [^)]*\))?)(?=\s|$)", re.IGNORECASE)
# Terminal failure signatures: the ticket/credential will NOT work on a plain retry (re-forge
# or change credential). Conservative: NO bare STATUS_ACCESS_DENIED (benign, e.g. a guest that
# cannot list shares), and NO transient errors -- KRB_AP_ERR_SKEW (fix the clock) and
# STATUS_ACCOUNT_LOCKED_OUT (unlocks after the lockout window) are deliberately excluded.
_TERMINAL_SIGNATURES = (
    ("auth_error", re.compile(
        r"KDC_ERR_(?:TGT_REVOKED|WRONG_REALM|CLIENT_REVOKED|C_PRINCIPAL_UNKNOWN|PREAUTH_FAILED)"
        r"|WRONG_REALM|STATUS_USER_SESSION_DELETED"
        r"|STATUS_ACCOUNT_DISABLED|STATUS_PASSWORD_EXPIRED|KRB_AP_ERR_MODIFIED"
        r"|KRB_AP_ERR_TKT_EXPIRED", re.I)),
    ("op_error", re.compile(r"rpc_s_access_denied|DRSUAPI.*denied|DCSync.*denied", re.I)),
)
# A saved Kerberos ticket (getST/S4U/ticketer): a real success even when sibling hosts fail.
# Requires the save VERB (no bare `.ccache` catch-all, which matched any line merely NAMING a
# cache path -- incl. a failure line -- and falsely flipped a terminal error to "success").
_TICKET_SAVED_RE = re.compile(r"sav(?:ed|ing)\b.*(?:\.ccache|\.kirbi|ticket)", re.I)


def _auth_label(marker: str, message: str, pwn3d_label: str) -> str | None:
    """Classify a `[+]` auth line. See StatusRecord.auth."""
    if marker != "+":
        return None
    m = _TRAILING_QUAL_RE.search(message)
    if m:
        q = m.group(1).strip()
        if q.casefold() == pwn3d_label.casefold():
            return "pwned"
        if q.casefold() == "guest":
            return "guest_fallback"
    if _is_auth_line(message):
        # SSH prints the label mid-line, before the platform (`user:secret (Pwn3d!) Linux - Shell
        # access!`), so an admin SSH login was never marked pwned.
        if re.search(rf"\s\({re.escape(pwn3d_label)}\)(?:\s|$)", message):
            return "pwned"
        return "valid"
    return None


def _is_auth_line(message: str) -> bool:
    """A login line: `user:secret ...` or one of the secret-less forms of _NO_SECRET_AUTH_RE."""
    return bool(_AUTH_CRED_RE.match(message) or _NO_SECRET_AUTH_RE.match(message))


def _error_tag(marker: str, message: str) -> tuple[str | None, bool]:
    """Classify a failure line against the terminal-signature table."""
    if marker in ("-", "!"):
        for cls, rx in _TERMINAL_SIGNATURES:
            if rx.search(message):
                return cls, True
    return None, False


def count_unmarked_lines(text: str) -> int:
    """Count the non-empty stdout lines that carry NO status marker.

    nxc publishes headings through `log.display()`/`success()`/`fail()`/`info()`
    (which render a `[*]`/`[+]`/`[-]`/`[!]` marker and so land in `records`) but
    publishes its *findings* through `log.highlight()`, which prints no marker at
    all. `records`/`counts` therefore describe only the headings: for a tool with no
    dedicated parser, a caller triaging on them reads "2 info, 1 success" and
    concludes nothing was found, while the payload sits in `stdout`.

    This is a *pointer*, not a capture -- it says "there are N lines I did not
    summarise for you, read `stdout`". It is deliberately unfiltered: table headers,
    `----` separators and nxc's block-separating blank highlights all count, because
    deciding which of them are noise is exactly the lossy judgement a pointer avoids
    having to make. See docs/unmarked-output-salience.md.
    """
    return sum(
        1 for raw in (text or "").splitlines()
        if raw.strip() and not _MARKER_ANYWHERE_RE.search(raw)
    )


def parse_markers(text: str, pwn3d_label: str = "Pwn3d!") -> list[StatusRecord]:
    """Turn nxc stdout into a list of StatusRecord (one per marker line).

    `pwn3d_label` is the operator-configured pwn marker (``config.pwn3d_label``, default
    ``Pwn3d!``); it decides which ``[+]`` lines are tagged ``auth="pwned"``. The default
    is only a last-resort fallback for direct unit calls -- production always threads the
    configured value.
    """
    records: list[StatusRecord] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        full = _LINE_RE.match(line)
        if full:
            marker = full["marker"]
            message = full["message"].strip()
            error_class, terminal = _error_tag(marker, message)
            records.append(
                StatusRecord(
                    status=_STATUS[marker],
                    marker=marker,
                    message=message,
                    protocol=full["proto"],
                    host=full["host"],
                    port=int(full["port"]),
                    hostname=full["name"],
                    auth=_auth_label(marker, message, pwn3d_label),
                    error_class=error_class,
                    terminal=terminal,
                )
            )
            continue

        marker_only = _MARKER_RE.search(line)
        if marker_only:
            marker = marker_only["marker"]
            message = marker_only["message"].strip()
            error_class, terminal = _error_tag(marker, message)
            records.append(
                StatusRecord(
                    status=_STATUS[marker],
                    marker=marker,
                    message=message,
                    auth=_auth_label(marker, message, pwn3d_label),
                    error_class=error_class,
                    terminal=terminal,
                )
            )
    return records


def _user_from_message(message: str) -> str | None:
    """Pull the bare username out of an auth line.

    Handles both the credential form `DOMAIN\\user:secret ...` and the secret-less forms
    `DOMAIN\\user from certificate|ccache [...]` / `DOMAIN\\target through S4U with X [...]`.
    """
    if (m := _NO_SECRET_AUTH_RE.match(message)):
        frag = m["who"]                                     # DOMAIN\user
    elif _AUTH_CRED_RE.match(message):
        frag = message.split(":", 1)[0]                     # DOMAIN\user
    else:
        return None
    return frag.split("\\", 1)[1] if "\\" in frag else frag


# The status code a failed login line ends with (SMB/MSSQL STATUS_*, Kerberos errors).
_FAIL_REASON_RE = re.compile(r"\b(?:STATUS_[A-Z_]+|KDC_ERR_[A-Z_]+|KRB_AP_ERR_[A-Z_]+)\b")


def build_verdict(records, returncode=None, unparsed_lines=0, stderr=""):
    """Derive one authoritative outcome from the parsed records.

    Returns ``(verdict, outcome_class, op_error, op_error_note)`` where ``verdict`` answers
    "did any host authenticate / did we pwn / was a ticket saved" in a single field, so a
    consumer never has to re-triage records or string-match. A call is a SUCCESS when ANY
    host authenticates (a sibling ``[-]`` never buries a pwn), a ``(Guest)`` fallback is a
    guest_only (the credential is INVALID), a returncode-0 call with nothing is benign-empty
    (not a failure), and a known-terminal error is flagged so the agent does not retry it.
    """
    authenticated, guest_only, auth_failed, errors = [], [], [], []
    ticket_saved = False
    for r in records:
        if r.auth == "pwned":
            authenticated.append({"host": r.host, "user": _user_from_message(r.message), "pwned": True})
        elif r.auth == "valid":
            authenticated.append({"host": r.host, "user": _user_from_message(r.message), "pwned": False})
        elif r.auth == "guest_fallback":
            guest_only.append({"host": r.host, "user": _user_from_message(r.message)})
        if r.marker in ("-", "!") and _is_auth_line(r.message):
            failed = {"host": r.host, "user": _user_from_message(r.message)}
            codes = _FAIL_REASON_RE.findall(r.message)
            if codes:             # e.g. STATUS_ACCOUNT_LOCKED_OUT: was only in records[].message
                failed["reason"] = codes[-1]     # the last one: a secret may contain STATUS_x
            auth_failed.append(failed)
        if r.terminal:
            errors.append({
                "host": r.host, "error_class": r.error_class, "message": r.message,
                "advice": "retrying as-is will not succeed; re-forge or use another credential",
            })
        if r.marker == "+" and _TICKET_SAVED_RE.search(r.message):
            ticket_saved = True       # only a POSITIVE line saves a ticket, never a failure line
    any_success = bool(authenticated) or ticket_saved
    verdict = {
        "authenticated": authenticated,
        "guest_only": guest_only,
        "auth_failed": auth_failed,
        "errors": errors,
        "ticket_saved": ticket_saved,
        "any_success": any_success,
        "pwned": any(a.get("pwned") for a in authenticated),
        "empty": returncode == 0 and not records and unparsed_lines == 0 and not (stderr or "").strip(),
    }
    op_error = errors[0]["error_class"] if errors else None
    op_error_note = errors[0]["advice"] if errors else None
    if any_success:
        outcome_class = "success"                 # never bury a success under a sibling failure
    elif op_error:
        outcome_class = "op_error"
    elif guest_only:
        outcome_class = "guest_only"
    elif auth_failed:
        outcome_class = "auth_failed"
    elif verdict["empty"]:
        outcome_class = "benign_empty"
    else:
        outcome_class = "ok"
    return verdict, outcome_class, op_error, op_error_note


# nxc actions decorated @requires_admin (nxc/connection.py): for a login that is not admin on
# the host (no privilege label on its [+] line) nxc returns before running them and prints
# nothing, so the call reads as a successful login with an empty result. In the bench reference
# of 2026-11-04 that "success" came back 50 times, 42 of them mssql_exec as a non-sysadmin, and
# models reported command output that never came back. The flags of those actions, per
# protocol, checked against nxc 1.5.1 (6965632b), plus the smb klist flags of 4d491dd3.
ADMIN_ONLY_FLAGS = {
    "smb": frozenset({"-x", "-X", "--sam", "--lsa", "--dpapi", "--sccm", "--qwinsta",
                      "--tasklist", "--taskkill", "--wmi-query", "--list-snapshots",
                      "--klist", "--klist-dump"}),
    "mssql": frozenset({"-x", "-X", "--put-file", "--get-file", "--sam", "--lsa", "--dpapi",
                        "--db-hash"}),
    "wmi": frozenset({"-x", "--get-file", "--sam", "--lsa", "--ntds", "--wmi-query", "--sccm",
                      "--dpapi"}),
}


def admin_only_flags(protocol: str, argv: list[str]) -> list[str]:
    """The flags in `argv` that nxc runs only for an admin login, in argv order. Empty with
    `--exec-method mmcexec`, which nxc's decorator lets through whatever the rights."""
    flags = ADMIN_ONLY_FLAGS.get(protocol, frozenset())
    if "--exec-method" in argv[:-1] and argv[argv.index("--exec-method") + 1] == "mmcexec":
        return []
    return list(dict.fromkeys(tok for tok in argv if tok in flags))


def admin_skip_note(flags: list[str], verdict: dict, pwn3d_label: str = "Pwn3d!") -> str | None:
    """The note for an admin-only action that met a login without admin rights: nxc skipped
    it on those hosts. None when no such host (or no admin-only flag)."""
    skipped = [a for a in verdict.get("authenticated", []) if not a.get("pwned")]
    if not flags or not skipped:
        return None
    hosts = ", ".join(dict.fromkeys(a.get("host") or "the target" for a in skipped))
    users = ", ".join(dict.fromkeys(a.get("user") or "the account" for a in skipped))
    what = " ".join(flags)
    return (f"{users} logged in on {hosts} but is not admin there (no ({pwn3d_label}) label): nxc "
            f"runs {what} only for an admin (sysadmin on MSSQL), so it skipped it. The login "
            f"worked, {what} did not run there, and the same account will not change that.")


_REMOVED_TAG = "[REMOVED]"


def removed_option_note(records, unparsed_lines: int) -> str | None:
    """The note for an option nxc has retired: nxc keeps it in argparse, answers it with one
    `[REMOVED] Use ... instead.` line and does nothing, so beside the login line the call read
    as a success with an empty result (`--trusted-for-delegation` since nxc df95344d). Only
    after a real login (not a `(Guest)` fallback) and when nothing else came back: no bare
    output line, no `[+]` line but the login, no failure line but the `[REMOVED]` one and
    failed logins. Some retired options still run what replaced them and print the line next
    to their output (`--loggedon-users-filter`, `--filter-shares`), and a raw command may
    pass a live flag beside the retired one. None otherwise."""
    removed = next((r.message for r in records if r.message.startswith(_REMOVED_TAG)), None)
    if removed is None or unparsed_lines:
        return None
    if not any(r.auth in ("valid", "pwned") for r in records):
        return None
    for r in records:
        if r.marker == "+" and r.auth is None:
            return None
        if (r.marker in ("-", "!") and not r.message.startswith(_REMOVED_TAG)
                and not _is_auth_line(r.message)):
            return None
    removed = removed.rstrip(". ") + "."             # "Arg moved to the ldap protocol" has none
    return (f"nxc no longer supports this option and ran nothing: {removed} The login worked, "
            "and the same call will keep returning nothing: use what nxc names instead.")


# Keys whose list value is NOT a dedicated-parser payload, so their presence must not trigger
# the stdout cap: `command` is the argv, `records` is the cross-tool marker summary.
_TRIM_EXCLUDE = frozenset({"command", "records"})
_STDOUT_CAP = 1024


def trim_for_model(payload: dict, cap: int = _STDOUT_CAP) -> dict:
    """Cap redundant raw `stdout` on a MODEL-FACING result dict.

    When a per-tool parser already populated a structured field (entries/shares/users/...),
    the raw `stdout` is a 2-3x duplicate of the same signal and only burns the agent's context
    budget, so cap it to `cap` chars behind ``stdout_truncated:true`` (+ ``stdout_bytes``).
    With NO structured field, `stdout` is the only copy of the signal (see
    ``count_unmarked_lines``) and is left intact. Pure and defensive -- never raises, and
    applied only at the model boundary so ``to_dict()`` and every direct caller/test keep full
    fidelity. Idempotent: an already-capped payload is returned as is (in dynamic mode the
    view runs on both the inner tool call and the outer ``nxc_call``).
    """
    try:
        if not isinstance(payload, dict) or payload.get("stdout_truncated"):
            return payload
        stdout = payload.get("stdout")
        if not isinstance(stdout, str) or len(stdout) <= cap:
            return payload
        has_structured = any(
            k not in _TRIM_EXCLUDE and isinstance(v, list) and v
            for k, v in payload.items()
        )
        if not has_structured:
            return payload
        out = dict(payload)
        out["stdout_bytes"] = len(stdout)
        full = f"; full output in {payload['log_file']}" if payload.get("log_file") else ""
        out["stdout"] = (
            stdout[:cap]
            + f"\n...[truncated {len(stdout) - cap} chars; structured fields above carry the parsed data{full}]"
        )
        out["stdout_truncated"] = True
        return out
    except Exception:
        return payload


# Model-view key order: what the caller needs first (the outcome, then what ran) at the head,
# the bulky raw fields at the tail, so a client that keeps only the head of a long result still
# sees the verdict, and parsed fields come before the raw `stdout` they were parsed from.
_VIEW_HEAD = ("_note", "outcome_class", "verdict", "op_error", "op_error_note", "auth_suggestion",
              "resolved", "returncode", "timed_out", "dry_run")
_VIEW_TAIL = ("unparsed_lines", "counts", "records", "stderr", "log_file", "stdout_truncated",
              "stdout_bytes", "stdout")
# ExecOutcome fields that only carry information when set: dropped at their empty default.
_VIEW_DROP_IF_EMPTY = frozenset({"auth_suggestion", "op_error", "op_error_note", "timed_out",
                                 "dry_run", "stderr", "log_file"})


def _is_empty_default(value) -> bool:
    return value is None or value is False or value == ""


_RECORD_DROP_IF_EMPTY = ("auth", "error_class", "terminal", "hostname")


def _view_records(records: list, hosts) -> list:
    """`records` as the model sees them (2026-11-24): every record was sent whole next to the
    parsed fields, so smb_enum_hosts came back ~3x the size of nxc's stdout (records were 33% of
    everything the bench sent to models in November). Drops (1) a host banner record when the
    parsed `hosts` list already has that host (parse_smb_hosts carries every banner field,
    null/guest auth and NTLM included: 1,553 banner records of the bench runs rebuilt, 0 field
    lost), (2) `protocol`/`port` when they are the call's usual pair (a module label such as
    ENUM_LINKS, or LDAPS on 636, differs and stays), (3) fields at their default. Login lines
    stay: they carry the secret that worked in a spray. Non-dict records pass through."""
    pairs = Counter((r.get("protocol"), r.get("port")) for r in records if isinstance(r, dict))
    usual = pairs.most_common(1)[0][0] if pairs else None
    banner_hosts = {h.get("host") for h in hosts if isinstance(h, dict)} if isinstance(hosts, list) else set()
    out = []
    for r in records:
        if not isinstance(r, dict):
            out.append(r)
            continue
        if (banner_hosts and r.get("marker") == "*" and r.get("host") in banner_hosts
                and "(name:" in str(r.get("message", ""))):
            continue
        same_pair = (r.get("protocol"), r.get("port")) == usual
        out.append({k: v for k, v in r.items()
                    if not (same_pair and k in ("protocol", "port"))
                    and not (k in _RECORD_DROP_IF_EMPTY and _is_empty_default(v))})
    return out


def model_view(payload: dict) -> dict:
    """The MODEL-FACING form of a tool result dict (applied by the server's view middleware).

    On top of :func:`trim_for_model`: drops ``command`` when ``resolved`` carries the same argv
    as one shell-quoted string, drops the ExecOutcome fields left at their empty default
    (``op_error: null``, ``timed_out: false``, ``stderr: ""``...), and orders keys head-first
    (see ``_VIEW_HEAD``/``_VIEW_TAIL``). Dicts that are not tool results (meta-tools, errors)
    keep their keys and order. Pure, idempotent and defensive -- never raises; ``to_dict()``
    and the audit log keep every field.
    """
    try:
        if not isinstance(payload, dict):
            return payload
        out = trim_for_model(payload)
        out = {
            k: v for k, v in out.items()
            if not (k == "command" and "resolved" in out)
            and not (k in _VIEW_DROP_IF_EMPTY and _is_empty_default(v))
        }
        if isinstance(out.get("records"), list):
            out["records"] = _view_records(out["records"], out.get("hosts"))
        head = [k for k in _VIEW_HEAD if k in out]
        tail = [k for k in _VIEW_TAIL if k in out]
        edges = set(head) | set(tail)
        return {k: out[k] for k in (*head, *(k for k in out if k not in edges), *tail)}
    except Exception:
        return payload


# The access labels nxc's --shares prints, comma-joined (nxc/protocols/smb.py).
_SHARE_PERM = r"(?:READ|WRITE(?: \((?:SUBDIR|ACL)\))?|UNKNOWN \(try '--no-smbv1'\))"
_SHARE_PERMS_RE = re.compile(rf"{_SHARE_PERM}(?:,{_SHARE_PERM})*(?= |$)")
# The share types nxc prints in its Type column since 3999b0ab (PR #1531, SMB_SHARE_TYPES in
# nxc/protocols/smb.py): the base type, UNKNOWN for any other, ",TEMPORARY" for a temporary share.
_SHARE_TYPE = (r"(?:DISKTREE|PRINTQ|DEVICE|IPC|CLUSTER_FS|CLUSTER_SOFS|CLUSTER_DFS|UNKNOWN)"
               r"(?:,TEMPORARY)?")
# The header row of the table, right after the host prefix: `{'Share':<15} {'Permissions':<22}
# {'Remark'}`, or with a Type column since nxc 3999b0ab. Anchored there and in this order: the
# words anywhere in the line made a remark ("Permissions are set per Share, see Remark") a header
# with negative column widths (IndexError, the whole call lost) and a host column holding "Share"
# (`-k FileShare01.corp.local`) shift every name (independent review, 2026-11-27).
_SHARES_HEADER_RE = re.compile(
    r"(?P<share>Share) {2,}(?P<perm>Permissions) {2,}(?:(?P<type>Type) {2,})?(?P<remark>Remark)$")
# The separator row under it (----- ----------- [----] ------), also when a capped output cut it
# ("-----           --"), but not a share named "-backup": only dashes and spaces.
_SHARES_SEPARATOR_RE = re.compile(r"-[- ]*")
# What follows the name in a row of that table: permissions (or none), Type, Remark.
_SHARE_TYPED_REST_RE = re.compile(
    rf"(?P<perms>{_SHARE_PERM}(?:,{_SHARE_PERM})*)?(?P<gap> +)(?P<type>{_SHARE_TYPE})(?= |$)"
    r" *(?P<remark>.*)$"
)


def _share_row(row: str, name_w: int, perm_w: int) -> tuple[str, str, str]:
    """Split one `--shares` row (from its Share column on) into (share, permissions, remark).

    `name_w` and `perm_w` are the padded widths of the first two columns, read off the
    header. The name ends at the first space, from the end of its column on, that is
    followed by permissions nxc prints or by the blank padding of an empty permissions
    column: where the header says when the name fits, further right when it is longer
    ("Finance Reports 2024" has a space just where the column ends). When no space fits, the
    row is a name with neither permissions nor remark, and runs to its end, unless what
    follows the header's position looks like a label nxc does not print yet (an upper-case
    word), which keeps that position. Permissions longer than their column (three labels)
    push the remark the same way."""
    end = name_w
    for i in range(name_w, len(row)):
        if row[i] == " " and (_SHARE_PERMS_RE.match(row, i + 1)
                              or not row[i + 1:i + 2 + perm_w].strip()):
            end = i
            break
    else:
        if not re.match(r" [A-Z]{3,}\b", row[name_w:]):
            end = len(row)
    field = row[end + 1:]
    m = _SHARE_PERMS_RE.match(field)
    perms = m.group(0) if m else field[:perm_w].strip()
    remark = field[max(perm_w, len(perms)) + 1:].strip()
    return row[:end].strip(), perms, remark


def _share_row_typed(row: str, name_w: int, perm_w: int, type_w: int) -> tuple[str, str, str, str]:
    """Split one row of the `--shares` table with a Type column (nxc 3999b0ab on,
    ``{name:<15} {perms:<15} {type:<10} {remark}``) into (share, permissions, type, remark).

    nxc prints a type from a closed set, so it anchors the row: the name ends at a space, from
    the end of its column on, followed by permissions nxc prints (or none) and then a type,
    separated by exactly the padding nxc puts there (``max(perm_w - len(perms), 0) + 1``
    spaces, the whole column plus one when there are no permissions). The exact gap keeps a long
    name ending in a permission word ("Accounting Dept READ", no access) from lending it its
    last word. A name, permissions or type longer than its column pushes the rest of the row to
    the right, which this follows. Only the split points that layout allows are tried in each
    run of spaces (its first space from the name's column on, its last one, and the one that
    leaves an empty permissions column before the type), so a name made of long runs of spaces
    stays linear (independent review, 2026-11-27: trying every space was quadratic, 8.9 s for
    16,000). When nothing fits (a label nxc does not print yet), the header's positions are
    kept, and the type is then whatever stands in its column, possibly empty."""
    for run in re.finditer(r" +", row):
        s, e = run.span()
        if e <= name_w:
            continue
        first = max(s, name_w)
        for i in sorted({first, e - 1, e - perm_w - 2}):
            if i < first or i >= e:
                continue
            m = _SHARE_TYPED_REST_RE.match(row, i + 1)
            if not m:
                continue
            perms = m["perms"] or ""
            if len(m["gap"]) != max(perm_w - len(perms), 0) + 1:
                continue
            return row[:i].strip(), perms, m["type"], m["remark"].strip()
    p0 = name_w + 1
    t0 = p0 + perm_w + 1
    r0 = t0 + type_w + 1
    return row[:name_w].strip(), row[p0:t0].strip(), row[t0:r0].strip(), row[r0:].strip()


def parse_shares(text: str) -> list[dict]:
    """Parse `nxc smb --shares` output into structured share records.

    nxc prints shares as a fixed-width table under a header row
    (``Share  Permissions  Remark``) with no status marker, so the generic marker
    parser skips them. We anchor on that header to learn the column offsets, then
    slice each following data row positionally -- which correctly yields an empty
    permissions list for shares the account can't access (e.g. ``ADMIN$``/``C$``).

    Each record: ``{host, share, permissions: [...], remark}``, plus ``type`` (``DISKTREE``,
    ``IPC``, ``PRINTQ``...) when nxc prints a Type column.

    nxc pads the columns (``{name:<15} {perms:<22} {remark}``) but does not cut a longer
    value, which pushes the rest of its row to the right: a share name of 16 characters or
    more came back cut, its permissions made of the end of its name. See
    :func:`_share_row`. Since nxc 3999b0ab (PR #1531) the table has a Type column
    (``{name:<15} {perms:<15} {type:<10} {remark}``): both formats are read, the header says
    which one (:func:`_share_row_typed`).
    """
    shares: list[dict] = []
    # One table per host: nxc runs hosts in parallel threads, so another host's lines (its
    # banner, its own table) can land in the middle of this host's table. A single table state
    # closed it at the first foreign marker line and lost every row after it (2026-11-24: 12 to
    # 24% of the rows on 100 simulated hosts; 0 lost with a state per host).
    # (Share, Permissions, Type or None before nxc 3999b0ab, Remark) offsets.
    tables: dict[str, tuple[int, int, int | None, int]] = {}

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue  # progress bar, warnings: not a table row, and not the end of one
        host = prefix["host"]

        header = _SHARES_HEADER_RE.match(line, prefix.end())
        if header:
            tables[host] = (header.start("share"), header.start("perm"),
                            header.start("type") if header["type"] else None,
                            header.start("remark"))
            continue
        if host not in tables:
            continue  # not inside a shares table of this host
        share_off, perm_off, type_off, remark_off = tables[host]

        # A marker line of this host (banner, auth line, "Enumerated shares") ends its table: its
        # marker follows the prefix. A marker inside a row ("[!] do not delete" as a remark) does
        # not, or that row and every later one of the host were lost.
        if _MARKER_ANYWHERE_RE.match(line, prefix.end()):
            del tables[host]
            continue
        # The separator row (----- ----------- ------).
        if _SHARES_SEPARATOR_RE.fullmatch(line[share_off:].strip()):
            continue

        share_type = None
        if type_off is None:
            share, perms, remark = _share_row(
                line[share_off:], perm_off - share_off - 1, remark_off - perm_off - 1
            )
        else:
            share, perms, share_type, remark = _share_row_typed(
                line[share_off:], perm_off - share_off - 1, type_off - perm_off - 1,
                remark_off - type_off - 1,
            )
        if not share:
            continue
        record = {
            "host": host,
            "share": share,
            "permissions": [p for p in perms.replace(" ", "").split(",") if p],
            "remark": remark,
        }
        if type_off is not None:
            record["type"] = share_type
        shares.append(record)
    return shares


def _parse_columns(text: str, columns: list[tuple[str, str]]) -> list[dict]:
    """Generic positional parser for nxc's fixed-width tables.

    `columns` is an ordered list of (field_name, header_label). We find the header
    row (the line containing every label), record each label's column offset, then
    slice each following data row positionally -- robust to empty middle columns.
    Each host has its own table: a marker line of that host ends it; lines of other hosts and
    lines without the PROTO HOST PORT NAME prefix do not.
    """
    fields = [f for f, _ in columns]
    labels = [lbl for _, lbl in columns]
    # One table per host (see parse_shares): another host's marker line in the middle of this
    # host's table no longer ends it; a line without the host prefix is skipped, not an end.
    tables: dict[str, list[int]] = {}
    rows: list[dict] = []

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue
        host = prefix["host"]

        if all(lbl in line for lbl in labels):
            tables[host] = [line.index(lbl) for lbl in labels]
            continue
        offsets = tables.get(host)
        if offsets is None:
            continue
        if _MARKER_ANYWHERE_RE.search(line):
            del tables[host]
            continue
        if line[offsets[0]:].lstrip().startswith("-"):  # separator row (----)
            continue

        rec = {"host": prefix["host"]}
        pos = offsets[0]
        for i, field in enumerate(fields):
            if i + 1 < len(fields):
                end = offsets[i + 1]
                # a value wider than its header column overflows past `end`; if we'd cut
                # mid-token, extend to the next space so it isn't split across fields.
                while 0 < end < len(line) and line[end - 1] != " " and line[end] != " ":
                    end += 1
                rec[field] = line[pos:end].strip()
                pos = end
            else:
                rec[field] = line[pos:].strip()
        if not rec[fields[0]]:
            continue
        rows.append(rec)
    return rows


def parse_users(text: str) -> list[dict]:
    """Parse `nxc smb --users` into `{host, username, last_pw_set, bad_pw_count, description}`."""
    rows = _parse_columns(
        text,
        [
            ("username", "-Username-"),
            ("last_pw_set", "-Last PW Set-"),
            ("bad_pw_count", "-BadPW-"),
            ("description", "-Description-"),
        ],
    )
    for r in rows:
        if r["bad_pw_count"].isdigit():
            r["bad_pw_count"] = int(r["bad_pw_count"])
    return rows


def parse_dir(text: str) -> list[dict]:
    """Parse `nxc smb --dir` into `{host, perms, size, date, name}`."""
    return _parse_columns(
        text,
        [
            ("perms", "Perms"),
            ("size", "File Size"),
            ("date", "Date"),
            ("name", "File Path"),
        ],
    )


def parse_ldap_groups(text: str) -> list[dict]:
    """Parse `nxc ldap --groups` into `{host, group, members (int), description}`."""
    rows = _parse_columns(
        text,
        [("group", "-Group-"), ("members", "-Members-"), ("description", "-Description-")],
    )
    for r in rows:
        if r["members"].isdigit():
            r["members"] = int(r["members"])
    return rows


def _parse_bare_names(text: str, field: str) -> list[dict]:
    """Parse nxc output that is bare `PROTO HOST PORT NAME <value>` lines with no
    status marker -- group members, adminCount principals.
    When a query narrows to a single object nxc drops its `-Header-` table and
    prints one value per line. The banner (`[*]`) / auth (`[+]`) lines carry markers
    and are skipped."""
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or _MARKER_ANYWHERE_RE.search(line):
            continue
        m = _PREFIX_RE.match(line)
        if not m:
            continue
        value = line[m.end():].strip()
        if value:
            rows.append({"host": m["host"], field: value})
    return rows


def parse_ldap_group_members(text: str) -> list[dict]:
    """`nxc ldap --groups <group>` member listing -> `{host, member}`. See _parse_bare_names."""
    return _parse_bare_names(text, "member")


def parse_ldap_ous(text: str) -> list[dict]:
    """Parse `nxc ldap --ous` into `{host, ou, distinguished_name}`.

    Bare `--ous` prints the OU inventory as a two-column table; the DN column is what
    makes the result usable, since it is the `base_dn` to feed back into `ldap_query`.
    """
    return _parse_columns(
        text, [("ou", "-OU-"), ("distinguished_name", "-Distinguished Name-")]
    )


def parse_ldap_ou_users(text: str) -> list[dict]:
    """Parse `nxc ldap --ous <OU>` (users scoped to that OU) into `{host, username, cn}`."""
    return _parse_columns(
        text, [("username", "-sAMAccountName-"), ("cn", "-cn-")]
    )


def parse_ldap_principals(text: str) -> list[dict]:
    """`nxc ldap --admin-count` -> `{host, name}` (bare principal list, same shape as a
    narrowed group)."""
    return _parse_bare_names(text, "name")


# The DelegationType values nxc's `--find-delegation` prints (nxc/protocols/ldap.py), longest
# first so "Constrained" never matches the start of the protocol-transition one.
DELEGATION_TYPES = ("Constrained w/ Protocol Transition", "Resource-Based Constrained",
                    "Unconstrained", "Constrained")
# The DelegationType column is 35 wide since df95344d, so a type is always followed by two
# spaces or more, or ends the line. Requiring it is what keeps an account named like
# "Tier 1 Constrained" (a type word as its third word) from being read as account "Tier",
# type "1", delegation "Constrained".
_DELEGATION_ROW_RE = re.compile(
    r"^(?P<account>.+?)\s+(?P<account_type>\S+)\s+(?P<delegation_type>"
    + "|".join(re.escape(t) for t in DELEGATION_TYPES)
    + r")(?:\s{2,}(?P<rights>\S.*?))?\s*$"
)
_DELEGATION_HEADER_RE = re.compile(r"^AccountName\s+AccountType\s+DelegationType")


def parse_ldap_delegation(text: str) -> list[dict]:
    """Parse `nxc ldap --find-delegation` into
    `[{host, account, account_type, delegation_type, rights_to: [spn, ...]}]`.

    Each DC prints its own table, a header and a `----` separator row above the rows::

        AccountName     AccountType     DelegationType                      DelegationRightsTo
        --------------- --------------- ----------------------------------- ------------------
        jon.snow        Person          Constrained w/ Protocol Transition  CIFS/winterfell, ...

    Since nxc df95344d the columns have FIXED widths (15/15/35/40) and a longer value is not
    cut, it pushes the rest of its row to the right: a 16-character account (a 15-character
    computer name plus `$`) or a gMSA type (`ms-DS-Group-Managed-Service-Account`). Sliced at
    the separator's positions, such a row came back with its account, its type AND its SPNs
    cut. So a row is read around its DelegationType, one of the fixed DELEGATION_TYPES followed
    by two spaces or more; the account may contain spaces (a group in an RBCD row), the type
    never does. A row that does not read that way is sliced at the separator's positions,
    which is exact for older nxc (its widths followed the data, so the longest type of a table
    is followed by one space) and, for a type not in the list, right unless a value is longer
    than its column."""
    out: list[dict] = []
    spans: dict[str, list[tuple[int, int]]] = {}     # host -> its separator's dash runs
    for raw in (text or "").splitlines():
        if _MARKER_ANYWHERE_RE.search(raw):          # skip [*] banner / [+] auth / [-] errors
            continue
        m = _PREFIX_RE.match(raw)
        if not m:
            continue
        host, row = m["host"], raw[m.end():].rstrip()   # keep internal spacing for slicing
        if not row:
            continue
        if _DELEGATION_HEADER_RE.match(row):
            spans.pop(host, None)
            continue
        if set(row) <= {"-", " "}:
            spans[host] = [(d.start(), d.end()) for d in re.finditer(r"-+", row)]
            continue
        if host not in spans:                        # not inside this host's table
            continue
        if (r := _DELEGATION_ROW_RE.match(row)):
            account, account_type = r["account"], r["account_type"]
            delegation_type, rights = r["delegation_type"], r["rights"] or ""
        elif len(cols := spans[host]) >= 4:
            def cell(j: int, _row: str = row, _cols: list = cols) -> str:
                s, e = _cols[j]
                return (_row[s:] if j == len(_cols) - 1 else _row[s:e]).strip()
            account, account_type, delegation_type, rights = cell(0), cell(1), cell(2), cell(3)
        else:
            continue
        if not account:
            continue
        out.append({
            "host": host,
            "account": account,
            "account_type": account_type,
            "delegation_type": delegation_type,
            "rights_to": [x.strip() for x in rights.split(",") if x.strip()],
        })
    return out


_DOMAIN_SID_RE = re.compile(r"Domain SID\s+(?P<sid>S-\d[-\d]+)")


def parse_domain_sid(text: str) -> list[dict]:
    """`nxc ldap --get-sid` -> `[{host, sid}]`. Line: `Domain SID S-1-5-21-...`."""
    out: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        m = _PREFIX_RE.match(line)
        if not m:
            continue
        sm = _DOMAIN_SID_RE.search(line)
        if sm:
            out.append({"host": m["host"], "sid": sm["sid"]})
    return out


# `$krb5asrep$23$user@REALM:...` and `$krb5tgs$23$*user$REALM$...` -- capture the account.
_ROAST_RE = re.compile(r"^\$krb5(?P<kind>asrep|tgs)\$\d+\$\*?(?P<account>[^@$*]+)")


def parse_roast_hashes(text: str) -> list[dict]:
    """`nxc ldap --asreproast` / `--kerberoasting` -> `[{host, kind, account, hash}]`.
    Crackable hashes print as bare `$krb5asrep$` / `$krb5tgs$` lines after the column
    prefix; the interleaved `[*] sAMAccountName:` info lines carry a marker and are skipped."""
    out: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        m = _PREFIX_RE.match(line)
        if not m:
            continue
        rest = line[m.end():].strip()
        rm = _ROAST_RE.match(rest)
        if rm:
            out.append({"host": m["host"], "kind": rm["kind"],
                        "account": rm["account"], "hash": rest})
    return out


def parse_ldap_gmsa(text: str) -> list[dict]:
    """Parse `nxc ldap --gmsa` into `[{host, account, ntlm, aes128, aes256, principals_allowed}]`.

    nxc prints one to three marker-less lines per gMSA account, which we merge::

        Account: gmsa-goad$  NTLM: <hash>  PrincipalsAllowedToReadPassword: <principals>
        Account: gmsa-goad$  aes128-cts-hmac-sha1-96: <key>
        Account: gmsa-goad$  aes256-cts-hmac-sha1-96: <key>

    OFFENSIVE: the NTLM is directly pass-the-hash-able."""
    by_account: dict[str, dict] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or _MARKER_ANYWHERE_RE.search(line):
            continue
        m = _PREFIX_RE.match(line)
        if not m:
            continue
        acc = re.match(r"Account:\s*(?P<account>\S+)\s+(?P<body>.*)$", line[m.end():].strip())
        if not acc:
            continue
        rec = by_account.setdefault(acc["account"], {"host": m["host"], "account": acc["account"]})
        body = acc["body"]
        if (x := re.search(r"\bNTLM:\s*([0-9a-fA-F]{32})", body)):
            rec["ntlm"] = x.group(1)
        if (x := re.search(r"aes128-cts-hmac-sha1-96:\s*(\S+)", body)):
            rec["aes128"] = x.group(1)
        if (x := re.search(r"aes256-cts-hmac-sha1-96:\s*(\S+)", body)):
            rec["aes256"] = x.group(1)
        if (x := re.search(r"PrincipalsAllowedToReadPassword:\s*(.+?)\s*$", body)):
            rec["principals_allowed"] = x.group(1)
    return list(by_account.values())


def parse_ldap_gmsa_id(text: str) -> list[dict]:
    """Parse `nxc ldap --gmsa-convert-id` into `[{host, account, gmsa_id}]`.
    Line: `Account: gmsa-goad$   ID: <hex id>` -- resolves a gMSA id back to its name."""
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or _MARKER_ANYWHERE_RE.search(line):
            continue
        m = _PREFIX_RE.match(line)
        if not m:
            continue
        acc = re.search(r"Account:\s*(?P<account>\S+)\s+ID:\s*(?P<id>\S+)", line[m.end():])
        if acc:
            rows.append({"host": m["host"], "account": acc["account"], "gmsa_id": acc["id"]})
    return rows


# `--klist`: one line per session holding a usable TGT, numbered for `--klist-dump`:
# `[1] NORTH\eddard.stark  0x16268e1b  (expires 2026-11-12 20:00:00 UTC)` (`N/A` when unknown).
_KLIST_SESSION_RE = re.compile(
    r"^\[(?P<index>\d+)\]\s+(?P<account>.+?)\s+(?P<logon_id>0x[0-9a-fA-F]+)\s+"
    r"\(expires (?P<expires>.+?)(?: UTC)?\)$")
# `--klist-dump`: the closing line names the folder, never the files written in it.
_KLIST_DUMPED_RE = re.compile(r"Dumped (?P<count>\d+) TGT\(s\) to (?P<dir>.+?)\s*$")


def parse_klist_sessions(text: str) -> list[dict]:
    """`nxc smb|winrm --klist` -> `[{host, index, account, logon_id, expires}]`. `index` is the
    number `--klist-dump` takes to dump only that session's TGT."""
    out: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        m = _PREFIX_RE.match(line)
        if not m:
            continue
        sm = _KLIST_SESSION_RE.match(line[m.end():].strip())
        if sm:
            out.append({"host": m["host"], "index": int(sm["index"]), "account": sm["account"],
                        "logon_id": sm["logon_id"], "expires": sm["expires"]})
    return out


def parse_klist_dumps(text: str) -> list[dict]:
    """`nxc smb|winrm --klist-dump` -> `[{host, dir, count}]`: the folder each host's ccache files
    went to and how many. nxc prints the account of each ticket but not its file, see
    config.klist_ccaches."""
    out: list[dict] = []
    for rec in parse_markers(text):
        if rec.status == "success" and rec.host and (dm := _KLIST_DUMPED_RE.search(rec.message)):
            out.append({"host": rec.host, "dir": dm["dir"], "count": int(dm["count"])})
    return out


def klist_failures(text: str) -> list[dict]:
    """The `[-]`/`[!]` lines of a klist call that are not login failures, as `[{host, message}]`:
    "Failed to enumerate Kerberos sessions" (the exec method was blocked), "No Kerberos TGTs
    found", "No valid TGTs dumped", a session number out of range, an expired or Credential
    Guard-protected ticket. Without them an empty `sessions`/`tickets` read as "no ticket cached"
    while klist never ran."""
    return [{"host": r.host, "message": r.message} for r in parse_markers(text)
            if r.marker in ("-", "!") and not _is_auth_line(r.message)]


def _drop_total_row(rows: list[dict], field: str) -> list[dict]:
    """nxc's mssql tables end with a `Total: N ...` summary line that shares the data
    column layout; drop it so it doesn't show up as a bogus row."""
    return [r for r in rows if not str(r.get(field, "")).startswith("Total:")]


def parse_mssql_databases(text: str) -> list[dict]:
    """Parse `nxc mssql --database` (no value) into `{host, name, owner}`."""
    rows = _parse_columns(
        text,
        [("name", "Database Name"), ("owner", "Owner")],
    )
    return _drop_total_row(rows, "name")


def parse_mssql_tables(text: str) -> list[dict]:
    """Parse `nxc mssql --database <name>` into `{host, name, modified}`."""
    rows = _parse_columns(
        text,
        [("name", "Table Name"), ("modified", "Last Modified")],
    )
    return _drop_total_row(rows, "name")


def parse_mssql_logins(text: str) -> list[dict]:
    """Parse `nxc mssql -M enum_logins` into `{host, login_name, type, status}`."""
    return _parse_columns(
        text,
        [("login_name", "Login Name"), ("type", "Type"), ("status", "Status")],
    )


# nxc prints a mssql -q result set as highlight lines (no status marker): one row per
# `--------------------` separator (nxc commit f7835c3b), then a `key:value` line per
# named column, or a bare `value` line for an unnamed one. Payload after the
# `PROTO HOST PORT NAME` prefix, e.g.:
#   --------------------
#   name:master
#   database_id:1
_MSSQL_ROW_SEP_RE = re.compile(r"^-{3,}$")


def parse_mssql_query(text: str) -> list[dict]:
    """Parse `nxc mssql -q <query>` output into a list of `{column: value}` rows.

    Rows are delimited by nxc's `--------------------` separator line. A first row with no
    separator before it (older nxc, which printed none) is still opened on its first value,
    so a single-row result parses either way; only multi-row results on pre-separator nxc
    are ambiguous and collapse. An unnamed column (a bare value line, e.g. `SELECT
    @@version`) is keyed positionally as `column_N`. A value may itself contain `:` -- only
    the first one splits key from value.
    """
    rows: list[dict] = []
    current: dict | None = None
    col = 0
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        prefix = _PREFIX_RE.match(raw)
        if not prefix:
            continue
        payload = raw[prefix.end():].strip()
        if not payload or _MARKER_RE.match(payload):
            # Skip nxc's own status lines (`[*]` fingerprint, `[+]` auth, `[-]` fail):
            # they share the PROTO HOST PORT NAME prefix but are not result rows. A query
            # result set is highlight lines with no marker.
            continue
        if _MSSQL_ROW_SEP_RE.match(payload):
            current = {}
            rows.append(current)
            col = 0
            continue
        if current is None:          # first row on nxc builds that print no separator
            current = {}
            rows.append(current)
            col = 0
        col += 1
        key, sep, value = payload.partition(":")
        if sep:
            current[key.strip()] = value.strip()
        else:
            current[f"column_{col}"] = payload
    return rows


# A RID-brute highlight-line payload (after the PROTO HOST PORT NAME prefix):
#   500: NORTH\Administrator                (mssql -- no SID-type suffix)
#   500: CORP\Administrator (SidTypeUser)   (smb-style -- tolerated, captured)
_RID_RE = re.compile(
    r"^(?P<rid>\d+):\s*(?P<principal>.+?)(?:\s+\((?P<sid_type>SidType\w+)\))?$"
)


def parse_rid_brute(text: str) -> list[dict]:
    """Parse `nxc --rid-brute` output into `{host, rid, domain, account, sid_type}`.

    RID cycling prints one highlight line per resolved SID, e.g.
    `MSSQL 10.4.10.22 1433 CASTELBLACK   512: NORTH\\Domain Admins`. `account` is
    the name after the domain -- users, groups, and machine accounts (`HOST$`)
    alike. `sid_type` is only present in the smb-style `(SidTypeUser)` form and is
    `None` for mssql (which resolves SIDs via `SUSER_SNAME` without a type).
    """
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue
        m = _RID_RE.match(line[prefix.end():].strip())
        if not m:
            continue
        domain, sep, account = m["principal"].partition("\\")
        if not sep:  # no `DOMAIN\` component
            domain, account = "", m["principal"]
        rows.append({
            "host": prefix["host"],
            "rid": int(m["rid"]),
            "domain": domain,
            "account": account,
            "sid_type": m["sid_type"],
        })
    return rows


def parse_hosts_file(text: str) -> list[dict]:
    """Parse an /etc/hosts-format file (`IP name [name...]`) into `[{ip, names}]`."""
    entries: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            entries.append({"ip": parts[0], "names": parts[1:]})
    return entries


def parse_ldap_computers(text: str) -> list[dict]:
    """Parse `nxc ldap --computers` (one machine account per line) into `{host, computer}`."""
    computers: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or _MARKER_ANYWHERE_RE.search(line):
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue
        name = line[prefix.end():].strip()
        if name:
            computers.append({"host": prefix["host"], "computer": name})
    return computers


# A WMI query result line (after the column prefix): `key => value`.
_WMI_KV_RE = re.compile(r"^(?P<key>.+?)\s+=>\s+(?P<value>.*)$")


def parse_wmi(text: str) -> list[dict]:
    """Parse `nxc smb --wmi-query` `key => value` lines into `{host, key, value}`."""
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or _MARKER_ANYWHERE_RE.search(line):
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue
        rest = line[prefix.end():]
        kv = _WMI_KV_RE.match(rest)
        if kv:
            rows.append({"host": prefix["host"], "key": kv["key"].strip(), "value": kv["value"].strip()})
    return rows


_GMSA_ID_RE = re.compile(r"^GMSA ID:\s*(?P<id>\S+)\s+NTLM:\s*(?P<ntlm>\S+)", re.IGNORECASE)
_KERB_KEY_RE = re.compile(
    r"^(?P<account>.+?):(?P<etype>aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):(?P<key>[0-9a-fA-F]+)$"
)
_PLAIN_HEX_RE = re.compile(r"^(?P<account>.+?):plain_password_hex:(?P<hex>[0-9a-fA-F]+)$")
_NTLM_RE = re.compile(r"^(?P<account>.+?):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::")
_DPAPI_KEY_RE = re.compile(r"^(?P<name>dpapi_(?:machine|user)key):(?P<value>\S+)$")


def _lsa_account_type(account: str) -> str:
    return "machine" if account.rstrip().endswith("$") else "user"


def _classify_lsa_secret(content: str, host: str) -> dict | None:
    """Classify one LSA secret line into a structured record (or None to skip)."""
    m = _GMSA_ID_RE.match(content)
    if m:
        return {"host": host, "type": "gmsa_id", "gmsa_id": m["id"], "ntlm": m["ntlm"]}
    if content.startswith("_SC_GMSA_DPAPI_"):
        return {"host": host, "type": "gmsa_dpapi_blob", "secret": content}
    if content.startswith("_SC_GMSA_"):
        # the value to feed to `ldap --gmsa-decrypt-lsa`
        return {"host": host, "type": "gmsa_lsa_blob", "secret": content}
    m = _DPAPI_KEY_RE.match(content)
    if m:
        return {"host": host, "type": "dpapi_key", "name": m["name"], "value": m["value"]}
    if "$DCC2$" in content:
        account, _, rest = content.partition(":")
        # rest is `$DCC2$...: (timestamp)` -> keep just the hash
        hash_ = re.split(r":\s*\(", rest)[0].strip().rstrip(":").strip()
        return {"host": host, "type": "dcc2", "account": account.strip(), "hash": hash_}
    m = _KERB_KEY_RE.match(content)
    if m:
        acct = m["account"].strip()
        return {"host": host, "type": "kerberos_key", "account": acct,
                "account_type": _lsa_account_type(acct), "etype": m["etype"], "key": m["key"]}
    m = _PLAIN_HEX_RE.match(content)
    if m:
        acct = m["account"].strip()
        return {"host": host, "type": "plaintext_hex", "account": acct,
                "account_type": _lsa_account_type(acct), "secret": m["hex"]}
    m = _NTLM_RE.match(content)
    if m:
        acct = m["account"].strip()
        return {"host": host, "type": "ntlm", "account": acct,
                "account_type": _lsa_account_type(acct), "lm": m["lm"], "nt": m["nt"]}
    if ":" in content:  # generic cleartext `account:password`
        account, _, secret = content.partition(":")
        account, secret = account.strip(), secret.strip()
        if account and secret:
            return {"host": host, "type": "plaintext", "account": account,
                    "account_type": _lsa_account_type(account), "secret": secret}
    return None


def parse_reauth_swap(text: str) -> list[dict]:
    """Parse `nxc smb -M reauth_swap` output into a per-host verdict list.

    The module reports whether a server still allows a cross-user re-auth swap on an SMB
    session (a posture signal for enforced SMB signing). Each record is
    `{host, verdict, detail}` with verdict one of: ``vulnerable`` (swap allowed),
    ``not_vulnerable`` (swap refused, same-user re-auth only), ``inconclusive`` (unexpected
    session-setup status) or ``skipped`` (signing not enforced, nothing to probe). Keyed on
    the message phrasing, not the marker, since the positive result is a highlight (no
    marker) while the negatives are display lines.
    """
    out: list[dict] = []
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        prefix = _PREFIX_RE.match(raw)
        if not prefix:
            continue
        payload = raw[prefix.end():].strip()
        mk = _MARKER_RE.match(payload)
        if mk:
            payload = mk["message"].strip()
        low = payload.lower()
        if "enforced smb signing bypassable" in low:
            verdict = "vulnerable"
        elif "not vulnerable" in low or "re-auth swap refused" in low:
            verdict = "not_vulnerable"
        elif "inconclusive" in low:
            verdict = "inconclusive"
        elif "signing not enforced" in low or "nothing to bypass" in low:
            verdict = "skipped"
        else:
            continue
        out.append({"host": prefix["host"], "verdict": verdict, "detail": payload})
    return out


def parse_lsa_secrets(text: str) -> list[dict]:
    """Parse `nxc smb --lsa` output into structured credential records.

    Recognises machine/user NTLM hashes, Kerberos keys, plaintext (incl. hex),
    DCC2 cached domain logons, DPAPI keys, and gMSA artifacts (`GMSA ID:…NTLM:…`,
    `_SC_GMSA_…` blobs) -- so an agent can extract a hash/id and chain it (e.g.
    feed a `gmsa_id` to ldap `--gmsa-convert-id`, or pass-the-hash a machine acct).

    Each record has `host`, `type`, and type-specific fields. Some secret lines in
    nxc output lack the column prefix (e.g. `dpapi_userkey:`); those inherit the
    host of the preceding prefixed line.
    """
    secrets: list[dict] = []
    last_host: str | None = None

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        prefix = _PREFIX_RE.match(line)
        if prefix:
            last_host = prefix["host"]
            content = line[prefix.end():].strip()
        else:
            content = line.strip()
        if not content or _MARKER_ANYWHERE_RE.match(content):
            continue  # banner / auth / "Dumping…" / "Dumped N secrets…" status lines
        rec = _classify_lsa_secret(content, last_host)
        if rec:
            secrets.append(rec)
    return secrets


# secretsdump pwdump line (SAM / NTDS): account:rid:lm:nt::: [optional (status=Enabled)]
_PWDUMP_RE = re.compile(
    r"^(?P<account>.+?):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::"
    r"(?:\s*\(status=(?P<status>\w+)\))?"
)


def parse_secretsdump(text: str) -> list[dict]:
    """Parse `nxc smb --sam` / `--ntds` output into structured credential records.

    Both emit secretsdump pwdump lines (`account:rid:lm:nt:::`, optionally with a
    `(status=Enabled)` suffix); `--ntds --kerberos-keys` adds `account:etype:key`
    lines. Returns records with `type` ("ntlm" or "kerberos_key"), `account`,
    `account_type` (machine/user), and the hash/key fields -- ready for replay
    (`username=account` + `ntlm_hash=nt`). Prefix-less lines inherit the prior host.
    """
    creds: list[dict] = []
    last_host: str | None = None

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        prefix = _PREFIX_RE.match(line)
        if prefix:
            last_host = prefix["host"]
            content = line[prefix.end():].strip()
        else:
            content = line.strip()
        if not content or _MARKER_ANYWHERE_RE.match(content):
            continue

        m = _PWDUMP_RE.match(content)
        if m:
            acct = m["account"].strip()
            rec = {
                "host": last_host, "type": "ntlm", "account": acct,
                "account_type": _lsa_account_type(acct), "rid": int(m["rid"]),
                "lm": m["lm"], "nt": m["nt"],
            }
            if m["status"]:
                rec["status"] = m["status"]
            creds.append(rec)
            continue
        m = _KERB_KEY_RE.match(content)
        if m:
            acct = m["account"].strip()
            creds.append({
                "host": last_host, "type": "kerberos_key", "account": acct,
                "account_type": _lsa_account_type(acct), "etype": m["etype"], "key": m["key"],
            })
    return creds


_PASSPOL_DOMAIN_RE = re.compile(r"Dumping password info for domain:\s*(?P<domain>.+)$")


def parse_pass_pol(text: str) -> list[dict]:
    """Parse `nxc smb --pass-pol` into `[{host, domain, settings: {key: value}}]`.

    The policy prints as `key: value` lines (no status marker), e.g.
    ``Minimum password length: 5`` / ``Account Lockout Threshold: 5``, preceded by a
    ``[+] Dumping password info for domain: X`` marker giving the domain.
    """
    by_host: dict[str, dict] = {}

    def _bucket(host: str) -> dict:
        return by_host.setdefault(host, {"host": host, "domain": None, "settings": {}})

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue
        host = prefix["host"]
        rest = line[prefix.end():].strip()

        dom = _PASSPOL_DOMAIN_RE.search(rest)
        if dom:
            _bucket(host)["domain"] = dom["domain"].strip()
            continue
        if _MARKER_ANYWHERE_RE.match(rest):  # banner / auth lines
            continue
        if ":" in rest:
            key, _, value = rest.partition(":")
            key, value = key.strip(), value.strip()
            if key and value:
                _bucket(host)["settings"][key] = value

    return list(by_host.values())


# --- SMB host fingerprint (`smb_enum_hosts`) ------------------------------- #
# `(key:value)` pairs in the SMB banner, e.g. `(name:DC01) (signing:True)`.
_BANNER_KV_RE = re.compile(r"\((?P<k>[A-Za-z0-9 ]+):(?P<v>[^)]*)\)")


def parse_smb_hosts(text: str) -> list[dict]:
    """Parse SMB fingerprint banners into
    `{host, port, hostname, os, name, domain, signing, smbv1, is_dc}` (one per host).

    A banner line is the info-marker fingerprint nxc prints on connect, e.g.::

        SMB 10.0.0.5 445 DC01 [*] Windows Server 2019 ... (name:DC01) (domain:CORP)
        (signing:True) (SMBv1:False) (DC:True)

    `is_dc` is `True` when nxc tags the host as a domain controller (the `(DC:True)`
    field, added in nxc build 595); `None` when the tag is absent. It is never `False`:
    nxc emits the field only for a truthy `isdc` (`smb.py:328`), so a member server and a
    check nxc left inconclusive look identical on the wire. Verified live at build 677
    (KINGSLANDING -> True, CASTELBLACK -> no field).
    """
    hosts: list[dict] = []
    for raw in (text or "").splitlines():
        m = _LINE_RE.match(raw.rstrip())
        if not m or m["marker"] != "*" or "(name:" not in m["message"]:
            continue
        kv = {k.strip().lower(): v.strip() for k, v in _BANNER_KV_RE.findall(m["message"])}
        dc_val = kv.get("dc")
        hosts.append({
            "host": m["host"],
            "port": int(m["port"]),
            "hostname": m["name"],
            "os": m["message"].split("(", 1)[0].strip(),
            "name": kv.get("name"),
            "domain": kv.get("domain"),
            "signing": kv.get("signing"),
            "smbv1": kv.get("smbv1"),
            "is_dc": None if dc_val is None else dc_val.lower() == "true",
            # printed only when true (or, for NTLM, when false): kept only when printed, so the
            # banner record can leave the model view without losing them (2026-11-24)
            **{key: kv[k] for key, k in (("null_auth", "null auth"), ("guest_auth", "guest auth"),
                                         ("ntlm", "ntlm")) if k in kv},
        })
    return hosts


# --- LDAP password-not-required (`ldap_password_not_required`) -------------- #
_NOTREQD_RE = re.compile(r"User:\s+(?P<account>\S+)\s+Status:\s+(?P<status>\S+)")


def parse_password_not_required(text: str) -> list[dict]:
    """Parse `nxc ldap --password-not-required` (`User: <name> Status: <state>` lines)
    into `{host, account, status}`."""
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        prefix = _PREFIX_RE.match(raw.rstrip())
        if not prefix:
            continue
        m = _NOTREQD_RE.search(raw[prefix.end():])
        if m:
            rows.append({"host": prefix["host"], "account": m["account"], "status": m["status"]})
    return rows


# --- LDAP DC list (`ldap_dc_list`) ----------------------------------------- #
# `<hostname> = <ip>` highlight lines (an optional `[domain] ` prefix is stripped).
_DCLIST_RE = re.compile(r"^(?P<dc>\S+)\s+=\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_TAG_RE = re.compile(r"^\[[^\]]+\]\s*")


def parse_dc_list(text: str) -> list[dict]:
    """Parse `nxc ldap --dc-list` (`<hostname> = <ip>` highlights) into `{host, dc, ip}`."""
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if _MARKER_ANYWHERE_RE.search(line):
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue
        payload = _DOMAIN_TAG_RE.sub("", line[prefix.end():].strip())
        m = _DCLIST_RE.match(payload)
        if m:
            rows.append({"host": prefix["host"], "dc": m["dc"], "ip": m["ip"]})
    return rows


# --- LDAP custom query (`ldap_query`) -------------------------------------- #
# nxc emits one `[+] Response for object: <DN>` marker line per hit, then each attribute as
# `{name:<20} {value}`, and the further values of a multi-valued attribute on lines of their
# own, `{'':<20} {value}` (nxc c2cb7521, 2025-03):
#     LDAP 10.0.0.1 389 DC01  [+] Response for object: CN=x,CN=System,DC=lab
#     LDAP 10.0.0.1 389 DC01  trustDirection       3
#     LDAP 10.0.0.1 389 DC01  servicePrincipalName HTTP/web01
#     LDAP 10.0.0.1 389 DC01                       HTTP/web01.lab
# A hit with NO attribute lines is the signature of an attribute list nxc could
# not use (e.g. comma-separated) -- surfacing `attrs: {}` is what makes that
# visible instead of the model seeing a wall of text and inferring nothing.
_QUERY_OBJECT_RE = re.compile(r"^Response for object:\s*(?P<dn>.+?)\s*$")


def _add_value(attrs: dict, name: str, value: str) -> None:
    """One more value of `name`: a second value turns the attribute into a list."""
    if name in attrs:
        existing = attrs[name]
        attrs[name] = existing + [value] if isinstance(existing, list) else [existing, value]
    else:
        attrs[name] = value


def parse_ldap_query(text: str) -> list[dict]:
    """Parse `nxc ldap --query <filter> <attributes>` into `{host, dn, attrs}` entries.

    A multi-valued attribute comes back as a list, a single value as a string. Returns `[]`
    when nothing matched, and entries with an empty `attrs` when the object was found but no
    attribute came back.

    A line is told apart by the column its text starts at, the same for every line of a host:
    there, it is an attribute, its name then its value; further right, it is one more value of
    the attribute above. The parser used to want two spaces after the name, so it dropped every
    name of 20 characters or more (servicePrincipalName, msDS-AllowedToDelegateTo, the msDS-*
    of a password policy), which nxc follows with one, and every value after the first.
    """
    entries: list[dict] = []
    # host -> its open entry, the column its lines start at, the attribute last read
    open_: dict[str, tuple[dict, int, str | None]] = {}
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            continue
        host, payload = prefix["host"], line[prefix.end():]
        current = open_.get(host)
        if current and prefix.end() > current[1]:    # `{'':<20} {value}`: one more value
            entry, _, last = current
            if last is not None:
                _add_value(entry["attrs"], last, payload.strip())
            continue
        # A status line starts with its marker; a value may contain one ("CN=[!] Tier0,...").
        if (marker := _MARKER_RE.match(payload)):
            obj = _QUERY_OBJECT_RE.match(marker["message"].strip())
            if obj:
                entry = {"host": host, "dn": obj["dn"], "attrs": {}}
                entries.append(entry)
                open_[host] = (entry, prefix.end(), None)
            elif current:                     # nothing after it continues an attribute
                open_[host] = (current[0], current[1], None)
            continue
        if current is None:                   # attribute line before any object header
            continue
        entry, column, _ = current
        name, _, value = payload.partition(" ")
        _add_value(entry["attrs"], name, value.strip())
        open_[host] = (entry, column, name)
    return entries


# --- MSSQL enum_impersonate / enum_links (`-M` modules) -------------------- #
# Both list items as `  - <value>` display lines under a success header.
_DASH_ITEM_RE = re.compile(r"^-\s+(?P<item>.+?)\s*$")


def parse_mssql_impersonate(text: str) -> list[dict]:
    """Parse `nxc mssql -M enum_impersonate` into `{host, principal}` — the logins the
    current session can impersonate (listed as `  - <user>` under
    'Users with impersonation rights:')."""
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        m = _LINE_RE.match(raw.rstrip())
        if not m:
            continue
        item = _DASH_ITEM_RE.match(m["message"].strip())
        if item:
            rows.append({"host": m["host"], "principal": item["item"]})
    return rows


def parse_mssql_links(text: str) -> list[dict]:
    """Parse `nxc mssql -M enum_links` into `{host, linked_server}`. Handles both the
    simple form (`  - HOST\\INSTANCE`) and the detailed form (`Linked server: <name>`
    followed by `- Local login:`/`- Remote login:` sub-rows, which are skipped)."""
    rows: list[dict] = []
    for raw in (text or "").splitlines():
        m = _LINE_RE.match(raw.rstrip())
        if not m:
            continue
        msg = m["message"].strip()
        server = None
        if msg.lower().startswith("linked server:"):
            server = msg.split(":", 1)[1].strip()
        else:
            item = _DASH_ITEM_RE.match(msg)
            if item and ":" not in item["item"]:      # skip `- Local login: X` sub-rows
                server = item["item"]
        if server:
            rows.append({"host": m["host"], "linked_server": server})
    return rows


# --- Numeric AD attribute decoding (`decoded`, a SIBLING of `attrs`) -------- #
# `ldap_query` returns exactly what nxc printed, which for these attributes is a bare
# integer: `trustDirection: "3"`, `trustAttributes: "32"`. Correct, and meaningless to a
# reader who doesn't know MS-ADTS. We add the reading NEXT TO the raw value, never in place
# of it: an operator keeps the number, a model gets the sense, nothing existing breaks.
#
# The tables are COPIED from sources on the machine, not written from memory, because a
# wrong flag table turns opaque data into credible-but-false data that nobody re-reads:
#   * trust tables       -> nxc/protocols/ldap.py (which cites MS-ADTS 6.1.6.7.9 / 6.1.6.7.12)
#   * userAccountControl -> impacket.dcerpc.v5.samr UF_* constants, which nxc itself imports
# See tests/test_results.py for the value-by-value assertions.

# trustDirection: an ENUMERATION (a single value), NOT a bitmask.
_TRUST_DIRECTION = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}

# trustType: also an enumeration.
_TRUST_TYPE = {
    1: "Windows NT",
    2: "Active Directory",
    3: "Kerberos",
    4: "Unknown",
    5: "Azure Active Directory",
}

# trustAttributes: a BITMASK. Several flags can be set at once.
_TRUST_ATTRIBUTE_FLAGS = {
    0x1: "Non-Transitive",
    0x2: "Uplevel-Only",
    0x4: "Quarantined Domain",
    0x8: "Forest Transitive",
    0x10: "Cross Organization",
    0x20: "Within Forest",
    0x40: "Treat as External",
    0x80: "Uses RC4 Encryption",
    0x200: "Cross Organization No TGT Delegation",
    0x800: "Cross Organization Enable TGT Delegation",
    0x2000: "PAM Trust",
}

# userAccountControl: a BITMASK, and the attribute every AD audit reads. The flags that
# answer an offensive-recon question directly are ACCOUNTDISABLE, PASSWD_NOTREQD,
# DONT_REQUIRE_PREAUTH (AS-REP roastable) and TRUSTED_FOR_DELEGATION (unconstrained).
_UAC_FLAGS = {
    0x1: "SCRIPT",
    0x2: "ACCOUNTDISABLE",
    0x8: "HOMEDIR_REQUIRED",
    0x10: "LOCKOUT",
    0x20: "PASSWD_NOTREQD",
    0x40: "PASSWD_CANT_CHANGE",
    0x80: "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
    0x100: "TEMP_DUPLICATE_ACCOUNT",
    0x200: "NORMAL_ACCOUNT",
    0x800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQUIRE_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
    0x2000000: "NO_AUTH_DATA_REQUIRED",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
    0x8000000: "USE_AES_KEYS",
}

_ENUM_ATTRS = {
    "trustdirection": _TRUST_DIRECTION,
    "trusttype": _TRUST_TYPE,
}
_FLAG_ATTRS = {
    "trustattributes": _TRUST_ATTRIBUTE_FLAGS,
    "useraccountcontrol": _UAC_FLAGS,
}


def _as_int(value) -> int | None:
    """The attribute value as an int, or None when it isn't one (never raises)."""
    if isinstance(value, bool):          # bool is an int subclass; not a numeric attribute
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _decode_one(name: str, value) -> dict | None:
    """Decode a single attribute value, or None when there is nothing certain to say."""
    key = name.lower()
    number = _as_int(value)
    if number is None:                   # not an integer -> no entry, no guess
        return None

    if (table := _ENUM_ATTRS.get(key)) is not None:
        meaning = table.get(number)
        # An unmapped enum value gets NO entry: half an answer here would read as an answer.
        return {"value": number, "meaning": meaning} if meaning is not None else None

    if (table := _FLAG_ATTRS.get(key)) is not None:
        flags = [text for bit, text in table.items() if number & bit]
        out = {"value": number, "flags": flags}
        # Bits we have no name for are REPORTED, not dropped: silence here would let an
        # unknown flag look like an absent one.
        if (unknown := number & ~sum(table)) :
            out["unknown_bits"] = hex(unknown)
        return out

    return None                          # attribute not in any table -> passes through intact


def decode_attributes(attrs: dict) -> dict:
    """Return the `decoded` sibling for an `attrs` mapping: `{name: {...}}`.

    Only attributes present in the tables produce an entry; everything else passes through
    untouched (this NEVER rewrites `attrs`, and never raises). A multi-valued attribute
    (`attrs[name]` is a list, since LDAP attributes are multi-valued) decodes to a list, so
    `decoded` mirrors the shape of `attrs`. Returns `{}` when nothing is decodable, which the
    caller uses to omit the key entirely rather than pay tokens for an empty object.
    """
    decoded: dict = {}
    for name, value in (attrs or {}).items():
        if isinstance(value, list):
            items = [d for v in value if (d := _decode_one(name, v)) is not None]
            if items:
                decoded[name] = items
        elif (one := _decode_one(name, value)) is not None:
            decoded[name] = one
    return decoded
