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


def parse_markers(text: str) -> list[StatusRecord]:
    """Turn nxc stdout into a list of StatusRecord (one per marker line)."""
    records: list[StatusRecord] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        full = _LINE_RE.match(line)
        if full:
            marker = full["marker"]
            records.append(
                StatusRecord(
                    status=_STATUS[marker],
                    marker=marker,
                    message=full["message"].strip(),
                    protocol=full["proto"],
                    host=full["host"],
                    port=int(full["port"]),
                    hostname=full["name"],
                )
            )
            continue

        marker_only = _MARKER_RE.search(line)
        if marker_only:
            marker = marker_only["marker"]
            records.append(
                StatusRecord(
                    status=_STATUS[marker],
                    marker=marker,
                    message=marker_only["message"].strip(),
                )
            )
    return records


def parse_shares(text: str) -> list[dict]:
    """Parse `nxc smb --shares` output into structured share records.

    nxc prints shares as a fixed-width table under a header row
    (``Share  Permissions  Remark``) with no status marker, so the generic marker
    parser skips them. We anchor on that header to learn the column offsets, then
    slice each following data row positionally -- which correctly yields an empty
    permissions list for shares the account can't access (e.g. ``ADMIN$``/``C$``).

    Each record: ``{host, share, permissions: [...], remark}``.
    """
    shares: list[dict] = []
    share_off = perm_off = remark_off = None

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        if "Share" in line and "Permissions" in line and "Remark" in line:
            share_off = line.index("Share")
            perm_off = line.index("Permissions")
            remark_off = line.index("Remark")
            continue

        if share_off is None:
            continue  # not inside a shares table yet

        # A marker line (host banner, auth line, "Enumerated shares") ends the table.
        if _MARKER_ANYWHERE_RE.search(line):
            share_off = None
            continue
        # The separator row (----- ----------- ------).
        if line[share_off:].lstrip().startswith("-"):
            continue

        prefix = _PREFIX_RE.match(line)
        if not prefix:
            share_off = None
            continue

        share = line[share_off:perm_off].strip()
        perms = line[perm_off:remark_off].strip()
        remark = line[remark_off:].strip()
        if not share:
            continue
        shares.append(
            {
                "host": prefix["host"],
                "share": share,
                "permissions": [p for p in perms.replace(" ", "").split(",") if p],
                "remark": remark,
            }
        )
    return shares


def _parse_columns(text: str, columns: list[tuple[str, str]]) -> list[dict]:
    """Generic positional parser for nxc's fixed-width tables.

    `columns` is an ordered list of (field_name, header_label). We find the header
    row (the line containing every label), record each label's column offset, then
    slice each following data row positionally -- robust to empty middle columns.
    Stops a table at a marker line or a row without the PROTO HOST PORT NAME prefix.
    """
    fields = [f for f, _ in columns]
    labels = [lbl for _, lbl in columns]
    offsets: list[int] | None = None
    rows: list[dict] = []

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        if all(lbl in line for lbl in labels):
            offsets = [line.index(lbl) for lbl in labels]
            continue
        if offsets is None:
            continue
        if _MARKER_ANYWHERE_RE.search(line):
            offsets = None
            continue
        if line[offsets[0]:].lstrip().startswith("-"):  # separator row (----)
            continue
        prefix = _PREFIX_RE.match(line)
        if not prefix:
            offsets = None
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
    status marker -- group members, adminCount principals, trusted-for-delegation.
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


def parse_ldap_principals(text: str) -> list[dict]:
    """`nxc ldap --admin-count` / `--trusted-for-delegation` -> `{host, name}`
    (bare principal list, same shape as a narrowed group)."""
    return _parse_bare_names(text, "name")


def parse_ldap_delegation(text: str) -> list[dict]:
    """Parse `nxc ldap --find-delegation` into
    `[{account, account_type, delegation_type, rights_to: [spn, ...]}]`.

    Output is a fixed-width table with a `----` separator row, e.g.::

        AccountName  AccountType DelegationType                     DelegationRightsTo
        ------------ ----------- ---------------------------------- -------------------
        jon.snow     Person      Constrained w/ Protocol Transition CIFS/winterfell, ...

    `DelegationType` contains spaces, so columns are sliced by the dash-run
    positions of the separator row -- never split on whitespace."""
    rests: list[str] = []
    for raw in (text or "").splitlines():
        if _MARKER_ANYWHERE_RE.search(raw):          # skip [*] banner / [+] auth
            continue
        m = _PREFIX_RE.match(raw)
        if m:
            rests.append(raw[m.end():])              # keep internal spacing for column slicing
    header = next((i for i, r in enumerate(rests) if "AccountName" in r), None)
    if header is None or header + 1 >= len(rests):
        return []
    spans = [(mm.start(), mm.end()) for mm in re.finditer(r"-+", rests[header + 1])]
    if len(spans) < 4:
        return []
    out: list[dict] = []
    for row in rests[header + 2:]:
        if not row.strip():
            continue

        def cell(j: int, _row: str = row) -> str:
            s, e = spans[j]
            return (_row[s:] if j == len(spans) - 1 else _row[s:e]).strip()

        account = cell(0)
        if not account:
            continue
        out.append({
            "account": account,
            "account_type": cell(1),
            "delegation_type": cell(2),
            "rights_to": [x.strip() for x in cell(3).split(",") if x.strip()],
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
    field, added in nxc build 595); `None` when the tag is absent (not a DC, or the
    `display_dc` config option is off).
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
