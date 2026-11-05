"""Dynamic tool mode -- progressive disclosure for the full tool surface.

Why this exists
---------------
With every protocol enabled the server registers ~100+ first-class tools. Their
JSON schemas total ~46k tokens -- which alone overflows the ~40k context window of a
typical local model (qwen3, gpt-oss, ...) *before any prompt is even added*. That
makes the MCP effectively cloud-only.

Dynamic mode fixes this at the root, the way large MCP servers (e.g. CrowdStrike's
falcon-mcp) do: instead of listing all tools, expose a handful of *meta-tools* and
let the model discover + invoke the real tools on demand:

  * ``nxc_catalog``       -- what protocols/tools exist (orientation)
  * ``nxc_find_tool``     -- keyword search -> ranked matches with a compact signature
  * ``nxc_describe_tool`` -- the full schema for one tool (all params, on demand)
  * ``nxc_call``          -- dispatch to a tool by name

The real tools stay registered and fully functional; ``DynamicModeMiddleware`` just
hides them from ``tools/list``. ``nxc_call`` reaches them via ``mcp.call_tool``, so
the scope / recon<loot<full gating enforced in ``execute()`` is preserved unchanged
-- dynamic mode is orthogonal to the operating mode.

The client-visible surface drops from ~46k tokens to ~1-3k, so a small-context model
becomes usable. Full capability (Kerberos aes_key / LAPS / certificate auth, every
parameter) is never lost -- it is delivered on demand via ``describe`` instead of up
front.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from typing import Annotated

from fastmcp.exceptions import ToolError
from pydantic import Field
from fastmcp.server.middleware import Middleware

from .config import DEFAULT_PROTOCOLS
from .executor import _folded_args

# Tools that stay visible in dynamic mode: the meta-tools + the health check.
DYNAMIC_VISIBLE = frozenset(
    {"nxc_catalog", "nxc_find_tool", "nxc_describe_tool", "nxc_call", "nxc_health"}
)

# Common params a model may pass at the TOP LEVEL of nxc_call (not only inside `arguments`).
# Weak models reliably drop the trailing `arguments` object after emitting the scalar `name`;
# accepting these flat keeps the essential data flowing (nxc_call folds them into `arguments`,
# the middleware leaves them for nxc_call instead of flagging them as strays).
NXC_CALL_FIRST_CLASS = ("targets", "username", "password", "domain", "ntlm_hash", "local_auth")

# Name prefixes that map to a protocol / group (for deriving `protocol`). nxc_* and
# workspace_* are meta/offline, not a wire protocol, but are still useful groupings.
_KNOWN_PREFIXES = frozenset(
    {"smb", "ldap", "winrm", "mssql", "wmi", "rdp", "ssh", "ftp", "nfs", "vnc",
     "workspace", "nxc"}
)

DYNAMIC_INSTRUCTIONS = (
    "This NetExec MCP server runs in DYNAMIC tool mode: only a few meta-tools are "
    "listed, not the full tool surface. To do anything:\n"
    "  1. Discover a tool: nxc_find_tool(query=\"...\"), or nxc_catalog() to browse "
    "by protocol.\n"
    "  2. Run it: nxc_call(name=\"<tool>\", arguments={...}).\n"
    "  3. Need every parameter (e.g. Kerberos/LAPS/certificate auth)? "
    "nxc_describe_tool(name=\"<tool>\").\n"
    "Example: nxc_find_tool(\"smb shares\") -> nxc_call(\"smb_shares\", "
    "{\"targets\": [\"10.0.0.1\"], \"username\": \"u\", \"password\": \"p\"}).\n"
    "The common params targets/username/password/ntlm_hash/domain/local_auth may be passed at "
    "the top level of nxc_call OR inside `arguments` (local_auth=true for a local account, "
    "ntlm_hash for pass-the-hash); every OTHER tool parameter goes inside `arguments`. So "
    "nxc_call(name=\"smb_get_file\", share=\"all\") is WRONG (share is not a common param); write "
    "nxc_call(name=\"smb_get_file\", arguments={\"share\": \"all\", \"targets\": [...]}). Only "
    "nxc_call takes `arguments` -- call a zero-arg tool (e.g. nxc_health) with no arguments.\n"
    "Search ONCE per capability: the top match carries a `suggested_call` -- fill in its "
    "arguments and call nxc_call; do NOT re-search the same thing.\n"
    "`targets` accepts an IP, a CIDR (10.0.0.0/24), an nxc range (10.0.0.1-20), or a hostname "
    "-- a CIDR/range scans every host in it, so pass the whole scope at once instead of asking "
    "for individual IPs.\n"
    "Results of EARLIER nxc runs (this session or before it) persist in the nxc workspace DB: "
    "credentials, who is admin where, who is logged in where, hosts. When asked what is already "
    "known or collected, query it BEFORE re-scanning, and never assume it is empty because you "
    "have not run anything yet: nxc_call(name=\"workspace_admins\") (likewise workspace_creds, "
    "workspace_loggedin, workspace_hosts, workspace_cred_reach) needs no arguments and contacts "
    "no target.\n"
    "The recon/loot/full permission gate still applies to whatever nxc_call runs."
)


@dataclass
class ToolEntry:
    """One searchable tool in the dynamic-mode catalog."""

    name: str
    protocol: str
    summary: str            # first non-empty line of the docstring
    description: str        # full docstring
    parameters: dict        # the tool's JSON input schema (.parameters)
    required: list[str] = field(default_factory=list)
    # "tool" = a dispatchable first-class @mcp.tool; "module" = an nxc -M module, searchable
    # here so find_tool can route to it via nxc_run_module, but NOT a nxc_call dispatch target.
    # Appended last with a default so positional ToolEntry(...) constructions keep working.
    kind: str = "tool"


def _protocol_of(name: str) -> str:
    head = name.split("_", 1)[0]
    return head if head in _KNOWN_PREFIXES else "other"


def _summary(description: str | None) -> str:
    for line in (description or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def build_index(tools, modules=None) -> list[ToolEntry]:
    """Build the searchable catalog from a snapshot of registered tools (and nxc -M modules).

    Must be called on the *full* tool list -- i.e. before the hiding middleware is
    installed, since the middleware also filters the server's own ``list_tools``.
    The meta-tools themselves are skipped (they are always visible, not findable
    dispatch targets).

    `modules` (optional) is a list of nxc -M module records
    ({name, description, category, privilege, protocol}, from meta.collect_module_catalog).
    They join the index tagged kind="module" so find_tool can surface and route to them via
    nxc_run_module -- without them the whole -M long-tail (raisechild, ticketer, nopac, ...)
    is invisible to discovery.
    """
    entries: list[ToolEntry] = []
    for t in tools:
        if t.name in DYNAMIC_VISIBLE:
            continue
        params = dict(t.parameters or {})
        entries.append(
            ToolEntry(
                name=t.name,
                protocol=_protocol_of(t.name),
                summary=_summary(t.description),
                description=t.description or "",
                parameters=params,
                required=list(params.get("required", [])),
            )
        )
    tool_names = {e.name for e in entries}
    for m in (modules or []):
        # A promoted module is its curated tool's own engine (smb_nopac runs -M nopac, with the
        # same options and gate). Indexed too, the bare module outranked its wrapper on an exact
        # name hit, so it is skipped -- on every protocol nxc lists it for (zerologon and spooler
        # also appear under wmi). nxc_run_module still runs it.
        wrapped = (m.get("name") or "").replace("-", "_")
        if any(f"{p}_{wrapped}" in tool_names for p in _KNOWN_PREFIXES):
            continue
        desc = m.get("description") or ""
        entries.append(
            ToolEntry(
                name=m.get("name", ""),
                protocol=m.get("protocol", "other"),
                summary=desc,
                description=desc,
                parameters={},
                required=[],
                kind="module",
            )
        )
    return entries


# Intent synonyms: if a query contains the key phrase, these extra tokens are also
# matched (query expansion via the existing name/description scoring -- no hardcoded
# tool names, so nothing breaks silently if a tool is renamed). Expansion only ever
# *adds* candidate matches; it never removes a literal hit.
_SYNONYMS = {
    "hashes": ("sam", "ntds", "lsa", "hash"),
    "hash": ("sam", "ntds", "lsa"),
    "dump": ("sam", "ntds", "lsa", "dpapi"),
    "credential": ("sam", "lsa", "dpapi", "gpp"),
    "secret": ("lsa", "sam"),
    "roast": ("kerberoast", "asreproast"),
    "kerberoast": ("kerberoast",),
    "asrep": ("asreproast",),
    "spray": ("spray",),
    "policy": ("pass_pol", "policy"),
    "execute": ("exec",),
    "command": ("exec",),
    "shell": ("exec",),
    # common shell-command words carry an exec intent -- without them "run whoami over winrm"
    # lost the signal ("run" is a stopword) and winrm_exec ranked #4 behind winrm_dir/dpapi/
    # enum_hosts (bughunt, qwen8b). "hostname"/"cmd" deliberately excluded (ambiguous nouns).
    "whoami": ("exec",),
    "ipconfig": ("exec",),
    "powershell": ("exec",),
    "cmdshell": ("exec",),
    "xp_cmdshell": ("exec",),
    "linked": ("links",),
    "impersonat": ("impersonate",),
    "delegat": ("delegation",),
    "antivirus": ("av",),
    "edr": ("av",),
    "collected": ("creds",),
    "harvested": ("creds",),
    # DCSync is how secretsdump pulls NTDS over DRSUAPI: the word returned nothing at all.
    "dcsync": ("ntds",),
    # fine-grained password policies are PSOs (q_join drops the hyphen of "fine-grained")
    "fine grained": ("pso",),
    "finegrained": ("pso",),
    "fgpp": ("pso",),
}


# Token-EXACT synonyms: matched against whole query words, not as a substring of the
# query string like `_SYNONYMS`. A short key has to live here: "ou" (the AD abbreviation
# a model writes for an organizational unit) sits inside "group", "you" and "about", so a
# substring key would fire on half the corpus. Same additive rule as above -- expansion
# only ever adds candidates, at the reduced `_SYN_W` weight.
_TOKEN_SYNONYMS = {
    "ou": ("ous", "organizational"),
    "organizational": ("ous", "ou"),
    # Domain trusts are listed by ldap_dc_list, but "trust" prefix-matches the name-part
    # "trusted" of ldap_trusted_for_delegation (a different subject) and led with it. Whole
    # words only, so "trusted" itself keeps pointing at delegation.
    "trust": ("dc", "list"),
    "trusts": ("dc", "list"),
    # "sql server" never reached the mssql tools: "sql" is a suffix of the name-part, not a prefix.
    "sql": ("mssql",),
}

# Words that state a command-execution intent. Each adds a full-weight literal "exec": as an
# intent verb "execute" is a stopword, and the 0.4 synonym weight lost to any concrete noun
# ("execute command remote" led with the remote-uac module, "cmd" with enable_cmdshell). The
# impacket method names are how operators say it. "shell"/"powershell" stay synonyms only:
# "get a meterpreter shell" belongs to met_inject.
_EXEC_WORDS = frozenset({
    "execute", "exec", "execution", "command", "commands", "cmd", "cmdshell",
    "psexec", "smbexec", "wmiexec", "atexec", "mmcexec", "dcomexec",
})


def _exec_intent(raw: list[str], protocol: str | None) -> list[str]:
    """Raw query words with the command-execution intent made explicit.

    A bare "whoami" is the command to run (the bench prompts say "Execute the command
    'whoami'"), but it was an exact-name hit on the ldap `whoami` module, so it reads as "exec"
    -- unless the query is about LDAP ("ldap whoami", "whoami module", protocol="ldap"). Other
    command names stay literal: smb_tasklist is a tool, and "hostname" is mostly a noun."""
    words = set(raw)
    if "whoami" in words and not (words & {"ldap", "module"} or protocol == "ldap"):
        raw = list(dict.fromkeys("exec" if w == "whoami" else w for w in raw))
        words = set(raw)
    if words & _EXEC_WORDS and "exec" not in words:
        raw = [*raw, "exec"]
    return raw


def _expand(query_lower: str, tokens: list[str] | None = None) -> list[str]:
    extra: list[str] = []
    for key, toks in _SYNONYMS.items():
        if key in query_lower:
            extra.extend(toks)
    for tok in tokens or ():
        extra.extend(_TOKEN_SYNONYMS.get(tok, ()))
    return extra


# --- scoring -------------------------------------------------------------------
# Literal query terms carry full weight; intent-synonym terms carry _SYN_W (< 1) so a
# literal user term always outranks an inferred one. A tool whose PROTOCOL matches the
# caller's hint is boosted -- but the hint is a soft boost, NOT a hard filter: the right
# tool often lives under a protocol the model didn't guess (kerberoasting is `ldap`, not
# "kerberos"), so cross-protocol matches still compete (see search()).
_SYN_W = 0.4
_PROTO_BOOST = 1.3

_WORD_RE = re.compile(r"[a-z0-9]+")

# Generic function words + intent verbs, dropped before scoring. They add description
# noise and -- worse -- a bare verb can match a tool NAME as a substring: "list" is in
# `smb_gen_relay_list`, "run"/"get"/"find" are in tool names too, so an unfiltered verb
# outranks the actual target. Domain nouns (share, user, hash, dump, roast, ...) are
# deliberately NOT here -- they carry the intent.
_STOPWORDS = frozenset({
    "a", "an", "the", "this", "that", "these", "those", "it", "its", "i", "me", "my",
    "we", "us", "you", "your", "they", "them", "their", "is", "are", "be", "am", "was",
    "to", "of", "on", "in", "at", "for", "from", "with", "and", "or", "if", "whether",
    "as", "by", "via", "into", "over", "do", "does", "did", "can", "could", "would",
    "should", "how", "what", "which", "where", "who", "when", "all", "any", "some",
    "no", "not", "want", "need", "please", "help",
    # generic intent verbs (express the action, not the target)
    "list", "show", "get", "find", "fetch", "retrieve", "enumerate", "enum", "check",
    "run", "execute", "read", "view", "see", "give", "tell", "use", "using", "perform",
    "make", "look", "scan", "try", "grab", "pull",
})


# Split points inside a camelCase word: before an Upper+lower pair (pwd|Not|Required,
# sAM|Account|Name). An all-caps acronym (gMSA, NTDS) has no such pair and stays whole.
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z][a-z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _query_words(query: str) -> list[str]:
    """The lowercased words of a query. A camelCase LDAP attribute (pwdNotRequired,
    userAccountControl) also yields its parts -- whole, it matched nothing -- and the word
    itself is kept."""
    words = _WORD_RE.findall((query or "").lower())
    for w in re.findall(r"[A-Za-z0-9]+", query or ""):
        parts = _CAMEL_RE.split(w)
        if len(parts) < 2:
            continue
        for part in parts:
            if part.lower() not in words:
                words.append(part.lower())
    return words


def _words(text: str) -> set[str]:
    """Word set of a string; hyphen is a SEPARATOR here (who-is-admin -> {who,is,admin})."""
    return set(_WORD_RE.findall((text or "").lower()))


def _part_match(tok: str, parts: set[str]) -> bool:
    """token vs a name/summary word set, tolerant to plural/prefix. Handles both plurals
    (share ~ shares, database ~ databases) and short abbreviations against the real
    3-char tool-name stems (rid ~ rids, lsa ~ lsass). Min 3 chars so 1-2 char tokens
    ("a", "id") stay exact-only and don't over-match. A stopword part never matches as the
    prefix of a LONGER query word: it carries no intent, yet "enumeration" hit every `enum`
    name-part and "force"/"forest" the `for` of ldap_trusted_for_delegation. The other way
    round is kept: "exec" still matches the summary word "Execute" of smb_exec."""
    if tok in parts:
        return True
    if len(tok) >= 3:
        for p in parts:
            if len(p) < 3:
                continue
            if (p.startswith(tok) or (tok.startswith(p) and p not in _STOPWORDS)
                    or _y_plural(tok, p) or _y_plural(p, tok)):
                return True
    return False


def _y_plural(word: str, other: str) -> bool:
    """policy ~ policies: the one plural a shared prefix misses ("polic" is neither word)."""
    return word.endswith("y") and other == word[:-1] + "ies"


def _stem_token(tok: str) -> str:
    """Fold a query word to a canonical stem so it prefix-matches the short tool name-parts.

    Currently just the ADMIN family: a query says "administrative access" / "administrator"
    (EN) or "administrateur" / "administratif" (FR), but the name-parts are the short stems
    "admin" / "admins". `_part_match` bridges admin<->admins (prefix), but NOT the longer
    variants ("administrative" is not a prefix of "admins", nor vice-versa), so they scored
    far too low against `workspace_admins` / `*_admin_*` and the admin reader was invisible.
    Folding any admin* token to "admin" lets it prefix-match every admin name-part at full
    weight. (Real Cline+qwen14b miss: "which hosts have administrative access, with which
    account" surfaced host-inventory tools, never `workspace_admins`.)

    Plus whole-word aliases in `_TOKEN_FOLDS`."""
    return "admin" if tok.startswith("admin") else _TOKEN_FOLDS.get(tok, tok)


# Whole-word aliases folded at FULL weight (a synonym only adds at _SYN_W). "hashdump" is
# meterpreter's SAM dump; as one word it prefix-matched the name-part `hash` and led with
# dpapi_hash / hash_spider (2026-10-31). "linked" prefix-matches the module name-part `link`
# but not `links`, so every "linked servers" query led with exec_on_link/link_enable_cmdshell
# (state-changing in full mode) above mssql_enum_links; as "links" it reaches both.
_TOKEN_FOLDS = {"hashdump": "sam", "linked": "links"}


def _score(entry: ToolEntry, tokens: list[str], expanded: list[str]) -> float:
    """Relevance of an entry for the query tokens (higher = better).

    A name-PART hit (``sam`` in ``smb_sam``) dominates; a mere substring hit (``list``
    in ``relay_list``) is weak; summary hits weaker, description weaker still. `tokens`
    are the literal query words (weight 1.0), `expanded` the intent synonyms (_SYN_W).
    """
    name = entry.name.lower()
    name_parts = set(name.split("_"))
    summ = _words(entry.summary)
    desc = _words(entry.description)

    def hit(tok: str, w: float) -> float:
        if tok == name:
            return 100.0 * w
        s = 0.0
        if _part_match(tok, name_parts):
            s += 60.0 * w
        elif tok in name:                       # substring only -> weak
            s += 12.0 * w
        if _part_match(tok, summ):
            s += 14.0 * w
        elif tok in desc:
            s += 4.0 * w
        return s

    return sum(hit(t, 1.0) for t in tokens) + sum(hit(t, _SYN_W) for t in expanded)


def _query_tokens(query: str, protocol: str | None = None) -> tuple[list[str], list[str], list[str]]:
    """(raw words, literal tokens, synonym-expanded tokens) of a query, as the scorer sees
    them. `protocol` is the lowercased hint: it decides whether "whoami" is the command."""
    q_join = (query or "").lower().replace("-", "")   # for synonym detection (as-rep -> asrep)
    raw = _exec_intent(_query_words(query), protocol)
    tokens = [t for t in raw if t not in _STOPWORDS] or raw   # keep raw if all-stopword
    tokens = [_stem_token(t) for t in tokens]                 # fold admin* -> admin, etc.
    expanded = list(dict.fromkeys(e for e in _expand(q_join, raw) if e not in tokens))
    return raw, tokens, expanded


def search_scored(index, query: str, protocol: str | None = None,
                  limit: int = 8) -> list[tuple[float, ToolEntry]]:
    """Ranked ``(score, entry)`` pairs -- the scoring core of :func:`search`. Exposing the
    score lets callers gauge match strength (e.g. a weak/zero top score -> suggest the nxc
    module long-tail rather than let the model give up)."""
    proto = protocol.strip().lower() if protocol else None
    raw, tokens, expanded = _query_tokens(query, proto)
    has_query = bool(raw)
    scored: list[tuple[float, ToolEntry]] = []
    for e in index:
        if proto and e.protocol != proto and not has_query:
            continue                                   # empty query + protocol = browse group
        if not has_query:
            s = 1.0
        else:
            s = _score(e, tokens, expanded)
            if proto and e.protocol == proto:
                s *= _PROTO_BOOST
        if s > 0:
            scored.append((s, e))
    if has_query:
        scored = _demote_modules(scored, tokens)
    _sort_ranked(scored)
    out: list[tuple[float, ToolEntry]] = []
    seen_modules: set[str] = set()
    for s, e in scored:
        if e.kind == "module":
            # One slot per module: nxc lists the same -M under several protocols (dpapi_hash x4
            # filled half the top 8). The best-scoring copy stays, so a protocol hint picks it.
            if e.name in seen_modules:
                continue
            seen_modules.add(e.name)
        out.append((s, e))
        if len(out) >= max(1, limit):
            break
    return out


_PROTO_ORDER = {p: i for i, p in enumerate(DEFAULT_PROTOCOLS)}


def _capability(e: ToolEntry) -> str:
    """smb_sam and mssql_sam are one capability over two protocols: the name minus its protocol."""
    if e.kind == "tool" and e.protocol in _PROTO_ORDER:
        return e.name.split("_", 1)[1]
    return e.name


def _sort_ranked(scored: list[tuple[float, ToolEntry]]) -> None:
    """Order by score; break exact ties in place.

    A tool wins a tie with a module: it returns parsed fields and takes typed params. Among
    tools, a protocol's `enum_hosts` wins a tie: a query that cannot tell the tools apart starts
    with the read-only entry point (a bare "mssql" was an 8-way tie handed to mssql_db_hash, a
    credential dump, on the alphabet). Within a tie, one capability offered by several protocols
    comes in DEFAULT_PROTOCOLS order, smb first -- on the alphabet "dump sam" led with mssql_sam
    and a bare "exec" with mssql_exec. Different capabilities keep their alphabetical order (no
    smb_local_groups over ldap_groups)."""
    def tie(se):
        return round(se[0], 6), se[1].kind == "module", _capability(se[1])
    lead: dict = {}
    for se in scored:
        lead[tie(se)] = min(lead.get(tie(se), se[1].name), se[1].name)
    scored.sort(key=lambda se: (-tie(se)[0], tie(se)[1], tie(se)[2] != "enum_hosts", lead[tie(se)],
                                _PROTO_ORDER.get(se[1].protocol, len(_PROTO_ORDER)), se[1].name))


# A module that matches fewer query words strongly than the best-matching tool has its score cut
# by this factor. Without it a module led on synonym and description words alone: "dump the local SAM
# hashes" ranked dpapi_hash first and smb_sam 8th.
_MODULE_DEMOTE = 0.5


def _demote_modules(scored: list[tuple[float, ToolEntry]],
                    tokens: list[str]) -> list[tuple[float, ToolEntry]]:
    """Demote the modules that answer the query's own words less well than some tool does.

    A module still leads when it matches as many words strongly as every tool, so a named
    one (raisechild, ntdsutil) or a capability no tool covers keeps the top slot."""
    bar = max((_token_hits(e, tokens)[1] for _, e in scored if e.kind == "tool"), default=0)
    return [(s * _MODULE_DEMOTE if e.kind == "module" and _token_hits(e, tokens)[1] < bar else s, e)
            for s, e in scored]


def search(index, query: str, protocol: str | None = None, limit: int = 8) -> list[ToolEntry]:
    """Rank the catalog for a query.

    `protocol` is a SOFT BOOST, not a filter: a matching-protocol tool ranks higher, but
    tools in other protocols still compete -- so a wrong/absent protocol hint can't hide
    the right tool. The one exception: an *empty* query with a protocol lists that group
    (browse mode). Stopwords/intent-verbs are dropped; hyphens are normalised so
    "as-rep" reaches "asreproast"; intent synonyms are expanded and de-duped.
    """
    return [e for _, e in search_scored(index, query, protocol, limit)]


# Module long-tail: nxc's `-M` modules are now indexed into find_tool (kind="module", via
# meta.collect_module_catalog) so a named one (ms17-010, raisechild, ...) surfaces directly with
# a ready nxc_run_module suggested_call. This generic hint is the fallback when nothing confident
# matches, or the module meta-tools themselves top the list.
_MODULE_META = frozenset({"nxc_list_modules", "nxc_search_tools", "nxc_run_module"})
_WEAK_MATCH_SCORE = 20.0     # below the lowest legit tool score (~30 for "check antivirus")
_MODULE_HINT = (
    'For a specific nxc `-M` module (e.g. ms17-010 or spooler on smb, raisechild on ldap): run it with '
    'nxc_run_module(protocol="<proto>", module="<name>", targets=[...]), or browse with '
    'nxc_list_modules(protocol="<proto>"). Modules are protocol-specific -- use the protocol on '
    'the match, not a guess.'
)

# Capabilities nxc does not implement. When a query clearly asks for one, say so instead of
# handing back the nearest read-only tool (the agent otherwise burns calls on enum_ca/relay_list).
_NOT_IMPLEMENTED = (
    (frozenset({"enroll", "esc", "esc1", "esc8", "certipy", "certificate", "request", "template"}),
     "certificate enrollment / ADCS ESC abuse is not implemented in nxc; use Certipy outside this MCP."),
    (frozenset({"relay", "ntlmrelay", "responder", "listener"}),
     "there is no NTLM-relay listener/responder in nxc; use ntlmrelayx/Responder outside this MCP."),
)


def _confidence_tokens(query: str, protocol: str | None = None) -> tuple[list[str], list[str]]:
    """(literal, synonym-expanded) tokens, exactly as search_scored builds them. The confidence
    gauge must count synonym hits too, or a match ranked #1 BY a synonym is wrongly flagged
    low-confidence."""
    _, lit, exp = _query_tokens(query, protocol.strip().lower() if protocol else None)
    return lit, exp


def _token_hits(entry: ToolEntry, tokens: list[str]) -> tuple[int, int]:
    """(# query tokens that hit `entry`, # that hit STRONGLY). Strong = exact/name-part/
    summary-part; weak = substring or description-only. Gauges top-match confidence so a lone
    substring hit (``inter`` -> ``interfaces``) is not sold as a confident answer."""
    name = entry.name.lower()
    name_parts = set(name.split("_"))
    summ = _words(entry.summary)
    desc = _words(entry.description)
    hits = strong = 0
    for t in tokens:
        hit = strong_hit = False
        if t == name or _part_match(t, name_parts):
            hit = strong_hit = True
        elif t in name:
            hit = True
        if _part_match(t, summ):
            hit = strong_hit = True
        elif t in desc:
            hit = True
        hits += int(hit)
        strong += int(strong_hit)
    return hits, strong


def _capability_note(tokens: list[str]) -> str | None:
    tokset = set(tokens)
    for phrases, note in _NOT_IMPLEMENTED:
        if len(tokset & phrases) >= 2:
            return note
    return None


def _is_list_param(schema) -> bool:
    """True if a JSON-schema property accepts an array (so a bare scalar can be coerced to [x])."""
    if not isinstance(schema, dict):
        return False
    if schema.get("type") == "array":
        return True
    return any(isinstance(s, dict) and s.get("type") == "array" for s in schema.get("anyOf", []))


def _reformat_validation(err: str, entry: "ToolEntry") -> dict | None:
    """Turn a raw pydantic ValidationError string into the same actionable shape as the
    missing-args path (accepted params + a ready suggested_call), stripping the pydantic URL.
    Returns None when the error is not a validation/shape error."""
    low = err.lower()
    if "validation error" not in low and "input should be" not in low:
        return None
    msg = " ".join(
        ln.strip() for ln in err.splitlines()
        if ln.strip() and "pydantic.dev" not in ln and "further information" not in ln.lower()
    )
    # pydantic v2 prints the offending field on its own line, then an indented reason.
    fields = re.findall(
        r"\n([A-Za-z_]\w*)\n\s+(?:Input should|Field required|Extra inputs|Unexpected keyword)",
        err,
    )
    unexpected = "unexpected keyword" in low or "extra inputs" in low
    if unexpected and fields:
        hint = (f"remove the unknown parameter(s) {', '.join(fields)} -- not accepted by "
                f"{entry.name!r}. Send only the params in `signature` (copy suggested_call).")
    elif fields:
        hint = (f"fix the type of {', '.join(fields)} to match `signature` "
                f"(a list[str] param like `targets` takes a JSON list, e.g. [\"10.0.0.0/24\"]). "
                "Copy suggested_call and fill it.")
    else:
        hint = "fix the flagged argument to match `signature`, then resend suggested_call."
    return {
        "error": f"invalid arguments for {entry.name!r}: {msg[:300]}",
        "invalid_fields": fields or None,
        "signature": _signature(entry),
        "suggested_call": _suggested_call(entry),
        "hint": hint,
    }


def _suggest(name: str, names, n: int = 5) -> list[str]:
    return difflib.get_close_matches(name, list(names), n=n, cutoff=0.4)


def _name_to_query(name: str) -> str:
    """Split an invented tool name into a capability query: ldap_trusts -> 'ldap trusts',
    smbEnumCve -> 'smb Enum Cve'."""
    return " ".join(p for p in re.split(r"[_\W]+|(?<=[a-z])(?=[A-Z])", name or "") if p)


def _capability_suggest(name, index, by_protocol, n: int = 5) -> dict:
    """Suggestions for an invented tool name by CAPABILITY, not name string-distance: route its
    tokens through the same search index find_tool uses, so 'ldap_trusts' -> ldap_query/
    ldap_dc_list and 'smb_enum_cve' -> the vuln tools, which difflib over names never finds.
    Adds a protocol_note when the name targets a known protocol that is not enabled here."""
    q = _name_to_query(name)
    # Rank the tools only: filtering AFTER the limit let -M modules take the slots, and the
    # suggestion list came back short or empty (26 of 149 invented bench names, 2026-10-31).
    tools = [e for e in index if getattr(e, "kind", "tool") == "tool"]
    hits = [e.name for e in search(tools, q, limit=n)]
    out = {"suggestions": hits}
    head = (name or "").split("_", 1)[0].lower()
    # 'nxc'/'workspace' are meta groups, not wire protocols -> never a "protocol not exposed" note.
    if (head in _KNOWN_PREFIXES and head not in ("other", "nxc", "workspace")
            and head not in by_protocol):
        out["protocol_note"] = (f"the {head!r} protocol is not exposed on this server; its tools "
                                "are unavailable (check NXC_PROTOCOLS).")
    return out


def _typestr(schema: dict) -> str:
    """Short readable type for a JSON-schema property, e.g. 'list[string]', 'string'.

    Live testing showed models pass a scalar where a list is required (targets=
    '10.0.0.1' instead of ['10.0.0.1']) when the signature shows only names. Surfacing
    the type on required params removes that wasted retry.
    """
    if not isinstance(schema, dict):
        return "any"
    if "anyOf" in schema:
        parts = [_typestr(s) for s in schema["anyOf"] if isinstance(s, dict)]
        non_null = [p for p in parts if p != "null"]
        return "|".join(dict.fromkeys(non_null or parts)) or "any"
    t = schema.get("type")
    if t == "array":
        return f"list[{_typestr(schema.get('items') or {})}]"
    if isinstance(t, list):
        return "|".join(t)
    return t or "any"


def _signature(entry: ToolEntry, drop: frozenset | None = None) -> dict:
    """Compact call signature: required params WITH types, optional param names.

    Types go on required only (usually 1-3 params) so the model gets the call right
    first try, while keeping the payload small -- the full schema (incl. every optional
    auth param's type) is one nxc_describe_tool away. `drop` removes shared optionals that
    find_tool emits once as a top-level legend instead of on every match.
    """
    props = (entry.parameters or {}).get("properties", {})
    req_set = set(entry.required)
    optional = [p for p in props if p not in req_set]
    if drop:
        optional = [p for p in optional if p not in drop]
    return {
        "required": {p: _typestr(props.get(p, {})) for p in entry.required},
        "optional": optional,
    }


def _common_optional(index) -> frozenset:
    """The optional params shared by MOST tools (the ~16-item kerberos/pfx/laps auth block).

    find_tool emits this once as a legend rather than repeating it on all 8 matches -- that
    repeated block was ~44% of find_tool's bytes, and find_tool is the most-called meta-tool.
    Frequency-based (>=60% of tools) because a strict intersection collapses to {username}
    (some tools lack the full auth block).
    """
    tools = [e for e in index if getattr(e, "kind", "tool") == "tool"]
    if not tools:
        return frozenset()
    counts: dict[str, int] = {}
    for e in tools:
        props = (e.parameters or {}).get("properties", {})
        req = set(e.required)
        for p in props:
            if p not in req:
                counts[p] = counts.get(p, 0) + 1
    thresh = 0.6 * len(tools)
    return frozenset(p for p, n in counts.items() if n >= thresh)


def _match_view(entry: ToolEntry, drop: frozenset | None = None) -> dict:
    view = {
        "name": entry.name,
        "protocol": entry.protocol,
        "summary": entry.summary,
        "kind": entry.kind,
    }
    if entry.kind == "module":
        view["run_via"] = "nxc_run_module"          # an -M module, not a dispatchable tool
    else:
        view["signature"] = _signature(entry, drop)
    return view


def _norm_query(query: str) -> str:
    """Normalise a query to its sorted word set, so 'dump ntds' == 'ntds dump'. The
    loop-breaker keys on this to spot a model re-phrasing the same intent."""
    return " ".join(sorted(_WORD_RE.findall((query or "").lower())))


def _auth_hint(entry: ToolEntry) -> str:
    """The creds clause of find_tool's hint, from the top tool's OWN params, so it never claims a
    param the tool lacks (ldap/ssh/... take no local_auth; smb_spray/nfs/vnc take no username).
    Replaces the 16-name optional_legend: the two auth params small models drop (local_auth,
    ntlm_hash) are named where the call is decided, and nothing points at nxc_describe_tool."""
    props = (entry.parameters or {}).get("properties", {})
    if "username" not in props:
        return ""
    secret = "password or ntlm_hash" if "ntlm_hash" in props else "password"
    clause = f" and creds: username + {secret}, domain"
    if "local_auth" in props:
        clause += "; local account: local_auth=true, no domain"
    return clause


def _suggested_call(entry: ToolEntry) -> dict:
    """A ready-to-run call skeleton for the top match: the tool name + its required params
    as typed placeholders. Handing the model a concrete next call (rather than a list to
    re-search) is what stops small models looping on discovery -- see docs/dynamic-mode.md."""
    if getattr(entry, "kind", "tool") == "module":
        # An nxc -M module: route via nxc_run_module with the protocol PRE-FILLED (so the model
        # doesn't guess smb for an ldap-only module like raisechild -- the raisechild friction).
        return {
            "name": "nxc_run_module",
            "arguments": {
                "protocol": entry.protocol,
                "module": entry.name,
                "targets": "<list[str]: IP, CIDR (10.0.0.0/24), range, or hostname>",
            },
        }
    sig = _signature(entry)
    args = {}
    for p, t in sig["required"].items():
        # `targets` is list[str] everywhere, which the model reads as "list of single IPs" and
        # then invents a "subnets not accepted" rule (bughunt/opencode: refused a /24 scope 3x).
        # Spell out that a CIDR/range/hostname is a valid entry so it targets the whole scope.
        if p == "targets":
            args[p] = ("<list[str]: IP, CIDR (10.0.0.0/24), range (10.0.0.1-20), or hostname -- "
                       "a CIDR/range scans every host in it>")
        else:
            args[p] = f"<{t}>"
    return {"name": entry.name, "arguments": args}


def register(mcp, get_config, index) -> None:
    """Attach the dynamic-mode meta-tools, backed by `index`.

    `get_config` is accepted for signature parity with the other registrars (and
    future mode-aware filtering); the meta-tools themselves are read-only over the
    index and dispatch through `mcp.call_tool`.
    """
    # Only TOOL-kind entries are nxc_call dispatch targets / catalog groups. Module entries are
    # searchable (find_tool) and describable, but run via nxc_run_module, not nxc_call dispatch.
    by_name = {e.name: e for e in index if e.kind == "tool"}
    # First-wins so describe() agrees with find_tool's first-sorted protocol for a module that
    # several enabled protocols expose under the same name.
    by_module: dict[str, ToolEntry] = {}
    for e in index:
        if e.kind == "module" and e.name not in by_module:
            by_module[e.name] = e
    by_protocol: dict[str, list[ToolEntry]] = {}
    for e in index:
        if e.kind == "tool":
            by_protocol.setdefault(e.protocol, []).append(e)
    # Shared optional auth params, emitted once as a find_tool legend (not per match).
    common_optional = _common_optional(index)
    # Loop-breaker state: normalised queries searched this session. Small models tend to
    # re-phrase the same intent (`dump ntds` -> `ntds dump`) instead of committing to a
    # call; on a repeat we nudge them to run the top match. Per-process = per-session.
    searched: set[str] = set()
    # Loop-break state: the last (tool, missing-args) failure and its consecutive count. A model
    # that drops `arguments` re-sends the byte-identical call; on the 2nd+ identical miss we
    # return a drastically shorter imperative payload instead of the same long error.
    arg_fail: dict = {"key": None, "n": 0}

    @mcp.tool()
    async def nxc_catalog(protocol: str | None = None) -> dict:
        """Browse the available tools (dynamic-mode orientation).

        Without `protocol`: the list of protocols and how many tools each has.
        With `protocol` (e.g. "smb"): that group's tools with one-line summaries.
        An unrecognised protocol returns matching tools as `suggestions` (a wrong guess
        redirects instead of dead-ending). Then search with nxc_find_tool and run with nxc_call.
        """
        if protocol:
            proto = protocol.strip().lower()
            tools = [{"name": e.name, "summary": e.summary}
                     for e in by_protocol.get(proto, [])]
            out = {"protocol": proto, "count": len(tools), "tools": tools}
            if not tools:
                # Unknown/empty protocol: DON'T dead-end. A model reads "count 0" as
                # "unsupported" -- the opencode/qwen14b asrep failure: it searched
                # protocol="kerberos", saw an empty catalog, and wrongly concluded Kerberos
                # was unsupported -- even though ldap_asreproast was already the #1 find_tool
                # hit. Redirect: surface the tools that MATCH the bogus name as suggestions.
                valid = ", ".join(sorted(by_protocol))
                sugg = search([e for e in index if e.kind == "tool"], proto, limit=5)
                if sugg:
                    out["suggestions"] = [{"name": s.name, "summary": s.summary} for s in sugg]
                    out["note"] = (
                        f"{proto!r} is not a protocol group here (valid: {valid}). But tools "
                        f"matching {proto!r} DO exist -- see `suggestions` (top: {sugg[0].name}). "
                        f"Run one with nxc_call or refine with nxc_find_tool; do NOT conclude "
                        f"the capability is unsupported.")
                else:
                    out["note"] = f"no tools for {proto!r}. Valid protocols: {valid}."
            return out
        protocols = [{"protocol": p, "tool_count": len(es)}
                     for p, es in sorted(by_protocol.items())]
        return {
            "protocols": protocols,
            "total": sum(len(es) for es in by_protocol.values()),   # tool-kind only (not modules)
            "hint": "nxc_find_tool(query=...) to search, then nxc_call(name, arguments) to run.",
        }

    @mcp.tool()
    async def nxc_find_tool(query: str, protocol: str | None = None, limit: int = 8) -> dict:
        """Search for a tool by keyword (dynamic-mode discovery).

        Case-insensitive, ranked match over tool name, summary and description. The top
        match carries a ready-to-run `suggested_call` -- once you see the right tool, run
        it with nxc_call rather than searching again. For a match's full parameter schema
        use nxc_describe_tool. Search narrowly (e.g. "dump sam", "kerberoast", "smb
        shares"). `protocol` (smb/ldap/mssql/...) is a soft hint that boosts that group;
        it is NOT a filter, so cross-protocol matches still surface (e.g. roasting lives
        under `ldap`, not "kerberos") -- an invalid protocol is noted. If your query names a
        specific nxc `-M` module (not a curated tool), a `module_hint` points at
        nxc_run_module / nxc_search_tools.
        """
        scored = search_scored(index, query, protocol, limit)
        matches = [e for _, e in scored]
        views = [_match_view(e, common_optional) for e in matches]
        out = {"query": query, "count": len(matches), "matches": views}
        note = None
        if protocol and protocol.strip().lower() not in by_protocol:
            note = (f"{protocol.strip().lower()!r} is not a valid protocol (valid: "
                    f"{', '.join(sorted(by_protocol))}); ranked across all protocols instead.")
        if not matches:
            out["note"] = (f"no tool matched {query!r}; browse with nxc_catalog() or rephrase "
                           f"to a capability (e.g. 'dump sam', 'kerberoast', 'shares').")
            out["module_hint"] = _MODULE_HINT     # nothing curated matched -> maybe an -M module
            return out
        # Hand the model a concrete next action so it commits instead of re-searching --
        # the failure mode that makes small models loop (validated: eliminates loop-deaths,
        # lifts small-model completion; see docs/dynamic-mode.md).
        top = matches[0]
        lit, exp = _confidence_tokens(query, protocol)
        tokens = lit
        hits, strong = _token_hits(top, lit + exp)   # count synonym hits, not just literals
        # LOW CONFIDENCE: a real multi-term query whose top match caught only one term, or caught
        # it only as a weak substring (the `inter`->`interfaces` false-positive that buried
        # raisechild). Don't sell it as the answer.
        low_conf = (len(tokens) >= 2 and hits <= 1) or (hits >= 1 and strong == 0)
        views[0]["suggested_call"] = _suggested_call(top)
        if top.kind == "module":
            # A module topped: the concrete nxc_run_module call (protocol pre-filled) beats the
            # generic hint -- this is the raisechild path, now routed correctly.
            out["hint"] = (f"Top match is the nxc -M module {top.name!r} (protocol "
                           f"{top.protocol!r}). Run it with the match's suggested_call: "
                           f"nxc_call(name='nxc_run_module', arguments={{...}}).")
        elif low_conf:
            out["low_confidence"] = True
            out["hint"] = (f"WEAK match: only ~{hits} of {len(tokens)} query terms hit "
                           f"{top.name!r}, so it may be the wrong tool. Browse with nxc_catalog(), "
                           f"or for a specific technique try an nxc -M module.")
            out["module_hint"] = _MODULE_HINT
        else:
            out["hint"] = (f"To run the top match: nxc_call(name={top.name!r}, arguments={{...}}) "
                           f"-- fill in targets{_auth_hint(top)}. Don't search again for the same thing.")
        # Absolute-weak score or a module meta-tool on top also routes to the module path.
        if (scored[0][0] < _WEAK_MATCH_SCORE or top.name in _MODULE_META) and "module_hint" not in out:
            out["module_hint"] = _MODULE_HINT
        # Query asks for a capability nxc does not implement -> say so, don't let it grab a near tool.
        cap_note = _capability_note(tokens)
        if cap_note:
            out["capability_note"] = cap_note
        nq = _norm_query(query)
        if nq in searched:      # same intent searched twice -> nudge harder toward committing
            note = (f"You already searched this. Stop searching -- call "
                    f"nxc_call(name={top.name!r}, arguments={{...}}) now, or nxc_catalog() to browse.")
        searched.add(nq)
        if note:
            out["note"] = note
        return out

    @mcp.tool()
    async def nxc_describe_tool(name: str) -> dict:
        """Return the full parameter schema + docstring for one tool by name.

        Use when nxc_find_tool's compact signature isn't enough -- e.g. to see every
        authentication option (Kerberos aes_key, LAPS, certificate params).
        """
        e = by_name.get(name)
        if e is None:
            m = by_module.get(name)
            if m is not None:
                # An nxc -M module: no first-class schema; it runs via nxc_run_module.
                return {
                    "name": m.name,
                    "protocol": m.protocol,
                    "kind": "module",
                    "description": m.description,
                    "run_via": "nxc_run_module",
                    "suggested_call": _suggested_call(m),
                }
            return {"error": f"unknown tool {name!r}",
                    **_capability_suggest(name, index, by_protocol)}
        props = (e.parameters or {}).get("properties", {})

        def _t(p):
            sch = props.get(p, {})
            d = sch.get("default") if isinstance(sch, dict) else None
            return _typestr(sch) + (f"={d}" if d not in (None, False, "") else "")
        return {
            "name": e.name,
            "protocol": e.protocol,
            "description": e.description,
            "required": {p: _t(p) for p in e.required},
            "optional": {p: _t(p) for p in props if p not in set(e.required)},
        }

    @mcp.tool()
    async def nxc_call(
        name: str,
        arguments: Annotated[dict | None, Field(description=(
            "The tool's own params (see its signature). Kerberos/certificate auth also goes here: "
            "kerberos, use_kcache, ccache, aes_key, kdc_host, pfx_cert, pfx_base64, pfx_pass, "
            "pem_cert, pem_key, cred_id."))] = None,
        targets: list | str | None = None, username: str | None = None,
        password: str | None = None, domain: str | None = None,
        ntlm_hash: Annotated[str | None, Field(description=(
            "NT hash for pass-the-hash, instead of password."))] = None,
        local_auth: Annotated[bool | None, Field(description=(
            "true = log in as a LOCAL account of the target (e.g. its local Administrator), "
            "not a domain account; leave domain unset."))] = None,
    ) -> dict:
        """Run a tool by name with the given arguments (dynamic-mode dispatch).

        `name` is a tool from nxc_find_tool/nxc_catalog; `arguments` is a dict keyed by
        that tool's parameter names (see nxc_describe_tool). The common params
        `targets`/`username`/`password`/`ntlm_hash`/`domain`/`local_auth` may ALSO be passed at
        the top level (folded into `arguments` when the tool takes them; an explicit `arguments`
        entry wins). Every OTHER tool parameter goes inside `arguments`. Returns the tool's result; the recon/loot/full gate still applies.
        """
        # Fold first-class top-level params into `arguments` (explicit arguments entry wins).
        # Only params the target tool ACCEPTS are folded: a top-level local_auth on an ldap tool,
        # or username on smb_spray, would otherwise turn into an "unexpected keyword" error round
        # trip. A truthy one the tool cannot take is reported in `auth_note`; None/"" are ignored
        # (clients mangle empty strings; auth.py adds -p '' itself for a username-only bind).
        arguments = dict(arguments) if isinstance(arguments, dict) else {}
        _accepts = (set(((by_name[name].parameters or {}).get("properties") or {}))
                    if name in by_name else None)
        # `arguments` nested in `arguments`: no tool takes an `arguments` param, so lift the inner
        # dict, its entries winning as an explicit `arguments` entry wins over a top-level one.
        # Left nested, the missing-args answer never broke the loop: 13 calls in 2 runs of the
        # 2026-11-04 bench reference, both ended at the step limit.
        nested = (isinstance(arguments.get("arguments"), dict) and _accepts is not None
                  and "arguments" not in _accepts)
        if nested:
            inner = arguments.pop("arguments")
            arguments = {**arguments, **inner}
        _auth_notes = []
        for _k, _v in (("targets", targets), ("username", username),
                       ("password", password), ("domain", domain),
                       ("ntlm_hash", ntlm_hash), ("local_auth", local_auth)):
            if _v is None or _v == "" or _k in arguments:
                continue
            if _accepts is not None and _k not in _accepts:
                if _v:
                    _auth_notes.append(f"{_k} ignored: {name} does not take it")
                continue
            arguments[_k] = _v
        # local_auth + domain is refused by auth.py; a local login has no domain, so drop it.
        if arguments.get("local_auth") is True and arguments.get("domain"):
            _auth_notes.append(f"domain {arguments.pop('domain')!r} ignored: local_auth=true logs in "
                               "as a local account")
        if name not in by_name:
            # The recurring small-model failure is GUESSING a tool name (smb_login,
            # smb_ms17_010, winrm_whoami), hitting this, and giving up. Catch it at the
            # point of failure with ONE clear next step: search, don't invent -- plus the
            # module path and the auth-check idiom (verifying a credential = running any
            # tool with it; the [+] marker means it authenticated -- there is no 'login' tool).
            return {
                "error": f"unknown tool {name!r}",
                **_capability_suggest(name, index, by_protocol),
                "hint": ('Do not invent tool names. Discover the right tool with '
                         'nxc_find_tool("<capability>") (e.g. "check credentials", "dump ntds", '
                         '"shares"), then nxc_call it. To VERIFY a credential, just run an smb '
                         'tool (e.g. smb_enum_hosts) with it -- a [+] result means it is valid. '
                         'For a specific nxc -M module (ms17-010, spooler...), use '
                         'nxc_run_module(module="<name>", targets=[...]).'),
            }
        entry = by_name[name]
        missing = [
            p for p in entry.required
            if p not in arguments or arguments[p] in (None, "", [])
        ]
        if missing:
            key = (name, tuple(missing))
            arg_fail["n"] = arg_fail["n"] + 1 if arg_fail["key"] == key else 1
            arg_fail["key"] = key
            if arg_fail["n"] >= 2:
                # Same miss re-sent -> break the superstition loop with a terse imperative
                # (the model got the full signature on the first miss; repeating it doesn't help).
                return {
                    "error": f"missing required argument(s) for {name!r}: {', '.join(missing)}",
                    "missing": missing,
                    "suggested_call": _suggested_call(entry),
                    "repeat": arg_fail["n"],
                    "hint": (f"Same error {arg_fail['n']}x. Copy `suggested_call` EXACTLY, fill its "
                             "values, and send THAT -- stop re-sending the same shape."),
                }
            # First miss: the recurring small-model failure is calling nxc_call with only a name
            # (or dropping `targets`/creds), then looping. Hand back the concrete call to make.
            return {
                "error": f"missing required argument(s) for {name!r}: {', '.join(missing)}",
                "missing": missing,
                "signature": _signature(entry),
                "suggested_call": _suggested_call(entry),
                "hint": ('Fill EVERY required param. The common ones (targets/username/password/'
                         'ntlm_hash/domain/local_auth) may be passed at the top level of nxc_call OR '
                         'inside `arguments`; '
                         'every other param goes inside `arguments`. `targets` takes the whole scope '
                         'in one call (IP, CIDR 10.0.0.0/24, range, or hostname). Nothing is '
                         'remembered between calls, so pass creds again each time.'),
            }
        arg_fail["key"] = None            # args complete -> clear any missing-args streak
        # Coerce a bare scalar into a 1-element list for list[str] params (targets='x' -> ['x']),
        # the single most common ValidationError, before it ever reaches pydantic.
        _props = (entry.parameters or {}).get("properties", {})
        for _p, _v in list(arguments.items()):
            if isinstance(_v, str) and _is_list_param(_props.get(_p)):
                arguments[_p] = [_v]
        folded = _folded_args.get()

        def _out(d):
            # The model view (stdout cap, key order) is applied by server.ModelViewMiddleware,
            # on the inner tool call and again on this nxc_call result -- not here.
            if _auth_notes and isinstance(d, dict):
                d = {**d, "auth_note": "; ".join(_auth_notes)}
            if nested and isinstance(d, dict) and "_note" not in d:
                d = {**d, "_note": ("`arguments` was nested inside `arguments` and was unwrapped. "
                                    "Next time put the tool's parameters directly in `arguments`.")}
            # If the middleware un-flattened this call, hint the model to nest next time.
            if folded and isinstance(d, dict) and "_note" not in d:
                return {**d, "_note": (
                    f"{', '.join(folded)} was passed at the top level of nxc_call and "
                    "auto-folded into `arguments`. Next time nest ALL tool parameters inside "
                    "`arguments`.")}
            return d

        # A repeat of an identical call is always re-dispatched: the server cannot tell a loop
        # from a re-check after a state change or a client that lost the first result.
        try:
            result = await mcp.call_tool(name, arguments or {})
        except ToolError as exc:
            # Tool-level failure incl. guardrail blocks (execute() raises, which FastMCP
            # surfaces as a ToolError carrying the original message) and arg-validation
            # errors -- a validation error is reshaped into the actionable missing-args form;
            # anything else is returned verbatim so the model can adjust rather than crash.
            return _out(_reformat_validation(str(exc), entry) or {"error": str(exc), "tool": name})
        except Exception as exc:  # noqa: BLE001 -- never let a dispatch failure kill the turn
            return _out(_reformat_validation(str(exc), entry)
                        or {"error": f"{type(exc).__name__}: {exc}", "tool": name})
        if result.structured_content is not None:
            return _out(result.structured_content)
        text = "\n".join(getattr(c, "text", "") for c in (result.content or []))
        return _out({"result": text})


class DynamicModeMiddleware(Middleware):
    """Hide all but the meta-tools from ``tools/list``.

    Hidden tools stay registered and callable via ``mcp.call_tool`` (how ``nxc_call``
    reaches them) -- this only changes what the client is offered, not what exists.
    """

    def __init__(self, visible=DYNAMIC_VISIBLE):
        self.visible = frozenset(visible)

    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        return [t for t in tools if t.name in self.visible]
