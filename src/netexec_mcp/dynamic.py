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

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

from .executor import _folded_args

# Tools that stay visible in dynamic mode: the meta-tools + the health check.
DYNAMIC_VISIBLE = frozenset(
    {"nxc_catalog", "nxc_find_tool", "nxc_describe_tool", "nxc_call", "nxc_health"}
)

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
    "ALL of the tool's parameters go INSIDE the `arguments` object -- NEVER at the top level "
    "of nxc_call. nxc_call(name=\"smb_get_file\", share=\"all\") is WRONG; write "
    "nxc_call(name=\"smb_get_file\", arguments={\"share\": \"all\", \"targets\": [...]}).\n"
    "Search ONCE per capability: the top match carries a `suggested_call` -- fill in its "
    "arguments and call nxc_call; do NOT re-search the same thing.\n"
    "`targets` accepts an IP, a CIDR (10.0.0.0/24), an nxc range (10.0.0.1-20), or a hostname "
    "-- a CIDR/range scans every host in it, so pass the whole scope at once instead of asking "
    "for individual IPs.\n"
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


def _protocol_of(name: str) -> str:
    head = name.split("_", 1)[0]
    return head if head in _KNOWN_PREFIXES else "other"


def _summary(description: str | None) -> str:
    for line in (description or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def build_index(tools) -> list[ToolEntry]:
    """Build the searchable catalog from a snapshot of registered tools.

    Must be called on the *full* tool list -- i.e. before the hiding middleware is
    installed, since the middleware also filters the server's own ``list_tools``.
    The meta-tools themselves are skipped (they are always visible, not findable
    dispatch targets).
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
}


def _expand(query_lower: str) -> list[str]:
    extra: list[str] = []
    for key, toks in _SYNONYMS.items():
        if key in query_lower:
            extra.extend(toks)
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


def _words(text: str) -> set[str]:
    """Word set of a string; hyphen is a SEPARATOR here (who-is-admin -> {who,is,admin})."""
    return set(_WORD_RE.findall((text or "").lower()))


def _part_match(tok: str, parts: set[str]) -> bool:
    """token vs a name/summary word set, tolerant to plural/prefix. Handles both plurals
    (share ~ shares, database ~ databases) and short abbreviations against the real
    3-char tool-name stems (rid ~ rids, lsa ~ lsass). Min 3 chars so 1-2 char tokens
    ("a", "id") stay exact-only and don't over-match."""
    if tok in parts:
        return True
    if len(tok) >= 3:
        for p in parts:
            if len(p) >= 3 and (tok.startswith(p) or p.startswith(tok)):
                return True
    return False


def _stem_token(tok: str) -> str:
    """Fold a query word to a canonical stem so it prefix-matches the short tool name-parts.

    Currently just the ADMIN family: a query says "administrative access" / "administrator"
    (EN) or "administrateur" / "administratif" (FR), but the name-parts are the short stems
    "admin" / "admins". `_part_match` bridges admin<->admins (prefix), but NOT the longer
    variants ("administrative" is not a prefix of "admins", nor vice-versa), so they scored
    far too low against `workspace_admins` / `*_admin_*` and the admin reader was invisible.
    Folding any admin* token to "admin" lets it prefix-match every admin name-part at full
    weight. (Real Cline+qwen14b miss: "which hosts have administrative access, with which
    account" surfaced host-inventory tools, never `workspace_admins`.)"""
    return "admin" if tok.startswith("admin") else tok


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


def search_scored(index, query: str, protocol: str | None = None,
                  limit: int = 8) -> list[tuple[float, ToolEntry]]:
    """Ranked ``(score, entry)`` pairs -- the scoring core of :func:`search`. Exposing the
    score lets callers gauge match strength (e.g. a weak/zero top score -> suggest the nxc
    module long-tail rather than let the model give up)."""
    proto = protocol.strip().lower() if protocol else None
    q_join = (query or "").lower().replace("-", "")   # for synonym detection (as-rep -> asrep)
    raw = _WORD_RE.findall((query or "").lower())
    tokens = [t for t in raw if t not in _STOPWORDS] or raw   # keep raw if all-stopword
    tokens = [_stem_token(t) for t in tokens]                 # fold admin* -> admin, etc.
    expanded = list(dict.fromkeys(e for e in _expand(q_join) if e not in tokens))
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
    scored.sort(key=lambda se: (-se[0], se[1].name))
    return scored[: max(1, limit)]


def search(index, query: str, protocol: str | None = None, limit: int = 8) -> list[ToolEntry]:
    """Rank the catalog for a query.

    `protocol` is a SOFT BOOST, not a filter: a matching-protocol tool ranks higher, but
    tools in other protocols still compete -- so a wrong/absent protocol hint can't hide
    the right tool. The one exception: an *empty* query with a protocol lists that group
    (browse mode). Stopwords/intent-verbs are dropped; hyphens are normalised so
    "as-rep" reaches "asreproast"; intent synonyms are expanded and de-duped.
    """
    return [e for _, e in search_scored(index, query, protocol, limit)]


# Module long-tail: nxc's `-M` modules aren't curated tools, so nxc_find_tool won't surface a
# named one (e.g. ms17-010). When a search finds no confident tool -- zero/weak match, or the
# module meta-tools themselves top the list -- point the model at the module path so it doesn't
# give up or grab a wrong tool (bughunt/qwen: "run the ms17-010 module" -> gave up / coerce).
_MODULE_META = frozenset({"nxc_list_modules", "nxc_search_tools", "nxc_run_module"})
_WEAK_MATCH_SCORE = 20.0     # below the lowest legit tool score (~30 for "check antivirus")
_MODULE_HINT = (
    'For a specific nxc `-M` module (e.g. ms17-010, spooler, petitpotam) rather than a curated '
    'tool: run it with nxc_run_module(module="<name>", targets=[...]), or find one with '
    'nxc_search_tools("<keyword>") / nxc_list_modules(). nxc_find_tool searches only the curated '
    'first-class tools, so a bare module name won\'t match here.'
)


def _suggest(name: str, names, n: int = 5) -> list[str]:
    return difflib.get_close_matches(name, list(names), n=n, cutoff=0.4)


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


def _signature(entry: ToolEntry) -> dict:
    """Compact call signature: required params WITH types, optional param names.

    Types go on required only (usually 1-3 params) so the model gets the call right
    first try, while keeping the payload small -- the full schema (incl. every optional
    auth param's type) is one nxc_describe_tool away.
    """
    props = (entry.parameters or {}).get("properties", {})
    req_set = set(entry.required)
    return {
        "required": {p: _typestr(props.get(p, {})) for p in entry.required},
        "optional": [p for p in props if p not in req_set],
    }


def _match_view(entry: ToolEntry) -> dict:
    return {
        "name": entry.name,
        "protocol": entry.protocol,
        "summary": entry.summary,
        "signature": _signature(entry),
    }


def _norm_query(query: str) -> str:
    """Normalise a query to its sorted word set, so 'dump ntds' == 'ntds dump'. The
    loop-breaker keys on this to spot a model re-phrasing the same intent."""
    return " ".join(sorted(_WORD_RE.findall((query or "").lower())))


def _suggested_call(entry: ToolEntry) -> dict:
    """A ready-to-run call skeleton for the top match: the tool name + its required params
    as typed placeholders. Handing the model a concrete next call (rather than a list to
    re-search) is what stops small models looping on discovery -- see docs/dynamic-mode.md."""
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
    by_name = {e.name: e for e in index}
    by_protocol: dict[str, list[ToolEntry]] = {}
    for e in index:
        by_protocol.setdefault(e.protocol, []).append(e)
    # Loop-breaker state: normalised queries searched this session. Small models tend to
    # re-phrase the same intent (`dump ntds` -> `ntds dump`) instead of committing to a
    # call; on a repeat we nudge them to run the top match. Per-process = per-session.
    searched: set[str] = set()

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
                sugg = search(index, proto, limit=5)
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
            "total": len(index),
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
        views = [_match_view(e) for e in matches]
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
        views[0]["suggested_call"] = _suggested_call(top)
        out["hint"] = (f"To run the top match: nxc_call(name={top.name!r}, arguments={{...}}) "
                       f"-- fill in targets and any auth. Don't search again for the same thing.")
        # Weak top match, or the module meta-tools themselves surfaced => the caller probably
        # wants an nxc -M module rather than a curated tool. Point at the module path.
        if scored[0][0] < _WEAK_MATCH_SCORE or top.name in _MODULE_META:
            out["module_hint"] = _MODULE_HINT
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
            return {"error": f"unknown tool {name!r}", "suggestions": _suggest(name, by_name)}
        return {
            "name": e.name,
            "protocol": e.protocol,
            "description": e.description,
            "input_schema": e.parameters,
        }

    @mcp.tool()
    async def nxc_call(name: str, arguments: dict | None = None) -> dict:
        """Run a tool by name with the given arguments (dynamic-mode dispatch).

        `name` is a tool from nxc_find_tool/nxc_catalog; `arguments` is a dict keyed by
        that tool's parameter names (see nxc_describe_tool). Returns the tool's result.
        The recon/loot/full permission gate still applies: a blocked action returns an
        `error` explaining which NXC_MODE would permit it.
        """
        if name not in by_name:
            # The recurring small-model failure is GUESSING a tool name (smb_login,
            # smb_ms17_010, winrm_whoami), hitting this, and giving up. Catch it at the
            # point of failure with ONE clear next step: search, don't invent -- plus the
            # module path and the auth-check idiom (verifying a credential = running any
            # tool with it; the [+] marker means it authenticated -- there is no 'login' tool).
            return {
                "error": f"unknown tool {name!r}",
                "suggestions": _suggest(name, by_name),
                "hint": ('Do not invent tool names. Discover the right tool with '
                         'nxc_find_tool("<capability>") (e.g. "check credentials", "dump ntds", '
                         '"shares"), then nxc_call it. To VERIFY a credential, just run an smb '
                         'tool (e.g. smb_enum_hosts) with it -- a [+] result means it is valid. '
                         'For a specific nxc -M module (ms17-010, spooler...), use '
                         'nxc_run_module(module="<name>", targets=[...]).'),
            }
        entry = by_name[name]
        provided = arguments or {}
        missing = [
            p for p in entry.required
            if p not in provided or provided[p] in (None, "", [])
        ]
        if missing:
            # The recurring small-model failure is calling nxc_call with only a name (or
            # dropping `targets`/credentials), then looping on the raw validation error.
            # Catch it at the point of failure with the concrete call to make: the missing
            # params, the signature, and a ready-to-fill skeleton -- same treatment as the
            # unknown-tool case above.
            return {
                "error": f"missing required argument(s) for {name!r}: {', '.join(missing)}",
                "missing": missing,
                "signature": _signature(entry),
                "suggested_call": _suggested_call(entry),
                "hint": ('Call nxc_call with an `arguments` object that fills EVERY required '
                         'param -- never just the name. `targets` takes the whole scope in one '
                         'call (an IP, a CIDR like 10.0.0.0/24, a range, or a hostname). Reuse the '
                         'same targets and any username/password/domain from your previous calls '
                         '-- nothing is remembered between calls, so pass them again each time.'),
            }
        folded = _folded_args.get()

        def _out(d):
            # If the middleware un-flattened this call, hint the model to nest next time.
            if folded and isinstance(d, dict) and "_note" not in d:
                return {**d, "_note": (
                    f"{', '.join(folded)} was passed at the top level of nxc_call and "
                    "auto-folded into `arguments`. Next time nest ALL tool parameters inside "
                    "`arguments`.")}
            return d

        try:
            result = await mcp.call_tool(name, arguments or {})
        except ToolError as exc:
            # Tool-level failure incl. guardrail blocks (execute() raises, which FastMCP
            # surfaces as a ToolError carrying the original message) and arg-validation
            # errors -- return it so the model can adjust rather than crash the turn.
            return _out({"error": str(exc), "tool": name})
        except Exception as exc:  # noqa: BLE001 -- never let a dispatch failure kill the turn
            return _out({"error": f"{type(exc).__name__}: {exc}", "tool": name})
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
