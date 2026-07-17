"""Command building and execution.

This is the execution layer that everything else sits on:

  * `build_command()` assembles a full nxc argv (never via a shell).
  * `run_async()` runs it with a hard timeout, capturing ANSI-stripped output.
  * `execute()` ties config + build + run + marker-parsing together, and honours
    suggest mode (`NXC_MODE=suggest`) by returning the resolved command without
    executing it.

`run()` (synchronous) and `parse_version()` remain for the boot health check.
"""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import os
import re
import shlex
import socket
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field

from .config import Config
from .guardrails import (
    GuardrailError,
    OffensiveBlocked,
    check_offensive,
    check_scope,
    check_target_cap,
    parse_scope,
    write_audit,
)
from .results import StatusRecord, parse_markers

# Matches CSI / SGR escape sequences such as the colour codes nxc emits.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION_RE = re.compile(r"\b(\d+\.\d+\.\d+)\b")

# Lines emitted by the *runner* (uv/pip), not by nxc -- pure noise on every call
# when nxc is invoked via `uv run` against an editable checkout. We drop these
# from captured stderr so results aren't cluttered; genuine nxc stderr is kept.
_RUNNER_NOISE_RE = re.compile(
    r"^(?:"
    r"warning:\s+.*VIRTUAL_ENV.*"                       # uv venv-mismatch warning
    r"|(?:Building|Built)\s+.+@\s+file://.*"            # uv editable (re)build
    r"|(?:Uninstalled|Installed|Audited|Resolved|Prepared|Downloaded)\s+\d+\s+packages?.*"
    r")$"
)


# Name of the MCP tool currently executing, set by the audit middleware (server.py) around
# each tool call. Recorded in the audit log so every command is attributable to the tool
# that issued it -- the crash-proof way to know the real trajectory (a mid-run crash wipes
# the LLM history, but the audit survives; in dynamic mode the inner dispatch re-enters the
# middleware so this resolves the real tool, not `nxc_call`). None when unset (e.g. tests).
_current_tool: contextvars.ContextVar = contextvars.ContextVar("nxc_current_tool", default=None)


def set_current_tool(name):
    """Set the current tool name; returns a token to pass to reset_current_tool()."""
    return _current_tool.set(name)


def reset_current_tool(token) -> None:
    _current_tool.reset(token)


# Set by the dynamic-mode middleware when it folds a *flattened* nxc_call (tool params passed
# at the top level instead of under `arguments`) back into place. Recorded in the audit so the
# benchmark can count how often a model flattens. None when no fold happened.
_folded_args: contextvars.ContextVar = contextvars.ContextVar("nxc_folded_args", default=None)


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def filter_runner_noise(text: str) -> str:
    """Drop uv/pip runner chatter from captured stderr, keeping real nxc output."""
    kept = [ln for ln in text.splitlines() if not _RUNNER_NOISE_RE.match(ln.strip())]
    return "\n".join(kept)


def parse_version(text: str) -> str | None:
    """Pull the first semver-looking token out of nxc's --version output."""
    match = _VERSION_RE.search(text or "")
    return match.group(1) if match else None


def build_command(
    base_command: list[str],
    protocol: str,
    targets: list[str] | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Assemble an nxc argv: `<base> <protocol> <targets...> <extra_args...>`.

    All pieces are plain argv tokens -- callers pass pre-resolved flags in
    `extra_args` (e.g. ['-u', 'admin', '--shares']); nothing is shell-interpreted.
    """
    if not protocol or not protocol.strip():
        raise ValueError("protocol is required to build an nxc command")
    return [
        *base_command,
        protocol.strip(),
        *(targets or []),
        *(extra_args or []),
    ]


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def run(argv: list[str], timeout: int) -> CommandResult:
    """Synchronous runner (no shell). Used by the boot health check.

    Raises FileNotFoundError if the executable itself is missing.
    """
    # stdin=DEVNULL: never let the child inherit the parent's stdin. Under the
    # stdio MCP transport that stdin is the JSON-RPC pipe; on Windows an inherited
    # pipe handle makes `nxc --version` hang until the timeout (observed: 300s).
    # The MCP always passes targets/creds via argv, so nxc never needs stdin.
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL
    )
    return CommandResult(
        argv=list(argv),
        returncode=proc.returncode,
        stdout=strip_ansi(proc.stdout),
        stderr=filter_runner_noise(strip_ansi(proc.stderr)),
    )


async def run_async(argv: list[str], timeout: int, env: dict | None = None) -> CommandResult:
    """Async runner (no shell) with a hard timeout.

    On timeout the process is killed and whatever output was produced is returned
    with `timed_out=True` and `returncode=None`. Raises FileNotFoundError if the
    executable is missing. `env` (if given) is merged over the inherited environment
    for this subprocess only (e.g. KRB5CCNAME for a per-call ccache).
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        # See run(): don't inherit the MCP's JSON-RPC stdin pipe (hangs nxc on Windows).
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=None if env is None else {**os.environ, **env},
    )
    timed_out = False
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        out, err = await proc.communicate()

    return CommandResult(
        argv=list(argv),
        returncode=None if timed_out else proc.returncode,
        stdout=strip_ansi(out.decode(errors="replace")),
        stderr=filter_runner_noise(strip_ansi(err.decode(errors="replace"))),
        timed_out=timed_out,
    )


@dataclass
class ExecOutcome:
    command: list[str]
    resolved: str          # shell-quoted, for display / audit only
    dry_run: bool
    returncode: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    records: list[StatusRecord] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    # Set (instead of running) when a named account was given with no secret but nxc already
    # holds a reusable credential for it in this protocol's DB -- see execute()'s auth-nudge.
    auth_suggestion: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# --- auth nudge ---------------------------------------------------------------
# Flags that supply a secret / alternate auth path; their presence means the caller already
# has a way to authenticate, so there is nothing to nudge about.
_SECRET_FLAGS = frozenset({"-H", "-id", "-k", "--use-kcache", "--aesKey", "--pfx-cert",
                           "--pfx-base64", "--pfx-pass", "--pem-cert", "--pem-key", "--laps"})


def _guest_bind_user(argv: list[str]) -> str | None:
    """If `argv` is a single named account with NO secret -- the auto guest/null bind
    (`-u <user> -p ''`, nothing else) -- return that username; else None. Multiple users
    (spray), any non-empty `-p`, any secret flag, or a guest/anonymous name -> None."""
    users: list[str] = []
    nonempty_pw = saw_secret_flag = False
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "-u" and i + 1 < len(argv):
            users.append(argv[i + 1]); i += 2; continue
        if tok == "-p" and i + 1 < len(argv):
            nonempty_pw = nonempty_pw or bool(argv[i + 1])
            i += 2; continue
        if tok in _SECRET_FLAGS:
            saw_secret_flag = True
        i += 1
    if len(users) != 1 or nonempty_pw or saw_secret_flag:
        return None
    user = users[0]
    return None if user.lower() in ("", "guest", "anonymous") else user


def _cred_retry_params(cred: dict) -> dict:
    """A stored cred -> the exact tool args to re-authenticate as it (password vs hash)."""
    params = {"username": cred["username"]}
    if cred.get("domain"):
        params["domain"] = cred["domain"]
    if cred.get("credtype") == "hash":
        params["ntlm_hash"] = cred["secret"]
    else:
        params["password"] = cred["secret"]
    return params


def _resolve_host(hostname: str) -> list:
    """Resolve a hostname to IP address(es) via the OS resolver -- the SAME one nxc uses on
    this box -- so a hostname target can be scope-checked against the address it will actually
    connect to. Returns [] when it does not resolve (the caller then treats it as out of
    scope). We do not rewrite the target: nxc still receives the hostname (so Kerberos SPNs
    etc. keep working); we only resolve to VERIFY scope."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (OSError, UnicodeError):
        return []
    out: list = []
    for *_, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0].split("%")[0])   # strip IPv6 zone id
        except (ValueError, IndexError):
            continue
        if ip not in out:
            out.append(ip)
    return out


def _auth_suggestion(config: Config, protocol: str, argv: list[str]) -> dict | None:
    """If a named account was passed with no secret but nxc already stored a credential for
    it in THIS protocol's DB, build a suggestion to retry with that credential rather than a
    doomed guest bind. Reading the workspace DB is a local file read (no target contact), so
    it is not mode-gated. Returns None (run as usual) when nothing matches."""
    user = _guest_bind_user(argv)
    if not user:
        return None
    from .modules import workspace          # local import: avoid an import cycle at load
    matches = workspace.match_stored_cred(config, protocol, user)
    if not matches:
        return None
    return {
        "reason": (f"'{user}' was given without a secret (a guest/null bind, which fails for a "
                   f"real account). nxc already stored {len(matches)} credential(s) for it in the "
                   f"{protocol} workspace DB -- retry with one of `retry_with`."),
        "retry_with": [_cred_retry_params(m) for m in matches],
        "note": (f"these are for {protocol} tools; a `cred_id` is per-protocol, so retry with the "
                 f"username + secret shown here, not an id from another protocol."),
    }


async def execute(
    config: Config,
    protocol: str,
    targets: list[str] | None = None,
    extra_args: list[str] | None = None,
    *,
    offensive: bool = False,
    dump: bool = False,
    ccache: str | None = None,
) -> ExecOutcome:
    """Build, guard, and (unless dry-run) run an nxc command, parsing markers.

    Guardrails are enforced here -- the single choke point every tool funnels
    through -- so scope/offensive/cap checks cannot be bypassed. Every command
    (executed, dry-run, or rejected) is written to the audit log. `ccache`, if given,
    sets KRB5CCNAME for the subprocess so `--use-kcache` reads that specific ticket
    cache (nxc has no ccache flag; it is env-only).
    """
    targets = list(targets or [])
    argv = build_command(config.base_command, protocol, targets, extra_args)
    resolved = " ".join(shlex.quote(tok) for tok in argv)
    audit_base = {
        "command": argv,
        "resolved": resolved,
        # Which MCP tool issued this command (None if unknown). Lets consumers reconstruct
        # the real trajectory even when the LLM history is lost to a mid-run crash.
        "tool": _current_tool.get(),
        "protocol": protocol,
        "targets": targets,
        "offensive": offensive,
        # tier lets consumers (audit/benchmark) see the recon<loot<full classification.
        "tier": "recon" if not offensive else ("dump" if dump else "exploit"),
        "dry_run": config.dry_run,
    }
    folded = _folded_args.get()
    if folded:
        # This call reached here only after the dynamic middleware un-flattened it.
        audit_base["folded_args"] = folded

    try:
        check_target_cap(targets, config.max_targets)
        check_scope(targets, parse_scope(config.scope), resolve=_resolve_host)
        # In suggest mode (dry_run) nothing executes, so we still surface the
        # resolved command for an offensive action -- the auditor decides whether
        # to run it. The offensive gate only matters when we would actually run.
        if not config.dry_run:
            check_offensive(config.allow_offensive, offensive,
                            dump=dump, allow_loot=config.allow_loot)
    except OffensiveBlocked as exc:
        # Blocked ONLY by the mode gate (not scope/cap): surface the exact command we WOULD
        # run and the mode that permits it, so the auditor can run it by hand or flip
        # NXC_MODE -- the same "show the command" courtesy suggest mode already gives.
        # Nothing executes here.
        required = "loot" if dump else "full"
        write_audit(
            config.audit_log,
            {**audit_base, "outcome": "rejected", "reason": str(exc),
             "required_mode": required},
        )
        raise OffensiveBlocked(
            f"{exc}\n\nRequires NXC_MODE={required}. Command that WOULD run "
            f"(not executed): {resolved}"
        ) from exc
    except GuardrailError as exc:
        write_audit(
            config.audit_log,
            {**audit_base, "outcome": "rejected", "reason": str(exc)},
        )
        raise

    # Auth-nudge (pre-run): a named account with no secret would attempt a guest/null bind
    # that fails for a real account. If nxc already holds a credential for that account in
    # this protocol's DB, don't run the doomed bind -- hand the stored credential back so the
    # caller retries with real auth. A local DB read, so it applies in every mode.
    suggestion = _auth_suggestion(config, protocol, argv)
    if suggestion:
        write_audit(config.audit_log, {**audit_base, "outcome": "auth_suggestion"})
        return ExecOutcome(command=argv, resolved=resolved, dry_run=config.dry_run,
                           auth_suggestion=suggestion)

    if config.dry_run:
        write_audit(config.audit_log, {**audit_base, "outcome": "dry_run"})
        return ExecOutcome(command=argv, resolved=resolved, dry_run=True)

    env = {"KRB5CCNAME": os.path.expanduser(ccache)} if ccache else None
    result = await run_async(argv, config.timeout, env=env)
    records = parse_markers(result.stdout)
    counts = dict(Counter(r.status for r in records))
    write_audit(
        config.audit_log,
        {
            **audit_base,
            "outcome": "executed",
            "returncode": result.returncode,
            "timed_out": result.timed_out,
        },
    )
    return ExecOutcome(
        command=argv,
        resolved=resolved,
        dry_run=False,
        returncode=result.returncode,
        timed_out=result.timed_out,
        stdout=result.stdout,
        stderr=result.stderr,
        records=records,
        counts=counts,
    )
