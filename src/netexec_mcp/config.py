"""Environment resolution and NetExec base-command detection.

The base command is how this server invokes nxc. Resolution order (per PLAN.md):
  1. NXC_COMMAND env (shlex-parsed) if set -- covers uv/poetry/pipx/docker installs.
  2. else auto-detect `nxc` / `netexec` on PATH.
  3. else fail fast with setup help.
"""

from __future__ import annotations

import configparser
import os
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path

# All protocol-modules nxc supports that we expose as tool groups. Enabled subset
# is controlled by NXC_PROTOCOLS; default is all of them.
DEFAULT_PROTOCOLS = [
    "smb", "ldap", "winrm", "ssh", "mssql", "wmi", "rdp", "ftp", "nfs", "vnc",
]

# The single operating-mode control (NXC_MODE), with four escalating levels:
#   suggest -- return the resolved command, never execute (the auditor runs it).
#              Scope is still enforced; offensive commands *can* be previewed.
#   recon   -- execute read-only enumeration; everything beyond it is blocked. (default)
#   loot    -- also permit read-only *credential-dumping* (sam/lsa/ntds/gpp/roasting):
#              no state change on the target, but it harvests credential material.
#   full    -- execute everything, including state-changing / privilege-escalation
#              actions (exec, write, spray, coercion-with-listener, exploits).
# The recon<loot<full split mirrors nxc's own module taxonomy (ENUMERATION <
# CREDENTIAL_DUMPING < PRIVILEGE_ESCALATION).
VALID_MODES = ("suggest", "recon", "loot", "full")

# How the tool surface is presented (NXC_TOOL_MODE), independent of the operating
# mode above:
#   dynamic -- (DEFAULT) expose only a few meta-tools (catalog/find/describe/call);
#              the real tools stay registered + callable but are hidden from tools/list.
#              Keeps the ~46k-token tool surface out of the model's context window --
#              what makes the server usable on small-context models (and ~8x cheaper on
#              big ones, same quality). See dynamic.py. Benchmark: dynamic is net-positive
#              or neutral for 4/5 models tested and the ONLY viable mode for <=8B/32k.
#   static  -- register every enabled tool as a first-class MCP tool (opt-out). Best for
#              a decisive one-shot model, or to avoid discovery round-trips on a
#              big-context model. On a small context the ~46k surface overflows -> a
#              startup warning is emitted.
VALID_TOOL_MODES = ("static", "dynamic")


class ConfigError(RuntimeError):
    """Raised when the server cannot determine a valid configuration."""


def nxc_home() -> Path:
    """nxc's home dir, mirroring ``nxc/paths.py``: ``$NXC_PATH`` if set, else
    ``~/.nxc``. Identical on Linux/macOS/Windows -- nxc uses ``expanduser`` (no
    ``%APPDATA%``/appdirs), so ``~`` resolves to ``C:\\Users\\<user>`` on Windows.
    Honoring nxc's own env var keeps our reads aligned with wherever nxc writes.
    """
    override = os.environ.get("NXC_PATH")
    if override and override.strip():
        return Path(os.path.expanduser(override.strip()))
    return Path(os.path.expanduser("~/.nxc"))


def nxc_config_path() -> Path:
    """Path to ``nxc.conf`` under the resolved nxc home."""
    return nxc_home() / "nxc.conf"


def nxc_workspace_dir() -> Path:
    """The ``workspaces/`` dir (per-protocol ``.db`` files) under the nxc home."""
    return nxc_home() / "workspaces"


# nxc's own fallbacks when nxc.conf is absent or a key is unset.
_NXC_CONF_DEFAULTS = {"pwn3d_label": "Pwn3d!", "workspace": "default"}


def read_nxc_conf() -> dict:
    """Read the operator-configurable ``[nxc]`` ``pwn3d_label`` and ``workspace``.

    Both live in ``nxc.conf`` and can be changed by the operator, so we read them
    from that single source of truth instead of hardcoding. Falls back to nxc's
    own defaults when the file is missing/unreadable. ``pwn3d_label`` is preserved
    verbatim when the key exists (even if blank); a blank ``workspace`` collapses
    to ``default``.
    """
    parser = configparser.ConfigParser(interpolation=None)  # values may contain %
    try:
        with open(nxc_config_path(), encoding="utf-8") as fh:
            parser.read_file(fh)
    except (OSError, configparser.Error):
        return dict(_NXC_CONF_DEFAULTS)
    if not parser.has_section("nxc"):
        return dict(_NXC_CONF_DEFAULTS)
    section = parser["nxc"]
    label = section.get("pwn3d_label", _NXC_CONF_DEFAULTS["pwn3d_label"])
    workspace = (section.get("workspace") or "").strip() or _NXC_CONF_DEFAULTS["workspace"]
    return {"pwn3d_label": label, "workspace": workspace}


def _env_list(name: str) -> list[str]:
    """Parse a comma/newline-separated env var into a clean list of tokens."""
    raw = os.environ.get(name, "")
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


def resolve_base_command() -> list[str]:
    """Resolve the nxc base command as an argv list (never via a shell).

    Tokens are user-expanded so values like
    `uv run --directory ~/NetExec netexec` work as written.
    """
    explicit = os.environ.get("NXC_COMMAND")
    if explicit and explicit.strip():
        argv = [os.path.expanduser(tok) for tok in shlex.split(explicit)]
        if not argv:
            raise ConfigError("NXC_COMMAND is set but empty after parsing.")
        return argv

    for candidate in ("nxc", "netexec"):
        found = shutil.which(candidate)
        if found:
            return [found]

    raise ConfigError(
        "Could not find NetExec. Set NXC_COMMAND (e.g. "
        "\"uv run --directory ~/NetExec netexec\") or put 'nxc'/'netexec' on PATH."
    )


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer.") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be a positive integer.")
    return value


def _resolve_mode() -> tuple[str, bool, bool]:
    """Resolve the operating mode -> (mode, dry_run, allow_offensive).

    `NXC_MODE` (suggest|recon|full) is the canonical control; the `dry_run` and
    `allow_offensive` booleans are derived from it. Defaults to `recon` when unset.
    """
    raw = os.environ.get("NXC_MODE")
    mode = raw.strip().lower() if raw and raw.strip() else "recon"
    if mode not in VALID_MODES:
        raise ConfigError(
            f"NXC_MODE must be one of {', '.join(VALID_MODES)}; got {raw!r}."
        )
    return mode, mode == "suggest", mode == "full"


def _resolve_tool_mode() -> str:
    """Resolve NXC_TOOL_MODE (static|dynamic); defaults to dynamic (progressive disclosure
    -- usable on small-context models, cheaper on large ones; set static to opt out)."""
    raw = (os.environ.get("NXC_TOOL_MODE") or "dynamic").strip().lower()
    if raw not in VALID_TOOL_MODES:
        raise ConfigError(
            f"NXC_TOOL_MODE must be one of {', '.join(VALID_TOOL_MODES)}; got {raw!r}."
        )
    return raw


@dataclass(frozen=True)
class Config:
    base_command: list[str]
    protocols: list[str]
    scope: list[str]
    allow_offensive: bool
    dry_run: bool
    timeout: int
    max_targets: int
    audit_log: str | None
    workspace: str | None
    mode: str = "recon"
    # loot mode permits credential-dumping (offensive but read-only) on top of recon;
    # full implies loot. Derived from `mode` in from_env(); see check_offensive().
    allow_loot: bool = False
    # Tool-surface presentation (NXC_TOOL_MODE), orthogonal to `mode`. Default "dynamic"
    # hides the full tool surface behind meta-tools so small-context models can use the
    # server (see dynamic.py); "static" opts out to listing every tool.
    tool_mode: str = "dynamic"
    # From nxc.conf's `[nxc] pwn3d_label` (operator-configurable). Surfaced to the
    # agent via the auth guide; the MCP itself keys auth on the `[+]` marker, which
    # nxc does not make configurable.
    pwn3d_label: str = "Pwn3d!"

    @classmethod
    def from_env(cls) -> "Config":
        mode, dry_run, allow_offensive = _resolve_mode()
        conf = read_nxc_conf()
        return cls(
            base_command=resolve_base_command(),
            protocols=_env_list("NXC_PROTOCOLS") or list(DEFAULT_PROTOCOLS),
            scope=_env_list("NXC_SCOPE"),
            allow_offensive=allow_offensive,
            # loot and full both permit credential-dumping; full additionally permits
            # state-changing/offensive actions (allow_offensive).
            allow_loot=mode in ("loot", "full"),
            dry_run=dry_run,
            timeout=_env_int("NXC_TIMEOUT", 300),
            max_targets=_env_int("NXC_MAX_TARGETS", 256),
            audit_log=os.environ.get("NXC_AUDIT_LOG"),
            # NXC_WORKSPACE wins; else default to whatever nxc.conf writes to, so
            # our reads track nxc's writes without extra configuration.
            workspace=os.environ.get("NXC_WORKSPACE") or conf["workspace"],
            mode=mode,
            tool_mode=_resolve_tool_mode(),
            pwn3d_label=conf["pwn3d_label"],
        )
