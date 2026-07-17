"""FastMCP application entry point.

Milestone 1: boot the server, resolve config + base command, and expose a single
`nxc_health` tool backed by a boot-time `--version` health check. Per PLAN.md the
server refuses to start if the health check fails -- except in suggest mode
(NXC_MODE=suggest), where it warns and continues so the command resolution can be
exercised without nxc.
"""

from __future__ import annotations

import asyncio
import json
import sys

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware

from .config import Config, ConfigError
from .executor import _folded_args, parse_version, reset_current_tool, run, set_current_tool
from . import dynamic, meta, resources
from .modules import register_enabled, workspace

mcp = FastMCP("netexec-mcp")


class ToolAuditMiddleware(Middleware):
    """Record which MCP tool issued each command, for the audit log. Wraps every tool call
    in both tool modes and stashes the tool name in a contextvar that executor.execute()
    reads when writing the audit. In dynamic mode the inner ``mcp.call_tool`` re-enters this
    hook, so the REAL tool (e.g. ``smb_ntds``) is recorded, not the ``nxc_call`` wrapper --
    a crash-proof, mode-independent record of what actually ran."""

    async def on_call_tool(self, context, call_next):
        name = getattr(getattr(context, "message", None), "name", None)
        token = set_current_tool(name)
        try:
            return await call_next(context)
        finally:
            reset_current_tool(token)


# Keys that only ever appear in a JSON Schema, never in a real argument payload.
_SCHEMA_ECHO_KEYS = {"type", "properties", "additionalProperties", "required",
                     "$schema", "title", "description", "definitions", "$defs"}
_JSON_SCHEMA_TYPES = {"object", "array", "string", "number", "integer", "boolean", "null"}


class NormalizeArgsMiddleware(Middleware):
    """Repair common small-model call-shape failures, before pydantic validation, in both tool
    modes. Two independent repairs:

    (1) FLATTENED / JSON-STRING nxc_call. Weaker models put the *target tool's* parameters at the
    top level of nxc_call -- nxc_call(name="smb_get_file", share="all", ...) -- instead of nested
    under `arguments`, or send `arguments` as a JSON *string*. FastMCP would reject the strays as
    unexpected kwargs (a misleading error the model then loops on). Fold them into `arguments` so
    the call routes. A flatten is recorded in `_folded_args` so execute() notes it in the audit
    and nxc_call hints the model to nest next time; an explicit `arguments` entry wins over a
    flattened duplicate. Only nxc_call has the name+arguments indirection -- its inner dispatch
    re-enters this hook as the real tool (name != "nxc_call") and is left alone.

    (2) SCHEMA ECHO. Some clients (e.g. Cline) render a tool's input *schema* under a heading
    literally called "Arguments", and weaker models copy that schema back as the call arguments
    -- e.g. nxc_health(type="object", properties={}, additionalProperties=false). A no-arg tool
    hard-errors on that, so the model burns a step or loops. When the payload is unmistakably a
    schema echo (a JSON `type` plus properties/additionalProperties, and nothing but schema keys),
    replace it with {} so the call proceeds: no-arg tools succeed, and tools with required args
    return a clean "field required" error. The signature is narrow enough never to touch a genuine
    call."""

    async def on_call_tool(self, context, call_next):
        msg = getattr(context, "message", None)
        args = getattr(msg, "arguments", None)
        token = None
        # (1) flattened / JSON-string nxc_call -> fold into `arguments`
        if isinstance(args, dict) and getattr(msg, "name", None) == "nxc_call":
            a = dict(args)
            changed = False
            if isinstance(a.get("arguments"), str):
                try:
                    a["arguments"] = json.loads(a["arguments"])
                    changed = True
                except (ValueError, TypeError):
                    pass
            strays = {k: v for k, v in a.items() if k not in ("name", "arguments")}
            if strays and "name" in a:
                inner = a.get("arguments")
                inner = dict(inner) if isinstance(inner, dict) else {}
                a = {"name": a["name"], "arguments": {**strays, **inner}}
                changed = True
                token = _folded_args.set(sorted(strays))
            if changed:
                msg.arguments = a
                args = a
        # (2) schema echo -> {}
        if (isinstance(args, dict) and args.get("type") in _JSON_SCHEMA_TYPES
                and ("properties" in args or "additionalProperties" in args)
                and set(args) <= _SCHEMA_ECHO_KEYS):
            msg.arguments = {}
        try:
            return await call_next(context)
        finally:
            if token is not None:
                _folded_args.reset(token)


# Resolved once at startup by main(); cached for tool calls.
_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def _check_version(config: Config) -> dict:
    """Run `<base> --version` and summarise the result."""
    try:
        result = run([*config.base_command, "--version"], timeout=config.timeout)
    except FileNotFoundError:
        return {
            "ok": False,
            "version": None,
            "base_command": config.base_command,
            "returncode": None,
            "error": f"Executable not found: {config.base_command[0]!r}",
        }

    version = parse_version(result.stdout) or parse_version(result.stderr)
    last_line = next(
        (ln.strip() for ln in reversed(result.stdout.splitlines()) if ln.strip()),
        "",
    )
    # Health is gauged by whether we got a parseable version back, NOT by the
    # exit code: nxc returns 1 even on a successful `--version`. A missing
    # executable is already handled above via FileNotFoundError.
    return {
        "ok": version is not None,
        "version": version,
        "base_command": config.base_command,
        "returncode": result.returncode,
        "detail": last_line,
    }


@mcp.tool()
def nxc_health() -> dict:
    """Report the configured NetExec base command and its --version output.

    Returns a dict with `ok`, the parsed `version`, the resolved `base_command`,
    the process `returncode`, and the raw version `detail` line.
    """
    return _check_version(get_config())


def _warn_if_surface_too_large(mcp) -> None:
    """Full mode: warn if the tool surface likely overflows a small model's context."""
    try:
        import json

        tools = asyncio.run(mcp.list_tools())
        approx = sum(
            len(json.dumps(t.to_mcp_tool().model_dump(exclude_none=True)))
            for t in tools
        ) // 4
    except Exception:
        return
    if approx > 30_000:
        print(
            f"[netexec-mcp] WARNING: tool surface ~{approx:,} tokens across "
            f"{len(tools)} tools -- small-context models (<~40k) will likely fail or "
            f"truncate. Set NXC_TOOL_MODE=dynamic, or narrow NXC_PROTOCOLS.",
            file=sys.stderr,
        )


def main() -> None:
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"[netexec-mcp] configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    global _config
    _config = config

    health = _check_version(config)
    base = " ".join(config.base_command)
    if health["ok"]:
        print(f"[netexec-mcp] NetExec {health['version']} OK via: {base}", file=sys.stderr)
        print(f"[netexec-mcp] operating mode: {config.mode}", file=sys.stderr)
    else:
        reason = health.get("error") or f"returncode={health['returncode']}"
        msg = f"[netexec-mcp] NetExec health check failed for {base!r} ({reason})."
        if config.dry_run:
            print(msg + " Continuing because NXC_MODE=suggest.", file=sys.stderr)
        else:
            print(
                msg + " Refusing to start. Set NXC_COMMAND or fix the install.",
                file=sys.stderr,
            )
            sys.exit(1)

    meta.register(mcp, get_config)
    resources.register(mcp, get_config)
    workspace.register(mcp, get_config)  # offline recall of nxc's workspace DB (always on)
    registered = register_enabled(mcp, get_config, config.protocols)
    skipped = [p for p in config.protocols if p not in registered]
    print(f"[netexec-mcp] protocol tools registered: {', '.join(registered) or 'none'}", file=sys.stderr)
    if skipped:
        print(f"[netexec-mcp] enabled but not yet implemented: {', '.join(skipped)}", file=sys.stderr)

    # Repair schema-echo argument payloads before validation (both modes), then record the
    # issuing tool on every audited command. Both only hook on_call_tool, so they don't
    # affect tool listing; both are added before the dynamic middleware.
    mcp.add_middleware(NormalizeArgsMiddleware())
    mcp.add_middleware(ToolAuditMiddleware())

    if config.tool_mode == "dynamic":
        # Snapshot the full tool surface BEFORE installing the hiding middleware -- the
        # middleware filters the server's own list_tools too (see dynamic.py).
        full_tools = asyncio.run(mcp.list_tools())
        index = dynamic.build_index(full_tools)
        dynamic.register(mcp, get_config, index)
        mcp.add_middleware(dynamic.DynamicModeMiddleware())
        mcp.instructions = dynamic.DYNAMIC_INSTRUCTIONS
        print(
            f"[netexec-mcp] tool mode: dynamic (default) -- {len(index)} tools behind "
            f"{len(dynamic.DYNAMIC_VISIBLE)} meta-tools; discover via nxc_find_tool/nxc_catalog, "
            f"run via nxc_call. Set NXC_TOOL_MODE=static to expose every tool.",
            file=sys.stderr,
        )
    else:
        _warn_if_surface_too_large(mcp)

    mcp.run()


if __name__ == "__main__":
    main()
