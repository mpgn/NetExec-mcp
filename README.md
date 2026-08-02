# netexec-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent drive
**[NetExec](https://github.com/Pennyw0rth/NetExec)** (`nxc`) for **authorized**
security testing only.

It is a **pure subprocess wrapper**: it shells out to the `nxc` CLI as an argv list
(never `shell=True`, never importing NetExec as a library) and declares **no** nxc
dependency. How nxc itself is installed (PATH / uv / pipx / docker) is entirely up to you.

<img width="1417" height="581" alt="image" src="https://github.com/user-attachments/assets/8c72cd0d-77bf-4ccf-a553-7c5ccce55513" />
<img width="1479" height="618" alt="image" src="https://github.com/user-attachments/assets/ae30ebcc-c613-47ec-a565-8a1247a67509" />

## Status

**v1 — all 10 nxc protocols, 131 tools** (117 protocol tools + 9 discovery/meta-tools +
5 offline workspace-DB readers). SMB, LDAP, WinRM, MSSQL, SSH, RDP, WMI, FTP, NFS, and VNC
are built out (native flags, credential dumping/gathering, command exec, file transfer, promoted
high-value `-M` modules, and structured output). The first seven are validated end-to-end against a
live AD lab; FTP/NFS/VNC are source-verified + unit-tested (no lab yet). A 3-level safety model gates
everything; the long tail of nxc `-M` modules is reachable via meta-tools.

## Built for small / local models

With 131 tools, listing every one to the model would spend ~46k tokens of context
before any work starts enough to overflow a small-context (≤8B / 32k) model and to
make every call on a large one needlessly expensive. So the default `NXC_TOOL_MODE`
is **`dynamic`**: only a handful of meta-tools are exposed (`nxc_catalog`,
`nxc_find_tool`, `nxc_describe_tool`, `nxc_call`, `nxc_health`), and the model
discovers and dispatches the real tools on demand. This keeps the tool surface out
of the context window required to run on small local models, and cheaper (same
quality) on large ones. Set `NXC_TOOL_MODE=static` to opt out and list every tool. See
the `NXC_TOOL_MODE` row under [Configuration](#configuration-env-vars) and the
step-budget note beneath it.

## Requirements

- Python ≥ 3.10, [`uv`](https://docs.astral.sh/uv/) or [`pipx`](https://pipx.pypa.io/)
- **NetExec installed separately** — it is not a pip dependency and is not on PyPI.
  See the [official install guide](https://www.netexec.wiki/getting-started/installation).
  Any install works as long as `nxc` / `netexec` is reachable on `PATH` or via
  `NXC_COMMAND`; the server runs `nxc --version` on boot and refuses to start if it
  can't find it.

## Quick start

### Option A: uv (run from a source checkout)

```bash
uv sync

# Point at your nxc install (example: a uv-managed source checkout)
export NXC_COMMAND="uv run --directory ~/NetExec netexec"
export NXC_SCOPE="10.0.0.0/24"          # required to target anything (fail-closed)

uv run netexec-mcp
```

MCP client config (`command`/`args` launch the server itself):

```json
{
  "command": "uv",
  "args": ["run", "--directory", "/path/to/netexec-mcp", "netexec-mcp"]
}
```

### Option B: install from PyPI (standalone `netexec-mcp` CLI)

```bash
# Pick one installer — all put `netexec-mcp` on PATH:
pipx install netexec-mcp                 # pipx
uv tool install netexec-mcp              # uv
# or run without installing:
uvx netexec-mcp                          # uv, one-shot

export NXC_COMMAND="nxc"                 # or however your nxc install is invoked
export NXC_SCOPE="10.0.0.0/24"

netexec-mcp
```

MCP client config — `netexec-mcp` is on `PATH`, so no `uv`/`--directory` wrapper:

```json
{
  "command": "netexec-mcp",
  "args": []
}
```

On boot the server runs `<base> --version` and **refuses to start** if it fails
(unless mode `suggest`, which downgrades that to a warning). See `.mcp.json.example`
for a ready-to-edit MCP client config (uv variant).

## Operating modes (`NXC_MODE`)

Four escalating levels of how much the server is allowed to *do*:

| Mode | What runs | Use when |
| --- | --- | --- |
| `suggest` | **Nothing executes.** Tools return the resolved nxc command for a human (the auditor) to run. Scope still enforced; offensive commands *can* be previewed. | You want the agent to plan commands you run yourself. |
| `recon` _(default)_ | Read-only enumeration; executes, credential-dumping and state-changing actions are refused. | Day-to-day authorized recon. |
| `loot` | Recon **plus** read-only credential-dumping (sam/lsa/ntds/gpp/roasting) — no state change on the target, but it harvests credential material. | Authorized credential-harvesting. |
| `full` | Everything executes, including state-changing / privilege-escalation actions (exec, write, spray, coercion-with-listener, exploits). | Authorized active testing. |

`NXC_MODE` is the canonical control; it defaults to `recon` when unset.

## Configuration (env vars)

| Var | Purpose | Default |
| --- | --- | --- |
| `NXC_COMMAND` | Base command (shlex-parsed). Falls back to `nxc`/`netexec` on `PATH`. | autodetect |
| `NXC_PROTOCOLS` | Comma-separated protocols to enable (e.g. `smb,ldap`). | all implemented |
| `NXC_TOOL_MODE` | Tool-surface presentation — `dynamic` (**default**: expose only meta-tools; the ~100-tool surface is discovered via `nxc_find_tool`/`nxc_catalog` and run via `nxc_call`) or `static` (list every tool). Dynamic keeps the ~46k-token surface out of the context window — required for small-context models, ~8× cheaper (same quality) on large ones. Set `static` to opt out (best for a decisive model, or to avoid discovery round-trips on a big-context model). | `dynamic` |
| `NXC_SCOPE` | Comma-separated target allowlist (IP/CIDR/range/hostname). **Fail-closed**: targets with no scope are rejected. | _(none)_ |
| `NXC_MODE` | Operating level — `suggest` / `recon` / `loot` / `full`. | `recon` |
| `NXC_TIMEOUT` | Per-call timeout (seconds). | `300` |
| `NXC_MAX_TARGETS` | Max target tokens per call. | `256` |
| `NXC_AUDIT_LOG` | Path to an append-only JSONL audit log. | _(none)_ |
| `NXC_WORKSPACE` | nxc workspace to read for richer results. | _(none — reads nxc.conf's `workspace`, else `default`)_ |
| `NXC_PATH` | Override nxc's home dir (mirrors nxc's own `NXC_PATH`); where `nxc.conf` and `workspaces/` are read from. | `~/.nxc` |

> **Dynamic mode needs a bigger client-side step budget.** `max_steps` (how many tool
> calls the agent may make) is **not** an MCP setting — the server can't see or set it.
> It lives in your client's agent loop. In `dynamic` mode each action costs ~2 calls
> (`nxc_find_tool` → `nxc_call`), so a chain that needs 4 calls in `full` needs ~10 in
> `dynamic`. Set the budget high enough there, e.g. mcp-use:
> ```python
> MCPAgent(llm=ChatOllama(model="qwen3:14b"), client=client, max_steps=30)  # default is 5 — too low
> ```
> Other clients (Claude Desktop, Cursor, Cline, …) have their own max-iterations
> setting. The MCP can only *hint* this via its startup `instructions`; it can't enforce it.

## Resources

The server publishes cheatsheets as MCP resources so an agent can ground itself:

- `netexec://guide/operating-modes`
- `netexec://guide/auth`
- `netexec://guide/workflows` (incl. the cross-protocol gMSA chain)
- `netexec://guide/workspace` (cached recall vs. live — when to use which)
- `netexec://guide/safety`
- `netexec://catalog/tools` (live, auto-generated tool inventory)
- `netexec://workspace/credentials`, `/admins`, `/loggedin`, `/hosts` (workspace DB data,
  same source as the `workspace_*` tools, filterless)

## Safety & guardrails

Enforced at a single choke point before any command runs:

- **Scope allowlist** (`NXC_SCOPE`) — every target checked; **fail-closed**.
- **Mode gating** (`NXC_MODE`) — offensive actions refused outside `full`.
- **Target cap** + per-call **timeout**.
- **Audit log** — every command (executed / dry-run / rejected) appended as JSON.
- **No shell** — nxc is invoked as an argv list; nothing is shell-interpreted.

## Example: the gMSA credential chain

```
smb_lsa (full)            -> secrets[] incl. { type: "gmsa_id", gmsa_id, ntlm }
ldap_gmsa_convert_id      -> resolves the gmsa_id to an account name (gmsa-robin$)
<any tool>                -> replay with username="gmsa-robin$", ntlm_hash=<nt>
```

## Development

```bash
uv run pytest -q          # mocked-subprocess unit tests (no nxc/network needed)
```

Architecture and milestone history live in `PLAN.md`. Tools/flags are verified against
the nxc source (`nxc/protocols/<proto>/proto_args.py`) — `--help` lists args the
handlers reject.

### nxc version

This MCP is a subprocess wrapper and pins no nxc dependency, but its tools/flags are
verified against a specific nxc build:

> **nxc 1.5.1 "Yippie-Ki-Yay", commit `738b842a`** (`738b842a…`, 2026-07-31, build 595)

Check your local build with `nxc --version` (it prints `version - codename - commit - build`).
nxc moves fast and occasionally moves/removes flags, so when you bump nxc, re-verify the
affected protocol's `proto_args.py` + handler and re-run the tests.
