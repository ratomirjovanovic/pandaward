# Telemetry

Pandaward sends nothing about your use of it unless you turn telemetry on. It is off after installing and after every upgrade, and it stays off until you run `pandaward telemetry on` yourself in a terminal.

## Turning it on and off

```sh
pandaward telemetry          # status
pandaward telemetry on       # needs an interactive terminal; an agent cannot turn it on
pandaward telemetry show     # the exact JSON that would be sent next, and today's counters
pandaward telemetry off      # stops it and deletes everything not yet sent, including the install ID
```

`PANDAWARD_TELEMETRY=off` or `DO_NOT_TRACK=1` in the environment turns it off whatever the setting says. The setting is kept only in your user config directory (`telemetry.json` next to `approval.key`). A repository, `.pandaward/config.yaml`, a skill or the MCP server cannot turn it on.

## What is recorded

While it is on, Pandaward keeps one set of counters per UTC day:

| Field | Example | Notes |
|---|---|---|
| `install_id` | `dd8def0e3c95...` | Random, created when you turn telemetry on; deleted when you turn it off |
| `version`, `os`, `arch` | `0.2.2`, `linux`, `amd64` | From the binary |
| `counts` | `{"cli:scan": 3, "mcp:pandaward_get_status": 5, "hook:stop": 12}` | Entry point (`cli`, `mcp`, `hook`) and the command, MCP tool or hook name. Only names from Pandaward's own fixed lists are counted |
| `projects` | `["9f2c41d0a7b3e815"]` | One ID per project root a command ran in: an HMAC-SHA256 of the absolute path under a random salt that never leaves your machine. It cannot be turned back into a path, and the same project gives different IDs on different installs |

Skills and the plugin show up as the commands and MCP tools they run.

Pandaward never records arguments, paths, file or project names, findings, evidence, code, environment variables or anything read from the scanned project.

## When it is sent

Finished days are sent at most once a day, from a CLI command or when the MCP server starts, with a 3 second timeout. Hooks only count and never send, so they never wait on the network. A failed send is silent and changes nothing about the command. Unsent days are kept for at most 30 days.

This build has no collector address built in, so nothing is sent yet. `pandaward telemetry status` says so.
