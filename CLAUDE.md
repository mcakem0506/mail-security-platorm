# CLAUDE.md

Repository-wide instructions for Claude Code are defined in [`AGENTS.md`](AGENTS.md).

Read `AGENTS.md` first and treat it as the canonical agent contract.

Also read, before substantial changes:

- `README.md`;
- `docs/ARCHITECTURE.md`;
- `docs/SECURITY_MODEL.md`;
- `docs/THREAT_MODEL.md`;
- the current stage specification and acceptance document;
- `docs/DETECTION_GAPS.md` for detection/authentication/enforcement work.

Do not duplicate or override `AGENTS.md` here. If Claude-specific instructions are ever required, add only the delta to this file.

## Claude-specific working rule

When a requirement appears already implemented:

1. locate the implementation;
2. prove it with tests/runtime evidence;
3. mark it `ALREADY IMPLEMENTED`;
4. do not create a second competing mechanism.

For defects: regression test first, fix second.

Never report a stage as ready solely because code was written.
