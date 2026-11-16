# Security

zedr is a proof of concept. Do not rely on it to protect production endpoints yet.

## Reporting a vulnerability

Report it privately through GitHub: open the Security tab of [auditware/zedr](https://github.com/auditware/zedr/security) and choose "Report a vulnerability". Please do not open a public issue for it.

Say which part is affected (agent, prover, control server or console), the commit you tested, what an attacker gains and how to reproduce it.

## What we want to hear about

- Reading sealed telemetry without a rule match and without the keys of the endpoint
- Making the control server accept a window, a release or a proof it should refuse
- Taking over an agent or its identity without root on the endpoint
- Reaching the console or the admin API without credentials

## Known limits

The ways around the agent and the control server that are already known are listed in [docs/BYPASSES.md](./docs/BYPASSES.md), and the limits of the design in [ADR 031](./docs/adr/031-sealed-telemetry-opened-by-proven-rules.md). A better answer to one of those is welcome as a contribution.
