# zedr

We are building zedr as an open source EDR that stays in userland and keeps endpoint telemetry private, aiming for the CrowdStrike and SentinelOne standard without a kernel driver.
The plan is one project with a real-time on-host sensor and a cross platform fleet console, where the control server can only read the events that provably match a detection rule. It is still early work.

goal is to be the tiniest possible, while still keeping to a professional EDR standards. the standards:

- [Core Agent Uncompromisable Capabilities](.github/instructions/agent.instructions.md#core-agent-uncompromisable-capabilities)
- [Central Management Uncompromisable Capabilities](.github/instructions/control_server_backend.instructions.md#central-management-uncompromisable-capabilities)
- [Operating System Capabilities](./docs/OS_CAPABILITIES.md)
- [Developments and Deployment Standards](.github/copilot-instructions.md#developments-and-deployment-standards)
