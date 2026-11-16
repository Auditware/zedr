# zedr - Zero-knowledge Endpoint Detection & Response

zedr is meant to be the most lightweight professional EDR agent in the world.

## Definition of a Professional EDR Agent

We classify a professional EDR agent as one that provides the following definitive capabilities with absolutely no compromises:

- Core Agent Uncompromisable Capabilities: see [agent.instructions.md](./instructions/agent.instructions.md#core-agent-uncompromisable-capabilities)
- Central Management Uncompromisable Capabilities: see [control_server_backend.instructions.md](./instructions/control_server_backend.instructions.md#central-management-uncompromisable-capabilities)

### Developments and Deployment Standards

- The agent and central control server must have an organized development and deployment practices, including:
- ARD-based (Architectural Decision Record) feature development, see [https://github.com/adr/madr](https://github.com/adr/madr). All features considered major must have an ADR created for it, on `../docs/adr/00X-<feature-name>.md`
- Comprehensive unit and integration tests with at least 90% code coverage
- Comprehensive security testing as part of the unit and integration tests
- Contribution approval process, with clear defined steps to assure there are no security or quality issues, see `../CONTRIBUTING.md`
- The agent on every commit, must be built and tested automatically using CI/CD pipelines, across all supported operating systems, ensuring no regressions are introduced, and ensuring stability of the operating system hosting the agent
- Benchmarked security performance metrics must be published on every major release, including memory and CPU usage, detection rates, false positive rates, and response times
- The agent and central control server must be deployable using Infrastructure as Code (IaC) for auditable and repeatable deployments

## Contribution Guidelines

- Contributor friendlyness is a high priority. in any addition that can affect the contributor or developer experience, the `../Makefile` must be updated to simplify / efficiently reuse the process
- To increase development friendlyness, the local development machine is optimized solely for MacOS users. this allows to provide consistency
- Don't leave unused code, comments, notes, or un-needed single-task helper scripts. Every piece of code must have a clear purpose, and if it's not needed anymore, it must be removed to avoid confusion
- All environmental dependencies must be specified in `../secrets/.env.local` and never hardcoded in the code (server urls, ports, credentials, etc)
- Every feature addition or bug fix must be accompanied by appropriate unit, integration tests or both. These tests must be defined to run under `make test`.
- After deploying to main or staging branches, ensure to actively watch the github actions for any failures and to investigate and address them promptly. You can use `gh run list --limit 5` followed by `gh run view <run-id>` or `gh run view <run-id> --log-failed` to inspect recent runs
- Never use comments or at least reduce code comments to the absolute minimum. Quality code explains itself
- If a challenging setup or devmachine related issue is discovered, update the `../docs/devmachine/` documentation accordingly to help future developers
- Don't create temporary files like `/tmp` files, 1-time scripts, etc.
- Emoji's are not allowed anywhere in the code
- Don't use echo statements to state instructions that you were tasked to implement
- Always follow the contribution guidelines specified above
- Always follow the coding style and patterns already established in the codebase
- Always store passwords or secrets in `../secrets/.env.local` and never hardcode them in the code
- Any `pm2 logs *` command must follow `--nostream` flag to avoid hanging I/O
- Code should not compile if ENVs are missing
- Future proofing is a requirement for every feature added or modified
- It's imperative that during development and testing a future proof mindset will be applied. Hackish workarounds that won't solve the problem a few steps down the line are not acceptable
- Turning off signature verification or any other security features is not acceptable even if for testing and troubleshooting
- Never write direct shell commands through code. Use the OS-native APIs or libraries to achieve the goal
- A task is not considered successful if it relied on manual steps, workarounds, or temporary fixes
- Remaking a file from scratch, when the file is already present, is not acceptable