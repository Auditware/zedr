---
applyTo: "agent/**"
---

## Core Agent Uncompromisable Capabilities

- Works on the same detection standards the EDR agent itself applies to Windows, Linux, and macOS
  - Windows: Windows 11 and Windows Server 2022, or later
  - Linux: Major distributions (Ubuntu, Debian, CentOS, RHEL, Fedora), supported kernels (5.4+)
  - macOS: macOS 13 (Ventura) or later
- Maintains a minimal memory and CPU footprint
- Is not easily turned off, paused, or stopped at any manner by regular or root/administrator users
- Is not easily hooked, intercepted, or tampered with at any manner by regular or root/administrator users
- Maintains a trusted record of it's core technical measures to prevent tampering and bypassing, per each operating system capabilities and research, see `../../docs/ANTI_TAMPERING.md`
- Maintains a trusted record of all detections techniques applied by the agent, and corresponding up to date research data per each operating system capabilities and research, see `../../docs/DETECTIONS.md`
- Maintains a trusted record of all known bypass techniques and corresponding up to date research data per each operating system capabilities and research, see `../../docs/BYPASSES.md`
- Reports detections to a central control server in real-time
- Keeps telemetry private: every event is sealed on the endpoint, a detection rule opens only its own evidence, the rule run is proven, and the agent runs no command for the control server, see `../../docs/adr/031-sealed-telemetry-opened-by-proven-rules.md`
- Has the ability to quarantine files, processes, and network activity on the host system
- Has the ability to query system information, running processes, network connections, and file system activity on the host system, and report it to the central control server sealed, in real-time and reliably
- Has conditional automatic remediation rules
- Next-generation antivirus capabilities:
  - Signature-based malware detection and removal
  - AI-based malware detection and removal (meaning it can detect malware and exploits even if they don't match a known file signature)
    - Local but small AI model inference
    - Central Control Server based AI model inference
- Behavioral-based threat detection and response capabilities
- Heuristic-based threat detection and response capabilities
  - Local heuristic analysis engine
  - Central Control Server based heuristic analysis engine
- Collects forensic data on demand and in real-time, including memory dumps, file system snapshots, network traffic captures, logs and events.
- Reports and prevents password dumping and credential theft in real-time
- Supports automatic updates of the agent software itself, with cryptographic signature verification of the update packages
- Supports offline mode, where the agent can operate and store detections locally for up to 30 days without connection to the central control server, and then report all collected data once connection is re-established
- Has a stable rule-based mechanism to create custom detection and response rules, utilizing the full power of the agent's capabilities - researchers should be able to contribute new detection and response rules easily and accessibly
- The agent must support seamless upgrades to new versions without causing significant downtime
- The upgrade process must ensure that all existing configurations and data are preserved during the upgrade

## Agent Development Instructions

- Follow the architecture and design decisions outlined in `../../docs/adr/002-agent-core-architecture.md`
- At all times you have to keep `../../docs/ANTI_TAMPERING.md`, `../../docs/DETECTIONS.md`, and `../../docs/BYPASSES.md` up to date - AN ABSOLUTE MUST
- Strive to constantly get `../../docs/ANTI_TAMPERING.md` and `../../docs/DETECTIONS.md` to be consistently as equivalent to each other in terms of content and quality, across all supported operating systems
- Track operating system wanted, or already implemented capabilities in `../../docs/OS_CAPABILITIES.md`
- Agent testing is not done on the local development operating system, but rather on dedicated testing environments as described in `../../docs/adr/003-agent-os-testing.md`
- Agent code must not have unsafe primitives like `unwrap_or_else` or `unsafe`, it is agent code designed to be running on critical systems
- Agent compilation and building is done via `Makefile` commands and focuses on building and testing on the native OS (Windows, Linux, macOS). cross-compilation is not used
- When rebuilding the agent, always ensure to do a clean rebuild to avoid any caching issues or stale build artifacts
- When rebuilding the agent, ensure to use the control server to fetch the binary via it's normal order of operations to test a real flow. If a new agent code is to be built, it is built via the vm, then retreived back to the control server's binaries folder, then the control server serves it to the agent and generates an install command with a key, and the install command is executed on the vm.