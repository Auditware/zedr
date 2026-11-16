# Developer-Managed Test VMs

## Context and Problem Statement

The project initially attempted to automate cross-platform VM provisioning using QEMU
Not only the different OS's make it difficult, but developers use diverse VM solutions based on their preferences and host system configurations and virtualization framework support.

Forcing a single approach creates friction rather than enabling productivity. The question is: should the project manage VM provisioning or should developers manage their own test infrastructure?

## Considered Options

- Continue QEMU-based VM
- Quickemu, which is not ideal at macos
- tart, which is not ideal at windows/linux
- Developer-managed VMs with SSH-based testing

## Decision Outcome

Chosen option: "Developer-managed VMs with SSH-based testing", because it eliminates complex VM provisioning code, allows developers to use their preferred virtualization tools, reduces project maintenance burden, and provides clear separation between agent testing and VM management.

Test VMs are now developer-managed infrastructure. The project provides minimal requirements and testing interface, not VM provisioning automation.

### Positive Consequences

- Developers use their preferred VM solution (VMware, Parallels, UTM, etc)
- Reduced project complexity and maintenance burden
- Faster onboarding for developers who already have VM tools
- Clear separation of concerns: project tests agents, not VMs
- Eliminates cross-platform VM provisioning issues
- No more QEMU compatibility debugging on Apple Silicon

### Negative Consequences

- Each developer must set up VMs once (one-time setup cost)
- Potential for environment inconsistencies between developers
- No automated VM reset/snapshot capability in project tooling
- Requires manual VM configuration and maintenance