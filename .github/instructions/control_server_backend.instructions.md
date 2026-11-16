---
applyTo: "control_server/backend/**"
---

## Central Management Uncompromisable Capabilities

- Provides a central control server to manage all deployed agents, view detections, and respond to incidents:
  - Cage network activity of the host system through the agent
  - Provides remote shell access for up to 30 minutes at an approval window to the host system through the agent. Approval window must be authorized by 3 different signers from different login sessions
- Communicates securely to a central control server, over encrypted, highest-of-integrity channels
- Access to the central control server is protected with multi-factor authentication and role-based access control
- Any event collected must reach the central control server within 30 seconds of occurrence
- If the agent is disconnected from the central control server, it must alert the central control server within 1 minute of reconnection
- All logs of the central control server and the agent must be tamper-proof and auditable
- Backend secrets must be encrypted at rest, e.g. using git secret for git repositories, see [https://git-secret.io/](https://git-secret.io/)
- The central control server must support rolling upgrades to minimize disruption to ongoing operations


## Contribution guidelines
- Don't hardcode or even fallback to environments outside the standardized environment files, we prefer failing fast than leaking secrets
