# Agent Self-Upgrade Mechanism Using Service-Native Staging Pattern

## Context and Problem Statement

EDR agents must be updatable to receive security patches, new detection capabilities, and bug fixes. Additionally, agents must support binary transitions of any kind: upgrades, downgrades (rollbacks), and same-version reinstalls (to fix corruption). However, agent upgrades present unique challenges: the agent is a critical security service that must maintain near-zero downtime, validate new versions before deployment, and resist tampering by attackers who may attempt to hijack the upgrade process. How can we implement secure, reliable agent binary transitions across Windows, Linux, and macOS that minimize downtime, validate new versions before deployment, provide defense-in-depth against tampering, and maintain operational visibility?

**Note**: Throughout this document, "upgrade" refers to any binary transition: forward upgrade (v0.1.0→v0.2.0), downgrade/rollback (v0.2.0→v0.1.0), or same-version reinstall (v0.1.0→v0.1.0).

## Considered Options

- **Simple Stop-Replace-Start**: Stop service → Replace binary on disk → Restart service (5-10s downtime)
- **Batch Script/Shell Script Approach**: Agent spawns external script to handle replacement after exit
- **Exec Replacement**: Agent downloads new binary, replaces itself on disk, then exec() into new binary
- **File-Coordinated Staging**: New version starts as separate service, coordinates via files, validates itself, old version hands off
- **Service-Native Staging**: New version starts as separate service, coordinates via OS service manager, validates itself, old version hands off

## Decision Outcome

Chosen option: **Service-Native Staging Pattern**, because it provides zero-downtime upgrades, validates new versions before handoff, enables proactive rollback on validation failure, creates multiple security checkpoints that make tampering significantly harder, eliminates file-based coordination vulnerabilities, and provides real-time operational visibility. This pattern aligns with industry-standard blue-green deployment practices and leverages OS-native service management primitives instead of custom filesystem coordination.

### Decision Outcome Visualization

```mermaidX.Y.Z]

    B --> C{Download & Verify}
    C -->|✓ Signature Valid| D[Create Staging Service]
    C -->|✗ Invalid| Z[Abort - Stay Running]

    D --> E[Staging Service vA.B.C Starts]

    E --> F{Staging Validation}
    F -->|Self-Test| G[Check Version]
    F -->|Connectivity| H[Test Server Connection]
    F -->|Integrity| I[Verify Binary Hash]

    G --> J{All Checks Pass?}
    H --> J
    I --> J

    J -->|✓ Healthy| K[Signal Ready]
    J -->|✗ Failed| L[Exit - Old Stays Running]

    K --> M[Old Service Receives Ready Signal]

    M --> N{Health Confirmed?}
    N -->|✓ Yes| O[Old Service Stops]
    N -->|✗ Timeout| P[Kill Staging - Stay Running]

    O --> Q[Staging Detects Old Stopped]

    Q --> R[Takeover as Primary Service]
    R --> S[Move Staging to Primary Location]
    R --> T[Delete Old Binary & Staging Artifacts]
    R --> U[Reconfigure Service Manager]

    S --> V[New Primary Service vA.B.C]
    T --> V
    U --> V
    V --> W[Report Success to Server]

    L --> Y[Old Service Continues]
    P --> Y
    Z --> Y

    classDef oldService fill:#4a5568,stroke:#2d3748,stroke-width:2px,color:#e2e8f0
    classDef newService fill:#2b6cb0,stroke:#3182ce,stroke-width:2px,color:#e2e8f0
    classDef validation fill:#805ad5,stroke:#6b46c1,stroke-width:2px,color:#e2e8f0
    classDef decision fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#e2e8f0
    classDef failure fill:#c53030,stroke:#9b2c2c,stroke-width:2px,color:#e2e8f0
    classDef success fill:#38a169,stroke:#2f855a,stroke-width:2px,color:#e2e8f0

    class B,M,O,Y oldService
    class E,Q,R,V newService
    class F,G,H,I,K validation
    class C,J,N decision
    class L,P,Z failure
    class W success
```

**Note**: Versions shown as vX.Y.Z (current) → vA.B.C (target) can represent: upgrade (0.1.0→0.2.0), downgrade (0.2.0→0.1.0), or reinstall (0.1.0→0.1.0). class L,P,Z failure
class W success

### Consequences

**Good:**

- **Zero-downtime upgrades**: At least one service instance running at all times during upgrade
- **Proactive validation**: New version validates before old version stops, enabling safe abort if validation fails
- **Secure handoff protocol**: Old service verifies new service health via service manager status, preventing failed upgrades from causing outages
- **Automatic rollback**: If new version fails validation or crashes during takeover, old version continues running
- **Tamper resistance**: Multiple validation checkpoints (signature, version, connectivity) make injection attacks harder
- **No file coordination**: Uses OS service manager as source of truth, eliminating file tampering attacks
- **Real-time observability**: Server tracks upgrade phases (initiated → handoff → completed) for operational visibility
- **Graceful degradation**: Upgrades proceed even if server communication fails, reporting completion later
- **Consistent cross-platform**: Same pattern works across Windows, Linux, and macOS with platform-specific service manager integration
- **Industry-proven pattern**: Mirrors blue-green deployment and Kubernetes rolling update strategies
- **Persistent staging service**: Staging service remains installed (stopped) between upgrades, avoiding Windows Error 1072 (service marked for deletion) that prevents service name reuse

**Bad:**

- **Increased complexity**: More moving parts than simple stop-restart approach
- **Temporary resource overhead**: Brief period where both services are running simultaneously (1-2 seconds)
- **Service manager integration**: Requires platform-specific code for Windows Services, systemd, and launchd
- **Network dependency for observability**: Real-time upgrade tracking requires successful server communication
- **Persistent staging service**: Stopped SYSTEM-privilege service exists permanently, same security posture as any Windows service

**Implementation Notes:**

**Windows Error 1072 Mitigation**: Windows Service Control Manager marks services for deletion rather than removing them immediately. Even with proper shutdown sequence (stop → wait for STOPPED state → terminate processes), the service name remains locked indefinitely. Solution: Staging service is created once and reused across all upgrades. After completing upgrade, staging service stops itself but remains installed, avoiding deletion-related name locks.

### Upgrade Event Timeline

```
T+0s: Agent receives upgrade command in heartbeat response
T+1s: Agent verifies command signature ✓
T+2s: Agent downloads new binary to temp location
T+3s: Agent verifies binary signature ✓
T+4s: Agent creates/starts staging service (creates if first upgrade, starts if exists)
T+5s: Staging service loads, validates signature ✓
T+6s: Staging validates version, connectivity ✓
T+7s: Staging sets ServiceState::Running (signals health)
T+8s: Agent sees Running state, stops itself (zedr-agent.exe unlocked)
T+9s: Staging waits for main service STOPPED state
T+10s: Staging verifies main process terminated
T+11s: Staging replaces C:\Program Files\zedr\zedr-agent.exe (in-place)
T+12s: Staging starts main service (loads new binary from disk)
T+13s: Staging waits for main service Running state
T+14s: Staging sends Completed event to server
T+15s: Staging stops itself (service remains installed for next upgrade)
T+16s: Main service validates signature, begins normal operation ✓
T+60s: Main service first heartbeat confirms new version

Downtime: ~5 seconds (T+8s to T+13s - main service stopped during binary swap)
Total upgrade time: ~16 seconds
Service deletion: None (staging persists in stopped state)
Coordination: OS service manager state only
Rollback: Server issues new upgrade command with previous/fixed version
```

## References

- Industry pattern: Kubernetes rolling updates with readiness probes
- Industry pattern: Blue-green deployments
- Industry pattern: Docker container replacement
- Security: ed25519 signature scheme (modern, fast, 128-bit security)
- Windows: Service Control Manager documentation
- Linux: systemd service management
- macOS: launchd and launchctl documentation