# Agent Operating System Testing on Virtualization Solution

## Context and Problem Statement

On each change, the agents must be tested against Windows, Linux, and macOS. For the userspace-only architecture, we need lightweight, automated VM orchestration that works on Apple Silicon development machines.

## Considered Options

- Tart for macOS, quickemu for Linux and Windows
- UTM (requires manual VM setup)
- Parallels Desktop (commercial, requires license)
- GitHub Actions only (no local testing)

## Decision Outcome

Chosen option: "Tart for macOS, quickemu for Linux and Windows", because it provides automated image downloading and VM orchestration for all three OSes on Apple Silicon.

### Decision Outcome Visualization
```mermaid
flowchart TB
    A[Code Change] --> B[Local VM Testing]
    B --> C{Multi-OS VMs}
    
    C -->|quickemu| D[Linux VM<br/>Ubuntu 24.04]
    C -->|quickemu| E[Windows VM<br/>Windows 11]
    C -->|Tart| F[macOS VM<br/>Sequoia ARM64]
    
    D --> G[Build & Unit Tests]
    E --> H[Build & Unit Tests]
    F --> I[Build & Unit Tests]
    
    G --> J[Integration Tests]
    H --> K[Integration Tests]
    I --> L[Integration Tests]
    
    J --> M{All Tests Pass?}
    K --> M
    L --> M
    
    M -->|Yes| N[Commit & Push]
    M -->|No| O[Debug & Fix]
    O --> A
    
    N --> P[CI/CD Pipeline]
    P --> Q[Deploy]

    classDef local fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#e2e8f0
    classDef decision fill:#2b6cb0,stroke:#3182ce,stroke-width:2px,color:#e2e8f0
    classDef test fill:#1a202c,stroke:#2d3748,stroke-width:1px,color:#cbd5e0
    classDef success fill:#22543d,stroke:#2f855a,stroke-width:2px,color:#9ae6b4
    classDef fail fill:#742a2a,stroke:#9b2c2c,stroke-width:2px,color:#feb2b2

    class A,B local
    class C,M decision
    class D,E,F,G,H,I,J,K,L test
    class N,P,Q success
    class O fail
```

### Consequences

- Good, because Tart provides native Apple Silicon macOS VMs with OCI image registry
- Good, because quickemu automates Linux/Windows VM downloads and configuration
- Good, because both tools support headless operation for CI/CD integration
- Good, because developers can test all three OSes locally before committing
- Good, because VM images are automatically downloaded on first use
- Bad, because requires ~50GB disk space for VM images (25GB macOS, ~10GB Linux, ~15GB Windows)
- Bad, because initial image download takes time on first run
- Bad, because requires Apple Silicon Mac for development (no Intel support)
