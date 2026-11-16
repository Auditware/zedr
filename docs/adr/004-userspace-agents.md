# Userspace Agents to Overcome Kernel Cross-development Difficulty

## Context and Problem Statement

Initially it was believed that for an EDR to meet industry standards it has to have kernel-level support. this is to be able to provide reliable, anti-tampering capabilities, actionable OS-level blocking, and trusted data sources.

This was proven highly difficult, and to harm the speed of progress, not only for development but for future developers.

Setup isn't automatable without long human intervention, if it's bypassing SIP, secure boot, TPM requirements, signing requirements and a lot of hurdles that the OS providers position, making cross-kernel development un-productive to say the least.

Moreover, CrowdStrike has shown us ( [CrowdStrike issue impacting Windows endpoints causing an 0x50 or 0x7E error message on a blue screen](https://support.microsoft.com/en-us/topic/kb5042421-crowdstrike-issue-impacting-windows-endpoints-causing-an-0x50-or-0x7e-error-message-on-a-blue-screen-b1c700e0-7317-4e95-aeee-5d67dd35b92f) ) that kernel level protection has its downfalls and can lead to crashes and unexpected behavior.

An alternative is to have a user-space process, that proves reliable by enforcing sophisticated anti-tampering mechanisms from user-space. Even though the agent will be killable rather easily by an admin, it can still employ tricks and multiple detection fallbacks to fight this, and meeting an EDR standard without leaving user-space.

## Considered Options

- Kernel-oriented agents (Minifilter driver, Driver extensions, etc)
- User-space agents with sophisticated anti-tampering

## Decision Outcome

Chosen option: "User-space agents with sophisticated anti-tampering", because it enables rapid cross-platform development without kernel-level complexity, maintains EDR functionality through userspace APIs, and avoids the operational risks demonstrated by kernel-level protection failures like the CrowdStrike incident.

### Decision Outcome Visualization
```mermaid
flowchart TB
    A[EDR Agent<br/>Userspace Process] --> B{Platform Detection}
    
    B -->|macOS| C[macOS APIs<br/>ps, top, lsof]
    B -->|Linux| D[Linux APIs<br/>/proc, netstat]
    B -->|Windows| E[Windows APIs<br/>tasklist, netstat]
    
    C --> F[Process Monitor]
    D --> F
    E --> F
    
    F --> G[Event Collection]
    G --> H[Local Analysis]
    H --> I{Threat Detected?}
    
    I -->|Yes| J[Alert Control Server]
    I -->|No| K[Continue Monitoring]
    
    J --> L[Control Server<br/>Backend]
    K --> F
    
    L --> M[Dashboard<br/>Frontend]
    
    N[Anti-Tampering<br/>Mechanisms] -.Protects.-> A
    N -.Protects.-> F
    N -.Protects.-> G

    classDef agent fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#e2e8f0
    classDef platform fill:#1a202c,stroke:#2d3748,stroke-width:1px,color:#cbd5e0
    classDef decision fill:#2b6cb0,stroke:#3182ce,stroke-width:2px,color:#e2e8f0
    classDef protection fill:#22543d,stroke:#2f855a,stroke-width:2px,color:#9ae6b4
    classDef server fill:#742a2a,stroke:#9b2c2c,stroke-width:2px,color:#feb2b2

    class A,N agent
    class C,D,E,F,G,H,K platform
    class B,I decision
    class L,M server
```

### Consequences

- Good, because development velocity increases dramatically without kernel driver signing and testing overhead
- Good, because cross-platform testing is fully automated through VM orchestration (Tart for macOS, quickemu for Linux/Windows)
- Good, because userspace agents avoid system crashes and boot loops that plague kernel-level protection
- Good, because security posture remains strong through sophisticated anti-tampering mechanisms and process monitoring
- Good, because deployment is simpler without requiring kernel module signatures or secure boot bypasses
- Good, because debugging is significantly easier with standard userspace tools
- Bad, because agents can be terminated by privileged users more easily than kernel components
- Bad, because some deep system visibility requires elevated privileges or workarounds
- Bad, because anti-tampering mechanisms must be implemented in userspace rather than kernel-protected memory
