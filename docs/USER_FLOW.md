<!-- user worklow.md -->
# User flow

SecAi accepts evidence through either the Alibaba Cloud integration or the lightweight browser snippet. Both paths enter the same durable investigation pipeline, but only trusted Alibaba server evidence can authorize a network response.

```mermaid
flowchart TD
    Owner(["Website Owner"])
    Connect["Connects website<br/>+ deploys Alibaba setup"]

    subgraph Sources["Evidence Sources"]
        direction LR
        Browser["Browser Snippet<br/>live site events"]
        Cloud["Alibaba Cloud SLS<br/>server logs"]
    end

    Detect["SecAi Detects<br/>Suspicious Activity"]

    subgraph Agents["Qwen Agent Team"]
        direction LR
        Investigator["Investigator<br/>gathers evidence"]
        Reviewer{"Reviewer<br/>challenges finding"}
        Responder["Responder<br/>writes report + action"]
    end

    Close["Closed<br/>no report"]
    Report[("Incident Report<br/>+ Recommended Action")]

    subgraph Notify["Owner Notified"]
        direction LR
        Dashboard["SecAi Dashboard"]
        Discord["Discord Alert"]
    end

    Decision{"Owner<br/>Decision"}
    Execute["Qwen Executor<br/>calls guarded MCP tool"]
    Apply["Alibaba Cloud<br/>applies protection"]
    Expire["Expires or<br/>owner removes"]
    Reject["No cloud<br/>change"]

    Owner --> Connect --> Sources
    Browser --> Detect
    Cloud --> Detect
    Detect --> Investigator --> Reviewer
    Reviewer -->|"weak evidence"| Close
    Reviewer -->|"strong evidence"| Responder --> Report
    Report --> Dashboard
    Report --> Discord
    Dashboard --> Decision
    Discord --> Decision
    Decision -->|Approve| Execute --> Apply --> Expire
    Decision -->|Reject| Reject/
```
