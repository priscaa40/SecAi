# SecAi Agent

This package is the core Track 4 Autopilot Agent.

The workflow in `workflow.py` connects five Qwen-backed LangGraph nodes:

1. `triage_agent` decides whether ambiguous web activity should become an incident.
2. `supervisor_agent` checks that the triage has enough evidence.
3. `investigator_agent` gathers recent context and can pull fresh Alibaba SLS evidence.
4. `reporter_agent` writes the plain-language incident report.
5. `remediation_agent` recommends an action constrained by site mode, security profile, and approval policy.

`jobs.py` runs the workflow synchronously or in the background. `tools.py` exposes event context, security knowledge, live Alibaba SLS pulls, policy context, NVD, and OSV lookups. `validation.py` rejects invented attack types, missing source IDs, and remediation actions that are not allowed for the selected security profile.
