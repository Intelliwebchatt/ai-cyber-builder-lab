# AI Cyber Builder Lab

Hands-on cybersecurity and generative AI projects built with AI-assisted development, free-tier tools, and practical system design.

## Purpose

This repository turns formal study, certification preparation, and prior professional experience into reviewable cybersecurity evidence. Each project is designed to show the full work cycle: define the problem, build a safe lab, collect evidence, analyze findings, recommend remediation, validate the result, and explain what was learned.

The long-term focus is the intersection of:

- cyber investigations and digital forensics
- security operations and incident response
- CJIS and public-safety technology
- operational technology and critical infrastructure
- application security and automation
- AI security, governance, and risk

## Current status

| Area | Status | Next evidence |
|---|---|---|
| Repository foundation | In progress | Review and merge the foundation pull request |
| Mission 001 | Scaffolded | Run the synthetic investigation and complete the case files |
| Networking foundation | Planned | Network diagram and packet-analysis lab |
| Certification preparation | Planned | Networking study followed by Security+ |
| Degree integration | Planned | One original portfolio artifact per relevant course |

## Career tracks

| Track | What this repository will demonstrate |
|---|---|
| [Investigations and DFIR](01-investigations-and-dfir/) | Evidence handling, timelines, host artifacts, forensic reasoning, and defensible reporting |
| [SOC and incident response](02-soc-and-incident-response/) | Log analysis, alert triage, detection rules, containment, recovery, and lessons learned |
| [CJIS and public-safety security](03-cjis-and-public-safety-security/) | Access control, auditability, sensitive-data handling, incident planning, and operational continuity |
| [OT and critical infrastructure](04-ot-and-critical-infrastructure/) | Safety-aware threat modeling, segmentation, monitoring, resilience, and recovery |
| [Application security](05-application-security/) | Secure design, API protection, testing, remediation, and secure software delivery |
| [AI security and governance](06-ai-security-and-governance/) | AI threat modeling, prompt-injection testing, data protection, governance, and risk decisions |

## Evidence standard

Every completed project should include:

1. A clear problem statement and authorized scope.
2. A reproducible lab or synthetic dataset.
3. Architecture or data-flow documentation.
4. Collected evidence with provenance and integrity notes.
5. Analysis that separates facts, assumptions, and conclusions.
6. Findings mapped to an established framework when useful.
7. Prioritized remediation with validation steps.
8. A technical report and a concise executive summary.
9. A personal reflection explaining decisions, limitations, and next improvements.

See the reusable [project template](docs/PROJECT_TEMPLATE.md).

## Mission 001: Phishing and PowerShell investigation

The first mission is a safe, fictional investigation of suspicious email and PowerShell activity. The repository provides a synthetic event dataset, a small Python analysis tool, case-file templates, and tests. Completing the mission requires running the tool, validating its output, documenting the evidence, and writing an original conclusion.

[Open Mission 001](01-investigations-and-dfir/mission-001-phishing-powershell/)

## Degree and certification integration

- [Degree, project, and certification map](docs/DEGREE_CERT_PROJECT_MAP.md)
- [Certification roadmap](docs/CERTIFICATION_ROADMAP.md)
- [Career evidence map](docs/CAREER_EVIDENCE_MAP.md)

Coursework may inspire an independent extension, but graded prompts, supplied solutions, restricted lab materials, and instructor-owned content do not belong in this repository.

## Responsible AI disclosure

AI may assist with planning, research, scaffolding, code review, test generation, and editing. The repository owner remains responsible for running the work, validating every claim, understanding the code, documenting limitations, and writing the final analysis in their own voice.

## Safety and privacy

All projects are defensive, authorized, and isolated. They use synthetic, public, or explicitly permitted data. Real investigative records, credentials, secrets, personal data, customer data, and active-case information are prohibited.

Read the full [ethics and safety policy](docs/ETHICS_AND_SAFETY.md).

## License

Code is available under the repository's MIT License. Reports, diagrams, and written case materials should be treated as portfolio content unless a file states otherwise.
