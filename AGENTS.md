# Repository guidance for AI-assisted work

## Mission

Build defensible, employer-reviewable cybersecurity evidence through safe labs, original analysis, and transparent validation.

## Safety boundaries

- Work only with synthetic, public, or explicitly authorized systems and data.
- Never target public infrastructure, third-party accounts, or systems outside the documented lab scope.
- Do not add live credentials, tokens, personal data, customer information, real case evidence, or restricted course material.
- Do not create deployable malware, persistence, credential theft, evasion, destructive actions, or uncontrolled scanning.
- Use reserved example domains and IP address ranges in synthetic scenarios.
- Stop and request clarification when authorization or data provenance is uncertain.

## Project requirements

Every project must document:

- problem and scope
- environment and data provenance
- evidence and integrity controls
- analysis method
- findings and confidence
- remediation and validation
- limitations
- owner-authored reflection

Use `docs/PROJECT_TEMPLATE.md` as the default structure.

## Implementation standards

- Prefer standard-library dependencies when they are sufficient.
- Keep scripts small, readable, and testable.
- Add tests for parsing, detection logic, and failure conditions.
- Use explicit paths and safe defaults.
- Never silently invent evidence or claim that a lab was run when it was only scaffolded.
- Mark incomplete work as `Planned`, `Scaffolded`, or `In progress`.

## Validation

Before marking work complete:

1. Run the documented commands.
2. Run the relevant automated tests.
3. Review generated output against the source evidence.
4. Confirm that no secrets or private data are present.
5. Confirm that README status labels match reality.
