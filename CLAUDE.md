You are implementing an authorized, defensive web VAPT platform.
 
Engineering rules:
1. Read the project docs before coding. Inspect the existing repository before changing it.
2. Preserve working code. Do not rewrite the application wholesale without a documented reason and explicit approval.
3. Implement one milestone at a time. Do not silently skip acceptance criteria.
4. Scope enforcement, scan safety, risk calculations, validation states and authorization must be deterministic Python code.
5. The LLM may propose actions only from a fixed allowlisted tool catalogue. It may not run shell commands, invent targets, expand scope or override safety controls.
6. Never scan a real target unless a valid written ScopeGrant and approval are present in the application.
7. Default to mock adapters and localhost-only fixtures. Do not contact external targets during tests.
8. Production active scanning is disabled by default. Intrusive tests require explicit approval and an approved profile.
9. Do not implement DoS, destructive tests, persistence, credential theft, brute force, malware, data exfiltration or unrestricted exploitation.
10. Scanner jobs must be asynchronous, cancellable, idempotent and auditable.
11. Use subprocess argument arrays, never shell=True with user input. Pin tool versions and restrict egress.
12. Store raw scanner observations separately from normalized findings. Every finding needs provenance.
13. Never let the LLM set confirmed status, CVSS, EPSS, KEV membership, risk score, scope or rate limits.
14. Add unit and integration tests for every new safety-sensitive feature.
15. After each milestone, run tests, lint/type checks and report: files changed, commands run, pass/fail results, unresolved risks and next milestone.
16. If requirements are ambiguous or an implementation would weaken a safety control, stop and document the issue rather than guessing.
