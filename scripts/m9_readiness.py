#!/usr/bin/env python3
"""M9 readiness: what remains before the first genuine passive assessment.

Reports every precondition with its LIVE state and who must act. It changes
nothing: it signs nothing, enables nothing and starts nothing. A precondition
that this platform must not satisfy itself is marked `human` and stays that way.

Usage: scripts/m9_readiness.py [--json OUT]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8000/api/v1"
DOC = REPO / "lab" / "authorisation" / "MOCK-WEB-001.md"
DOC_REF = "lab/authorisation/MOCK-WEB-001.md"

READY, BLOCKED, UNKNOWN = "READY", "BLOCKED", "UNKNOWN"


def api(path: str, token: str):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:   # noqa: S310 - loopback forwarder
            return json.loads(r.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None


def docker(*args: str) -> str:
    out = subprocess.run(["docker", *args], capture_output=True, text=True)
    return out.stdout.strip()


def signature_filled() -> bool:
    text = DOC.read_text()
    block = text[text.index("## 7."):]
    for row in [r for r in block.splitlines() if r.startswith("|") and "---" not in r][1:]:
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if len(cells) >= 5 and any(cells[1:5]):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    tokens_path = REPO / ".lab-state" / "tokens.json"
    if not tokens_path.exists():
        print("no .lab-state/tokens.json — run `make db-seed`", file=sys.stderr)
        return 2
    tokens = json.loads(tokens_path.read_text())
    # Read-only throughout: the analyst token cannot sign, verify, activate or enable
    # anything, which is the point — this script reports, it never advances the chain.
    analyst = tokens["analyst"]

    checks: list[dict] = []

    def check(name: str, state: str, detail: str, actor: str) -> None:
        checks.append({"check": name, "state": state, "detail": detail, "actor": actor})

    # --- the lab -------------------------------------------------------------
    js = docker("inspect", "vapt_juiceshop", "--format", "{{.State.Health.Status}}")
    zap = docker("inspect", "vapt_zap", "--format", "{{.State.Status}}")
    check("lab target running", READY if js == "healthy" else BLOCKED,
          f"vapt_juiceshop health={js or 'absent'}", "operator: `make lab-up`")
    check("ZAP container running", READY if zap == "running" else BLOCKED,
          f"vapt_zap status={zap or 'absent'}", "operator: `make lab-up`")

    # --- containment and hygiene (gate 2) ------------------------------------
    iso = api("/system/isolation", analyst) or {}
    contained = iso.get("isolation_passed")
    hygiene = iso.get("host_hygiene_passed")
    check("containment (gate 2a)", READY if contained else BLOCKED,
          f"isolation_passed={contained}", "operator: `make lab-check`")
    check("host hygiene (gate 2b)", READY if hygiene else BLOCKED,
          f"host_hygiene_passed={hygiene}; listeners="
          f"{iso.get('host_wildcard_listeners', 'unknown')}",
          "owner of the foreign service: bind it to loopback (ADR-0015)")

    # --- scanner daemon (gate 13) --------------------------------------------
    st = api("/system/scanner/state", analyst) or {}
    zap_state = next((d for d in st.get("daemon_state", [])
                      if d.get("adapter") == "zap"), {})
    dirty = zap_state.get("is_dirty")
    check("ZAP daemon clean (gate 13)", READY if dirty is False else BLOCKED,
          f"adapter={st.get('adapters', {}).get('zap')} is_dirty={dirty} "
          f"reason={zap_state.get('dirty_reason')}",
          "operator: restart ZAP and acknowledge, or enable the adapter so its state is tracked")

    # --- authorisation (gate 5) ----------------------------------------------
    digest = hashlib.sha256(DOC.read_bytes()).hexdigest()
    signed = signature_filled()
    check("authorisation document signed", READY if signed else BLOCKED,
          f"§7 signature table {'filled' if signed else 'EMPTY'}; current digest {digest[:12]}…",
          "HUMAN: sign §7 by hand — nothing in this repository may do it")

    attestations = api(f"/authorisation-documents/attestations?document_ref={DOC_REF}", analyst)
    latest = (attestations or [{}])[0] if attestations else {}
    matches = latest.get("document_sha256") == digest
    check("document digest attested", READY if matches else BLOCKED,
          f"attested={str(latest.get('document_sha256'))[:12]}… current={digest[:12]}…",
          "operator: `make attest-authorisation`")

    assets = api("/assets", analyst) or []
    asset = next((a for a in assets if a["asset_identifier"] == "MOCK-WEB-001"), None)
    grants = api(f"/assets/{asset['id']}/scope-grants", analyst) if asset else []
    grant = (grants or [None])[0]
    gstate = grant["state"] if grant else "none"
    dstate = grant["document_state"] if grant else "none"
    check("scope grant signed+verified", READY if dstate == "signed_verified" else BLOCKED,
          f"document_state={dstate}",
          "admin: POST verify-document with the signed digest (after the signature exists)")
    check("scope grant active", READY if gstate == "active" else BLOCKED,
          f"grant state={gstate}",
          "approver (a SECOND person): POST activate")

    # --- flags ----------------------------------------------------------------
    caps = api("/system/capabilities", analyst) or {}
    exec_on = caps.get("scanner_execution_enabled")
    zap_on = caps.get("zap_adapter_enabled")
    active_on = caps.get("active_scan_enabled")
    check("scanner execution enabled (gate 1)", READY if exec_on else BLOCKED,
          f"SCANNER_EXECUTION_ENABLED={exec_on}",
          "owner: a separate, deliberate configuration decision")
    check("ZAP adapter enabled", READY if zap_on else BLOCKED,
          f"ZAP_ADAPTER_ENABLED={zap_on}", "owner: a separate configuration decision")
    check("active scanning OFF (required)", READY if active_on is False else BLOCKED,
          f"ACTIVE_SCAN_ENABLED={active_on}", "must stay false for M9")

    # --- the gate chain itself -------------------------------------------------
    denied: list[str] = []
    if asset:
        req = urllib.request.Request(
            f"{BASE}/assets/{asset['id']}/scope/validate",
            data=json.dumps({"profile_key": "zap-passive", "path": "/", "method": "GET"}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {analyst}"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:   # noqa: S310
                decision = json.loads(r.read().decode())
            denied = [f"{g['gate']}: {g.get('reason', '')[:80]}"
                      for g in decision["gate_results"] if not g["pass"]]
            check("preflight dry run", READY if not denied else BLOCKED,
                  f"decision={decision['decision']} policy={decision['policy_version']} "
                  f"denying={len(denied)}", "see the gates above")
        except Exception as exc:                                  # noqa: BLE001
            check("preflight dry run", UNKNOWN, f"{type(exc).__name__}: {exc}", "operator")

    blocked = [c for c in checks if c["state"] != READY]
    human = [c for c in blocked if c["actor"].startswith("HUMAN")]

    width = max(len(c["check"]) for c in checks)
    print("\nM9 — first genuine passive assessment: readiness\n")
    for c in checks:
        mark = "ok " if c["state"] == READY else ("-- " if c["state"] == UNKNOWN else "XX ")
        print(f"  {mark}{c['check']:<{width}}  {c['detail']}")
        if c["state"] != READY:
            print(f"     {'':<{width}}  -> {c['actor']}")
    if denied:
        print("\n  gates currently denying:")
        for d in denied:
            print(f"     - {d}")
    print(f"\n  {len(checks) - len(blocked)}/{len(checks)} ready · "
          f"{len(human)} need a person, not this platform\n")

    out = {"checks": checks, "denying_gates": denied,
           "ready": len(checks) - len(blocked), "total": len(checks)}
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(out, indent=2))
    return 0 if not blocked else 1


if __name__ == "__main__":
    sys.exit(main())
