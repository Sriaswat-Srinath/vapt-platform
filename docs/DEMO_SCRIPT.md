# Stakeholder demonstration — the one journey to rehearse

One scenario, end to end, in the order a stakeholder will understand it. Roughly 12 minutes.

**Say this first, before anything else:** the target is **OWASP Juice Shop and a static mock
portal, both synthetic lab applications running on this laptop**. Nothing in this demonstration
touches a Brakes India system, and the platform is built so that it *cannot* — you will see it
refuse.

---

## Before the room

```bash
make lab-up net-up                 # lab + application plane
make db-migrate db-seed            # schema and seed data
make api-publish frontend-publish  # loopback-only forwarders
make lab-check                     # containment, measured
make m9-readiness                  # what is and is not ready, honestly
```

Open `http://127.0.0.1:5173`, sign in, and leave the dashboard on **Ask the analyst**.
Have a terminal visible for the two commands in §3 and §9.

---

## 1. The problem (1 min, no screen)

Scanners produce noise. A report that lists five findings implies "these are the problems", which
is almost never true. This platform spends most of its effort on two things scanners don't: *may
I touch this target*, and *what did I not look at*.

## 2. The application, and that there is more than one (1 min)

Sidebar: switch **MOCK-WEB-001 → MOCK-WEB-002** and back. Every screen follows the selection.
Point out they are different applications with **separate authorisation documents** — signing one
grants nothing for the other.

## 3. It refuses (2 min) — *the most important moment*

**Scope** screen → *Check the gate chain* → **Check**.

Thirteen gates, with the failing ones named:

* gate 1 — scanner execution is disabled
* gate 2 — host hygiene fails (a foreign service on this machine)
* gate 5 — the authorisation document is an **unsigned draft**

Then, in the terminal:

```bash
./scripts/prove_authorisation_tamper.sh
```

PASS with the approved digest → **DENY** after an edit → PASS when reverted. Editing a signed
authorisation stops scanning. We measure that rather than claim it.

> If asked "can you scan our website?" — the answer is **no, and here is the code that stops it**:
> a real domain cannot even be registered, and the component that talks to the target has no route
> to the internet. Show `make net-verify`: 118 probes.

## 4. Discovery (1 min)

**Assessments** → *Discover surface*. Endpoints, parameters, forms, cookies, and **candidate
tests** — surfaces worth examining, explicitly **not** findings, with the intrusive ones marked as
needing an approved profile and two approvals.

## 5. Assessment (1 min)

Start an assessment. Watch the state and the timeline. Cancel one to show cancellation is real
(measured at 1.6 s), and note the job is then marked **partial coverage**.

## 6. Findings (2 min)

**Findings**. Open one and show, in this order:

1. **Provenance** — adapter, rule id, payload digest.
2. **The deterministic rule** that set the validation state. *No model decided this.*
3. **Evidence**, redacted, rendered as escaped text.
4. A **false positive** — the scanner said missing, the stored response contradicts it.

## 7. Coverage (2 min) — *the differentiator*

**Coverage**. Of 12 priority categories: 5 detected, 1 partial, 5 surface-only, 1 with no
capability at all — each row naming what blocks it.

> "A report that doesn't tell you what it couldn't check is misleading you. This one does."

## 8. Ask the analyst (2 min)

**Ask the analyst**, then in sequence:

* *"What vulnerabilities were discovered?"* → note the **read list_findings** chip and the
  **cites f1, f2…** chips.
* *"Explain the most serious confirmed finding."* → it keeps context; no need to repeat anything.
* *"Which categories could this assessment not check?"*

Then say what it **cannot** do: every tool it has is a read. There is no tool that starts, stops
or changes an assessment, so the question "could the AI run a scan?" has a structural answer, not
a policy one. Show the *What it can read* panel.

## 9. The report (1 min)

**Reports** → generate → open the PDF. Show the **coverage section** and the **limitations**,
which are computed, not written:

> "N of 12 Tier-1 categories were NOT assessable by this build… their absence from this report is
> not evidence of their absence in the target."

## 10. Close (30 s)

Three claims, each demonstrated rather than asserted:

1. **It refuses** — thirteen gates, measured containment, a tamper-proof authorisation chain.
2. **It reasons about evidence** — deterministic validation with provenance, and an AI that
   explains findings while citing them.
3. **It is honest** — every report states what it could not look at.

---

## What to say when asked

**"Has this found real vulnerabilities?"**
Not yet. Every finding here comes from hand-authored scanner-shaped fixtures. The first genuine
scan needs a signed authorisation, a second approver, and one environment issue resolved — by
design, and the platform shows exactly what is outstanding (`make m9-readiness`).

**"Is the AI making the security decisions?"**
No. It proposes and explains; it cites what it read. Validation states, severities, CVSS and scope
are deterministic Python. The AI's tools are all reads.

**"Can it scan our production site?"**
Not as built, deliberately. Adding an authorised external target would be a scoped change with its
own authorisation and a target-scoped egress path — a decision, not a switch.

**"How do we know the isolation works?"**
It is measured, not asserted — 118 network probes and 46 lab probes — and there are scripts that
deliberately break each control to prove the check *can* fail.

---

## Do not improvise

Do not enable a flag, sign a document, or point anything at a real host to make a moment land
better. The refusals **are** the product. A demo that bypasses them demonstrates the opposite of
what is being sold.
