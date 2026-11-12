# Scanner Integration Interfaces

## 1. Adapter protocol (`app/scanners/base.py`)

```python
class Capabilities(BaseModel):
    name: str
    version: str
    supports_passive: bool
    supports_active: bool
    supports_spider: bool
    supports_pause: bool
    supports_cancel: bool
    emits_request_response: bool

class ScanJobSpec(BaseModel):          # built ONLY from a persisted allow ScopeDecision
    job_id: UUID
    asset: AssetSnapshot               # hostname, protocol, port, base_path
    pinned_ips: list[IPv4Address | IPv6Address]
    profile: ScanProfileSnapshot       # budgets, policies, exclusions, rule denylist
    seed_urls: list[HttpUrl]           # from the discovery inventory
    excluded_patterns: list[str]
    auth: AuthRecipe | None            # named credential ref, never a literal secret

class ScannerHandle(BaseModel):
    job_id: UUID
    external_ids: dict[str, str]       # e.g. {"context": "7", "scan": "12"}

class ScannerProgress(BaseModel):
    phase: ScanPhase
    percent: int | None
    requests_made: int
    alerts_seen: int
    is_running: bool
    messages: list[str]

class RawObservationBatch(BaseModel):
    cursor: str | None                 # resumable incremental collection
    items: list[RawObservation]        # verbatim payload + hashes

class ScannerAdapter(Protocol):
    def capabilities(self) -> Capabilities: ...
    async def preflight(self, spec: ScanJobSpec) -> PreflightResult: ...
    async def start(self, spec: ScanJobSpec) -> ScannerHandle: ...
    async def poll(self, handle: ScannerHandle) -> ScannerProgress: ...
    async def pause(self, handle: ScannerHandle) -> None: ...
    async def resume(self, handle: ScannerHandle) -> None: ...
    async def cancel(self, handle: ScannerHandle) -> CancelResult: ...
    async def collect(self, handle: ScannerHandle,
                      cursor: str | None) -> RawObservationBatch: ...
    async def teardown(self, handle: ScannerHandle) -> None: ...

    # pure, no I/O, unit-tested against recorded fixtures
    def normalize(self, obs: RawObservation) -> NormalizedFinding | None: ...
```

Contract rules:
- `start()` must refuse any spec whose `ScopeDecision` is not `allow` — the adapter re-checks rather
  than trusting the caller (belt and braces).
- Adapters never write to `findings`; they return raw observations. Normalisation is a separate,
  pure step so re-normalising historical scans with an improved mapper is possible and auditable.
- `cancel()` returns `CancelResult{confirmed_stopped: bool}`; unconfirmed cancellation fails the job.
- All adapters are registered in `scanners/registry.py` by name+version; `profile.adapter_name`
  selects one. Default registry contents in the MVP: `mock` (default), `zap`.

## 2. Mock adapter (default, used by all tests)

Replays recorded ZAP JSON fixtures from `tests/fixtures/zap/` against a fake clock, with injectable
behaviours: slow start, partial results, mid-scan cancellation, malformed alert, duplicate alert,
alert for an out-of-scope URL (must be dropped by normalisation + audited). No network, no
containers — so the full pipeline is testable in CI without ZAP or Juice Shop.

## 3. ZAP adapter

- Transport: ZAP REST API over the `lab` network, `ZAP_API_KEY` required, `apikey` on every call.
- Per job: create a **context** with include/exclude regexes derived from the scope rules and
  `excluded_patterns`; set `connection.timeoutInSecs`, thread counts and the per-host delay from the
  profile budgets; load the pinned ZAP **scan policy** (`lab/zap/zap-baseline-policy.xml`) with the
  rule denylist applied; disable all active rules for passive-only profiles.
- Phases: `spider` (depth/children-capped) → `passive` (wait for the passive queue to drain) →
  `active` (only when the profile and approval allow it) → `collect`.
- Collection: `/JSON/alert/view/alertsByRiskSummary` for progress, `/JSON/alert/view/alerts` paginated
  with `baseurl` filter for records, plus `/JSON/core/view/messages` for request/response pairs that
  become `evidence`. Each alert is stored verbatim as one `raw_observations` row.
- Mapping (`zap/mapping.py`): `pluginId` → `vuln_catalogue.key`, ZAP risk → platform `severity`,
  ZAP confidence → platform `confidence`. The mapping table is explicit and versioned; an unmapped
  `pluginId` produces a finding with `catalogue_key = null`, `severity` from a conservative default,
  and `validation_state='candidate'` — it is **never** dropped silently and is surfaced in a
  "unmapped detections" report section.
- Teardown: `stopScan`, `removeContext`, `newSession` so sessions never bleed between jobs.

## 4. Nuclei adapter (later milestone)

`subprocess` with an argument array (never `shell=True`), `-target` restricted to pinned IP + Host
header, `-t` limited to a vendored, reviewed template subset (no `dos`, `fuzzing`, `intrusive` tags),
`-rate-limit`/`-timeout`/`-concurrency` from the profile, JSONL stdout → raw observations. Runs in
the same `lab` network with the same L2 process restrictions.

## 5. Normalisation and dedup

`fingerprint = sha256(canonical(asset_id, catalogue_key_or_rule_id, normalized_url_path,
http_method, parameter_name, evidence_class))`

- Query **values** are excluded; parameter **names** are included — so the same reflected-parameter
  issue across different payloads collapses to one finding, while two different parameters stay
  distinct.
- A repeat fingerprint increments `occurrence_count`, updates `last_seen_at`, appends a
  `finding_observations` link, and preserves the existing `validation_state` unless the evidence class
  changes (which re-opens it to `candidate` with a recorded reason).
- Findings whose `affected_url` is out of scope are discarded with an audit entry — a scanner alert
  about a third-party host must never enter the findings table.

## 6. Open integration decisions

- **ZAP daemon reuse vs per-job container.** Daemon reuse is faster and simpler; per-job containers
  give stronger blast-radius isolation and trivially correct teardown. Proposal: daemon in the MVP
  with strict session/context teardown, switch to per-job containers in M11 hardening if session
  bleed appears. (Needs your call — see `OPEN_DECISIONS.md` D4.)
- **Authenticated scanning of Juice Shop** in the MVP (login script + session token handling) or defer
  to a later milestone. Proposal: defer; discovery records auth entry points, scanning stays
  unauthenticated until M12. (D6.)
