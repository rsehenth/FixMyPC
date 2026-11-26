# Changelog

## Unreleased - artwork provenance and identity

### Added
- `docs/artwork-provenance.md` (runtime package): the C2PA evidence (ChatGPT `gpt-image`, no declared ingredient,
  signatures not validated) and the owner's declaration of 2026-11-26 are recorded separately, along with OpenAI's
  output terms, the limits on copyright in AI output, the per-image hash chain, the rights status and a preliminary
  INPI / WIPO name search.
- Artwork license: by the owner's decision, the nine v2 images and their derived copies are released under the MIT
  License to the extent of the holder's rights. No exclusive rights are claimed, and the AI-generation credit and the
  C2PA record are kept. MIT grants no trademark rights; the FIX MY PC name is kept, and the similar US registration
  "FIX MY PC STORE" (8110109, Nice 37) is on record. The owner approved the edited banner and logo on 2026-11-26, and
  `LEGAL-REVIEW` moved to `resolved` in `distribution-manifest.json` (the V12 check in `tests/Visual.Tests.ps1` now
  requires it there). No professional legal review has taken place.
- `docs/screenshots/readme-*.png`: three new README captures showing the new banner. The historical stage screenshots
  were kept unchanged.

### Changed
- Product subtitle: "Windows Diagnostic & Audit Skill" became **"PC Diagnostic & Audit Skill"**. The banner and logo
  sources had only that text line redrawn (Montserrat, same size, colour and position). Optimized variants, Base64 and
  `assets/optimized/manifest.json` were regenerated; the other seven derivatives came out byte-identical.
  `assets/brand-review.json` and the V12 pins in `tests/Visual.Tests.ps1` follow the new hashes, and the retired hashes
  are blocked from returning. Labels updated in `locales/*.json` (`app.tagline`, `cli.banner.title`,
  `report.brand.product`, `report.brand.bannerAlt`), `fixmypc.ps1`, `src/analysis/Evidence.ps1` (`run.tool`), `SKILL.md`,
  `distribution-manifest.json`, `docs/homologation-plan.md` and the `tool` field of the test fixtures. "Windows" stays
  only in compatibility statements. No diagnostic behaviour changed.
- Samples: the banner and logo payloads and the subtitle text were replaced in place in `samples/*.html`,
  `samples/visual/*.html` and the sample JSON files; nothing else in them changed.
- `NOTICE.md`, `README.md`, `README.pt-BR.md`, `distribution-manifest.json`: record the artwork license, the name
  decision and the owner's visual approval.

## Unreleased - MIT license migration

### Changed
- License: the owner chose the **MIT License** (SPDX `MIT`) as the only license of the current version, with the notice
  `Copyright (c) 2026 Lucas Sehenth`. `LICENSE` holds the standard MIT text; `SKILL.md` uses `license: MIT`;
  `README.md`, `README.pt-BR.md` and `NOTICE.md` describe the MIT License and no longer carry noncommercial
  restrictions or source-available wording. The PolyForm Noncommercial License 1.0.0 no longer applies to this version.
- `NOTICE.md` names the copyright holder, keeps the Microsoft non-affiliation statement, and states that the MIT License
  does not grant rights to the FIX MY PC name, logo or v2 artwork, whose rights remain unrecorded.
- `distribution-manifest.json`: `LICENSE-CHOICE` now records the MIT decision. `LEGAL-REVIEW` stays open, narrowed to
  artwork rights and naming / non-affiliation wording (the copyright holder is now set).

## Unreleased - 2.0 diagnostic evolution (approved for supervised personal use, with caveats)

Previously recorded (2026-11-25): Phases A, B and C were implemented. The consolidated regression recorded 1,481
synthetic assertions with no failures. Supervised `standard` and `deep` audits in a Windows 11 virtual machine were
approved with caveats for personal use. The read-only policy and mandatory per-run consent were preserved.
Physical-hardware validation is pending (GPU, administrator run, `-IncidentAt`, port exhaustion and process cost).
Public distribution remains blocked. See [NOTICE.md](NOTICE.md) and [distribution-manifest.json](distribution-manifest.json).

Original note (before the virtual-machine homologation): not validated on real Windows machines; every new measurement was
tested with synthetic fixtures and mocked providers only.

### Fixed (virtual-machine homologation)
- `service_hosts`: service names inside `svchost` were serialized as `{"Length":n}` in the JSON and shown as
  `System.Collections.Specialized.OrderedDictionary` in the HTML. `Get-FmpServiceHostData` now casts the sorted names to
  `[string[]]` (`src/collectors/Investigations.ps1`); 2 regression assertions in `tests/PhaseBC.Tests.ps1`.

### Added
- Symptom-oriented Full audit: `-Symptom general|boot|slow|crash`, `-ObserveSeconds 15-300` (default per symptom),
  `-DuringProblem yes|no|unknown`. The symptom changes the observation window, the event history (30 days for crashes)
  and the ranking of results.
- Observation collector (`src/collectors/Observation.ps1`, Full audit): CPU, memory (available, commit, hard page
  reads), physical disks (latency, queue, throughput) and per-process CPU/private memory over the window, computed from
  raw CIM perf counter deltas (locale independent). Hard caps on window, interval, samples, disks and processes; time
  budget; per-family states; query cost recorded.
- Windows boot history (`Microsoft-Windows-Diagnostics-Performance/Operational` 100-109, read by field name) and
  Kernel-Power 41 context (bugcheck / power button) in the Full audit. Access denied is reported, never elevated.
- Deterministic diagnosis layer (`src/analysis/Diagnosis.ps1`, `diagnosis` in the JSON): eight questions with evidence
  values, source, window, relevance, confidence, limitations and alternative explanations; up to three key findings;
  conclusion `found|weak|none|insufficient`; safe next steps; list of what could not be verified. Thresholds and the
  symptom relevance matrix in `rules/rules.json` (`diagnosis`).
- `-Plan`: prints the chat authorization request (mode, language, goal, data read, duration estimate, folder, AI
  processing, no repairs, exact command) with a one-run `-ConsentToken`; collects and writes nothing.
- Report: "Investigation result" panel first (plain language; *what we observed / why it matters / what you can do*),
  "Technical details" separator, "Measurements and history" panel. Console prints the same summary.
- `tests/Diagnosis.Tests.ps1`, observation and boot-history suites in `tests/Collector.Tests.ps1`, four synthetic
  fixtures (`diag-slow-use`, `diag-slow-boot`, `diag-crash-recurring`, `diag-healthy-full`).
- **Phase A (synthetic validation at implementation):** per-process committed memory (`commitPrivateMB`), Working Set and private
  Working Set as separate fields; I/O rates from counter deltas with PID-reuse, reset and missing-counter handling;
  groups by executable name with simultaneous totals; closed System event catalog by provider + ID + level with log
  retention; `-IncidentAt` / `-IncidentToleranceMinutes` bound to the consent token; incident timeline and time-correlated
  pairs; findings now separate observed evidence, likely hypothesis and complementary evidence.
- **Phases B and C (synthetic validation at implementation):** closed investigation catalog with deterministic selection,
  two levels, time budgets and stop criteria; GPU driver events and engine/VRAM use; WER 1001 deduplicated by ReportId with
  new vs re-sent failures; TCP counts by state and process with dynamic range and trend; services in top `svchost` hosts;
  `HarddiskN` mapped to current disks; `-Depth standard|deep` bound to the consent token; hypothesis states
  (`supported`, `not_supported`, `inconclusive`, `untested`). Covered by `tests/PhaseBC.Tests.ps1`.

### Changed
- **Scanner (Phases B/C):** new GPU and `MSFT_Net*` classes with a mandatory literal `-Property` allowlist, namespace
  `root\StandardCimv2`, AMD/Intel/WER providers, and `Get-StorageReliabilityCounter` with `-PhysicalDisk` only.
- **Scanner (Phase A):** `Get-WinEvent` accepts `ProviderName` (closed literal list, with `LogName`) and `-Oldest` (only
  with `-MaxEvents 1` and a `LogName` filter); `TimeZoneInfo` local-time checks are allowed in `Common.ps1` only.
- The report column formerly labeled "private memory" now says "private Working Set", which is what it always measured.
- **Consent (migration):** a real run with `-AcceptReadOnlyPolicy` now also needs the `-ConsentToken` printed by `-Plan`
  for exactly that run (scope-bound, 30 minutes, single use); otherwise exit code 3. Interactive terminal and fixture
  runs are unchanged. `Test-FmpCollectionConsent` gained a `TokenState` parameter (default `missing`).
- **Consent single use (Phase 0, gate blocker C1):** a real run now consumes its authorization before any collector:
  it creates the approved output folder (private ACL) and an exclusive `run-reservation.json` (`New-FmpRunReservation`).
  Replays after success, failure or interruption, and concurrent runs with the same token, end with exit 3 and collect
  nothing. An interrupted real run leaves the folder with that file only. Fixture runs are unchanged.
- The score is presented as secondary ("Score, coverage and confidence" section, after the result); its algorithm (2.0)
  and JSON fields are unchanged.
- `SKILL.md` and adapters: `/fixmypc audit` (Claude Code), `$fixmypc` (Codex), welcome text, Quick/Full choice, symptom
  question, single chat confirmation, result explanation rules.
- Scanner allowlist: four raw perf classes, the Diagnostics-Performance log, `ToXml()`, in-memory SHA-256 in Common.ps1.

### Compatibility
- `schemaVersion` stays `1.0.0`: `observation`, `diagnosis`, `run.symptom`, `run.duringProblem`, `run.observeSeconds`
  and `events.bootPerformance`/`events.restartContext` are additive and optional; 1.0 documents still validate and render.
- Phase A fields are additive. `privateMB` keeps its old meaning (private Working Set) and is deprecated in favor of
  `workingSetPrivateMB`. Consent scopes without an incident time are byte-identical to the previous format.

## Unreleased - Stage 11.1: Git publication audit and documentation

### Changed
- License (historical, superseded by the MIT license migration above): the owner chose the PolyForm Noncommercial
  License 1.0.0. `LICENSE` then held the unmodified official text (replacing the draft MIT text); `SKILL.md` uses `license: PolyForm-Noncommercial-1.0.0`; READMEs and `NOTICE.md`
  describe it as source-available (not OSI open source) and free for noncommercial use.
- `NOTICE.md` records third-party components (none bundled) and separates ownership of the name, logo and v2 artwork
  from the software license; both remain open under `LEGAL-REVIEW`.
- `distribution-manifest.json`: `LICENSE-PENDING` removed (consistency across LICENSE, SKILL.md, READMEs and NOTICE.md
  verified); `LEGAL-REVIEW` kept and widened to cover artwork ownership and the copyright holder / Required Notice line.
  `tests/Visual.Tests.ps1` (V12 manifest assertion) updated accordingly.
- `README.md` and `README.pt-BR.md` rewritten: Still in Development / Functional Preview status, verified requirements,
  commands, privacy and AI-service disclosure, limitations, synthetic screenshots only.
- `.gitignore` reviewed: added local-only rule for the Stage 9 real-machine validation record, Python/Node caches,
  virtual environments, IDE and editor files, `.playwright-cli/`, `.codebase-memory/`, backups and extra archive types;
  `.env.example` stays trackable.

## Unreleased - Stage 11: independent release gate fixes

### Changed
- Output folder must not exist yet; the CLI creates it with a protected ACL (current user + SYSTEM, no inheritance
  from the parent), so reports no longer inherit broader access (S11-01). Existing output folders are refused (exit 3).
  Existing ACLs are never changed; `SetAccessControl` stays banned.
- Warnings before consent now flag drives without Windows permissions (FAT/exFAT) and OneDrive folders (S11-02),
  replacing the "outside your profile" heuristic.
- CLI policy text, READMEs, SKILL.md and adapters say that an AI agent running the skill reads the sanitized JSON and
  console output, which its AI service then processes (S11-03).
- `-Help` shows the real default output folder; script header example no longer uses `C:\temp` (S11-04).
- SKILL.md no longer suggests `pwsh`: only Windows PowerShell 5.1 is supported.

## Unreleased - Stage 10: public-release audit, hardening and Print / Save as PDF

### Added
- Report header button **Print / Save as PDF** (`Imprimir / Salvar em PDF`) that opens the browser's native print
  dialog, plus a "Ctrl+P" hint. One static script, authorized only by its SHA-256 in `script-src`; the button stays
  hidden if the script is blocked or altered. Hidden when printing.
- Run.Tests suite R (22 checks) and Visual.Tests suite V13 (print button, hash, CSS).

### Changed
- Default output folder is now `%LOCALAPPDATA%\FixMyPC\fixmypc-<time>-<id>` instead of `out\` inside the install
  folder; without a valid `%LOCALAPPDATA%` and no `-OutDir`, the CLI exits 3. A warning is printed (before consent)
  when the chosen folder is outside the user profile. Permissions are never read or changed.
- Provisional score card no longer says "no problem found" when findings exist.
- Summary uses correct singular/plural and states seconds; module timings show `ms`; event logs with status `ok`
  read "Query completed"; disk health is labelled as reported by Windows and the SMART-unavailable note says it does
  not certify physical integrity; storage-event finding text says events do not prove a physical defect (Volsnap).
- Sharing guidance (CLI, report, READMEs, SKILL.md): optional, user-reviewed, never automatic, anonymization not perfect.
- Sanitizer: dictionary keys are scrubbed of private identifiers; IPv6 addresses are masked; `USERDOMAIN` and
  `USERDNSDOMAIN` join the private identifiers.
- CLI no longer prints the artifact paths during validation (it listed `diagnostic-internal.json` even when not requested).
- README no longer claims PowerShell 7 compatibility; examples use a private output folder.

### Unchanged on purpose
- Rule weights, penalties, thresholds and the score algorithm (`scoreAlgorithmVersion` 2.0). JSON schema unchanged.

## Unreleased - Stage 7.1: v2 identity (FMP-10) and final report polish

### Changed
- All nine assets replaced by the v2 art (no Windows logo, no approval shields or gauges). Old originals, optimized
  variants and Base64 payloads were deleted; their SHA-256 are pinned in `tests/Visual.Tests.ps1` (V12) so they cannot
  return. `tools/Optimize-Assets.ps1` reads the `-v2` sources and records `sourceSha256` in `manifest.json`.
- Score card is tinted by `riskLevel` (critical = red, elevated = amber); the critical explanation uses an error-tone
  callout. Risk badge is a rounded rectangle. Evidence text wraps at spaces. (A left severity bar on findings was tried and removed: the tinted header with icon and text already carries severity.)
- Banner cropped to 260 px on wide screens so the summary sits near the first screen; sticky score card on desktop;
  two-column header metadata on phones; print keeps lead text with the following block.

### Added
- `assets/brand-review.json` (visual brand review bound to each source hash) and Visual suite V12 (pinned hashes,
  stale/retired art, Base64 inside the HTML, size, exact CSP, external URLs, risk tints, FMP-10 gate).
- `tests/fixtures/critical-disk.json` and three more sample states (`none-detected`, `critical`, `access-denied`).
- FMP-10 is closed in `distribution-manifest.json`; license and legal review remain open.

## Stage 7: release preparation (no release created)

### Changed
- Report footer shows a Microsoft non-affiliation notice (PT-BR/EN); the A4 page footer is now localized
  (`report.print.footer`) instead of fixed English text in `style.css`.
- `style.css`: `forced-colors` support (bars use system colors, badges get real borders).

### Added
- `.gitignore`, `distribution-manifest.json` (runtime / development / never-ship groups, release blockers) and
  `tools/Test-DistributionManifest.ps1`.
- `NOTICE.md`: trademark non-affiliation (EN/PT-BR) and pending license decision. `LICENSE` is unchanged and **not**
  confirmed by the owner.

### Known / open
- (Closed in stage 7.1.) FMP-10 remained **open** at this stage: the artwork still contained the Windows logo and green "all clear" shields. No image
  generation/editing tool was available; see `docs/reviews/SONNET-5.5-STAGE7-RELEASE-PREP.md`.

## Unreleased - Stage 6: P2 hardening (FMP-02, 03, 05, 06, 07, 08, 09 and scoring review)

### Security
- Read-only scanner (FMP-02): property/index setters, `++`/`--` and state-changing instance methods
  (`Add`, `Append`, `Clear`, `Remove`, `Replace`, `Sort`, `Stop`) are accepted only on receivers proven to be local data.
  Live-object receivers (`Get-*` results, loop variables, untyped parameters) are rejected
  (`property_setter_not_allowed`, `index_setter_not_allowed`, `receiver_not_proven`). Nested member assignment
  (`a.b.c = x`) must be written `a['b']['c'] = x`.
- Read-only scanner (FMP-03): path-consuming cmdlets accept only allowlisted literals or checked-path variables;
  UNC, device, provider-qualified and sensitive paths, pipeline path input, non-allowlisted event logs / filter keys /
  CIM classes / namespaces are rejected. New runtime twin `Get-FmpSafeRegistryPath` guards the Run/RunOnce and
  Uninstall keys the collectors read. Collectors take a typed `[System.Collections.IDictionary]$ctx`.
- Privacy (FMP-08): sanitized JSON/HTML mask machine/account SIDs (`<SID>`) and per-user service suffixes (`_<LUID>`);
  computer/user names are masked in every string field, not only a fixed field list (identifiers shorter than
  3 characters stay limited to name-like fields).
- Consent (FMP-09): `-AcceptReadOnlyPolicy` documented as a caller declaration that does not prove human
  authorization; per-run consent rules added to SKILL.md and both adapters. No token mechanism added (evaluated in
  `docs/readonly-policy.md`).

### Changed
- Severity scale (FMP-05): `storage.disk_space_critical`, `storage.disk_health_unhealthy` and
  `events.critical_recurring` are now `review_recommended`, so no dedupe group ranks a higher penalty below a lower one.
  Penalties are unchanged.
- `startup.high_count` counts user-facing entries only (Run keys, Startup folders, logon tasks); automatic services are
  reported in `measured.services` and never counted (FMP-06).
- `perf.cpu_sustained_high` (id kept) is an informative observation ("CPU elevada durante a amostragem" /
  "High CPU during the sampling window") with penalty 0 and a `windowSec` value (FMP-07). Fixture scores:
  cpu-ram-spike 91 -> 95; worst case 28 -> 33.
- `healthScore.scoreAlgorithmVersion` (`2.0`) added (optional in the schema). A provisional score now says "no problem
  found in the checks that completed (coverage N%)" instead of the generic scale caption. A failed Startup module no
  longer makes the score unavailable, because Startup has no scored category.

## Unreleased — Stage 5 fixes: FMP-01 (score) and FMP-04 (PT-BR limitations)

### Changed
- Score is renormalized over eligible categories only (a penalizable base rule
  plus evidence in the run). Startup (no base rule in v0.1.0) and categories
  without evidence no longer add free points. Fixture scores changed accordingly
  (demo 82 -> 79, win10-outdated 94 -> 90, cpu-ram-spike 92 -> 91,
  events-mixed 84 -> 81, low-disk 82 -> 49 capped).
- New `healthScore.riskLevel` (critical / elevated / none_detected /
  undetermined) plus `riskReasons`, `uncappedScore`, `scoreCap`, `capped`,
  `eligibleWeight`, and per-category `eligible` / `excludedReason`. A proven
  critical storage failure (`Unhealthy` or SMART `PredictFailure=true`) caps
  the score at `riskGates.critical.scoreCap` (49). The confidence label now
  says "data confidence".
- Limitations are rendered from stable locale keys: `limitationKeys` (rules,
  score) and `limit.<key|localeKey>` + `values` (collectors). Canonical English
  text is unchanged in the JSON. Unknown keys fall back to the canonical text,
  never to the key. Module ids and statuses are shown by localized name.

## Unreleased — Stage 4: visual redesign of the HTML report

### Changed
- Report redesigned: banner header, executive summary (score, coverage,
  confidence, findings by severity, main observations, score by category),
  findings with severity/confidence/evidence/limitations/suggested check,
  hardware cards, usage meters for volumes and RAM, startup tables,
  events with historical/truncation notes, privacy and next steps.
- Official assets embedded as validated `data:` images (optimized variants in
  `assets/optimized/`, 10.8 MB of originals -> 455 KB); text fallback when an
  asset is missing or damaged. CSP now adds `script-src 'none'` and, only when
  images are embedded, `img-src data:`.
- Responsive layout (320-1440 px, tables stack on phones) and A4 print CSS.
- `Get-FmpLocaleString` returns list-valued keys as lists (bullets and steps
  were being fused into one paragraph in the HTML and the CLI).
- Fixes found during the redesign: doubled `%` in the commit-charge line,
  `state.` key leak for missing sub-sections, "no finding" text on empty tables.

### Added
- `tests/Visual.Tests.ps1` (193 assertions, run by `Run.Tests.ps1`).
- `tools/Optimize-Assets.ps1`, `tools/Render-Samples.ps1` (development only).
- `docs/visual-integration.md`, `docs/reviews/SONNET-5.5-VISUAL-REVIEW.md`,
  `docs/screenshots/`, synthetic samples in `samples/` (PT-BR and EN).
- 41 new locale keys per language (337 total, parity kept).


## 0.1.0 — 2026-11-20

Initial version.

### Added
- Read-only collectors: System, Events, Startup, Performance, Storage, Advanced
  (full mode), all passively querying WMI/CIM, event logs (filtered at the
  source), registry and filesystem metadata.
- AST-based read-only policy scanner with per-command/parameter allowlists,
  hard-banned lists, banned .NET method scan and network/Win32_Product text
  scans; pre-execution compliance gate with exit code 2.
- Evidence pipeline: per-module timing, sub-checks, limitations, error
  capture; partial progress allowed.
- Deterministic rules engine (22 conservative rules) with thresholds in
  `rules/rules.json`, dedupe groups and analysis-only (full mode) rules.
- Health score 0–100 with configurable weights, per-category caps, coverage
  and confidence; provisional/unavailable statuses when data is insufficient.
- Privacy layer: field-level redaction (accounts, device ids) plus global
  scrubbing of profile paths, computer names, IPs, MACs, e-mails, GUIDs and
  credential-like strings; sanitized JSON artifact.
- Zero-JavaScript self-contained HTML report (local CSS, CSP, A4 print,
  responsive, accessible), fully HTML-escaped data.
- i18n `pt-BR`/`en` with flat key files, fallback and parity validation.
- `SKILL.md` agent contract plus Claude Code and Codex adapters.
- JSON Schema for diagnostic documents.
- Offline test suite: 128 assertions, 10 synthetic fixtures + forbidden-command
  snippets; XSS, malformed JSON, access-denied and false-reassurance scenarios.
- Synthetic demonstration report in `samples/`.
