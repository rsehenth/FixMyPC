# Changelog

## Unreleased - Stage 11.1: Git publication audit and documentation

### Changed
- License: the owner chose the PolyForm Noncommercial License 1.0.0. `LICENSE` now holds the unmodified official text
  (replacing the draft MIT text); `SKILL.md` uses `license: PolyForm-Noncommercial-1.0.0`; READMEs and `NOTICE.md`
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
