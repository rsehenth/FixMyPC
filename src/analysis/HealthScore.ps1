# =====================================================================
# FIX MY PC - HealthScore.ps1
#
# Deterministic 0-100 score, fully explainable:
# - score = 100 * (sum of eligible weights - deductions) / sum of eligible
#   weights. A category is eligible only if a base rule with penalty > 0
#   exists for it AND one of its base checks produced evidence; otherwise
#   it is excluded (excludedReason) and contributes no points (FMP-01).
# - Only 'finding' states with penalty > 0 deduct.
# - riskLevel (critical/elevated/none_detected/undetermined) is separate
#   from status (availability) and confidence (data quality). A proven
#   critical storage failure caps the score at riskGates.critical.scoreCap.
# - Category penalties are capped at the category weight.
# - Rules sharing a dedupeGroup count once (highest penalty wins).
# - unknown / access_denied / unsupported / not_collected / error NEVER
#   deduct and never imply health.
# - The base metric uses the same central set of checks (rules whose
#   modes include 'simple') in BOTH audit modes; full-mode rules are
#   analysis-only and never penalize.
# - Coverage below the configured thresholds yields 'provisional' or
#   'unavailable' status - a 100 score with weak coverage is never
#   presented as excellent health.
# =====================================================================

# Identifies the formula, so consumers can tell scores apart across versions.
#   1   - v0.1.0 original: weights were ceilings, uncovered categories counted as healthy.
#   2.0 - FMP-01: eligibility + renormalization, riskLevel/riskReasons, critical score cap.
# Rule calibration (severities, penalties in rules.json) is versioned by rules.json "version", not by this value.
$script:FmpScoreAlgorithmVersion = '2.0'

function Get-FmpHealthScore {
    param(
        [Parameter(Mandatory)][object]$Analysis,   # output of Invoke-FmpRules
        [Parameter(Mandatory)][object]$RuleConfig,
        [object]$Modules = $null                   # module records (for failure detection)
    )
    $weights = [ordered]@{}
    $weightsTotal = [double]0
    foreach ($p in (Get-FmpEntries (Get-FmpValue $RuleConfig 'weights'))) {
        $weight = [double]$p.Value
        if ([double]::IsNaN($weight) -or [double]::IsInfinity($weight) -or $weight -lt 0 -or $weight -gt 100) {
            throw 'Category weights must be finite and between 0 and 100.'
        }
        $weights[$p.Key] = $weight
        $weightsTotal += $weight
    }
    if ([Math]::Abs($weightsTotal - 100) -gt 0.000001) { throw 'Category weights must add up to 100.' }
    $provBelow = [double](Get-FmpValue -Data $RuleConfig -Path 'coverage.provisionalBelowPct' -Default 60)
    $unavBelow = [double](Get-FmpValue -Data $RuleConfig -Path 'coverage.unavailableBelowPct' -Default 35)

    if (-not (0 -le $unavBelow -and $unavBelow -le $provBelow -and $provBelow -le 100)) {
        throw 'Coverage limits must be ordered between 0 and 100.'
    }
    $criticalCap = $null
    $rawCap = Get-FmpValue -Data $RuleConfig -Path 'riskGates.critical.scoreCap'
    if ($null -ne $rawCap) {
        $criticalCap = Get-FmpRuleNumber $rawCap -Max 100
        if ($null -eq $criticalCap) { throw 'riskGates.critical.scoreCap must be a number between 0 and 100.' }
    }
    # Categories that can lose points at all: at least one base ('simple') rule with penalty > 0.
    $penalizable = @{}
    foreach ($r in @(Get-FmpValue -Data $RuleConfig -Path 'rules')) {
        if (@(Get-FmpValue -Data $r -Path 'modes') -notcontains 'simple') { continue }
        $rulePenalty = Get-FmpRuleNumber (Get-FmpValue -Data $r -Path 'penalty')
        if ($null -ne $rulePenalty -and $rulePenalty -gt 0) { $penalizable[[string](Get-FmpValue -Data $r -Path 'category')] = $true }
    }
    $categoryCoverage = @{}
    foreach ($category in $weights.Keys) {
        $categoryCoverage[$category] = @{ applicable = 0; covered = 0 }
    }

    $applicable = 0
    $attempted = 0
    $covered = 0
    $inconclusive = 0
    $errorCount = 0
    $seen = @{}
    foreach ($c in @(Get-FmpValue $Analysis 'checks')) {
        $id = [string](Get-FmpValue $c 'id')
        if ((Get-FmpValue $c 'analysisOnly') -eq $true -or $id -eq '' -or $seen.ContainsKey($id)) { continue }
        $state = [string](Get-FmpValue $c 'state')
        $seen[$id] = $state
        $cat = [string](Get-FmpValue $c 'category')
        if ($state -notin @('pass', 'finding')) { $inconclusive++ }
        if ($state -in @('unsupported', 'not_collected')) { continue }
        $applicable++
        $bucket = $categoryCoverage[$cat]
        if ($null -ne $bucket) { $categoryCoverage[$cat]['applicable']++ }
        if ($state -in @('pass', 'finding', 'unknown', 'access_denied', 'error')) { $attempted++ }
        if ($state -in @('pass', 'finding')) {
            $covered++
            if ($null -ne $bucket) { $categoryCoverage[$cat]['covered']++ }
        }
        if ($state -eq 'error') { $errorCount++ }
    }

    # ---- Dedupe + per-category capped penalties ----
    $appliedByCategory = [ordered]@{}
    $penaltyItems = New-Object System.Collections.Generic.List[object]
    foreach ($cat in $weights.Keys) { $appliedByCategory[$cat] = [double]0 }

    $groups = @{}
    foreach ($f in @(Get-FmpValue $Analysis 'findings')) {
        if ((Get-FmpValue $f 'analysisOnly') -eq $true -or (Get-FmpValue $f 'severity') -eq 'info') { continue }
        $ruleId = [string](Get-FmpValue $f 'id')
        if ($ruleId -eq '' -or $seen[$ruleId] -ne 'finding') { continue }
        $pen = Get-FmpRuleNumber (Get-FmpValue $f 'penalty')
        if ($null -eq $pen -or $pen -le 0) { continue }
        $cat = [string](Get-FmpValue -Data $f -Path 'category')
        if (-not $weights.Contains($cat)) { continue }
        $grp = Get-FmpValue -Data $f -Path 'dedupeGroup'
        $key = if ($grp) { $cat + '::' + $grp } else { $cat + '::' + [string](Get-FmpValue -Data $f -Path 'id') }
        if (-not $groups.ContainsKey($key) -or $pen -gt $groups[$key].penalty) {
            $groups[$key] = @{ category = $cat; penalty = $pen; id = [string](Get-FmpValue -Data $f -Path 'id') }
        }
    }
    foreach ($key in ($groups.Keys | Sort-Object)) {
        $g = $groups[$key]
        $capped = [Math]::Min($g.penalty, ([double]$weights[$g.category] - $appliedByCategory[$g.category]))
        if ($capped -le 0) { continue }
        $appliedByCategory[$g.category] += $capped
        $penaltyItems.Add([ordered]@{ ruleId = $g.id; category = $g.category; points = $capped })
    }

    # ---- Eligibility + renormalization ----
    # A category contributes points only when it can be penalized by a base
    # rule AND produced evidence in this run. Otherwise it is excluded from
    # the denominator instead of being counted as fully healthy.
    $categoryBreakdown = New-Object System.Collections.Generic.List[object]
    $totalDeduction = [double]0
    $eligibleWeight = [double]0
    $keptWeight = [double]0
    foreach ($cat in $weights.Keys) {
        $weight = [double]$weights[$cat]
        $applied = [Math]::Min($appliedByCategory[$cat], $weight)
        $excludedReason = $null
        if ($weight -le 0) { $excludedReason = 'zero_weight' }
        elseif (-not $penalizable.ContainsKey($cat)) { $excludedReason = 'no_base_rules' }
        elseif ($categoryCoverage[$cat].covered -lt 1) { $excludedReason = 'no_evidence' }
        if ($null -eq $excludedReason) {
            $eligibleWeight += $weight
            $keptWeight += ($weight - $applied)
            $totalDeduction += $applied
        }
        $categoryBreakdown.Add([ordered]@{
            category  = $cat
            weight    = $weight
            eligible  = ($null -eq $excludedReason)
            excludedReason = $excludedReason
            deduction = [Math]::Round($applied, 1)
            remaining = [Math]::Round($weight - $applied, 1)
            coveredChecks = $categoryCoverage[$cat].covered
            applicableChecks = $categoryCoverage[$cat].applicable
        })
    }

    $score = $null
    if ($eligibleWeight -gt 0) {
        $score = [Math]::Round(100 * $keptWeight / $eligibleWeight, 0)
        if ($score -lt 0) { $score = 0 }
        if ($score -gt 100) { $score = 100 }
    }

    # ---- Diagnostic risk (independent from availability and confidence) ----
    $criticalIds = New-Object System.Collections.Generic.List[string]
    $elevatedIds = New-Object System.Collections.Generic.List[string]
    foreach ($f in @(Get-FmpValue $Analysis 'findings')) {
        $ruleId = [string](Get-FmpValue $f 'id')
        if ((Get-FmpValue $f 'analysisOnly') -eq $true -or $ruleId -eq '' -or $seen[$ruleId] -ne 'finding') { continue }
        if ((Get-FmpValue $f 'riskGate') -ceq 'critical') {
            if (-not $criticalIds.Contains($ruleId)) { $criticalIds.Add($ruleId) }
            continue
        }
        $pen = Get-FmpRuleNumber (Get-FmpValue $f 'penalty')
        if ((Get-FmpValue $f 'severity') -ne 'info' -and $null -ne $pen -and $pen -gt 0 -and -not $elevatedIds.Contains($ruleId)) { $elevatedIds.Add($ruleId) }
    }
    $criticalIds.Sort()
    $elevatedIds.Sort()

    # ---- Coverage & status ----
    # Inconclusive checks ('unknown') do NOT count as covered: missing
    # evidence is neither health nor failure, and must keep the score
    # from looking complete.
    $coveragePct = $null
    if ($applicable -gt 0) { $coveragePct = [Math]::Round(($covered / $applicable) * 100, 1) }

    # Overall confidence: any inconclusive check degrades it; errors make it low.
    $overall = 'high'
    if ($inconclusive -gt 0 -or $covered -ne $applicable) { $overall = 'medium' }
    if ($inconclusive -gt ([Math]::Floor($applicable * 0.4)) -or $errorCount -gt 0) { $overall = 'low' }

    # A failed base module makes the score unavailable only when it feeds a category that can be scored. Startup has no
    # base rule (FMP-01 keeps it outside the score), so its failure cannot invalidate a score it never contributed to.
    $anyModuleFailed = $false
    if ($null -ne $Modules) {
        $moduleCategory = @{ system = 'os'; storage = 'storage'; performance = 'performance'; startup = 'startup' }
        foreach ($m in $Modules) {
            $moduleId = [string](Get-FmpValue $m 'id')
            if ($moduleCategory.ContainsKey($moduleId) -and $penalizable.ContainsKey($moduleCategory[$moduleId]) -and
                (Get-FmpValue $m 'status') -eq 'failed') { $anyModuleFailed = $true }
        }
    }

    $status = 'ok'
    if ($null -eq $coveragePct -or $coveragePct -lt $unavBelow -or $applicable -eq 0 -or $anyModuleFailed -or $null -eq $score) {
        $status = 'unavailable'
    }
    elseif ($coveragePct -lt $provBelow -or $overall -ne 'high') {
        $status = 'provisional'
    }
    if ($status -eq 'unavailable') { $overall = 'low'; $score = $null }

    $riskLevel = 'none_detected'
    $riskReasons = @()
    if ($criticalIds.Count -gt 0) { $riskLevel = 'critical'; $riskReasons = $criticalIds.ToArray() }
    elseif ($elevatedIds.Count -gt 0) { $riskLevel = 'elevated'; $riskReasons = $elevatedIds.ToArray() }
    elseif ($status -eq 'unavailable') { $riskLevel = 'undetermined' }

    # A proven critical failure caps the score: it can never read as normal health.
    $uncappedScore = $score
    $scoreCap = $null
    $capped = $false
    if ($riskLevel -eq 'critical' -and $null -ne $criticalCap) {
        $scoreCap = $criticalCap
        if ($null -ne $score -and $score -gt $criticalCap) { $score = [Math]::Floor($criticalCap); $capped = $true }
    }

    return [ordered]@{
        scoreAlgorithmVersion = $script:FmpScoreAlgorithmVersion
        score             = $score
        uncappedScore     = $uncappedScore
        scoreCap          = $scoreCap
        capped            = $capped
        status            = $status
        confidence        = $overall
        riskLevel         = $riskLevel
        riskReasons       = $riskReasons
        coveragePct       = $coveragePct
        applicableChecks  = $applicable
        attemptedChecks   = $attempted
        coveredChecks     = $covered
        eligibleWeight    = $eligibleWeight
        totalDeduction    = [Math]::Round($totalDeduction, 1)
        categories        = $categoryBreakdown.ToArray()
        penaltyItems      = $penaltyItems.ToArray()
        limitations       = @(
            'The score is a review aid, not a hardware diagnosis, a warranty or a security certification.',
            'Unknown or inaccessible checks never reduce the score - and never prove health.'
        )
        limitationKeys    = @('score.limitation.reviewAid', 'score.limitation.unknownNeverProves')
    }
}
