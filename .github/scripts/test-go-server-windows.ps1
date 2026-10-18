param([Parameter(Mandatory = $true)][string]$ResultsDirectory)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This gate must run natively on Windows' }
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$module = Join-Path $repository 'implementations/go/server'
if (Test-Path -LiteralPath $ResultsDirectory) { throw 'Preserve existing test evidence; use a fresh results directory' }
New-Item -ItemType Directory -Path $ResultsDirectory | Out-Null
$commit = git -C $repository rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify tested checkout' }
$scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
$stdout = Join-Path $ResultsDirectory 'tests.jsonl'
$stderr = Join-Path $ResultsDirectory 'stderr.log'
Push-Location $module
try {
    # Module-local toolchain selection may differ from the global Go launcher.
    $platform = go env GOOS
    if ($LASTEXITCODE -ne 0 -or $platform -ne 'windows') { throw 'Expected native Windows Go target' }
    $architecture = go env GOARCH
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read Go architecture' }
    $version = go version
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read Go version' }
    # The entire suite, cache disabled. Keep Go's original per-package timeout:
    # no -run, -short, package filter, increased timeout or serialized workaround.
    & go test -count=1 -json ./... 1> $stdout 2> $stderr
    $testExit = $LASTEXITCODE
} finally { Pop-Location }

$events = @(Get-Content -LiteralPath $stdout | ForEach-Object { $_ | ConvertFrom-Json })
$passed = @($events | Where-Object { $_.Action -eq 'pass' -and $_.Test })
$skipped = @($events | Where-Object { $_.Action -eq 'skip' -and $_.Test })
$failed = @($events | Where-Object Action -eq 'fail')
$requiredNames = @(
    'TestSQLiteBaseSchemaRollsBackBeforeCompatibilityRepair',
    'TestSQLiteBaseSchemaCommitsAndKeepsDurabilitySettings'
)
$requiredPassed = @($passed | Where-Object {
    $_.Package -eq 'github.com/devShuai/specus/implementations/go/server/internal/store' -and $_.Test -in $requiredNames
})
$requiredDistinct = @($requiredPassed.Test | Sort-Object -Unique).Count
$success = $testExit -eq 0 -and $failed.Count -eq 0 -and $requiredPassed.Count -eq 2 -and $requiredDistinct -eq 2
$summary = @{
    success = $success; exitCode = $testExit; sourceCommit = $commit
    platform = $platform; architecture = $architecture; compiler = $version
    runnerScriptSHA256 = $scriptHash; originalDefaultTimeoutUnchanged = $true
    fullSuiteWithoutFilters = $true; requiredSqliteRegressionsPassed = $requiredPassed.Count
    requiredDistinctSqliteRegressionsPassed = $requiredDistinct
    packages = @($events | Where-Object { $_.Action -in @('pass','skip','fail') -and -not $_.Test }).Count
    topLevelPassed = @($passed | Where-Object Test -NotMatch '/').Count
    passedIncludingSubtests = $passed.Count
    skippedOptInTests = @($skipped | Select-Object Package,Test)
    failedEvents = @($failed | Select-Object Package,Test,Action)
}
$summary | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'summary.json') -Encoding utf8NoBOM
Get-Content -LiteralPath $stdout -Tail 30
if ((Get-Item -LiteralPath $stderr).Length) { Get-Content -LiteralPath $stderr -Tail 15 }
if ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash -ne $scriptHash) { throw 'Runner changed during execution' }
if (-not $success) { throw "Native Windows full suite failed (exit $testExit); original JSON and stderr retained" }
Write-Output "Native Windows Go server: $($summary.topLevelPassed) top-level cases passed; $($skipped.Count) opt-in cases skipped, not counted as passes"
