$ErrorActionPreference = 'Stop'
$cli = Join-Path $PWD 'target/debug/ghidra-cli.exe'
$root = Join-Path $env:RUNNER_TEMP 'concurrent-language-probe'
New-Item -ItemType Directory -Path $root | Out-Null
$binary = Join-Path $root 'sample.bin'
[IO.File]::WriteAllBytes($binary, [byte[]](0x31, 0xc0, 0xc3))
$sla = Get-ChildItem "$env:LOCALAPPDATA/ghidra-cli/ghidra/*/Ghidra/Processors/x86/data/languages/x86-64.sla"
if (@($sla).Count -ne 1) { throw 'Expected one cached x86-64 language' }
$originalTime = $sla.LastWriteTimeUtc
$failed = $false

for ($attempt = 1; $attempt -le 5; $attempt++) {
    # Reproduce first use after restoring the old cache; do not alter file bytes.
    # Previous iteration's bridges have been stopped before changing this time.
    $sla.LastWriteTimeUtc = $originalTime
    $processes = @()
    $projects = @()
    try {
        foreach ($index in 1, 2) {
            $project = Join-Path $root "project-$attempt-$index"
            $projects += $project
            $start = [Diagnostics.ProcessStartInfo]::new($cli)
            $start.UseShellExecute = $false
            foreach ($argument in @('import', $binary, '--project', $project,
                    '--language', 'x86:LE:64:default', '--loader', 'BinaryLoader',
                    '--base-address', '0x1000', '--no-analyze', '--json')) {
                $start.ArgumentList.Add($argument)
            }
            $processes += [Diagnostics.Process]::Start($start)
        }
        foreach ($process in $processes) {
            if (-not $process.WaitForExit(240000)) {
                $process.Kill($true)
                throw 'Owned import process exceeded 240 seconds'
            }
            Write-Output "Attempt $attempt, PID $($process.Id), exit $($process.ExitCode)"
            if ($process.ExitCode -ne 0) { $failed = $true }
        }
    } finally {
        foreach ($process in $processes) {
            if (-not $process.HasExited) { $process.Kill($true) }
            $process.Dispose()
        }
        foreach ($project in $projects) {
            & $cli bridge stop --project $project --json
            if ($LASTEXITCODE -ne 0) { throw "Could not stop owned project $project" }
        }
    }
    if ($failed) { break }
}
if ($failed) { exit 1 }
