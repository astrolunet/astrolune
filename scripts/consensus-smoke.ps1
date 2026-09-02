# Four-validator quorum smoke test.

param(
    [string]$Preset = "dev"
)

$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $PSScriptRoot
$Alnode = Join-Path $Root "build\$Preset\bin\alnode.exe"
$Work = Join-Path $Root "build\consensus-smoke"

if (-not (Test-Path $Alnode)) {
    Write-Host "FAIL: $Alnode not found - build first" -ForegroundColor Red
    exit 1
}

$Seeds = @(("31" * 32), ("32" * 32), ("33" * 32), ("34" * 32))
$P2pPorts = @(46101, 46102, 46103, 46104)
$RpcPorts = @(46201, 46202, 46203, 46204)
$Processes = @()
$Failures = 0
$script:RequestId = 1

function Check($Name, $Condition, $Detail) {
    if ($Condition) {
        Write-Host ("  ok   {0}" -f $Name) -ForegroundColor Green
    } else {
        Write-Host ("  FAIL {0}" -f $Name) -ForegroundColor Red
        if ($Detail) {
            Write-Host ("       -> {0}" -f $Detail) -ForegroundColor DarkYellow
        }
        $script:Failures++
    }
}

function Rpc($Port, $Body) {
    $file = Join-Path $Work ("request-{0}.json" -f $script:RequestId++)
    Set-Content -Encoding Ascii -Path $file -Value $Body
    return curl.exe -s -X POST "http://127.0.0.1:$Port" `
        -H "Content-Type: application/json" --data-binary "@$file"
}

function Wait-For([scriptblock]$Probe, $Seconds, $What) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $script:LastProbe = & $Probe
        if ($script:LastProbe) { return $true }
        Start-Sleep -Milliseconds 250
    }
    Write-Host "  timeout waiting for: $What" -ForegroundColor Yellow
    return $false
}

function Start-Validator($Index, $Genesis, $PublicKeys, $Peers) {
    $dir = Join-Path $Work ("node-{0}" -f $Index)
    $args = @('run', $Genesis, '--no-config', '--datadir', $dir,
        '--p2p', ("127.0.0.1:{0}" -f $P2pPorts[$Index]),
        '--rpc', ("127.0.0.1:{0}" -f $RpcPorts[$Index]),
        '--proposer-seed', $Seeds[$Index], '--interval', '800',
        '--round-timeout', '1200', '--allow-insecure-crypto', '--unsafe-rpc')
    foreach ($key in $PublicKeys) { $args += @('--validator', $key) }
    foreach ($peer in $Peers) { $args += @('--peer', $peer) }
    $out = Join-Path $Work ("node-{0}.out" -f $Index)
    $err = Join-Path $Work ("node-{0}.err" -f $Index)
    return Start-Process -FilePath $Alnode -ArgumentList $args -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $out `
        -RedirectStandardError $err
}

Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Work | Out-Null
Write-Host "== astrolune four-validator consensus smoke =="

$Addresses = @()
$PublicKeys = @()
for ($i = 0; $i -lt 4; $i++) {
    $keyInfo = & $Alnode keygen --seed $Seeds[$i]
    $Addresses += ($keyInfo | Select-String "^address ").ToString().Split(" ")[1]
    $PublicKeys += ($keyInfo | Select-String "^public_key ").ToString().Split(" ")[1]
}

$Genesis = Join-Path $Work "genesis.bin"
& $Alnode init-genesis $Genesis 7331 `
    ("{0}=1000000000000000000" -f $Addresses[0]) `
    ("{0}=1000000000" -f $Addresses[1]) 2>$null | Out-Null
Check "four validator identities and genesis created" `
    ((Test-Path $Genesis) -and $PublicKeys.Count -eq 4)

try {
    $p0 = Start-Validator 0 $Genesis $PublicKeys @(
        "127.0.0.1:$($P2pPorts[1])", "127.0.0.1:$($P2pPorts[2])")
    $p1 = Start-Validator 1 $Genesis $PublicKeys @("127.0.0.1:$($P2pPorts[0])")
    $p2 = Start-Validator 2 $Genesis $PublicKeys @("127.0.0.1:$($P2pPorts[0])")
    $Processes = @($p0, $p1, $p2)
    Check "three validators running" `
        (($Processes | Where-Object { $_ -and -not $_.HasExited }).Count -eq 3)

    $meshed = Wait-For {
        $info0 = Rpc $RpcPorts[0] '{"jsonrpc":"2.0","id":1,"method":"get_info"}'
        $info1 = Rpc $RpcPorts[1] '{"jsonrpc":"2.0","id":9,"method":"get_info"}'
        $info2 = Rpc $RpcPorts[2] '{"jsonrpc":"2.0","id":10,"method":"get_info"}'
        return ($info0 -match '"peers":[1-9]' -and
                $info1 -match '"peers":[1-9]' -and
                $info2 -match '"peers":[1-9]')
    } 20 "three-validator connectivity"
    Check "three live validators connected" $meshed

    $reply = Rpc $RpcPorts[0] `
        ('{"jsonrpc":"2.0","id":2,"method":"transfer","params":' +
         '{"to":"' + $Addresses[1] + '","amount":"1000"}}')
    Check "transaction accepted with one validator offline" ($reply -match '"hash"') $reply

    $finalized = Wait-For {
        $info0 = Rpc $RpcPorts[0] '{"jsonrpc":"2.0","id":3,"method":"get_info"}'
        $info2 = Rpc $RpcPorts[2] '{"jsonrpc":"2.0","id":4,"method":"get_info"}'
        if ($info0 -notmatch '"height":(\d+)') { return $false }
        $height0 = $Matches[1]
        if ($info2 -notmatch '"height":(\d+)') { return $false }
        return $height0 -eq $Matches[1] -and $info0 -match '"mempool":0'
    } 30 "quorum finality with one validator offline"
    Check "three of four validators finalize" $finalized

    Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue
    Wait-Process -Id $p2.Id -Timeout 5 -ErrorAction SilentlyContinue
    $Processes = @($p0, $p1)
    Start-Sleep -Milliseconds 1500
    Check "second validator is offline" $p2.HasExited

    $before = Rpc $RpcPorts[0] '{"jsonrpc":"2.0","id":6,"method":"get_info"}'
    $heightBefore = if ($before -match '"height":(\d+)') { $Matches[1] } else { "" }
    $reply = Rpc $RpcPorts[0] `
        ('{"jsonrpc":"2.0","id":7,"method":"transfer","params":' +
         '{"to":"' + $Addresses[1] + '","amount":"1"}}')
    Check "transaction accepted below quorum" ($reply -match '"hash"') $reply
    Start-Sleep -Milliseconds 6500
    $after = Rpc $RpcPorts[0] '{"jsonrpc":"2.0","id":8,"method":"get_info"}'
    $heightAfter = if ($after -match '"height":(\d+)') { $Matches[1] } else { "" }
    Check "two of four validators do not finalize" `
        (($heightBefore -ne "") -and ($heightAfter -eq $heightBefore)) $after
    Check "transaction remains pending below quorum" ($after -match '"mempool":1') $after
}
finally {
    foreach ($process in $Processes) {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ""
if ($Failures -eq 0) {
    Write-Host "CONSENSUS SMOKE PASSED" -ForegroundColor Green
    exit 0
}

Write-Host "CONSENSUS SMOKE FAILED ($Failures assertion(s))" -ForegroundColor Red
foreach ($i in 0..2) {
    $err = Join-Path $Work ("node-{0}.err" -f $i)
    if (Test-Path $err) {
        Write-Host ("--- validator {0} stderr ---" -f $i) -ForegroundColor Yellow
        Get-Content $err | Select-Object -First 30 | Write-Host
    }
}
exit 1
