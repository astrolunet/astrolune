# Astrolune two-node smoke test.
#
# Boots a real devnet on loopback: genesis with prefunded identities, two
# daemons connected over P2P, an RPC-initiated transfer on node A, and block
# propagation until node B's state reflects it. One command, one report:
#
#   powershell -ExecutionPolicy Bypass -File scripts\smoke.ps1
#
# Exits 0 when every assertion holds; any failure prints the collected node
# logs and exits 1. Requires only the built binaries (dev preset paths).

param(
    # Preset build directory whose bin\ contains alnode.exe; the dev preset
    # is the default for local runs, CI passes its own.
    [string]$Preset = "dev"
)

$ErrorActionPreference = "Continue"  # native stderr warnings must not abort

$Root    = Split-Path -Parent $PSScriptRoot
$Alnode  = Join-Path $Root "build\$Preset\bin\alnode.exe"
$Trocto  = Join-Path $Root "build\$Preset\bin\trocto.exe"
$Counter = Join-Path $Root "examples\counter.tc"
$Smoke   = Join-Path $Root "build\smoke"

if (-not (Test-Path $Alnode)) {
    Write-Host "FAIL: $Alnode not found - build first (scripts\build.bat)" -ForegroundColor Red
    exit 1
}

# Deterministic devnet identities: same seeds, same addresses, every run.
$SeedA = "11" * 32
$SeedB = "22" * 32
$PortA = 45101; $RpcA = 45201
$PortB = 45102; $RpcB = 45202

$Failures = 0
function Check($Name, $Condition, $Detail) {
    if ($Condition) {
        Write-Host ("  ok   {0}" -f $Name) -ForegroundColor Green
    } else {
        Write-Host ("  FAIL {0}" -f $Name) -ForegroundColor Red
        if ($Detail) { Write-Host ("       -> {0}" -f $Detail) -ForegroundColor DarkYellow }
        $script:Failures++
    }
}

function Rpc($Port, $Body) {
    $file = Join-Node $Smoke ("req-{0}.json" -f $global:reqId++)
    Set-Content -Encoding Ascii -Path $file -Value $Body
    return curl.exe -s -X POST "http://127.0.0.1:$Port" `
        -H "Content-Type: application/json" --data-binary "@$file"
}

# PowerShell lacks a per-call unique name helper here; simple counter file.
$global:reqId = 1
function Join-Node($Base, $Leaf) { Join-Path $Base $Leaf }

function Start-Node($Dir, $NodeArgs, $OutTag) {
    $out = Join-Path $Smoke "$OutTag.out"
    $err = Join-Path $Smoke "$OutTag.err"
    return Start-Process -FilePath $Alnode -ArgumentList $NodeArgs `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err
}

function Wait-For([scriptblock]$Probe, $Seconds, $What) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $script:lastProbeOutput = & $Probe
        if ($script:lastProbeOutput) { return $true }
        Start-Sleep -Milliseconds 250
    }
    Write-Host "  timeout waiting for: $What" -ForegroundColor Yellow
    if ($script:lastProbeOutput) {
        Write-Host "       last: $($script:lastProbeOutput)" -ForegroundColor DarkYellow
    }
    return $false
}

# --- Reset ----------------------------------------------------------------

Get-Process alnode -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 400
Remove-Item -Recurse -Force $Smoke -ErrorAction SilentlyContinue
New-Item -ItemType Directory $Smoke | Out-Null

Write-Host "== astrolune smoke =="

# --- Identities and genesis ------------------------------------------------

$KeyInfoA = & $Alnode keygen --seed $SeedA
$KeyInfoB = & $Alnode keygen --seed $SeedB
$AddrA = ($KeyInfoA | Select-String "^address ").ToString().Split(" ")[1]
$AddrB = ($KeyInfoB | Select-String "^address ").ToString().Split(" ")[1]
$PubA = ($KeyInfoA | Select-String "^public_key ").ToString().Split(" ")[1]
$PubB = ($KeyInfoB | Select-String "^public_key ").ToString().Split(" ")[1]
Check "keygen derives stable addresses" (($AddrA -like "al1*") -and ($AddrA.Length -ge 58) -and ($AddrB -like "al1*"))

$Genesis = Join-Path $Smoke "genesis.bin"
& $Alnode init-genesis $Genesis 1337 "$AddrA=1000000000000000000" "$AddrB=5000000000000" 2>$null | Out-Null
Check "genesis with allocations created" (Test-Path $Genesis)

# --- Launch ----------------------------------------------------------------

$DirA = Join-Path $Smoke "nodeA"
$DirB = Join-Path $Smoke "nodeB"
$NodeBArgs = @('run', $Genesis, '--datadir', $DirB,
    '--p2p', "127.0.0.1:$PortB", '--rpc', "127.0.0.1:$RpcB",
    '--peer', "127.0.0.1:$PortA", '--proposer-seed', $SeedB,
    '--interval', '1000', '--round-timeout', '1500',
    '--validator', $PubA, '--validator', $PubB,
    '--allow-insecure-crypto', '--unsafe-rpc')
$pA = Start-Node $DirA @('run', $Genesis, '--datadir', $DirA,
    '--p2p', "127.0.0.1:$PortA", '--rpc', "127.0.0.1:$RpcA",
    '--proposer-seed', $SeedA, '--interval', '1000',
    '--round-timeout', '1500',
    '--validator', $PubA, '--validator', $PubB,
    '--allow-insecure-crypto', '--unsafe-rpc') "a"
$pB = Start-Node $DirB $NodeBArgs "b"

try {
    # --- Peering -------------------------------------------------------------

    Check "both nodes running" (($null -ne $pA) -and (-not $pA.HasExited) -and ($null -ne $pB) -and (-not $pB.HasExited))

    $peered = Wait-For { (Rpc $RpcB '{"jsonrpc":"2.0","id":1,"method":"get_info"}') -match '"peers":1' } 15 "peer handshake"
    Check "nodes peer over P2P" $peered

    # --- Transfer A -> B -----------------------------------------------------

    $Amount = "25000000000"
    $reply = Rpc $RpcA ('{"jsonrpc":"2.0","id":2,"method":"transfer","params":' +
                        '{"to":"' + $AddrB + '","amount":"' + $Amount + '"}}')
    Check "transfer accepted into mempool" ($reply -match '"hash"')

    # --- Propagation and execution on B ---------------------------------------

    $expected = [uint64]"5000000000000" + [uint64]$Amount
    $settled = Wait-For {
        $acc = Rpc $RpcB ('{"jsonrpc":"2.0","id":3,"method":"get_account",' +
                          '"params":{"address":"' + $AddrB + '"}}')
        return ($acc -match ('"balance":' + $expected))
    } 20 "block propagation and execution"
    Check "transfer executed on remote node" $settled

    # --- Chain agreement --------------------------------------------------------

    $infoA = Rpc $RpcA '{"jsonrpc":"2.0","id":4,"method":"get_info"}'
    $infoB = Rpc $RpcB '{"jsonrpc":"2.0","id":5,"method":"get_info"}'
    $hA = if ($infoA -match '"height":(\d+)') { $Matches[1] } else { "" }
    $hB = if ($infoB -match '"height":(\d+)') { $Matches[1] } else { "" }
    Check "heights agree across nodes" (($hA -ne "") -and ($hA -eq $hB))
    # Height starts at 0 for the first produced block; inclusion of the
    # transfer is proven by the mempool draining instead.
    Check "produced block included the transfer" ($infoA -match '"mempool":0')

    $gA = if ($infoA -match '"genesis":"0x([0-9a-f]+)"') { $Matches[1] } else { "" }
    $gB = if ($infoB -match '"genesis":"0x([0-9a-f]+)"') { $Matches[1] } else { "" }
    Check "same genesis binding" ($gA -eq $gB)

    Stop-Process -Id $pB.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    $finalityLog = Join-Path $DirB "finality.log"
    $finalitySize = (Get-Item $finalityLog).Length
    $stream = [System.IO.File]::Open($finalityLog,
        [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    [void]$stream.Seek(0, [System.IO.SeekOrigin]::End)
    $stream.Write([byte[]](0x41, 0x4c, 0x46, 0x43, 0x01), 0, 5)
    $stream.Dispose()
    $pB = Start-Node $DirB $NodeBArgs "b-restart"
    $restarted = Wait-For {
        $probe = Rpc $RpcB '{"jsonrpc":"2.0","id":6,"method":"get_info"}'
        return ($probe -match '"height":' -and $probe -match '"peers":')
    } 15 "validator restart"
    Check "validator restarts from finalized storage" $restarted
    Check "recovery truncates an incomplete finality record" `
        ((Get-Item $finalityLog).Length -eq $finalitySize)
    $recovered = Rpc $RpcB ('{"jsonrpc":"2.0","id":7,"method":"get_account",' +
                            '"params":{"address":"' + $AddrB + '"}}')
    Check "finalized state survives restart" ($recovered -match ('"balance":' + $expected))

    # --- Contract deployment (Trocto -> container -> DEPLOY tx) --------------

    if (-not (Test-Path $Trocto)) {
        Write-Host "  FAIL trocto binary not found" -ForegroundColor Red
        $script:Failures++
    } else {
        $counterBin = Join-Path $Smoke "counter.bin"
        & $Trocto $Counter -o $counterBin | Out-Null
        Check "trocto compiles counter contract" (Test-Path $counterBin)

        # Nonces must track everything this signer already sent on chain.
        $addrA = $AddrA
        $getNonce = {
            param($Port, $Owner)
            $acc = Rpc $Port ('{"jsonrpc":"2.0","id":90,"method":"get_account",' +
                              '"params":{"address":"' + $Owner + '"}}')
            if ($acc -match '"nonce":(\d+)') { return [int]$Matches[1] }
            return 0
        }
        $deployNonce = & $getNonce $RpcA $addrA

        # The core derives the contract address from (deployer, tx nonce,
        # code hash): the prediction must use the deploy's actual nonce.
        $contract = (& $Alnode contract-address $counterBin --seed $SeedA --nonce $deployNonce)
        Check "contract address derived" ($contract -like "al1*")

        & $Alnode make-tx deploy $counterBin -o (Join-Path $Smoke "deploy.txhex") --seed $SeedA --nonce $deployNonce --chain-id 1337 --value 1000000000 | Out-Null
        $deployHex = Get-Content (Join-Path $Smoke "deploy.txhex")
        '{"jsonrpc":"2.0","id":10,"method":"send_raw_transaction","params":{"data":"0x' + $deployHex + '"}}' |
            Set-Content -Encoding Ascii (Join-Path $Smoke "deploy.json")
        $deployReply = Rpc $RpcA (Get-Content (Join-Path $Smoke "deploy.json") -Raw).Trim()
        Check "deploy transaction accepted" ($deployReply -match '"hash"') $deployReply

        # Wait for a block containing it, then read state through node B.
        $deployed = Wait-For {
            $sim = Rpc $RpcB ('{"jsonrpc":"2.0","id":11,"method":"dry_run_call",' +
                              '"params":{"to":"' + $contract +
                              '","entrypoint":2}}')
            return ($sim -match '"status":"ok"')
        } 25 "contract deployed and readable from peer"
        Check "contract deployed on chain" $deployed

        $getZero = Rpc $RpcB ('{"jsonrpc":"2.0","id":12,"method":"dry_run_call",' +
                              '"params":{"to":"' + $contract + '","entrypoint":2}}')
        Check "counter starts at zero" ($getZero -match '"data":"0x0000000000000000"')

        # inc(5) submitted to A; executed in a block; visible via B.
        # inc(5) submitted to A; executed in a block; visible via B.
        $incNonce = & $getNonce $RpcA $addrA
        & $Alnode make-tx call $contract 1 -a 5 -o (Join-Path $Smoke "inc.txhex") --seed $SeedA --nonce $incNonce --chain-id 1337 | Out-Null
        $incHex = Get-Content (Join-Path $Smoke "inc.txhex")
        '{"jsonrpc":"2.0","id":13,"method":"send_raw_transaction","params":{"data":"0x' + $incHex + '"}}' |
            Set-Content -Encoding Ascii (Join-Path $Smoke "inc.json")
        $incReply = Rpc $RpcA (Get-Content (Join-Path $Smoke "inc.json") -Raw).Trim()
        Check "increment accepted into mempool" ($incReply -match '"hash"') $incReply

        $counted = Wait-For {
            $simA = Rpc $RpcA ('{"jsonrpc":"2.0","id":14,"method":"dry_run_call",' +
                               '"params":{"to":"' + $contract +
                               '","entrypoint":2}}')
            $simB = Rpc $RpcB ('{"jsonrpc":"2.0","id":15,"method":"dry_run_call",' +
                               '"params":{"to":"' + $contract +
                               '","entrypoint":2}}')
            Write-Host ("       [get] A=" + ($simA -replace '\s+', ' ') +
                        "  B=" + ($simB -replace '\s+', ' ')) -ForegroundColor DarkGray
            return ($simB -match '"data":"0x0500000000000000"')
        } 10 "state change propagated and readable"
        Check "on-chain counter equals 5 via remote node" $counted

        Stop-Process -Id $pB.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $pB.Id -Timeout 5 -ErrorAction SilentlyContinue
        $disconnected = Wait-For {
            (Rpc $RpcA '{"jsonrpc":"2.0","id":16,"method":"get_info"}') -match '"peers":0'
        } 10 "validator disconnect"
        Check "validator disconnect is observed" $disconnected
        Start-Sleep -Milliseconds 500
        $beforePartition = Rpc $RpcA '{"jsonrpc":"2.0","id":19,"method":"get_info"}'
        $partitionHeight = if ($beforePartition -match '"height":(\d+)') {
            $Matches[1]
        } else { "" }
        $rollbackReply = Rpc $RpcA ('{"jsonrpc":"2.0","id":17,"method":"transfer","params":' +
                                    '{"to":"' + $AddrB + '","amount":"1"}}')
        Check "transaction accepted before quorum loss" ($rollbackReply -match '"hash"')
        Start-Sleep -Milliseconds 4500
        $afterPartition = Rpc $RpcA '{"jsonrpc":"2.0","id":18,"method":"get_info"}'
        $afterHeight = if ($afterPartition -match '"height":(\d+)') {
            $Matches[1]
        } else { "" }
        Check "block is not finalized without quorum" `
            (($partitionHeight -ne "") -and ($afterHeight -eq $partitionHeight))
        Check "round rollback restores the mempool" ($afterPartition -match '"mempool":1')
    }
}
finally {
    Get-Process alnode -ErrorAction SilentlyContinue | Stop-Process -Force
}

Write-Host ""
if ($Failures -eq 0) {
    Write-Host "SMOKE PASSED" -ForegroundColor Green
    exit 0
}
Write-Host "SMOKE FAILED ($Failures assertion(s))" -ForegroundColor Red
foreach ($tag in @("a", "b")) {
    $err = Join-Path $Smoke "$tag.err"
    if (Test-Path $err) {
        Write-Host "--- node $tag stderr ---" -ForegroundColor Yellow
        Get-Content $err | Select-Object -First 20 | Write-Host
    }
}
exit 1
