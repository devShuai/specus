[CmdletBinding()]
param(
    [ValidateSet("All", "Primary", "Standby")]
    [string]$Target = "All",
    [string]$ConfigPath = "",
    [switch]$Yes,
    [switch]$DryRun,
    [switch]$ValidateOnly,
    [switch]$SkipBuild,
    [switch]$NoClean,
    [switch]$KeepRemoteTemp
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot "stun-deploy.config.json"
} elseif (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
    $ConfigPath = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $ConfigPath))
}

function Write-DeployLog {
    param([string]$Message)
    Write-Host "[stun-deploy] $Message"
}

function Get-PropertyValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Fallback = $null,
        [switch]$Required
    )
    if ($null -ne $Object) {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property -and $null -ne $property.Value) {
            return $property.Value
        }
    }
    if ($Required) {
        throw "Missing required config field: $Name"
    }
    return $Fallback
}

function Get-MergedValue {
    param(
        [object]$Node,
        [object]$Defaults,
        [string]$Name,
        [object]$Fallback = $null
    )
    $nodeProperty = $Node.PSObject.Properties[$Name]
    if ($null -ne $nodeProperty -and $null -ne $nodeProperty.Value) {
        return $nodeProperty.Value
    }
    $defaultProperty = $Defaults.PSObject.Properties[$Name]
    if ($null -ne $defaultProperty -and $null -ne $defaultProperty.Value) {
        return $defaultProperty.Value
    }
    return $Fallback
}

function ConvertTo-RequiredString {
    param(
        [object]$Value,
        [string]$Field
    )
    $text = if ($null -eq $Value) { "" } else { ([string]$Value).Trim() }
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "$Field must not be empty"
    }
    if ($text.Contains("`r") -or $text.Contains("`n") -or $text.Contains("`0")) {
        throw "$Field contains an unsupported control character"
    }
    return $text
}

function ConvertTo-OptionalString {
    param(
        [object]$Value,
        [string]$Field
    )
    if ($null -eq $Value) {
        return ""
    }
    $text = ([string]$Value).Trim()
    if ($text.Contains("`r") -or $text.Contains("`n") -or $text.Contains("`0")) {
        throw "$Field contains an unsupported control character"
    }
    return $text
}

function ConvertTo-BooleanValue {
    param(
        [object]$Value,
        [string]$Field
    )
    if ($Value -is [bool]) {
        return [bool]$Value
    }
    switch (([string]$Value).Trim().ToLowerInvariant()) {
        "1" { return $true }
        "true" { return $true }
        "yes" { return $true }
        "on" { return $true }
        "0" { return $false }
        "false" { return $false }
        "no" { return $false }
        "off" { return $false }
        default { throw "$Field must be true or false" }
    }
}

function ConvertTo-IntegerValue {
    param(
        [object]$Value,
        [string]$Field,
        [int]$Minimum,
        [int]$Maximum
    )
    try {
        $number = [System.Convert]::ToInt32($Value)
    } catch {
        throw "$Field must be an integer"
    }
    if ($number -lt $Minimum -or $number -gt $Maximum) {
        throw "$Field must be between $Minimum and $Maximum"
    }
    return $number
}

function ConvertTo-IpAddressValue {
    param(
        [string]$Value,
        [string]$Field
    )
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$parsed)) {
        throw "$Field must be an IP literal: $Value"
    }
    return $parsed
}

function Assert-AddressFamilyMatch {
    param(
        [System.Net.IPAddress]$First,
        [System.Net.IPAddress]$Second,
        [string]$Field
    )
    if ($First.AddressFamily -ne $Second.AddressFamily) {
        throw "$Field must use the same address family"
    }
}

function Test-IsDocumentationAddress {
    param([System.Net.IPAddress]$Address)
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $Address.GetAddressBytes()
        return ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 2) -or
            ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) -or
            ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113)
    }
    return $Address.ToString().ToLowerInvariant().StartsWith("2001:db8:")
}

function Test-IsPrivateNetworkAddress {
    param([System.Net.IPAddress]$Address)
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $Address.GetAddressBytes()
        return $bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
    }
    $ipv6 = $Address.GetAddressBytes()
    return ($ipv6[0] -band 0xFE) -eq 0xFC
}

function Assert-SafeText {
    param(
        [string]$Value,
        [string]$Field,
        [string]$Pattern
    )
    if ($Value -notmatch $Pattern) {
        throw "$Field contains unsupported characters"
    }
}

function Format-CommandArgument {
    param([string]$Value)
    if ($Value -match '\s' -or $Value.Contains('"') -or $Value.Contains("'")) {
        return '"' + $Value.Replace('"', '\"') + '"'
    }
    return $Value
}

function Invoke-DeployCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )
    $display = @($Command) + @($Arguments | ForEach-Object { Format-CommandArgument $_ })
    Write-Host ("+ " + ($display -join " "))
    if ($DryRun) {
        return
    }
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Command"
    }
}

function Require-Command {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $found) {
            return $found.Source
        }
    }
    throw "Required command not found: $($Names -join ' or ')"
}

function ConvertTo-EnvBoolean {
    param([bool]$Value)
    if ($Value) { return "true" }
    return "false"
}

function ConvertTo-Base64Secret {
    param(
        [object]$Value,
        [string]$Field
    )
    $text = ConvertTo-RequiredString $Value $Field
    if ($text -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
        throw "$Field must be standard base64"
    }
    try {
        $bytes = [System.Convert]::FromBase64String($text)
    } catch {
        throw "$Field must be standard base64"
    }
    if ($bytes.Length -lt 32 -or $bytes.Length -gt 256) {
        throw "$Field must decode to between 32 and 256 bytes"
    }
    return $text
}

function Write-NodeEnvironment {
    param(
        [object]$Node,
        [string]$Path
    )
    $lines = @(
        "# Generated by deploy/stun-server/remote/deploy.ps1.",
        "# Node: $($Node.Name); role: $($Node.Role); SSH host: $($Node.SshHost)",
        "STUN_PRIMARY_BIND_ADDRESS=$($Node.PrimaryBindAddress)",
        "STUN_PRIMARY_PUBLIC_ADDRESS=$($Node.PrimaryPublicAddress)",
        "STUN_ALTERNATE_BIND_ADDRESS=$($Node.AlternateBindAddress)",
        "STUN_ALTERNATE_PUBLIC_ADDRESS=$($Node.AlternatePublicAddress)",
        "STUN_PRIMARY_PORT=$($Node.PrimaryPort)",
        "STUN_ALTERNATE_PORT=$($Node.AlternatePort)",
        "",
        "STUN_DISTRIBUTED_ENABLED=$(ConvertTo-EnvBoolean $Node.DistributedEnabled)"
    )
    if ($Node.DistributedEnabled) {
        $lines += @(
            "STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT=$($Node.DistributedLocalAddressSlot)",
            "STUN_DISTRIBUTED_STUN_BIND_ADDRESS=$($Node.DistributedStunBindAddress)",
            "STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS=$($Node.DistributedControlBindAddress)",
            "STUN_DISTRIBUTED_CONTROL_PORT=$($Node.DistributedControlPort)",
            "STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS=$($Node.DistributedPeerControlAddress)",
            "STUN_DISTRIBUTED_PEER_CONTROL_PORT=$($Node.DistributedPeerControlPort)",
            "STUN_DISTRIBUTED_SHARED_SECRET=$($Node.DistributedSharedSecret)",
            "STUN_DISTRIBUTED_MAX_CLOCK_SKEW_SECONDS=$($Node.DistributedMaxClockSkewSeconds)",
            "STUN_DISTRIBUTED_REPLAY_CACHE_SIZE=$($Node.DistributedReplayCacheSize)",
            "STUN_DISTRIBUTED_MAX_FORWARD_PACKET_BYTES=$($Node.DistributedMaxForwardPacketBytes)",
            "STUN_DISTRIBUTED_FORWARD_RATE_PER_SECOND=$($Node.DistributedForwardRatePerSecond)",
            "STUN_DISTRIBUTED_FORWARD_BURST=$($Node.DistributedForwardBurst)"
        )
    }
    $lines += @(
        "",
        "STUN_SOFTWARE=$($Node.Software)",
        "STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS=$(ConvertTo-EnvBoolean $Node.LegacySingleIpOtherAddress)",
        "",
        "STUN_RATE_LIMIT_PER_SECOND=$($Node.RateLimitPerSecond)",
        "STUN_RATE_LIMIT_BURST=$($Node.RateLimitBurst)",
        "STUN_GLOBAL_RATE_LIMIT_PER_SECOND=$($Node.GlobalRateLimitPerSecond)",
        "STUN_GLOBAL_RATE_LIMIT_BURST=$($Node.GlobalRateLimitBurst)",
        "STUN_MAX_TRACKED_SOURCES=$($Node.MaxTrackedSources)",
        "STUN_SOURCE_IDLE_SECONDS=$($Node.SourceIdleSeconds)",
        "STUN_MAX_PACKET_BYTES=$($Node.MaxPacketBytes)",
        "STUN_MAX_PADDING_RESPONSE_BYTES=$($Node.MaxPaddingResponseBytes)",
        "",
        "STUN_METRICS_BIND_ADDRESS=$($Node.MetricsBindAddress)",
        "STUN_METRICS_PORT=$($Node.MetricsPort)",
        "",
        "JAVA_OPTS=`"$($Node.JavaOpts)`""
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, (($lines -join "`n") + "`n"), $encoding)
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    $examplePath = Join-Path $PSScriptRoot "stun-deploy.config.example.json"
    throw "STUN deploy config not found: $ConfigPath`nCopy and edit: $examplePath"
}
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path

try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    throw "Invalid JSON config $ConfigPath`: $($_.Exception.Message)"
}

$schemaVersion = ConvertTo-IntegerValue `
    (Get-PropertyValue $config "schemaVersion" 0) "schemaVersion" 1 1
$deployment = Get-PropertyValue $config "deployment" $null -Required
$defaults = Get-PropertyValue $config "defaults" $null -Required
$nodeValues = @(Get-PropertyValue $config "nodes" $null -Required)
if ($nodeValues.Count -eq 0) {
    throw "nodes must contain primary and standby entries"
}

$remoteTempRoot = ConvertTo-RequiredString `
    (Get-PropertyValue $deployment "remoteTempRoot" "/tmp") `
    "deployment.remoteTempRoot"
if ($remoteTempRoot -notmatch '^/(tmp|var/tmp)(/[A-Za-z0-9._-]+)*$' -or $remoteTempRoot.Contains("..")) {
    throw "deployment.remoteTempRoot must be a safe absolute path under /tmp or /var/tmp"
}
$remoteTempRoot = $remoteTempRoot.TrimEnd("/")
$connectTimeout = ConvertTo-IntegerValue `
    (Get-PropertyValue $deployment "sshConnectTimeoutSeconds" 10) `
    "deployment.sshConnectTimeoutSeconds" 1 300
$activeTimeout = ConvertTo-IntegerValue `
    (Get-PropertyValue $deployment "serviceActiveTimeoutSeconds" 25) `
    "deployment.serviceActiveTimeoutSeconds" 5 300
$backupKeep = ConvertTo-IntegerValue `
    (Get-PropertyValue $deployment "backupKeep" 5) `
    "deployment.backupKeep" 1 50

$normalizedNodes = @()
$nodeNames = @{}
$nodeRoles = @{}
$exampleDistributedSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
foreach ($node in $nodeValues) {
    $name = ConvertTo-RequiredString (Get-PropertyValue $node "name" $null -Required) "node.name"
    if ($name -notmatch '^[a-z][a-z0-9-]{0,31}$') {
        throw "node.name must match ^[a-z][a-z0-9-]{0,31}`$: $name"
    }
    if ($nodeNames.ContainsKey($name)) {
        throw "Duplicate node.name: $name"
    }
    $nodeNames[$name] = $true

    $role = (ConvertTo-RequiredString `
        (Get-PropertyValue $node "role" $null -Required) "nodes[$name].role").ToLowerInvariant()
    if ($role -notin @("primary", "standby")) {
        throw "nodes[$name].role must be primary or standby"
    }
    if ($nodeRoles.ContainsKey($role)) {
        throw "Duplicate STUN node role: $role"
    }
    $nodeRoles[$role] = $true

    $enabled = ConvertTo-BooleanValue `
        (Get-PropertyValue $node "enabled" $true) "nodes[$name].enabled"
    $sshHost = ConvertTo-RequiredString `
        (Get-PropertyValue $node "sshHost" $null -Required) "nodes[$name].sshHost"
    if ($sshHost -notmatch '^[A-Za-z0-9][A-Za-z0-9._@-]*$') {
        throw "nodes[$name].sshHost is invalid; put ports and keys in ~/.ssh/config"
    }

    $primaryPublicText = ConvertTo-RequiredString `
        (Get-MergedValue $node $defaults "primaryPublicAddress") `
        "nodes[$name].primaryPublicAddress"
    $alternatePublicText = ConvertTo-OptionalString `
        (Get-MergedValue $node $defaults "alternatePublicAddress" "") `
        "nodes[$name].alternatePublicAddress"
    $primaryPort = ConvertTo-IntegerValue `
        (Get-MergedValue $node $defaults "primaryPort" 3478) `
        "nodes[$name].primaryPort" 1 65535
    $alternatePort = ConvertTo-IntegerValue `
        (Get-MergedValue $node $defaults "alternatePort" 3479) `
        "nodes[$name].alternatePort" 0 65535
    if ($alternatePort -eq $primaryPort) {
        throw "nodes[$name].alternatePort must differ from primaryPort"
    }

    $primaryPublicIp = ConvertTo-IpAddressValue `
        $primaryPublicText "nodes[$name].primaryPublicAddress"
    if ($primaryPublicIp.Equals([System.Net.IPAddress]::Any) -or
        $primaryPublicIp.Equals([System.Net.IPAddress]::IPv6Any)) {
        throw "nodes[$name].primaryPublicAddress cannot be a wildcard address"
    }
    if ([System.Net.IPAddress]::IsLoopback($primaryPublicIp)) {
        throw "nodes[$name].primaryPublicAddress cannot be a loopback address"
    }
    if (-not $DryRun -and -not $ValidateOnly -and
        (Test-IsDocumentationAddress $primaryPublicIp)) {
        throw "nodes[$name].primaryPublicAddress still uses a documentation-only IP"
    }

    $distributedEnabled = ConvertTo-BooleanValue `
        (Get-MergedValue $node $defaults "distributedEnabled" $false) `
        "nodes[$name].distributedEnabled"
    $mode = "basic"
    $primaryBindText = ""
    $alternateBindText = ""
    $distributedLocalSlot = ""
    $distributedStunBindText = ""
    $distributedControlBindText = ""
    $distributedControlPort = 0
    $distributedPeerControlText = ""
    $distributedPeerControlPort = 0
    $distributedSharedSecret = ""
    $distributedMaxClockSkewSeconds = 30
    $distributedReplayCacheSize = 65536
    $distributedMaxForwardPacketBytes = 4096
    $distributedForwardRatePerSecond = 10000
    $distributedForwardBurst = 20000

    if ($distributedEnabled) {
        if ([string]::IsNullOrWhiteSpace($alternatePublicText)) {
            throw "nodes[$name].alternatePublicAddress is required in distributed mode"
        }
        if ($alternatePort -eq 0) {
            throw "nodes[$name].alternatePort must be enabled in distributed mode"
        }
        $alternatePublicIp = ConvertTo-IpAddressValue `
            $alternatePublicText "nodes[$name].alternatePublicAddress"
        if ($alternatePublicIp.Equals([System.Net.IPAddress]::Any) -or
            $alternatePublicIp.Equals([System.Net.IPAddress]::IPv6Any)) {
            throw "nodes[$name].alternatePublicAddress cannot be a wildcard address"
        }
        if ([System.Net.IPAddress]::IsLoopback($alternatePublicIp)) {
            throw "nodes[$name].alternatePublicAddress cannot be a loopback address"
        }
        if (-not $DryRun -and -not $ValidateOnly -and
            (Test-IsDocumentationAddress $alternatePublicIp)) {
            throw "nodes[$name].alternatePublicAddress still uses a documentation-only IP"
        }
        if ($primaryPublicIp.Equals($alternatePublicIp)) {
            throw "nodes[$name] distributed mode requires two distinct public IP addresses"
        }
        Assert-AddressFamilyMatch `
            $primaryPublicIp $alternatePublicIp "nodes[$name] public addresses"

        $distributedStunBindText = ConvertTo-RequiredString `
            (Get-MergedValue $node $defaults "distributedStunBindAddress" "0.0.0.0") `
            "nodes[$name].distributedStunBindAddress"
        $distributedStunBindIp = ConvertTo-IpAddressValue `
            $distributedStunBindText "nodes[$name].distributedStunBindAddress"
        Assert-AddressFamilyMatch `
            $distributedStunBindIp $primaryPublicIp "nodes[$name] STUN bind/public addresses"

        $distributedLocalSlot = (ConvertTo-RequiredString `
            (Get-MergedValue $node $defaults "distributedLocalAddressSlot") `
            "nodes[$name].distributedLocalAddressSlot").ToLowerInvariant()
        if ($distributedLocalSlot -notin @("primary", "alternate")) {
            throw "nodes[$name].distributedLocalAddressSlot must be primary or alternate"
        }
        $expectedSlot = if ($role -eq "primary") { "primary" } else { "alternate" }
        if ($distributedLocalSlot -ne $expectedSlot) {
            throw "nodes[$name] role $role must use distributedLocalAddressSlot=$expectedSlot"
        }

        $distributedControlBindText = ConvertTo-RequiredString `
            (Get-MergedValue $node $defaults "distributedControlBindAddress") `
            "nodes[$name].distributedControlBindAddress"
        $distributedControlBindIp = ConvertTo-IpAddressValue `
            $distributedControlBindText "nodes[$name].distributedControlBindAddress"
        if ($distributedControlBindIp.Equals([System.Net.IPAddress]::Any) -or
            $distributedControlBindIp.Equals([System.Net.IPAddress]::IPv6Any) -or
            [System.Net.IPAddress]::IsLoopback($distributedControlBindIp) -or
            -not (Test-IsPrivateNetworkAddress $distributedControlBindIp)) {
            throw "nodes[$name].distributedControlBindAddress must be an explicit private-network IP"
        }
        $distributedPeerControlText = ConvertTo-RequiredString `
            (Get-MergedValue $node $defaults "distributedPeerControlAddress") `
            "nodes[$name].distributedPeerControlAddress"
        $distributedPeerControlIp = ConvertTo-IpAddressValue `
            $distributedPeerControlText "nodes[$name].distributedPeerControlAddress"
        if ($distributedPeerControlIp.Equals([System.Net.IPAddress]::Any) -or
            $distributedPeerControlIp.Equals([System.Net.IPAddress]::IPv6Any) -or
            [System.Net.IPAddress]::IsLoopback($distributedPeerControlIp) -or
            -not (Test-IsPrivateNetworkAddress $distributedPeerControlIp)) {
            throw "nodes[$name].distributedPeerControlAddress must be an explicit private-network IP"
        }
        if ($distributedControlBindIp.Equals($distributedPeerControlIp)) {
            throw "nodes[$name] distributed control endpoints must use distinct private IP addresses"
        }
        Assert-AddressFamilyMatch `
            $distributedControlBindIp $distributedPeerControlIp `
            "nodes[$name] distributed control addresses"

        $distributedControlPort = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "distributedControlPort" 3480) `
            "nodes[$name].distributedControlPort" 1 65535
        $distributedPeerControlPort = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "distributedPeerControlPort" `
                $distributedControlPort) `
            "nodes[$name].distributedPeerControlPort" 1 65535
        if ($distributedControlPort -in @($primaryPort, $alternatePort) -or
            $distributedPeerControlPort -in @($primaryPort, $alternatePort)) {
            throw "nodes[$name] distributed control ports must differ from public STUN ports"
        }
        $distributedSharedSecret = ConvertTo-Base64Secret `
            (Get-MergedValue $node $defaults "distributedSharedSecret") `
            "nodes[$name].distributedSharedSecret"
        if (-not $DryRun -and -not $ValidateOnly -and
            $distributedSharedSecret -eq $exampleDistributedSecret) {
            throw "nodes[$name].distributedSharedSecret still uses the public example secret"
        }
        $distributedMaxClockSkewSeconds = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "distributedMaxClockSkewSeconds" 30) `
            "nodes[$name].distributedMaxClockSkewSeconds" 1 300
        $distributedReplayCacheSize = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "distributedReplayCacheSize" 65536) `
            "nodes[$name].distributedReplayCacheSize" 1 1000000
        $distributedMaxForwardPacketBytes = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "distributedMaxForwardPacketBytes" 4096) `
            "nodes[$name].distributedMaxForwardPacketBytes" 512 65507
        $distributedForwardRatePerSecond = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "distributedForwardRatePerSecond" 10000) `
            "nodes[$name].distributedForwardRatePerSecond" 1 10000000
        $distributedForwardBurst = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "distributedForwardBurst" 20000) `
            "nodes[$name].distributedForwardBurst" 1 20000000

        $primaryBindIp = $distributedStunBindIp
        $primaryBindText = $distributedStunBindIp.ToString()
        $mode = "distributed-rfc5780"
    } else {
        $primaryBindText = ConvertTo-RequiredString `
            (Get-MergedValue $node $defaults "primaryBindAddress") `
            "nodes[$name].primaryBindAddress"
        $primaryBindIp = ConvertTo-IpAddressValue `
            $primaryBindText "nodes[$name].primaryBindAddress"
        Assert-AddressFamilyMatch `
            $primaryBindIp $primaryPublicIp "nodes[$name].primary address pair"
        $alternateBindText = ConvertTo-OptionalString `
            (Get-MergedValue $node $defaults "alternateBindAddress" "") `
            "nodes[$name].alternateBindAddress"
        if ([string]::IsNullOrWhiteSpace($alternateBindText) -xor
            [string]::IsNullOrWhiteSpace($alternatePublicText)) {
            throw "nodes[$name] must configure alternateBindAddress and alternatePublicAddress together"
        }
        if (-not [string]::IsNullOrWhiteSpace($alternateBindText)) {
            if ($alternatePort -eq 0) {
                throw "nodes[$name].alternatePort must be enabled in RFC 5780 mode"
            }
            $alternateBindIp = ConvertTo-IpAddressValue `
                $alternateBindText "nodes[$name].alternateBindAddress"
            $alternatePublicIp = ConvertTo-IpAddressValue `
                $alternatePublicText "nodes[$name].alternatePublicAddress"
            if ($primaryBindIp.Equals([System.Net.IPAddress]::Any) -or
                $primaryBindIp.Equals([System.Net.IPAddress]::IPv6Any) -or
                $alternateBindIp.Equals([System.Net.IPAddress]::Any) -or
                $alternateBindIp.Equals([System.Net.IPAddress]::IPv6Any)) {
                throw "nodes[$name] RFC 5780 mode requires explicit bind IP addresses"
            }
            if ($alternatePublicIp.Equals([System.Net.IPAddress]::Any) -or
                $alternatePublicIp.Equals([System.Net.IPAddress]::IPv6Any) -or
                [System.Net.IPAddress]::IsLoopback($alternatePublicIp)) {
                throw "nodes[$name].alternatePublicAddress is invalid"
            }
            if (-not $DryRun -and -not $ValidateOnly -and
                (Test-IsDocumentationAddress $alternatePublicIp)) {
                throw "nodes[$name].alternatePublicAddress still uses a documentation-only IP"
            }
            if ($primaryBindIp.Equals($alternateBindIp)) {
                throw "nodes[$name] RFC 5780 mode requires two distinct bind IP addresses"
            }
            if ($primaryPublicIp.Equals($alternatePublicIp)) {
                throw "nodes[$name] RFC 5780 mode requires two distinct public IP addresses"
            }
            Assert-AddressFamilyMatch `
                $alternateBindIp $alternatePublicIp "nodes[$name].alternate address pair"
            Assert-AddressFamilyMatch `
                $primaryPublicIp $alternatePublicIp "nodes[$name] public addresses"
            $mode = "rfc5780"
        }
    }

    $software = ConvertTo-RequiredString `
        (Get-MergedValue $node $defaults "software" "shuai-tunnel-rfc5780-stun") `
        "nodes[$name].software"
    Assert-SafeText $software "nodes[$name].software" `
        '^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,127}$'
    $javaOpts = ConvertTo-RequiredString `
        (Get-MergedValue $node $defaults "javaOpts" `
            "-Xms32m -Xmx128m -XX:+UseG1GC -Dfile.encoding=UTF-8") `
        "nodes[$name].javaOpts"
    Assert-SafeText $javaOpts "nodes[$name].javaOpts" `
        '^[A-Za-z0-9 ._:/+=-]{1,512}$'

    $metricsBindText = ConvertTo-RequiredString `
        (Get-MergedValue $node $defaults "metricsBindAddress" "127.0.0.1") `
        "nodes[$name].metricsBindAddress"
    $metricsBindIp = ConvertTo-IpAddressValue `
        $metricsBindText "nodes[$name].metricsBindAddress"
    if (-not [System.Net.IPAddress]::IsLoopback($metricsBindIp)) {
        throw "nodes[$name].metricsBindAddress must remain on loopback"
    }

    $normalizedNodes += [pscustomobject]@{
        Name = $name
        Role = $role
        Enabled = $enabled
        SshHost = $sshHost
        Mode = $mode
        PrimaryBindAddress = $primaryBindIp.ToString()
        PrimaryPublicAddress = $primaryPublicIp.ToString()
        AlternateBindAddress = if ($mode -eq "rfc5780") { $alternateBindIp.ToString() } else { "" }
        AlternatePublicAddress = if ($mode -in @("rfc5780", "distributed-rfc5780")) {
            $alternatePublicIp.ToString()
        } else { "" }
        PrimaryPort = $primaryPort
        AlternatePort = $alternatePort
        DistributedEnabled = $distributedEnabled
        DistributedLocalAddressSlot = $distributedLocalSlot
        DistributedStunBindAddress = $distributedStunBindText
        DistributedControlBindAddress = $distributedControlBindText
        DistributedControlPort = $distributedControlPort
        DistributedPeerControlAddress = $distributedPeerControlText
        DistributedPeerControlPort = $distributedPeerControlPort
        DistributedSharedSecret = $distributedSharedSecret
        DistributedMaxClockSkewSeconds = $distributedMaxClockSkewSeconds
        DistributedReplayCacheSize = $distributedReplayCacheSize
        DistributedMaxForwardPacketBytes = $distributedMaxForwardPacketBytes
        DistributedForwardRatePerSecond = $distributedForwardRatePerSecond
        DistributedForwardBurst = $distributedForwardBurst
        Software = $software
        LegacySingleIpOtherAddress = ConvertTo-BooleanValue `
            (Get-MergedValue $node $defaults "legacySingleIpOtherAddress" $false) `
            "nodes[$name].legacySingleIpOtherAddress"
        RateLimitPerSecond = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "rateLimitPerSecond" 100) `
            "nodes[$name].rateLimitPerSecond" 1 1000000
        RateLimitBurst = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "rateLimitBurst" 200) `
            "nodes[$name].rateLimitBurst" 1 2000000
        GlobalRateLimitPerSecond = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "globalRateLimitPerSecond" 10000) `
            "nodes[$name].globalRateLimitPerSecond" 1 10000000
        GlobalRateLimitBurst = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "globalRateLimitBurst" 20000) `
            "nodes[$name].globalRateLimitBurst" 1 20000000
        MaxTrackedSources = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "maxTrackedSources" 65536) `
            "nodes[$name].maxTrackedSources" 1 1000000
        SourceIdleSeconds = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "sourceIdleSeconds" 300) `
            "nodes[$name].sourceIdleSeconds" 1 86400
        MaxPacketBytes = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "maxPacketBytes" 65507) `
            "nodes[$name].maxPacketBytes" 20 65507
        MaxPaddingResponseBytes = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "maxPaddingResponseBytes" 1472) `
            "nodes[$name].maxPaddingResponseBytes" 0 65503
        MetricsBindAddress = $metricsBindIp.ToString()
        MetricsPort = ConvertTo-IntegerValue `
            (Get-MergedValue $node $defaults "metricsPort" 9108) `
            "nodes[$name].metricsPort" 0 65535
        JavaOpts = $javaOpts
    }
}

foreach ($requiredRole in @("primary", "standby")) {
    if (-not $nodeRoles.ContainsKey($requiredRole)) {
        throw "Config must define exactly one $requiredRole node"
    }
}

$primaryNode = $normalizedNodes | Where-Object { $_.Role -eq "primary" } | Select-Object -First 1
$standbyNode = $normalizedNodes | Where-Object { $_.Role -eq "standby" } | Select-Object -First 1
if ($primaryNode.DistributedEnabled -or $standbyNode.DistributedEnabled) {
    if (-not $primaryNode.DistributedEnabled -or -not $standbyNode.DistributedEnabled) {
        throw "primary and standby must both enable distributed mode"
    }
    foreach ($field in @(
        "PrimaryPublicAddress",
        "AlternatePublicAddress",
        "PrimaryPort",
        "AlternatePort",
        "DistributedSharedSecret",
        "DistributedMaxClockSkewSeconds",
        "DistributedReplayCacheSize",
        "DistributedMaxForwardPacketBytes",
        "DistributedForwardRatePerSecond",
        "DistributedForwardBurst")) {
        if ($primaryNode.$field -ne $standbyNode.$field) {
            throw "distributed pair field $field must match on primary and standby"
        }
    }
    if ($primaryNode.DistributedPeerControlAddress -ne
        $standbyNode.DistributedControlBindAddress -or
        $primaryNode.DistributedPeerControlPort -ne
        $standbyNode.DistributedControlPort -or
        $standbyNode.DistributedPeerControlAddress -ne
        $primaryNode.DistributedControlBindAddress -or
        $standbyNode.DistributedPeerControlPort -ne
        $primaryNode.DistributedControlPort) {
        throw "distributed control addresses and ports must point to each other"
    }
}

$selectedNodes = @($normalizedNodes | Where-Object {
    $_.Enabled -and ($Target -eq "All" -or $_.Role -eq $Target.ToLowerInvariant())
} | Sort-Object @{ Expression = {
    if ($_.Role -eq "primary") { 0 } else { 1 }
} }, Name)
if ($selectedNodes.Count -eq 0) {
    throw "No enabled STUN node matches target $Target"
}

Write-DeployLog "validated config schema $schemaVersion"
Write-Host "  config: $ConfigPath"
Write-Host "  target: $Target"
foreach ($node in $selectedNodes) {
    $alternate = if ($node.Mode -in @("rfc5780", "distributed-rfc5780")) {
        "$($node.AlternateBindAddress) -> $($node.AlternatePublicAddress)"
    } else {
        "(not configured)"
    }
    Write-Host "  $($node.Role): $($node.SshHost) [$($node.Mode)]"
    if ($node.DistributedEnabled) {
        Write-Host "    public A1: $($node.PrimaryPublicAddress)"
        Write-Host "    public A2: $($node.AlternatePublicAddress)"
        Write-Host "    local:     $($node.DistributedLocalAddressSlot) on $($node.DistributedStunBindAddress)"
        Write-Host "    control:   $($node.DistributedControlBindAddress):$($node.DistributedControlPort) -> $($node.DistributedPeerControlAddress):$($node.DistributedPeerControlPort)"
    } else {
        Write-Host "    primary:   $($node.PrimaryBindAddress) -> $($node.PrimaryPublicAddress)"
        Write-Host "    alternate: $alternate"
    }
    Write-Host "    ports:     $($node.PrimaryPort)/udp, $($node.AlternatePort)/udp"
}

if ($ValidateOnly) {
    Write-DeployLog "configuration is valid"
    return
}

if (-not $DryRun -and -not $Yes) {
    $hosts = ($selectedNodes | ForEach-Object { "$($_.Role)=$($_.SshHost)" }) -join ", "
    $answer = Read-Host "Build and deploy STUN to $hosts? [y/N]"
    if ($answer -notin @("y", "Y", "yes", "YES")) {
        Write-DeployLog "cancelled"
        return
    }
}

$maven = "mvn"
$ssh = "ssh"
$scp = "scp"
if (-not $DryRun) {
    $ssh = Require-Command @("ssh.exe", "ssh")
    $scp = Require-Command @("scp.exe", "scp")
    if (-not $SkipBuild) {
        $maven = Require-Command @("mvn.cmd", "mvn.exe", "mvn")
    }
}

$jarPath = Join-Path $RepoRoot "implementations/java/stun-server/target/stun-server.jar"
if (-not $SkipBuild) {
    $mavenArguments = @("-pl", ":stun-server", "-am", "-Dmaven.test.skip=true")
    if ($NoClean) {
        Write-Warning "Using the explicit non-clean Maven fallback."
        $mavenArguments += "package"
    } else {
        $mavenArguments += @("clean", "package")
    }
    Push-Location $RepoRoot
    try {
        Invoke-DeployCommand $maven $mavenArguments
    } finally {
        Pop-Location
    }
}
if (-not $DryRun -and -not (Test-Path -LiteralPath $jarPath -PathType Leaf)) {
    throw "Deployable STUN JAR not found: $jarPath"
}

$localTempRoot = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ("shuai-stun-deploy-" + [System.Guid]::NewGuid().ToString("N"))
$remoteStates = @()
$deploymentSucceeded = $false

try {
    New-Item -ItemType Directory -Force -Path $localTempRoot | Out-Null
    $environmentFiles = @{}
    foreach ($node in $selectedNodes) {
        $environmentPath = Join-Path $localTempRoot "$($node.Name).env"
        Write-NodeEnvironment $node $environmentPath
        $environmentFiles[$node.Name] = $environmentPath
    }

    $systemdPath = Join-Path $RepoRoot "deploy/stun-server/systemd"
    $sshCommon = @("-o", "ConnectTimeout=$connectTimeout")
    $scpCommon = @("-o", "ConnectTimeout=$connectTimeout")
    $deployTag = if ($DryRun) { "dry-run" } else { Get-Date -Format "yyyyMMddHHmmss" }

    foreach ($node in $selectedNodes) {
        $remoteRoot = "$remoteTempRoot/shuai-stun-deploy-$deployTag-$PID-$($node.Name)"
        $state = [pscustomobject]@{
            Host = $node.SshHost
            Root = $remoteRoot
            Started = $false
        }
        $remoteStates += $state

        Write-DeployLog "deploying $($node.Role) node to $($node.SshHost)"
        Invoke-DeployCommand $ssh `
            ($sshCommon + @($node.SshHost, "mkdir -p $remoteRoot"))
        if (-not $DryRun) {
            $state.Started = $true
        }
        Invoke-DeployCommand $scp `
            ($scpCommon + @("-r", $systemdPath, "$($node.SshHost):$remoteRoot/systemd"))
        Invoke-DeployCommand $scp `
            ($scpCommon + @($environmentFiles[$node.Name],
                "$($node.SshHost):$remoteRoot/stun-server.env"))
        $remotePreflight = "sudo bash $remoteRoot/systemd/check-ports.sh " +
            "$remoteRoot/stun-server.env --allow-service stun-server"
        Invoke-DeployCommand $ssh ($sshCommon + @($node.SshHost, $remotePreflight))
        Invoke-DeployCommand $scp `
            ($scpCommon + @($jarPath, "$($node.SshHost):$remoteRoot/stun-server.jar"))

        $remoteDeploy = "sudo env STUN_ACTIVE_TIMEOUT_SEC=$activeTimeout " +
            "STUN_BACKUP_KEEP=$backupKeep bash $remoteRoot/systemd/deploy.sh " +
            "$remoteRoot/stun-server.jar $remoteRoot/stun-server.env"
        Invoke-DeployCommand $ssh ($sshCommon + @($node.SshHost, $remoteDeploy))
        Invoke-DeployCommand $ssh `
            ($sshCommon + @($node.SshHost, "systemctl is-active stun-server"))
    }

    $deploymentSucceeded = $true
    if ($DryRun) {
        Write-DeployLog "dry run completed; no build or remote command was executed"
    } else {
        $deployedRoles = ($selectedNodes | ForEach-Object { $_.Role }) -join " and "
        Write-DeployLog "$deployedRoles STUN deployment completed successfully"
    }
} finally {
    if (Test-Path -LiteralPath $localTempRoot) {
        $resolvedTemp = (Resolve-Path -LiteralPath $localTempRoot).Path
        $systemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedTemp.StartsWith($systemTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
        } else {
            Write-Warning "Refusing to remove unexpected local temp path: $resolvedTemp"
        }
    }

    if (-not $DryRun) {
        foreach ($state in $remoteStates) {
            if (-not $state.Started) {
                continue
            }
            if ($deploymentSucceeded -and -not $KeepRemoteTemp) {
                try {
                    Invoke-DeployCommand $ssh `
                        ($sshCommon + @($state.Host, "rm -rf -- $($state.Root)"))
                } catch {
                    Write-Warning "Could not remove remote temp path $($state.Host):$($state.Root)"
                }
            } else {
                Write-Warning "Remote files kept for diagnosis: $($state.Host):$($state.Root)"
            }
        }
    }
}
