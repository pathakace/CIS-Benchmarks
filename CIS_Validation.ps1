#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CIS Level 1 Windows Server 2022 - Comprehensive Validation Script
    Validates all P0, P1, P2, and P3 controls independently.

.DESCRIPTION
    Reads every setting directly from the OS (registry, secedit, auditpol,
    firewall API, local users) and reports PASS / FAIL / WARN for each CIS control.
    Does NOT modify any settings. Safe to run at any time, including on production.

    Output:
      - Color-coded console (green=PASS, red=FAIL, yellow=WARN)
      - Timestamped .log file (plain text)
      - CSV report for import into Excel / SIEM / ticketing

.PARAMETER Priority
    Which priority tiers to validate. Default: All (P0,P1,P2,P3).
    Accepts: P0, P1, P2, P3, or any combination e.g. 'P0','P1'

.PARAMETER LogPath
    Path for the plain-text log. Auto-named with timestamp if omitted.

.PARAMETER CsvPath
    Path for the CSV report. Auto-named with timestamp if omitted.

.PARAMETER FailOnly
    If set, console output only shows FAIL and WARN results (reduces noise).

.EXAMPLE
    # Full validation, all tiers
    .\CIS_Validation.ps1

    # P0 and P1 only, failures only on console
    .\CIS_Validation.ps1 -Priority P0,P1 -FailOnly

    # Save CSV to a specific path
    .\CIS_Validation.ps1 -CsvPath "C:\Reports\CIS_$(hostname)_$(Get-Date -f yyyyMMdd).csv"

.NOTES
    Author  : Enterprise Windows Architecture Team
    Version : 1.0
    Safe    : Read-only. Makes zero changes to the system.
#>

[CmdletBinding()]
param(
    [ValidateSet('P0','P1','P2','P3')]
    [string[]]$Priority = @('P0','P1','P2','P3'),

    [string]$LogPath = "C:\Windows\Logs\CIS_Validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    [string]$CsvPath = "C:\Windows\Logs\CIS_Validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [switch]$FailOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ═══════════════════════════════════════════════════════════════
#  RESULT TRACKING
# ═══════════════════════════════════════════════════════════════
$script:Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0
$script:SeceditCache = $null   # lazy-loaded once

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','PASS','FAIL','WARN','SECTION')]$Level = 'INFO')
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'PASS'    { 'Green'   }
        'FAIL'    { 'Red'     }
        'WARN'    { 'Yellow'  }
        'SECTION' { 'Magenta' }
        default   { 'Cyan'    }
    }
    if (-not $FailOnly -or $Level -in 'FAIL','WARN','SECTION') {
        Write-Host $entry -ForegroundColor $color
    }
    Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
}

function Add-Result {
    param(
        [string]$Priority,
        [string]$CISRef,
        [string]$Description,
        [ValidateSet('PASS','FAIL','WARN')]$Status,
        [string]$Expected,
        [string]$Actual,
        [string]$Notes = ''
    )
    $script:Results.Add([PSCustomObject]@{
        Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Priority    = $Priority
        CISRef      = $CISRef
        Description = $Description
        Status      = $Status
        Expected    = $Expected
        Actual      = $Actual
        Notes       = $Notes
    })
    switch ($Status) {
        'PASS' { $script:PassCount++; Write-Log "[$CISRef] PASS - $Description | Expected: $Expected | Got: $Actual" -Level PASS }
        'FAIL' { $script:FailCount++; Write-Log "[$CISRef] FAIL - $Description | Expected: $Expected | Got: $Actual" -Level FAIL }
        'WARN' { $script:WarnCount++; Write-Log "[$CISRef] WARN - $Description | Expected: $Expected | Got: $Actual $Notes" -Level WARN }
    }
}

# --- Registry read (returns $null if missing) ---
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch { return $null }
}

# --- Registry check helper ---
function Test-RegValue {
    param(
        [string]$Priority,
        [string]$CISRef,
        [string]$Description,
        [string]$Path,
        [string]$Name,
        $ExpectedValue,
        [string]$Operator = 'eq',   # eq | ge | le | ne | contains
        [string]$Notes = ''
    )
    $actual = Get-RegValue -Path $Path -Name $Name
    $actualStr = if ($null -eq $actual) { '<not set>' } else { "$actual" }
    $expectedStr = "$ExpectedValue"

    $pass = switch ($Operator) {
        'eq'       { $actual -eq $ExpectedValue }
        'ne'       { $actual -ne $ExpectedValue }
        'ge'       { $actual -ge $ExpectedValue }
        'le'       { $actual -le $ExpectedValue }
        'contains' { "$actual" -match "$ExpectedValue" }
        default    { $actual -eq $ExpectedValue }
    }

    if ($null -eq $actual -and $Operator -eq 'eq') { $pass = $false }

    Add-Result -Priority $Priority -CISRef $CISRef -Description $Description `
        -Status $(if ($pass) { 'PASS' } else { 'FAIL' }) `
        -Expected $expectedStr -Actual $actualStr -Notes $Notes
}

# --- Secedit export (cached) ---
function Get-SeceditPolicy {
    if ($null -eq $script:SeceditCache) {
        $tmpFile = [System.IO.Path]::GetTempFileName()
        secedit /export /cfg $tmpFile /quiet 2>$null
        $script:SeceditCache = Get-Content $tmpFile -ErrorAction SilentlyContinue
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }
    return $script:SeceditCache
}

function Get-SeceditValue {
    param([string]$Key)
    $policy = Get-SeceditPolicy
    $line = $policy | Where-Object { $_ -match "^\s*$Key\s*=" }
    if ($line) {
        return ($line -split '=',2)[1].Trim()
    }
    return $null
}

# --- auditpol check ---
function Test-AuditPolicy {
    param(
        [string]$Priority,
        [string]$CISRef,
        [string]$SubCategory,
        [string]$Description,
        [bool]$RequireSuccess,
        [bool]$RequireFailure
    )
    try {
        $raw = auditpol /get /subcategory:"$SubCategory" 2>$null
        $line = $raw | Where-Object { $_ -match $SubCategory }
        $successOk = $true
        $failureOk = $true
        $actual = 'Unknown'

        if ($line) {
            $actual = ($line -split '\s{2,}')[-1].Trim()
            $hasSuccess = $actual -match 'Success'
            $hasFailure = $actual -match 'Failure'
            if ($RequireSuccess -and -not $hasSuccess) { $successOk = $false }
            if ($RequireFailure -and -not $hasFailure) { $failureOk = $false }
        } else {
            $successOk = $false; $failureOk = $false; $actual = '<not found>'
        }

        $expected = @()
        if ($RequireSuccess) { $expected += 'Success' }
        if ($RequireFailure) { $expected += 'Failure' }
        $expectedStr = $expected -join ' and '

        $status = if ($successOk -and $failureOk) { 'PASS' } else { 'FAIL' }
        Add-Result -Priority $Priority -CISRef $CISRef -Description $Description `
            -Status $status -Expected $expectedStr -Actual $actual
    } catch {
        Add-Result -Priority $Priority -CISRef $CISRef -Description $Description `
            -Status 'WARN' -Expected 'auditable' -Actual "Error: $_"
    }
}

# --- User Rights check via secedit ---
function Test-UserRight {
    param(
        [string]$Priority,
        [string]$CISRef,
        [string]$Privilege,
        [string]$Description,
        [string[]]$RequiredSIDs,     # SIDs that MUST be present (empty = No One)
        [string[]]$ForbiddenSIDs = @() # SIDs that must NOT be present
    )
    $policy = Get-SeceditPolicy
    $line   = $policy | Where-Object { $_ -match "^\s*$Privilege\s*=" }
    $actual = if ($line) { ($line -split '=',2)[1].Trim() } else { '<not configured>' }

    if ($RequiredSIDs.Count -eq 0) {
        # "No One" — line should be absent or empty
        $pass = (-not $line) -or ($actual -eq '') -or ($actual -eq '*')
        $expectedStr = 'No One (empty)'
    } else {
        $pass = $true
        foreach ($sid in $RequiredSIDs) {
            if ($actual -notmatch [regex]::Escape($sid)) { $pass = $false; break }
        }
    }
    foreach ($sid in $ForbiddenSIDs) {
        if ($actual -match [regex]::Escape($sid)) { $pass = $false; break }
    }

    $expectedStr = if ($RequiredSIDs.Count -eq 0) { 'No One (empty)' } else { $RequiredSIDs -join ', ' }
    Add-Result -Priority $Priority -CISRef $CISRef -Description $Description `
        -Status $(if ($pass) { 'PASS' } else { 'FAIL' }) `
        -Expected $expectedStr -Actual $actual
}

# --- Firewall profile check ---
function Test-FirewallProfile {
    param([string]$Profile, [string]$Property, $ExpectedValue, [string]$CISRef, [string]$Description, [string]$Priority)
    try {
        $prof   = Get-NetFirewallProfile -Profile $Profile -ErrorAction Stop
        $actual = $prof.$Property
        $pass   = $actual -eq $ExpectedValue
        Add-Result -Priority $Priority -CISRef $CISRef -Description $Description `
            -Status $(if ($pass) { 'PASS' } else { 'FAIL' }) `
            -Expected "$ExpectedValue" -Actual "$actual"
    } catch {
        Add-Result -Priority $Priority -CISRef $CISRef -Description $Description `
            -Status 'WARN' -Expected "$ExpectedValue" -Actual "Error: $_"
    }
}

# ═══════════════════════════════════════════════════════════════
#  SCRIPT START
# ═══════════════════════════════════════════════════════════════
Write-Log "================================================================" -Level INFO
Write-Log " CIS Level 1 Windows Server 2022 - Validation Report" -Level INFO
Write-Log " Host      : $env:COMPUTERNAME" -Level INFO
Write-Log " OS        : $((Get-CimInstance Win32_OperatingSystem).Caption)" -Level INFO
Write-Log " Run By    : $env:USERDOMAIN\$env:USERNAME" -Level INFO
Write-Log " Tiers     : $($Priority -join ', ')" -Level INFO
Write-Log " Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
Write-Log "================================================================" -Level INFO

# Pre-load secedit once
$null = Get-SeceditPolicy

# ═══════════════════════════════════════════════════════════════
#  P0 — CRITICAL CONTROLS
# ═══════════════════════════════════════════════════════════════
if ('P0' -in $Priority) {

Write-Log "" -Level INFO
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION
Write-Log " P0 — CRITICAL CONTROLS (Golden Image Must-Haves)" -Level SECTION
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION

# --- 1.1 Password Policy ---
Write-Log "  [Section 1.1] Password Policy" -Level INFO

$pwHistory = Get-SeceditValue 'PasswordHistorySize'
Add-Result -Priority 'P0' -CISRef '1.1.1' -Description 'Password history >= 24' `
    -Status $(if ([int]($pwHistory ?? 0) -ge 24) { 'PASS' } else { 'FAIL' }) `
    -Expected '>= 24' -Actual ($pwHistory ?? '<not set>')

$maxAge = Get-SeceditValue 'MaximumPasswordAge'
Add-Result -Priority 'P0' -CISRef '1.1.2' -Description 'Maximum password age <= 365 and != 0' `
    -Status $(if ([int]($maxAge ?? 999) -le 365 -and [int]($maxAge ?? 0) -ne 0) { 'PASS' } else { 'FAIL' }) `
    -Expected '<= 365 and != 0' -Actual ($maxAge ?? '<not set>')

$minLen = Get-SeceditValue 'MinimumPasswordLength'
Add-Result -Priority 'P0' -CISRef '1.1.4' -Description 'Minimum password length >= 14' `
    -Status $(if ([int]($minLen ?? 0) -ge 14) { 'PASS' } else { 'FAIL' }) `
    -Expected '>= 14' -Actual ($minLen ?? '<not set>')

$complexity = Get-SeceditValue 'PasswordComplexity'
Add-Result -Priority 'P0' -CISRef '1.1.5' -Description 'Password complexity = Enabled' `
    -Status $(if ($complexity -eq '1') { 'PASS' } else { 'FAIL' }) `
    -Expected '1 (Enabled)' -Actual ($complexity ?? '<not set>')

$clearText = Get-SeceditValue 'ClearTextPassword'
Add-Result -Priority 'P0' -CISRef '1.1.7' -Description 'Reversible encryption = Disabled' `
    -Status $(if ($clearText -eq '0') { 'PASS' } else { 'FAIL' }) `
    -Expected '0 (Disabled)' -Actual ($clearText ?? '<not set>')

# --- 1.2 Account Lockout ---
Write-Log "  [Section 1.2] Account Lockout Policy" -Level INFO

$lockDur = Get-SeceditValue 'LockoutDuration'
Add-Result -Priority 'P0' -CISRef '1.2.1' -Description 'Lockout duration >= 15 min' `
    -Status $(if ([int]($lockDur ?? 0) -ge 15) { 'PASS' } else { 'FAIL' }) `
    -Expected '>= 15' -Actual ($lockDur ?? '<not set>')

$lockThresh = Get-SeceditValue 'LockoutBadCount'
Add-Result -Priority 'P0' -CISRef '1.2.2' -Description 'Lockout threshold 1-5 attempts (not 0)' `
    -Status $(if ([int]($lockThresh ?? 0) -ge 1 -and [int]($lockThresh ?? 999) -le 5) { 'PASS' } else { 'FAIL' }) `
    -Expected '1-5' -Actual ($lockThresh ?? '<not set>')

$lockWindow = Get-SeceditValue 'ResetLockoutCount'
Add-Result -Priority 'P0' -CISRef '1.2.4' -Description 'Lockout observation window >= 15 min' `
    -Status $(if ([int]($lockWindow ?? 0) -ge 15) { 'PASS' } else { 'FAIL' }) `
    -Expected '>= 15' -Actual ($lockWindow ?? '<not set>')

# --- 2.3.1 Account Options ---
Write-Log "  [Section 2.3.1] Account Options" -Level INFO

$guest = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
Add-Result -Priority 'P0' -CISRef '2.3.1.1' -Description 'Guest account disabled' `
    -Status $(if ($guest -and -not $guest.Enabled) { 'PASS' } else { 'FAIL' }) `
    -Expected 'Disabled' -Actual $(if ($guest) { if ($guest.Enabled) { 'Enabled' } else { 'Disabled' } } else { '<not found>' })

Test-RegValue -Priority 'P0' -CISRef '2.3.1.2' `
    -Description 'Limit blank passwords to console only' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' `
    -ExpectedValue 1

$adminAcct = Get-LocalUser | Where-Object { $_.SID -like '*-500' }
Add-Result -Priority 'P0' -CISRef '2.3.1.3' -Description 'Administrator account renamed' `
    -Status $(if ($adminAcct -and $adminAcct.Name -ne 'Administrator') { 'PASS' } else { 'WARN' }) `
    -Expected 'Not named Administrator' -Actual ($adminAcct.Name ?? '<not found>') `
    -Notes 'WARN if still default name'

$guestAcct = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
Add-Result -Priority 'P0' -CISRef '2.3.1.4' -Description 'Guest account renamed' `
    -Status $(if ($guestAcct -and $guestAcct.Name -ne 'Guest') { 'PASS' } else { 'WARN' }) `
    -Expected 'Not named Guest' -Actual ($guestAcct.Name ?? '<not found>') `
    -Notes 'WARN if still default name'

# --- 2.3.7 Interactive Logon ---
Write-Log "  [Section 2.3.7] Interactive Logon" -Level INFO

Test-RegValue -Priority 'P0' -CISRef '2.3.7.2' `
    -Description 'Do not display last signed-in username' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'DontDisplayLastUserName' -ExpectedValue 1

# --- 2.3.10 Network Access ---
Write-Log "  [Section 2.3.10] Network Access" -Level INFO

Test-RegValue -Priority 'P0' -CISRef '2.3.10.1' `
    -Description 'Block anonymous SID/Name translation' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'TurnOffAnonymousBlock' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '2.3.10.2' `
    -Description 'Block anonymous SAM account enumeration' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '2.3.10.3' `
    -Description 'Block anonymous SAM accounts and shares enumeration' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '2.3.10.4' `
    -Description 'Prevent credential caching for network auth' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '2.3.10.5' `
    -Description 'Everyone permissions do not apply to anonymous users' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -ExpectedValue 0

Test-RegValue -Priority 'P0' -CISRef '2.3.10.10' `
    -Description 'Restrict anonymous access to Named Pipes and Shares' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'RestrictNullSessAccess' -ExpectedValue 1

# --- 2.3.11 Network Security ---
Write-Log "  [Section 2.3.11] Network Security" -Level INFO

Test-RegValue -Priority 'P0' -CISRef '2.3.11.4' `
    -Description 'Kerberos: AES encryption only (no DES/RC4)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
    -Name 'SupportedEncryptionTypes' -ExpectedValue 2147483640

Test-RegValue -Priority 'P0' -CISRef '2.3.11.5' `
    -Description 'Do not store LM hash value' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '2.3.11.7' `
    -Description 'LAN Manager auth level = NTLMv2 only (5)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' `
    -ExpectedValue 5 -Operator 'ge'

# --- 2.3.17 UAC ---
Write-Log "  [Section 2.3.17] UAC Controls" -Level INFO

Test-RegValue -Priority 'P0' -CISRef '2.3.17.1' `
    -Description 'UAC: Admin Approval Mode for built-in Administrator' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'FilterAdministratorToken' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '2.3.17.2' `
    -Description 'UAC: Elevation prompt for admins = Prompt for consent (2)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'ConsentPromptBehaviorAdmin' -ExpectedValue 2

Test-RegValue -Priority 'P0' -CISRef '2.3.17.3' `
    -Description 'UAC: Elevation prompt for standard users = Auto deny (0)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'ConsentPromptBehaviorUser' -ExpectedValue 0

Test-RegValue -Priority 'P0' -CISRef '2.3.17.6' `
    -Description 'UAC: Run all admins in Admin Approval Mode' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'EnableLUA' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '2.3.17.7' `
    -Description 'UAC: Use secure desktop for elevation prompts' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'PromptOnSecureDesktop' -ExpectedValue 1

# --- 2.2 User Rights (Deny) ---
Write-Log "  [Section 2.2] User Rights - Deny Assignments" -Level INFO

Test-UserRight -Priority 'P0' -CISRef '2.2.21' -Privilege 'SeDenyNetworkLogonRight' `
    -Description 'Deny network logon: Guests (*S-1-5-32-546) and Local Accounts (*S-1-5-114)' `
    -RequiredSIDs @('*S-1-5-32-546','*S-1-5-114')

Test-UserRight -Priority 'P0' -CISRef '2.2.26' -Privilege 'SeDenyRemoteInteractiveLogonRight' `
    -Description 'Deny RDP logon: Guests and Local Accounts' `
    -RequiredSIDs @('*S-1-5-32-546','*S-1-5-114')

# --- Section 9: Windows Firewall ---
Write-Log "  [Section 9] Windows Firewall" -Level INFO

foreach ($profile in @('Domain','Private','Public')) {
    $pfx = switch ($profile) { 'Domain' {'9.1'} 'Private' {'9.2'} 'Public' {'9.3'} }
    Test-FirewallProfile -Priority 'P0' -CISRef "${pfx}.1" -Profile $profile -Property 'Enabled' `
        -ExpectedValue $true -Description "Firewall $profile profile = Enabled"
    Test-FirewallProfile -Priority 'P0' -CISRef "${pfx}.2" -Profile $profile -Property 'DefaultInboundAction' `
        -ExpectedValue 'Block' -Description "Firewall $profile inbound = Block"
}

# 9.3.5 Public: local firewall rules disabled
Test-FirewallProfile -Priority 'P0' -CISRef '9.3.5' -Profile 'Public' -Property 'AllowLocalFirewallRules' `
    -ExpectedValue $false -Description 'Public firewall: local rule merge disabled'

# --- Section 17: Audit Policy ---
Write-Log "  [Section 17] Audit Policy (P0)" -Level INFO

Test-AuditPolicy -Priority 'P0' -CISRef '17.1.1' -SubCategory 'Credential Validation' `
    -Description 'Audit Credential Validation = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P0' -CISRef '17.2.6' -SubCategory 'User Account Management' `
    -Description 'Audit User Account Management = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P0' -CISRef '17.5.4' -SubCategory 'Logon' `
    -Description 'Audit Logon = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P0' -CISRef '17.5.6' -SubCategory 'Special Logon' `
    -Description 'Audit Special Logon = Success' -RequireSuccess $true -RequireFailure $false

# --- Section 18.4: SMBv1 ---
Write-Log "  [Section 18.4] SMBv1 Removal" -Level INFO

Test-RegValue -Priority 'P0' -CISRef '18.4.2' `
    -Description 'SMBv1 client driver disabled (Start=4)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10' -Name 'Start' -ExpectedValue 4

try {
    $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    Add-Result -Priority 'P0' -CISRef '18.4.3' -Description 'SMBv1 Server disabled' `
        -Status $(if (-not $smb1) { 'PASS' } else { 'FAIL' }) `
        -Expected 'False' -Actual "$smb1"
} catch {
    Add-Result -Priority 'P0' -CISRef '18.4.3' -Description 'SMBv1 Server disabled' `
        -Status 'WARN' -Expected 'False' -Actual "Error reading SMB config: $_"
}

# --- Section 18.5/18.6/18.10 ---
Write-Log "  [Section 18] Miscellaneous Security Settings (P0)" -Level INFO

Test-RegValue -Priority 'P0' -CISRef '18.5.1' `
    -Description 'Automatic logon disabled' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
    -Name 'AutoAdminLogon' -ExpectedValue 0

Test-RegValue -Priority 'P0' -CISRef '18.6.8.1' `
    -Description 'Insecure guest logons disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' `
    -Name 'AllowInsecureGuestAuth' -ExpectedValue 0

Test-RegValue -Priority 'P0' -CISRef '18.10.57.3.9.4' `
    -Description 'RDP: Network Level Authentication required' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'UserAuthentication' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '18.10.57.3.9.5' `
    -Description 'RDP: Encryption level = High (3)' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'MinEncryptionLevel' -ExpectedValue 3

Test-RegValue -Priority 'P0' -CISRef '18.10.87.1' `
    -Description 'PowerShell Script Block Logging enabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name 'EnableScriptBlockLogging' -ExpectedValue 1

Test-RegValue -Priority 'P0' -CISRef '18.10.89.1.1' `
    -Description 'WinRM Client: Basic authentication disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
    -Name 'AllowBasic' -ExpectedValue 0

Test-RegValue -Priority 'P0' -CISRef '18.10.89.2.1' `
    -Description 'WinRM Service: Basic authentication disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
    -Name 'AllowBasic' -ExpectedValue 0

$auOpt = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'AUOptions'
$noAU  = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
Add-Result -Priority 'P0' -CISRef '18.10.93.2.1' -Description 'Automatic Updates enabled (AUOptions=4, NoAutoUpdate=0)' `
    -Status $(if ($auOpt -eq 4 -and $noAU -eq 0) { 'PASS' } else { 'FAIL' }) `
    -Expected 'AUOptions=4, NoAutoUpdate=0' -Actual "AUOptions=$auOpt, NoAutoUpdate=$noAU"

} # end P0

# ═══════════════════════════════════════════════════════════════
#  P1 — HIGH PRIORITY CONTROLS
# ═══════════════════════════════════════════════════════════════
if ('P1' -in $Priority) {

Write-Log "" -Level INFO
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION
Write-Log " P1 — HIGH PRIORITY CONTROLS (Immediate Post-Launch)" -Level SECTION
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION

# 1.1.3 / 1.1.6
$minAge = Get-SeceditValue 'MinimumPasswordAge'
Add-Result -Priority 'P1' -CISRef '1.1.3' -Description 'Minimum password age >= 1 day' `
    -Status $(if ([int]($minAge ?? 0) -ge 1) { 'PASS' } else { 'FAIL' }) `
    -Expected '>= 1' -Actual ($minAge ?? '<not set>')

Test-RegValue -Priority 'P1' -CISRef '1.1.6' `
    -Description 'Relax minimum password length limits = Enabled' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' `
    -Name 'RelaxMinimumPasswordLengthLimits' -ExpectedValue 1

# 1.2.3
Test-RegValue -Priority 'P1' -CISRef '1.2.3' `
    -Description 'Allow Administrator account lockout' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'AllowAdministratorLockout' -ExpectedValue 1

Write-Log "  [Section 2.2] User Rights (P1)" -Level INFO

Test-UserRight -Priority 'P1' -CISRef '2.2.1' -Privilege 'SeTrustedCredManAccessPrivilege' `
    -Description 'Access Credential Manager = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P1' -CISRef '2.2.3' -Privilege 'SeNetworkLogonRight' `
    -Description 'Network access = Administrators + Authenticated Users' `
    -RequiredSIDs @('*S-1-5-32-544','*S-1-5-11')

Test-UserRight -Priority 'P1' -CISRef '2.2.4' -Privilege 'SeTcbPrivilege' `
    -Description 'Act as part of OS = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P1' -CISRef '2.2.7' -Privilege 'SeInteractiveLogonRight' `
    -Description 'Allow log on locally = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P1' -CISRef '2.2.9' -Privilege 'SeRemoteInteractiveLogonRight' `
    -Description 'Allow RDP = Administrators + Remote Desktop Users' `
    -RequiredSIDs @('*S-1-5-32-544','*S-1-5-32-555')

Test-UserRight -Priority 'P1' -CISRef '2.2.14' -Privilege 'SeCreateTokenPrivilege' `
    -Description 'Create a token object = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P1' -CISRef '2.2.16' -Privilege 'SeCreatePermanentPrivilege' `
    -Description 'Create permanent shared objects = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P1' -CISRef '2.2.19' -Privilege 'SeDebugPrivilege' `
    -Description 'Debug programs = Administrators only' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P1' -CISRef '2.2.22' -Privilege 'SeDenyBatchLogonRight' `
    -Description 'Deny batch logon to Guests' -RequiredSIDs @('*S-1-5-32-546')

Test-UserRight -Priority 'P1' -CISRef '2.2.23' -Privilege 'SeDenyServiceLogonRight' `
    -Description 'Deny service logon to Guests' -RequiredSIDs @('*S-1-5-32-546')

Test-UserRight -Priority 'P1' -CISRef '2.2.24' -Privilege 'SeDenyInteractiveLogonRight' `
    -Description 'Deny local logon to Guests' -RequiredSIDs @('*S-1-5-32-546')

Test-UserRight -Priority 'P1' -CISRef '2.2.28' -Privilege 'SeEnableDelegationPrivilege' `
    -Description 'Trusted for delegation = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P1' -CISRef '2.2.30' -Privilege 'SeAuditPrivilege' `
    -Description 'Generate security audits = LOCAL SERVICE + NETWORK SERVICE' `
    -RequiredSIDs @('*S-1-5-19','*S-1-5-20')

Test-UserRight -Priority 'P1' -CISRef '2.2.35' -Privilege 'SeLockMemoryPrivilege' `
    -Description 'Lock pages in memory = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P1' -CISRef '2.2.38' -Privilege 'SeSecurityPrivilege' `
    -Description 'Manage auditing and security log = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P1' -CISRef '2.2.39' -Privilege 'SeRelabelPrivilege' `
    -Description 'Modify an object label = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P1' -CISRef '2.2.44' -Privilege 'SeAssignPrimaryTokenPrivilege' `
    -Description 'Replace process level token = LOCAL SERVICE + NETWORK SERVICE' `
    -RequiredSIDs @('*S-1-5-19','*S-1-5-20')

Write-Log "  [Section 2.3] Security Options (P1)" -Level INFO

Test-RegValue -Priority 'P1' -CISRef '2.3.2.1' `
    -Description 'Force audit policy subcategory settings' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '2.3.6.1' `
    -Description 'Domain member: Encrypt secure channel (always)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name 'RequireSignOrSeal' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '2.3.6.2' `
    -Description 'Domain member: Encrypt secure channel (when possible)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name 'SealSecureChannel' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '2.3.6.3' `
    -Description 'Domain member: Sign secure channel (when possible)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name 'SignSecureChannel' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '2.3.6.4' `
    -Description 'Machine account password changes enabled (DisablePasswordChange=0)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name 'DisablePasswordChange' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '2.3.6.5' `
    -Description 'Machine account password age <= 30 days' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name 'MaximumPasswordAge' -ExpectedValue 30 -Operator 'le'

Test-RegValue -Priority 'P1' -CISRef '2.3.6.6' `
    -Description 'Domain member: Require strong session key' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name 'RequireStrongKey' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '2.3.7.1' `
    -Description 'Require CTRL+ALT+DEL for logon (DisableCAD=0)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'DisableCAD' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '2.3.8.1' `
    -Description 'Network client: Digitally sign communications (always)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
    -Name 'RequireSecuritySignature' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '2.3.8.2' `
    -Description 'Network client: No unencrypted passwords' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
    -Name 'EnablePlainTextPassword' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '2.3.9.1' `
    -Description 'Network server: Idle disconnect <= 15 min' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'AutoDisconnect' -ExpectedValue 15 -Operator 'le'

Test-RegValue -Priority 'P1' -CISRef '2.3.9.2' `
    -Description 'Network server: Digitally sign communications (always)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'RequireSecuritySignature' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '2.3.9.3' `
    -Description 'Network server: Disconnect clients at logon hour expiry' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'EnableForcedLogOff' -ExpectedValue 1

$samRestrict = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictRemoteSAM'
Add-Result -Priority 'P1' -CISRef '2.3.10.11' -Description 'Restrict remote SAM calls to Administrators' `
    -Status $(if ($samRestrict -match 'BA') { 'PASS' } else { 'FAIL' }) `
    -Expected 'O:BAG:BAD:(A;;RC;;;BA)' -Actual ($samRestrict ?? '<not set>')

Test-RegValue -Priority 'P1' -CISRef '2.3.10.13' `
    -Description 'Sharing/security model = Classic (ForceGuest=0)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'ForceGuest' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '2.3.11.2' `
    -Description 'LocalSystem NULL session fallback = Disabled' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
    -Name 'allownullsessionfallback' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '2.3.11.3' `
    -Description 'PKU2U online identity authentication = Disabled' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' `
    -Name 'AllowOnlineID' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '2.3.11.8' `
    -Description 'LDAP client signing = Negotiate (1) or Require (2)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' `
    -Name 'LDAPClientIntegrity' -ExpectedValue 1 -Operator 'ge'

Test-RegValue -Priority 'P1' -CISRef '2.3.11.9' `
    -Description 'NTLM SSP clients: NTLMv2 + 128-bit (537395200)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
    -Name 'NtlmMinClientSec' -ExpectedValue 537395200

Test-RegValue -Priority 'P1' -CISRef '2.3.11.10' `
    -Description 'NTLM SSP servers: NTLMv2 + 128-bit (537395200)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
    -Name 'NtlmMinServerSec' -ExpectedValue 537395200

Test-RegValue -Priority 'P1' -CISRef '2.3.13.1' `
    -Description 'Require authentication to shut down system' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'ShutdownWithoutLogon' -ExpectedValue 0

Write-Log "  [Section 9] Firewall Logging (P1)" -Level INFO

foreach ($profile in @('Domain','Private','Public')) {
    $pfx = switch ($profile) { 'Domain' {'9.1'} 'Private' {'9.2'} 'Public' {'9.3'} }
    Test-FirewallProfile -Priority 'P1' -CISRef "${pfx}.4" -Profile $profile -Property 'NotifyOnListen' `
        -ExpectedValue $false -Description "Firewall $profile: notifications disabled"
    Test-FirewallProfile -Priority 'P1' -CISRef "${pfx}.7" -Profile $profile -Property 'LogBlocked' `
        -ExpectedValue $true -Description "Firewall $profile: log dropped packets = Yes"
}

Write-Log "  [Section 17] Audit Policy (P1)" -Level INFO

Test-AuditPolicy -Priority 'P1' -CISRef '17.5.1' -SubCategory 'Account Lockout' `
    -Description 'Audit Account Lockout = Failure' -RequireSuccess $false -RequireFailure $true

Test-AuditPolicy -Priority 'P1' -CISRef '17.5.3' -SubCategory 'Logoff' `
    -Description 'Audit Logoff = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P1' -CISRef '17.5.5' -SubCategory 'Other Logon/Logoff Events' `
    -Description 'Audit Other Logon/Logoff = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P1' -CISRef '17.7.1' -SubCategory 'Audit Policy Change' `
    -Description 'Audit Policy Change = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P1' -CISRef '17.7.2' -SubCategory 'Authentication Policy Change' `
    -Description 'Authentication Policy Change = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P1' -CISRef '17.9.3' -SubCategory 'Security State Change' `
    -Description 'Security State Change = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P1' -CISRef '17.9.5' -SubCategory 'System Integrity' `
    -Description 'System Integrity = Success and Failure' -RequireSuccess $true -RequireFailure $true

Write-Log "  [Section 18] Additional Security (P1)" -Level INFO

Test-RegValue -Priority 'P1' -CISRef '18.4.1' `
    -Description 'UAC restrictions on local accounts over network (LocalAccountTokenFilterPolicy=0)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '18.5.8' `
    -Description 'Safe DLL search mode enabled (prevents DLL hijacking)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name 'SafeDllSearchMode' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '18.10.6.1' `
    -Description 'Block Microsoft accounts' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'NoConnectedUser' -ExpectedValue 3

Test-RegValue -Priority 'P1' -CISRef '18.10.7.2' `
    -Description 'AutoRun default = Do not execute' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -Name 'NoAutorun' -ExpectedValue 1

Test-RegValue -Priority 'P1' -CISRef '18.10.7.3' `
    -Description 'Autoplay disabled on all drives (255)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -Name 'NoDriveTypeAutoRun' -ExpectedValue 255

Test-RegValue -Priority 'P1' -CISRef '18.10.81.2' `
    -Description 'Always install with elevated privileges = Disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
    -Name 'AlwaysInstallElevated' -ExpectedValue 0

Test-RegValue -Priority 'P1' -CISRef '18.10.89.2.4' `
    -Description 'WinRM: Disallow storing RunAs credentials' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
    -Name 'DisableRunAs' -ExpectedValue 1

} # end P1

# ═══════════════════════════════════════════════════════════════
#  P2 — MEDIUM PRIORITY CONTROLS
# ═══════════════════════════════════════════════════════════════
if ('P2' -in $Priority) {

Write-Log "" -Level INFO
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION
Write-Log " P2 — MEDIUM PRIORITY CONTROLS (Post-Deployment)" -Level SECTION
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION

Write-Log "  [Section 2.2] User Rights (P2)" -Level INFO

Test-UserRight -Priority 'P2' -CISRef '2.2.6' -Privilege 'SeIncreaseQuotaPrivilege' `
    -Description 'Adjust memory quotas = Admins + LOCAL/NETWORK SERVICE' `
    -RequiredSIDs @('*S-1-5-32-544','*S-1-5-19','*S-1-5-20')

Test-UserRight -Priority 'P2' -CISRef '2.2.11' -Privilege 'SeSystemtimePrivilege' `
    -Description 'Change system time = Administrators + LOCAL SERVICE' `
    -RequiredSIDs @('*S-1-5-32-544','*S-1-5-19')

Test-UserRight -Priority 'P2' -CISRef '2.2.13' -Privilege 'SeCreatePagefilePrivilege' `
    -Description 'Create a pagefile = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.14' -Privilege 'SeCreateTokenPrivilege' `
    -Description 'Create a token object = No One' -RequiredSIDs @()

Test-UserRight -Priority 'P2' -CISRef '2.2.18' -Privilege 'SeCreateSymbolicLinkPrivilege' `
    -Description 'Create symbolic links = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.29' -Privilege 'SeRemoteShutdownPrivilege' `
    -Description 'Force shutdown from remote = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.33' -Privilege 'SeIncreaseBasePriorityPrivilege' `
    -Description 'Increase scheduling priority = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.34' -Privilege 'SeLoadDriverPrivilege' `
    -Description 'Load/unload device drivers = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.40' -Privilege 'SeSystemEnvironmentPrivilege' `
    -Description 'Modify firmware environment = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.41' -Privilege 'SeManageVolumePrivilege' `
    -Description 'Perform volume maintenance = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.42' -Privilege 'SeProfileSingleProcessPrivilege' `
    -Description 'Profile single process = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.45' -Privilege 'SeRestorePrivilege' `
    -Description 'Restore files/directories = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.46' -Privilege 'SeShutdownPrivilege' `
    -Description 'Shut down system = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Test-UserRight -Priority 'P2' -CISRef '2.2.48' -Privilege 'SeTakeOwnershipPrivilege' `
    -Description 'Take ownership = Administrators' -RequiredSIDs @('*S-1-5-32-544')

Write-Log "  [Section 2.3] Security Options (P2)" -Level INFO

Test-RegValue -Priority 'P2' -CISRef '2.3.4.1' `
    -Description 'Format removable media = Administrators only (AllocateDASD=0)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
    -Name 'AllocateDASD' -ExpectedValue '0'

Test-RegValue -Priority 'P2' -CISRef '2.3.7.3' `
    -Description 'Machine inactivity limit <= 900 seconds' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'InactivityTimeoutSecs' -ExpectedValue 900 -Operator 'le'

$legalText = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LegalNoticeText'
Add-Result -Priority 'P2' -CISRef '2.3.7.4' -Description 'Interactive logon legal notice text configured' `
    -Status $(if ($legalText -and $legalText.Length -gt 5) { 'PASS' } else { 'WARN' }) `
    -Expected 'Non-empty legal notice text' -Actual $(if ($legalText) { "Set ($($legalText.Length) chars)" } else { '<not set>' })

$legalTitle = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LegalNoticeCaption'
Add-Result -Priority 'P2' -CISRef '2.3.7.5' -Description 'Interactive logon legal notice title configured' `
    -Status $(if ($legalTitle -and $legalTitle.Length -gt 2) { 'PASS' } else { 'WARN' }) `
    -Expected 'Non-empty legal notice title' -Actual $(if ($legalTitle) { "Set: $legalTitle" } else { '<not set>' })

Test-RegValue -Priority 'P2' -CISRef '2.3.7.7' `
    -Description 'Password expiry warning 5-14 days before (PasswordExpiryWarning=14)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
    -Name 'PasswordExpiryWarning' -ExpectedValue 5 -Operator 'ge'

Test-RegValue -Priority 'P2' -CISRef '2.3.9.4' `
    -Description 'Server SPN target name validation = Accept if provided (1)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name 'SMBServerNameHardeningLevel' -ExpectedValue 1 -Operator 'ge'

Test-RegValue -Priority 'P2' -CISRef '2.3.11.1' `
    -Description 'Allow LocalSystem NTLM computer identity = Enabled' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
    -Name 'UseMachineId' -ExpectedValue 1

Test-RegValue -Priority 'P2' -CISRef '2.3.15.1' `
    -Description 'Case insensitivity for non-Windows subsystems' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' `
    -Name 'ObCaseInsensitive' -ExpectedValue 1

Test-RegValue -Priority 'P2' -CISRef '2.3.15.2' `
    -Description 'Strengthen default permissions of system objects' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
    -Name 'ProtectionMode' -ExpectedValue 1

Write-Log "  [Section 9] Firewall Log Paths (P2)" -Level INFO

try {
    $fwDomain  = Get-NetFirewallProfile -Profile Domain  -ErrorAction Stop
    $fwPrivate = Get-NetFirewallProfile -Profile Private -ErrorAction Stop
    $fwPublic  = Get-NetFirewallProfile -Profile Public  -ErrorAction Stop

    Add-Result -Priority 'P2' -CISRef '9.1.6' -Description 'Domain firewall log size >= 16384 KB' `
        -Status $(if ($fwDomain.LogMaxSizeKilobytes -ge 16384) { 'PASS' } else { 'FAIL' }) `
        -Expected '>= 16384 KB' -Actual "$($fwDomain.LogMaxSizeKilobytes) KB"

    Add-Result -Priority 'P2' -CISRef '9.2.6' -Description 'Private firewall log size >= 16384 KB' `
        -Status $(if ($fwPrivate.LogMaxSizeKilobytes -ge 16384) { 'PASS' } else { 'FAIL' }) `
        -Expected '>= 16384 KB' -Actual "$($fwPrivate.LogMaxSizeKilobytes) KB"

    Add-Result -Priority 'P2' -CISRef '9.3.8' -Description 'Public firewall log size >= 16384 KB' `
        -Status $(if ($fwPublic.LogMaxSizeKilobytes -ge 16384) { 'PASS' } else { 'FAIL' }) `
        -Expected '>= 16384 KB' -Actual "$($fwPublic.LogMaxSizeKilobytes) KB"

    foreach ($p in @(@{Name='Domain';Obj=$fwDomain;Ref='9.1.8'},@{Name='Private';Obj=$fwPrivate;Ref='9.2.8'},@{Name='Public';Obj=$fwPublic;Ref='9.3.10'})) {
        Add-Result -Priority 'P2' -CISRef $p.Ref -Description "Firewall $($p.Name): log successful connections = True" `
            -Status $(if ($p.Obj.LogAllowed -eq $true) { 'PASS' } else { 'FAIL' }) `
            -Expected 'True' -Actual "$($p.Obj.LogAllowed)"
    }

    Add-Result -Priority 'P2' -CISRef '9.3.3' -Description 'Public firewall outbound = Allow' `
        -Status $(if ($fwPublic.DefaultOutboundAction -eq 'Allow') { 'PASS' } else { 'FAIL' }) `
        -Expected 'Allow' -Actual "$($fwPublic.DefaultOutboundAction)"

    Add-Result -Priority 'P2' -CISRef '9.3.6' -Description 'Public: local connection security rules = Disabled' `
        -Status $(if ($fwPublic.AllowLocalIPsecRules -eq $false) { 'PASS' } else { 'FAIL' }) `
        -Expected 'False' -Actual "$($fwPublic.AllowLocalIPsecRules)"
} catch {
    Add-Result -Priority 'P2' -CISRef '9.x' -Description 'Firewall log size/successful connections check' `
        -Status 'WARN' -Expected 'N/A' -Actual "Error: $_"
}

Write-Log "  [Section 17] Audit Policy (P2)" -Level INFO

Test-AuditPolicy -Priority 'P2' -CISRef '17.2.1' -SubCategory 'Application Group Management' `
    -Description 'Audit App Group Management = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.2.5' -SubCategory 'Security Group Management' `
    -Description 'Audit Security Group Management = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P2' -CISRef '17.3.1' -SubCategory 'Plug and Play Events' `
    -Description 'Audit PNP Activity = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P2' -CISRef '17.3.2' -SubCategory 'Process Creation' `
    -Description 'Audit Process Creation = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P2' -CISRef '17.5.2' -SubCategory 'Group Membership' `
    -Description 'Audit Group Membership = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P2' -CISRef '17.6.1' -SubCategory 'Detailed File Share' `
    -Description 'Audit Detailed File Share = Failure' -RequireSuccess $false -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.6.2' -SubCategory 'File Share' `
    -Description 'Audit File Share = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.6.3' -SubCategory 'Other Object Access Events' `
    -Description 'Audit Other Object Access = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.6.4' -SubCategory 'Removable Storage' `
    -Description 'Audit Removable Storage = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.7.3' -SubCategory 'Authorization Policy Change' `
    -Description 'Audit Authorization Policy Change = Success' -RequireSuccess $true -RequireFailure $false

Test-AuditPolicy -Priority 'P2' -CISRef '17.7.4' -SubCategory 'MPSSVC Rule-Level Policy Change' `
    -Description 'Audit MPSSVC Rule-Level Policy Change = S&F' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.7.5' -SubCategory 'Other Policy Change Events' `
    -Description 'Audit Other Policy Change = Failure' -RequireSuccess $false -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.8.1' -SubCategory 'Sensitive Privilege Use' `
    -Description 'Audit Sensitive Privilege Use = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.9.1' -SubCategory 'IPsec Driver' `
    -Description 'Audit IPsec Driver = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.9.2' -SubCategory 'Other System Events' `
    -Description 'Audit Other System Events = Success and Failure' -RequireSuccess $true -RequireFailure $true

Test-AuditPolicy -Priority 'P2' -CISRef '17.9.4' -SubCategory 'Security System Extension' `
    -Description 'Audit Security System Extension = Success' -RequireSuccess $true -RequireFailure $false

Write-Log "  [Section 18.9.26] LAPS (P2)" -Level INFO

Test-RegValue -Priority 'P2' -CISRef '18.9.26.1' `
    -Description 'LAPS: Local admin password management enabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' `
    -Name 'AdmPwdEnabled' -ExpectedValue 1

Test-RegValue -Priority 'P2' -CISRef '18.9.26.2' `
    -Description 'LAPS: Password age <= 30 days' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' `
    -Name 'PasswordAgeDays' -ExpectedValue 30 -Operator 'le'

Test-RegValue -Priority 'P2' -CISRef '18.9.26.3' `
    -Description 'LAPS: Password complexity = 4 (all chars)' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' `
    -Name 'PasswordComplexity' -ExpectedValue 4

Test-RegValue -Priority 'P2' -CISRef '18.9.26.4' `
    -Description 'LAPS: Password length >= 15' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' `
    -Name 'PasswordLength' -ExpectedValue 15 -Operator 'ge'

Write-Log "  [Section 18.10] UI Security (P2)" -Level INFO

Test-RegValue -Priority 'P2' -CISRef '18.10.14.1' `
    -Description 'Do not display password reveal button' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI' `
    -Name 'DisablePasswordReveal' -ExpectedValue 1

Test-RegValue -Priority 'P2' -CISRef '18.10.14.2' `
    -Description 'Do not enumerate administrator accounts on elevation' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' `
    -Name 'EnumerateAdministrators' -ExpectedValue 0

} # end P2

# ═══════════════════════════════════════════════════════════════
#  P3 — LOWER PRIORITY CONTROLS
# ═══════════════════════════════════════════════════════════════
if ('P3' -in $Priority) {

Write-Log "" -Level INFO
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION
Write-Log " P3 — LOWER PRIORITY CONTROLS (Environment-Specific)" -Level SECTION
Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level SECTION

Test-RegValue -Priority 'P3' -CISRef '18.4.5' `
    -Description 'SEHOP enabled (DisableExceptionChainValidation=0)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' `
    -Name 'DisableExceptionChainValidation' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.4.6' `
    -Description 'NetBT NodeType = P-node (2)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
    -Name 'NodeType' -ExpectedValue 2

Test-RegValue -Priority 'P3' -CISRef '18.5.2' `
    -Description 'IPv6 source routing disabled (2)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
    -Name 'DisableIPSourceRouting' -ExpectedValue 2

Test-RegValue -Priority 'P3' -CISRef '18.5.3' `
    -Description 'IPv4 source routing disabled (2)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
    -Name 'DisableIPSourceRouting' -ExpectedValue 2

Test-RegValue -Priority 'P3' -CISRef '18.5.4' `
    -Description 'ICMP redirects disabled' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
    -Name 'EnableICMPRedirect' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.5.6' `
    -Description 'NetBIOS name release on WINS conflict blocked' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
    -Name 'NoNameReleaseOnDemand' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.6.4.3' `
    -Description 'LLMNR (multicast name resolution) disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
    -Name 'EnableMulticast' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.6.11.2' `
    -Description 'Network Bridge installation prohibited' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' `
    -Name 'NC_AllowNetBridge_NLA' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.6.11.3' `
    -Description 'Internet Connection Sharing disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' `
    -Name 'NC_ShowSharedAccessUI' -ExpectedValue 0

# 18.6.14.1 Hardened UNC Paths
try {
    $uncSysvol   = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\SYSVOL'
    $uncNetlogon = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' '\\*\NETLOGON'
    $uncOk = ($uncSysvol -match 'RequireMutualAuthentication=1') -and ($uncNetlogon -match 'RequireMutualAuthentication=1')
    Add-Result -Priority 'P3' -CISRef '18.6.14.1' -Description 'Hardened UNC paths: SYSVOL + NETLOGON' `
        -Status $(if ($uncOk) { 'PASS' } else { 'FAIL' }) `
        -Expected 'RequireMutualAuthentication=1,RequireIntegrity=1' `
        -Actual "SYSVOL=$uncSysvol | NETLOGON=$uncNetlogon"
} catch {
    Add-Result -Priority 'P3' -CISRef '18.6.14.1' -Description 'Hardened UNC paths' `
        -Status 'WARN' -Expected 'Configured' -Actual "Error: $_"
}

Test-RegValue -Priority 'P3' -CISRef '18.9.3.1' `
    -Description 'Process creation: Include command line in audit events' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name 'ProcessCreationIncludeCmdLine_Enabled' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.9.4.1' `
    -Description 'CredSSP: Encryption Oracle Remediation = Force Updated Clients (0)' `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' `
    -Name 'AllowEncryptionOracle' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.9.4.2' `
    -Description 'Remote Credential Guard enabled (AllowProtectedCreds=1)' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' `
    -Name 'AllowProtectedCreds' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.9.13.1' `
    -Description 'Boot-Start Driver Init = Good + unknown (3)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' `
    -Name 'DriverLoadPolicy' -ExpectedValue 3

Test-RegValue -Priority 'P3' -CISRef '18.9.24.1' `
    -Description 'Kernel DMA Protection: Block DMA-capable devices' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' `
    -Name 'DeviceEnumerationPolicy' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.9.25.1' `
    -Description 'LSASS running as Protected Process (RunAsPPL=1)' `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'RunAsPPL' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.9.34.1' `
    -Description 'Unsolicited Remote Assistance disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'fAllowUnsolicited' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.9.34.2' `
    -Description 'Solicited Remote Assistance disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'fAllowToGetHelp' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.9.35.1' `
    -Description 'RPC Endpoint Mapper: Require client authentication' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' `
    -Name 'EnableAuthEpResolution' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.17.1' `
    -Description 'App Installer (winget) disabled via policy' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' `
    -Name 'EnableAppInstaller' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.10.17.2' `
    -Description 'ms-appinstaller protocol disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' `
    -Name 'EnableMSAppInstallerProtocol' -ExpectedValue 0

# 18.10.26 Event log sizes
$logSizeMap = @{
    'Application' = @{RegPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; CISRef='18.10.26.1'; MinKB=32768}
    'Security'    = @{RegPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security';    CISRef='18.10.26.2'; MinKB=196608}
    'System'      = @{RegPath='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System';      CISRef='18.10.26.3'; MinKB=32768}
}
foreach ($log in $logSizeMap.GetEnumerator()) {
    $maxSize = Get-RegValue $log.Value.RegPath 'MaxSize'
    Add-Result -Priority 'P3' -CISRef $log.Value.CISRef `
        -Description "$($log.Key) event log max size >= $($log.Value.MinKB) KB" `
        -Status $(if ([int]($maxSize ?? 0) -ge $log.Value.MinKB) { 'PASS' } else { 'FAIL' }) `
        -Expected ">= $($log.Value.MinKB) KB" -Actual ($maxSize ?? '<not set>')
}

Test-RegValue -Priority 'P3' -CISRef '18.10.42.1' `
    -Description 'Block consumer Microsoft account auth' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount' `
    -Name 'DisableUserAuth' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.57.2.2' `
    -Description 'RDP: Do not allow passwords to be saved' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'DisablePasswordSaving' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.57.3.3.3' `
    -Description 'RDP: Client drive redirection disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'fDisableCdm' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.57.3.11.1' `
    -Description 'RDP: Delete temp folders on exit' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'DeleteTempDirsOnExit' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.57.3.11.2' `
    -Description 'RDP: Per-session temp folders' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
    -Name 'PerSessionTempDir' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.76.2.1' `
    -Description 'Windows Defender SmartScreen enabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
    -Name 'EnableSmartScreen' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.81.1' `
    -Description 'User control over MSI install options disabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' `
    -Name 'EnableUserControl' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.10.87.2' `
    -Description 'PowerShell Transcription enabled' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
    -Name 'EnableTranscripting' -ExpectedValue 1

Test-RegValue -Priority 'P3' -CISRef '18.10.89.1.2' `
    -Description 'WinRM Client: Unencrypted traffic disallowed' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
    -Name 'AllowUnencryptedTraffic' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.10.89.1.3' `
    -Description 'WinRM Client: Digest authentication disallowed' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' `
    -Name 'AllowDigest' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.10.89.2.3' `
    -Description 'WinRM Service: Unencrypted traffic disallowed' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' `
    -Name 'AllowUnencryptedTraffic' -ExpectedValue 0

Test-RegValue -Priority 'P3' -CISRef '18.10.93.1.1' `
    -Description 'No auto-restart Windows Update with logged-on users' `
    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' `
    -Name 'NoAutoRebootWithLoggedOnUsers' -ExpectedValue 1

} # end P3

# ═══════════════════════════════════════════════════════════════
#  FINAL REPORT
# ═══════════════════════════════════════════════════════════════
$total = $script:PassCount + $script:FailCount + $script:WarnCount
$pct   = if ($total -gt 0) { [math]::Round(($script:PassCount / $total) * 100, 1) } else { 0 }

Write-Log "" -Level INFO
Write-Log "================================================================" -Level SECTION
Write-Log " VALIDATION SUMMARY" -Level SECTION
Write-Log "================================================================" -Level SECTION
Write-Log " Total Checks : $total" -Level INFO
Write-Log " PASS         : $($script:PassCount)  ($pct%)" -Level PASS
Write-Log " FAIL         : $($script:FailCount)" -Level FAIL
Write-Log " WARN         : $($script:WarnCount)" -Level WARN
Write-Log "================================================================" -Level SECTION

if ($script:FailCount -gt 0) {
    Write-Log "" -Level INFO
    Write-Log " FAILED CONTROLS:" -Level FAIL
    $script:Results | Where-Object { $_.Status -eq 'FAIL' } |
        Sort-Object Priority, CISRef |
        ForEach-Object {
            Write-Log "  [$($_.Priority)] $($_.CISRef) - $($_.Description) | Got: $($_.Actual)" -Level FAIL
        }
}

if ($script:WarnCount -gt 0) {
    Write-Log "" -Level INFO
    Write-Log " WARNINGS:" -Level WARN
    $script:Results | Where-Object { $_.Status -eq 'WARN' } |
        Sort-Object Priority, CISRef |
        ForEach-Object {
            Write-Log "  [$($_.Priority)] $($_.CISRef) - $($_.Description) | Got: $($_.Actual)" -Level WARN
        }
}

# Export CSV
try {
    $script:Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Log "" -Level INFO
    Write-Log " CSV Report : $CsvPath" -Level INFO
} catch {
    Write-Log " CSV export failed: $_" -Level WARN
}

Write-Log " Log File   : $LogPath" -Level INFO
Write-Log "================================================================" -Level SECTION

# Exit code: 0=all pass, 1=warnings only, 2=failures present
if     ($script:FailCount -gt 0) { exit 2 }
elseif ($script:WarnCount -gt 0) { exit 1 }
else                              { exit 0 }
