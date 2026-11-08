Clear-Host

# ================================================================
# ADMIN CHECK
# ================================================================
$isAdmin = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║        ADMINISTRATOR PRIVILEGES REQUIRED          ║" -ForegroundColor Red
    Write-Host "║      Please run this script as Administrator!     ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}

# ================================================================
# GLOBAL FINDINGS COLLECTOR
# ================================================================
$global:ssFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-SSFinding {
    param(
        [string]$Category,
        [string]$Item,
        [string]$Detail,
        [ValidateSet("CRITICAL","WARNING","INFO")]
        [string]$Severity = "WARNING"
    )
    $global:ssFindings.Add([PSCustomObject]@{
        Category = $Category
        Item     = $Item
        Detail   = $Detail
        Severity = $Severity
    })
}

# ================================================================
# BANNER
# ================================================================
Write-Host ""
Write-Host "  ██╗   ██╗ ██████╗  ██╗     ███████╗ ██████╗  █████╗  ██████╗██╗   ██╗" -ForegroundColor Magenta
Write-Host "  ╚██╗ ██╔╝██╔═══██╗ ██║     ██╔════╝██╔════╝ ██╔══██╗██╔════╝╚██╗ ██╔╝" -ForegroundColor Magenta
Write-Host "   ╚████╔╝ ██║   ██║ ██║     █████╗  ██║  ███╗███████║██║      ╚████╔╝ " -ForegroundColor Magenta
Write-Host "    ╚██╔╝  ██║   ██║ ██║     ██╔══╝  ██║   ██║██╔══██║██║       ╚██╔╝  " -ForegroundColor Magenta
Write-Host "     ██║   ╚██████╔╝ ███████╗███████╗╚██████╔╝██║  ██║╚██████╗   ██║   " -ForegroundColor Magenta
Write-Host "     ╚═╝    ╚═════╝     ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝  " -ForegroundColor Magenta
Write-Host ""
Write-Host "                   +---------------------------------+" -ForegroundColor Red
Write-Host "                   |      YoLegacy SS TOOL v1.0      |" -ForegroundColor Red
Write-Host "                   |              by YoLegacy        |" -ForegroundColor Red
Write-Host "                   |  DM yolegacy for bugs/questions |" -ForegroundColor Red
Write-Host "                   +---------------------------------+" -ForegroundColor Red
Write-Host ""

$toolStartTime = Get-Date

# ================================================================
# MODULE 1 — SYSTEM CHECKS
# ================================================================
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║            MODULE 1: SYSTEM CHECKS                  ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ── Boot Time ───────────────────────────────────────────────────
try {
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime   = (Get-Date) - $bootTime
    Write-Host "{ SYSTEM BOOT TIME }" -ForegroundColor Red
    Write-Host ("  Last Boot : {0}" -f $bootTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
    Write-Host ("  Uptime    : {0}d {1:D2}:{2:D2}:{3:D2}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) -ForegroundColor White
} catch {
    Write-Host "  Unable to retrieve boot time" -ForegroundColor Red
}

# ── Connected Drives ─────────────────────────────────────────────
$drives = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -ne 5 }
if ($drives) {
    Write-Host "`n{ CONNECTED DRIVES }" -ForegroundColor Red
    foreach ($d in $drives) {
        $freeGB = [math]::Round($d.FreeSpace / 1GB, 1)
        $totGB  = [math]::Round($d.Size / 1GB, 1)
        Write-Host ("  {0}: {1}  {2} GB free / {3} GB total" -f $d.DeviceID, $d.FileSystem, $freeGB, $totGB) -ForegroundColor Green
    }
}

# ── Service Status ───────────────────────────────────────────────
Write-Host "`n{ SERVICE STATUS }" -ForegroundColor Red

$services = @(
    @{Name="SysMain";    DisplayName="SysMain"},
    @{Name="PcaSvc";     DisplayName="Program Compatibility Assistant"},
    @{Name="DPS";        DisplayName="Diagnostic Policy Service"},
    @{Name="EventLog";   DisplayName="Windows Event Log"},
    @{Name="Schedule";   DisplayName="Task Scheduler"},
    @{Name="Bam";        DisplayName="Background Activity Moderator"},
    @{Name="Dusmsvc";    DisplayName="Data Usage"},
    @{Name="Appinfo";    DisplayName="Application Information"},
    @{Name="CDPSvc";     DisplayName="Connected Devices Platform"},
    @{Name="DcomLaunch"; DisplayName="DCOM Server Process Launcher"},
    @{Name="PlugPlay";   DisplayName="Plug and Play"},
    @{Name="wsearch";    DisplayName="Windows Search"}
)

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $dn = if ($svc.DisplayName.Length -gt 42) { $svc.DisplayName.Substring(0,39)+"..." } else { $svc.DisplayName }
        if ($service.Status -eq "Running") {
            Write-Host ("  {0,-12} {1,-44}" -f $svc.Name, $dn) -ForegroundColor Green -NoNewline
            if ($svc.Name -eq "Bam") {
                Write-Host " | Enabled" -ForegroundColor Yellow
            } else {
                try {
                    $spid = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).ProcessId
                    $proc = if ($spid -gt 0) { Get-Process -Id $spid -ErrorAction SilentlyContinue } else { $null }
                    if ($proc) { Write-Host (" | Started {0}" -f $proc.StartTime.ToString("HH:mm:ss")) -ForegroundColor Yellow }
                    else       { Write-Host " | N/A" -ForegroundColor Yellow }
                } catch { Write-Host " | N/A" -ForegroundColor Yellow }
            }
        } else {
            Write-Host ("  {0,-12} {1,-44} {2}" -f $svc.Name, $dn, $service.Status) -ForegroundColor Red
            Add-SSFinding -Category "Services" -Item $svc.Name -Detail "$($svc.DisplayName) is $($service.Status)" -Severity "WARNING"
        }
    } else {
        Write-Host ("  {0,-12} {1,-44} NOT FOUND" -f $svc.Name, $svc.DisplayName) -ForegroundColor Yellow
        Add-SSFinding -Category "Services" -Item $svc.Name -Detail "$($svc.DisplayName) not found on system" -Severity "WARNING"
    }
}

# ── Registry ─────────────────────────────────────────────────────
Write-Host "`n{ REGISTRY CHECKS }" -ForegroundColor Red

$regChecks = @(
    @{ Name="CMD";              Path="HKCU:\Software\Policies\Microsoft\Windows\System";                                         Key="DisableCMD";               WarningVal=0; WarningMsg="Disabled";  SafeMsg="Available" },
    @{ Name="PS ScriptBlock Logging"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";           Key="EnableScriptBlockLogging"; WarningVal=0; WarningMsg="Disabled";  SafeMsg="Enabled"   },
    @{ Name="Activity Feed";    Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";                                        Key="EnableActivityFeed";       WarningVal=0; WarningMsg="Disabled";  SafeMsg="Enabled"   },
    @{ Name="Prefetch";         Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key="EnablePrefetcher";      WarningVal=0; WarningMsg="Disabled";  SafeMsg="Enabled"   }
)

foreach ($r in $regChecks) {
    $status = Get-ItemProperty -Path $r.Path -Name $r.Key -ErrorAction SilentlyContinue
    Write-Host "  " -NoNewline
    if ($status -and $status.$($r.Key) -eq $r.WarningVal) {
        Write-Host "$($r.Name): " -NoNewline -ForegroundColor White
        Write-Host $r.WarningMsg -ForegroundColor Red
        Add-SSFinding -Category "Registry" -Item $r.Name -Detail "$($r.Name) is $($r.WarningMsg)" -Severity "WARNING"
    } else {
        Write-Host "$($r.Name): " -NoNewline -ForegroundColor White
        Write-Host $r.SafeMsg -ForegroundColor Green
    }
}

# ── Windows Defender Exclusions (extra check) ────────────────────
Write-Host "`n{ WINDOWS DEFENDER EXCLUSIONS }" -ForegroundColor Red
try {
    $wdPrefs = Get-MpPreference -ErrorAction SilentlyContinue
    if ($wdPrefs) {
        $exclPaths = $wdPrefs.ExclusionPath
        $exclProcs = $wdPrefs.ExclusionProcess
        $exclExts  = $wdPrefs.ExclusionExtension

        if ($exclPaths -and $exclPaths.Count -gt 0) {
            Write-Host "  Excluded Paths ($($exclPaths.Count)):" -ForegroundColor Yellow
            foreach ($ep in $exclPaths) {
                $color = if ($ep -match "minecraft|java|\.jar|temp|appdata" ) { "Red" } else { "Gray" }
                Write-Host "    $ep" -ForegroundColor $color
                if ($ep -match "minecraft|java|\.jar|cheat|vape|wurst|impact|meteor|lunar") {
                    Add-SSFinding -Category "Defender Exclusions" -Item "Path Exclusion" -Detail "Suspicious path excluded: $ep" -Severity "CRITICAL"
                } elseif ($ep) {
                    Add-SSFinding -Category "Defender Exclusions" -Item "Path Exclusion" -Detail "Excluded path: $ep" -Severity "INFO"
                }
            }
        } else {
            Write-Host "  Excluded Paths: None" -ForegroundColor Green
        }

        if ($exclProcs -and $exclProcs.Count -gt 0) {
            Write-Host "  Excluded Processes ($($exclProcs.Count)):" -ForegroundColor Yellow
            foreach ($ep in $exclProcs) {
                $color = if ($ep -match "java|javaw") { "Red" } else { "Gray" }
                Write-Host "    $ep" -ForegroundColor $color
                if ($ep -match "java|javaw") {
                    Add-SSFinding -Category "Defender Exclusions" -Item "Process Exclusion" -Detail "Java process excluded from Defender: $ep" -Severity "WARNING"
                }
            }
        } else {
            Write-Host "  Excluded Processes: None" -ForegroundColor Green
        }

        if ($exclExts -and $exclExts.Count -gt 0) {
            Write-Host "  Excluded Extensions ($($exclExts.Count)):" -ForegroundColor Yellow
            foreach ($ee in $exclExts) {
                Write-Host "    .$ee" -ForegroundColor Gray
                if ($ee -match "jar") {
                    Add-SSFinding -Category "Defender Exclusions" -Item "Extension Exclusion" -Detail ".jar extension excluded from Defender" -Severity "WARNING"
                }
            }
        } else {
            Write-Host "  Excluded Extensions: None" -ForegroundColor Green
        }
    } else {
        Write-Host "  Unable to query Defender preferences" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Unable to retrieve Defender exclusions: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ── Event Logs ───────────────────────────────────────────────────
Write-Host "`n{ EVENT LOGS }" -ForegroundColor Red

function Show-SSEventLog {
    param($logName, $eventID, $message, [bool]$isSuspicious = $true)
    $ev = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=$eventID]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($ev) {
        Write-Host "  $message at: " -NoNewline -ForegroundColor White
        Write-Host $ev.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
        if ($isSuspicious) { Add-SSFinding -Category "Event Logs" -Item $message -Detail "Occurred at $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" -Severity "WARNING" }
    } else {
        Write-Host "  $message - No records" -ForegroundColor Green
    }
}

Show-SSEventLog "Application" 3079  "USN Journal cleared"         $true
Show-SSEventLog "System"     1074   "Last PC Shutdown"             $false
Show-SSEventLog "Security"   4616   "System time changed"          $true
Show-SSEventLog "System"     6005   "Event Log Service started"    $false

# Event Logs cleared
$evCleared = Get-WinEvent -LogName "System" -FilterXPath "*[System[EventID=104 or EventID=1102]]" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($evCleared) {
    Write-Host "  Event Logs cleared (ID $($evCleared.Id)) at: " -NoNewline -ForegroundColor White
    Write-Host $evCleared.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Red
    Add-SSFinding -Category "Event Logs" -Item "Event Logs Cleared" -Detail "Cleared (ID $($evCleared.Id)) at $($evCleared.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" -Severity "CRITICAL"
} else {
    Write-Host "  Event Logs cleared - No records" -ForegroundColor Green
}

# Device changes
try {
    $evDev = Get-WinEvent -LogName "System" -FilterXPath "*[System[EventID=225 or EventID=400]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($evDev) {
        Write-Host "  Device change (ID $($evDev.Id)) at: " -NoNewline -ForegroundColor White
        Write-Host $evDev.TimeCreated.ToString("MM/dd HH:mm") -ForegroundColor Yellow
    } else {
        Write-Host "  Device changes - No records" -ForegroundColor Green
    }
} catch {}

# ── Prefetch Integrity ───────────────────────────────────────────
$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    Write-Host "`n{ PREFETCH INTEGRITY }" -ForegroundColor Red
    $pfFiles = Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue
    if (-not $pfFiles) {
        Write-Host "  No prefetch files found - folder may have been cleared!" -ForegroundColor Red
        Add-SSFinding -Category "Prefetch" -Item "Empty Prefetch" -Detail "Prefetch folder exists but contains no .pf files" -Severity "CRITICAL"
    } else {
        $hashTable  = @{}
        $suspicious = @{}
        $totalPF    = $pfFiles.Count

        foreach ($pf in $pfFiles) {
            try {
                $isHidden   = $pf.Attributes -band [System.IO.FileAttributes]::Hidden
                $isReadOnly = $pf.Attributes -band [System.IO.FileAttributes]::ReadOnly
                if ($isHidden -and $isReadOnly) {
                    $suspicious[$pf.Name] = "Hidden + Read-only"
                    Add-SSFinding -Category "Prefetch" -Item $pf.Name -Detail "Hidden and Read-only prefetch file" -Severity "WARNING"
                } elseif ($isHidden) {
                    $suspicious[$pf.Name] = "Hidden"
                    Add-SSFinding -Category "Prefetch" -Item $pf.Name -Detail "Hidden prefetch file" -Severity "WARNING"
                } elseif ($isReadOnly) {
                    $suspicious[$pf.Name] = "Read-only"
                }
                $h = Get-FileHash -Path $pf.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h) {
                    if ($hashTable.ContainsKey($h.Hash)) { $hashTable[$h.Hash].Add($pf.Name) }
                    else {
                        $hashTable[$h.Hash] = [System.Collections.Generic.List[string]]::new()
                        $hashTable[$h.Hash].Add($pf.Name)
                    }
                }
            } catch {}
        }

        $dups = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        if ($dups) {
            Write-Host "  Duplicate PF files found:" -ForegroundColor Yellow
            foreach ($d in $dups) {
                Write-Host "    $($d.Value -join ', ')" -ForegroundColor White
                Add-SSFinding -Category "Prefetch" -Item "Duplicate PF Files" -Detail ($d.Value -join ', ') -Severity "WARNING"
            }
        } else { Write-Host "  Duplicates   : None" -ForegroundColor Green }

        if ($suspicious.Count -gt 0) {
            Write-Host "  Suspicious PF : $($suspicious.Count) / $totalPF" -ForegroundColor Yellow
            foreach ($e in $suspicious.GetEnumerator()) {
                Write-Host "    $($e.Key) : $($e.Value)" -ForegroundColor White
            }
        } else {
            Write-Host "  Integrity     : Clean ($totalPF files)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "`n{ PREFETCH INTEGRITY }" -ForegroundColor Red
    Write-Host "  Prefetch folder not found!" -ForegroundColor Red
    Add-SSFinding -Category "Prefetch" -Item "Missing Prefetch Folder" -Detail "C:\Windows\Prefetch does not exist" -Severity "CRITICAL"
}

# ── Recycle Bin ──────────────────────────────────────────────────
try {
    $rbPath = "$env:SystemDrive" + '\$Recycle.Bin'
    Write-Host "`n{ RECYCLE BIN }" -ForegroundColor Red
    if (Test-Path $rbPath) {
        $rbItem      = Get-Item -LiteralPath $rbPath -Force
        $userFolders = Get-ChildItem -LiteralPath $rbPath -Directory -Force -ErrorAction SilentlyContinue
        if ($userFolders) {
            $allItems   = @()
            $latestTime = $rbItem.LastWriteTime
            foreach ($uf in $userFolders) {
                if ($uf.LastWriteTime -gt $latestTime) { $latestTime = $uf.LastWriteTime }
                $items = Get-ChildItem -LiteralPath $uf.FullName -File -Force -ErrorAction SilentlyContinue
                if ($items) {
                    $allItems += $items
                    $lf = $items | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($lf -and $lf.LastWriteTime -gt $latestTime) { $latestTime = $lf.LastWriteTime }
                }
            }
            Write-Host "  Last Modified : $($latestTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
            if ($allItems.Count -gt 0) {
                Write-Host "  Total Items   : $($allItems.Count)" -ForegroundColor Yellow
                $li = $allItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                Write-Host "  Latest Item   : $($li.Name)" -ForegroundColor Gray
                Add-SSFinding -Category "Recycle Bin" -Item "Items Present" -Detail "$($allItems.Count) items in recycle bin, latest: $($li.Name)" -Severity "INFO"
            } else {
                Write-Host "  Status        : Empty" -ForegroundColor Green
            }
        } else {
            Write-Host "  Status        : Empty" -ForegroundColor Green
            Write-Host "  Last Modified : $($rbItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
        }
    } else {
        Write-Host "  Not found at $rbPath" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
}

# ── Console History ──────────────────────────────────────────────
Write-Host "`n{ CONSOLE HISTORY }" -ForegroundColor Red
$histPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $histPath) {
    $hf = Get-Item -Path $histPath -Force
    Write-Host "  Last Modified : $($hf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
    $attrStr = $hf.Attributes.ToString()
    $attrColor = if ($attrStr -ne "Archive") { "Yellow" } else { "Green" }
    Write-Host "  Attributes    : $attrStr" -ForegroundColor $attrColor
    Write-Host "  File Size     : $([math]::Round($hf.Length/1024,2)) KB" -ForegroundColor Yellow
    if ($attrStr -ne "Archive") {
        Add-SSFinding -Category "Console History" -Item "ConsoleHost_history.txt" -Detail "Unusual file attributes: $attrStr" -Severity "WARNING"
    }
} else {
    Write-Host "  Not found — history may be disabled or cleared" -ForegroundColor Yellow
    Add-SSFinding -Category "Console History" -Item "ConsoleHost_history.txt" -Detail "PowerShell history file not found (may have been deleted)" -Severity "WARNING"
}

# ── Known Cheat Client Directories ──────────────────────────────
Write-Host "`n{ KNOWN CHEAT CLIENT DIRECTORIES }" -ForegroundColor Red

$cheatDirs = @(
    @{ Path = "$env:APPDATA\.vape";                  Name = "Vape"         },
    @{ Path = "$env:APPDATA\.weave";                 Name = "Weave"        },
    @{ Path = "$env:APPDATA\impact";                 Name = "Impact"       },
    @{ Path = "$env:APPDATA\.meteor-client";         Name = "Meteor"       },
    @{ Path = "$env:APPDATA\Wurst";                  Name = "Wurst"        },
    @{ Path = "$env:APPDATA\.flarial";               Name = "Flarial"      },
    @{ Path = "$env:APPDATA\Aristois";               Name = "Aristois"     },
    @{ Path = "$env:APPDATA\sigma";                  Name = "Sigma"        },
    @{ Path = "$env:APPDATA\.gorilla-tag";           Name = "GorillaTag Cheat" },
    @{ Path = "$env:LOCALAPPDATA\Temp\haste";        Name = "Haste (temp)" },
    @{ Path = "$env:APPDATA\.liquidbounce";          Name = "LiquidBounce" },
    @{ Path = "$env:APPDATA\.minecraft\autoclicker"; Name = "AutoClicker Folder" }
)

$cheatDirsFound = $false
foreach ($cd in $cheatDirs) {
    if (Test-Path $cd.Path) {
        Write-Host "  [FOUND] $($cd.Name) at $($cd.Path)" -ForegroundColor Red
        Add-SSFinding -Category "Cheat Directories" -Item $cd.Name -Detail "Directory exists: $($cd.Path)" -Severity "CRITICAL"
        $cheatDirsFound = $true
    }
}
if (-not $cheatDirsFound) {
    Write-Host "  No known cheat client directories found" -ForegroundColor Green
}

# ── Recent .minecraft Activity ───────────────────────────────────
Write-Host "`n{ RECENT .MINECRAFT ACTIVITY }" -ForegroundColor Red
$mcPath = "$env:APPDATA\.minecraft"
if (Test-Path $mcPath) {
    $cutoff      = (Get-Date).AddHours(-24)
    $recentFiles = Get-ChildItem -Path $mcPath -Recurse -File -Force -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -gt $cutoff } |
                   Sort-Object LastWriteTime -Descending |
                   Select-Object -First 20
    if ($recentFiles) {
        Write-Host "  Files modified in last 24h ($($recentFiles.Count) shown):" -ForegroundColor Yellow
        foreach ($rf in $recentFiles) {
            $relPath = $rf.FullName.Replace($mcPath, ".minecraft")
            Write-Host ("  {0,-55} {1}" -f $relPath, $rf.LastWriteTime.ToString("MM/dd HH:mm:ss")) -ForegroundColor Gray
        }
    } else {
        Write-Host "  No .minecraft files modified in last 24h" -ForegroundColor Green
    }
} else {
    Write-Host "  .minecraft folder not found at: $mcPath" -ForegroundColor Yellow
}

# ================================================================
# MODULE 2 — COMMON DIRECTORIES SCAN
# ================================================================
Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║         MODULE 2: COMMON DIRECTORIES SCAN           ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

$scanDirs   = @(
    "$env:windir\System32",
    "$env:windir\SysWOW64",
    "$env:USERPROFILE\AppData\Local\Temp"
)

$outputDir  = "C:\YoLegacy"
$outputFile = "$outputDir\paths.txt"

if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }

$microsoftRegex  = [regex]::new('Microsoft|Windows|Redmond',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$trustedRegex    = [regex]::new('NVIDIA|Intel|AMD|Realtek|VIA|Qualcomm|Razer|Lenovo|Dolby|HP Inc|Dell Inc|ASUS|Acer|Logitech|Corsair',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$knownCheatRegex = [regex]::new('manthe',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)

$knownGoodFiles  = @{
    'ntoskrnl.exe'=$true; 'kernel32.dll'=$true; 'user32.dll'=$true
    'advapi32.dll'=$true; 'shell32.dll'=$true;  'explorer.exe'=$true
    'svchost.exe'=$true;  'services.exe'=$true; 'lsass.exe'=$true
    'csrss.exe'=$true;    'winlogon.exe'=$true; 'dwm.exe'=$true
}
$signatureCache  = @{}

function Test-ShouldIncludeFile {
    param([System.IO.FileInfo]$FileInfo)
    try {
        $fn  = $FileInfo.Name
        if ($fn -like "*.mui") { return $false }
        $ext = $FileInfo.Extension.ToLower()
        $nonExec = @('.evtx','.etl','.dat','.db','.log','.log1','.log2','.regtrans-ms','.blf',
                     '.cab','.rtf','.inf','.txt','.tmp','.bin','.bak','.btx','.btr','.wal','.xml','.db-wal')
        if ($nonExec -contains $ext) { return $false }
        try {
            $s  = [System.IO.File]::OpenRead($FileInfo.FullName)
            $b  = New-Object byte[] 2
            $br = $s.Read($b, 0, 2)
            $s.Close()
            if ($br -lt 2 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { return $false }
        } catch { return $false }
        if ($fn -match '^(microsoft|windows|ms)') { return $false }
        if ($knownGoodFiles.ContainsKey($fn.ToLower()))            { return $false }
        try {
            $fp  = $FileInfo.FullName
            if ($signatureCache.ContainsKey($fp)) { return $signatureCache[$fp] }
            $sig = Get-AuthenticodeSignature -FilePath $fp -ErrorAction Stop
            if ($sig.Status -eq "Valid" -and $sig.SignerCertificate) {
                $subj = $sig.SignerCertificate.Subject
                if ($knownCheatRegex.IsMatch($subj)) { $signatureCache[$fp] = $true;  return $true  }
                if ($microsoftRegex.IsMatch($subj) -or $trustedRegex.IsMatch($subj)) {
                    $signatureCache[$fp] = $false; return $false
                }
            }
        } catch {}
        try {
            $vi = $FileInfo.VersionInfo
            if ($vi.CompanyName -and ($microsoftRegex.IsMatch($vi.CompanyName) -or $trustedRegex.IsMatch($vi.CompanyName))) {
                return $false
            }
        } catch {}
        return $true
    } catch { return $false }
}

if (Test-Path $outputFile) { Remove-Item $outputFile -Force }

Write-Host "Scanning for non-Microsoft executables (>=300 KB)..." -ForegroundColor Yellow
Write-Host "Output: $outputFile" -ForegroundColor Red
Write-Host ""

$dirScanStart    = Get-Date
$totalFileCount  = 0
$totalChecked    = 0
$sb              = [System.Text.StringBuilder]::new()
$cheatSignedList = @()

foreach ($dir in $scanDirs) {
    if (-not (Test-Path $dir)) { Write-Host "Not found: $dir" -ForegroundColor Red; continue }
    Write-Host "  Scanning: $dir" -ForegroundColor Yellow
    $dirStart  = Get-Date
    $dirCount  = 0
    try {
        $allFiles = Get-ChildItem -Path $dir -File -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -ge 300KB }
        foreach ($fi in $allFiles) {
            try {
                $totalChecked++
                if ($totalChecked % 500 -eq 0) {
                    Write-Host "    Checked: $totalChecked | Found: $totalFileCount" -ForegroundColor DarkGray
                }
                if (Test-ShouldIncludeFile -FileInfo $fi) {
                    [void]$sb.AppendLine($fi.FullName)
                    $totalFileCount++
                    $dirCount++
                    # Flag cheat-signed files
                    try {
                        $sig = Get-AuthenticodeSignature -FilePath $fi.FullName -ErrorAction SilentlyContinue
                        if ($sig -and $sig.SignerCertificate -and $knownCheatRegex.IsMatch($sig.SignerCertificate.Subject)) {
                            $cheatSignedList += $fi.FullName
                            Add-SSFinding -Category "Cheat Signed Files" -Item $fi.Name `
                                -Detail "Signed by known cheat author (Manthe Industries): $($fi.FullName)" -Severity "CRITICAL"
                            Write-Host "    [CHEAT SIGNED] $($fi.FullName)" -ForegroundColor Red
                        }
                    } catch {}
                }
            } catch {}
        }
        $dt = (Get-Date) - $dirStart
        Write-Host "    Found: $dirCount files ($([math]::Round($dt.TotalSeconds,1))s)" -ForegroundColor Green
    } catch { Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red }
}

[System.IO.File]::WriteAllText($outputFile, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))

$dirScanTotal = (Get-Date) - $dirScanStart
Write-Host ""
Write-Host "  Time    : $([math]::Round($dirScanTotal.TotalMinutes,1)) min" -ForegroundColor White
Write-Host "  Checked : $totalChecked files" -ForegroundColor White
Write-Host "  Found   : $totalFileCount non-MS executables" -ForegroundColor Red
if ($cheatSignedList.Count -gt 0) {
    Write-Host "  CHEAT SIGNED FILES: $($cheatSignedList.Count)" -ForegroundColor Red
    Add-SSFinding -Category "Cheat Signed Files" -Item "Summary" -Detail "$($cheatSignedList.Count) files signed by known cheat author" -Severity "CRITICAL"
} else {
    Write-Host "  Cheat-signed files: None detected" -ForegroundColor Green
}

# ================================================================
# MODULE 3 — JAR PARSER (Prefetch + Memory)
# ================================================================
Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║        MODULE 3: JAR PARSER / PREFETCH ANALYSIS     ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

$pecmdUrl      = "https://github.com/NoDiff-del/JARs/releases/download/Jar/PECmd.exe"
$xxstringsUrl  = "https://github.com/NoDiff-del/JARs/releases/download/Jar/xxstrings64.exe"
$pecmdPath     = "$env:TEMP\PECmd.exe"
$xxstringsPath = "$env:TEMP\xxstrings64.exe"

Write-Host "Downloading analysis tools..." -ForegroundColor Gray
$skipJarParser = $false
try {
    Invoke-WebRequest -Uri $pecmdUrl     -OutFile $pecmdPath     -UseBasicParsing -ErrorAction Stop
    Invoke-WebRequest -Uri $xxstringsUrl -OutFile $xxstringsPath -UseBasicParsing -ErrorAction Stop
    Write-Host "  Tools downloaded OK" -ForegroundColor Green
} catch {
    Write-Host "  Failed to download tools: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Skipping JAR Parser module" -ForegroundColor Yellow
    $skipJarParser = $true
}

if (-not $skipJarParser) {
    $logonTime   = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $prefetchDir = "C:\Windows\Prefetch"

    $pfJavaFiles = Get-ChildItem -Path $prefetchDir -Filter *.pf -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match "java|javaw" -and $_.LastWriteTime -gt $logonTime }

    if ($pfJavaFiles -and $pfJavaFiles.Count -gt 0) {
        Write-Host "Java prefetch files found after logon:" -ForegroundColor Yellow
        foreach ($pf in $pfJavaFiles) {
            Write-Host ""
            Write-Host "  $($pf.FullName)" -ForegroundColor DarkRed
            $pecmdOut = & $pecmdPath -f $pf.FullName 2>$null
            foreach ($line in $pecmdOut) {
                $line2 = $line
                if ($line2 -match '\\VOLUME{(.+?)}') { $line2 = $line2 -replace '\\VOLUME{(.+?)}','C:' }
                $line2 = $line2 -replace '^\d+: ',''
                try {
                    if ((Get-Content $line2 -First 1 -ErrorAction SilentlyContinue) -match 'PK\x03\x04') {
                        if ($line2 -notmatch "\.jar$") {
                            Write-Host "    [MODIFIED EXT] $line2" -ForegroundColor DarkRed
                            Add-SSFinding -Category "JAR Parser" -Item (Split-Path $line2 -Leaf) `
                                -Detail "JAR-format file with modified extension: $line2" -Severity "CRITICAL"
                        } else {
                            Write-Host "    [VALID JAR] $line2" -ForegroundColor DarkGreen
                        }
                    }
                } catch {}
                if ($line2 -match "\.jar$" -and !(Test-Path $line2)) {
                    Write-Host "    [DELETED JAR] $line2" -ForegroundColor DarkYellow
                    Add-SSFinding -Category "JAR Parser" -Item (Split-Path $line2 -Leaf) `
                        -Detail "Deleted JAR found in prefetch: $line2" -Severity "WARNING"
                }
            }
        }
    } else {
        Write-Host "  No Java prefetch files found after logon" -ForegroundColor Red
        Add-SSFinding -Category "JAR Parser" -Item "No Java Prefetch" -Detail "No java/javaw .pf files found since logon" -Severity "INFO"
    }

    # DcomLaunch memory scan
    Write-Host ""
    Write-Host "Searching DcomLaunch memory for -jar strings..." -ForegroundColor Gray
    try {
        $dcomPid = (Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq 'DcomLaunch' }).ProcessId
        $xxOut   = & $xxstringsPath -p $dcomPid -raw 2>$null | Select-String -Pattern "-jar"

        if ($xxOut) {
            Write-Host "  Strings containing '-jar' found:" -ForegroundColor DarkYellow
            foreach ($line in $xxOut) {
                Write-Host "    $line" -ForegroundColor Gray
                if ($line -match '-jar\s+"?([^"\s]+\.jar)"?') {
                    $jarPath = $Matches[1] -replace '\\VOLUME{[^}]+}','C:'
                    Write-Host "    -> Processing: $jarPath" -ForegroundColor Red
                    try {
                        $bytes = Get-Content $jarPath -Encoding Byte -TotalCount 4 -ErrorAction Stop
                        if ($bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04) {
                            Write-Host "       [VALID JAR] $jarPath" -ForegroundColor DarkGreen
                        } else {
                            Write-Host "       [INVALID MAGIC] $jarPath" -ForegroundColor DarkRed
                            Add-SSFinding -Category "JAR Parser" -Item (Split-Path $jarPath -Leaf) `
                                -Detail "JAR in memory has invalid magic bytes: $jarPath" -Severity "WARNING"
                        }
                    } catch {
                        Write-Host "       [NOT ON DISK] $jarPath" -ForegroundColor DarkYellow
                        Add-SSFinding -Category "JAR Parser" -Item (Split-Path $jarPath -Leaf) `
                            -Detail "JAR referenced in DcomLaunch memory but not found on disk: $jarPath" -Severity "WARNING"
                    }
                }
            }
        } else {
            Write-Host "  No '-jar' strings found in DcomLaunch memory" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Error scanning DcomLaunch memory: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ================================================================
# MODULE 4 — MOD ANALYZER
# ================================================================
Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║              MODULE 4: MOD ANALYZER                 ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ── Mod Analyzer Helper Functions ────────────────────────────────

function Get-SHA1 {
    param([string]$filePath)
    return (Get-FileHash -Path $filePath -Algorithm SHA1).Hash
}

function Get-ZoneIdentifier {
    param([string]$filePath)
    try {
        $ads = Get-Content -Raw -Stream Zone.Identifier $filePath -ErrorAction SilentlyContinue
        if ($ads -match "HostUrl=(.+)") {
            $url = $matches[1]
            if ($url -match "modrinth\.com")                                           { return @{ Source="Modrinth"; URL=$url; IsModrinth=$true  } }
            elseif ($url -match "curseforge\.com")                                     { return @{ Source="CurseForge"; URL=$url; IsModrinth=$false } }
            elseif ($url -match "github\.com")                                         { return @{ Source="GitHub"; URL=$url; IsModrinth=$false } }
            elseif ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com")   { return @{ Source="Discord"; URL=$url; IsModrinth=$false } }
            else                                                                        { return @{ Source="Other"; URL=$url; IsModrinth=$false } }
        }
    } catch {}
    return @{ Source="Unknown"; URL=""; IsModrinth=$false }
}

function Get-Mod-Info-From-Jar {
    param([string]$jarPath)
    $modInfo = @{
        ModId=""; Name=""; Version=""; Description=""; Authors=@(); License=""
        Contact=@{}; Icon=""; Environment=""; Entrypoints=@{}; Mixins=@()
        AccessWidener=""; Depends=@{}; Suggests=@{}; Breaks=@{}; Conflicts=@{}; ModLoader=""
    }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($jarPath)

        $fabricModJson = $zip.Entries | Where-Object { $_.Name -eq 'fabric.mod.json' } | Select-Object -First 1
        if ($fabricModJson) {
            $stream = $fabricModJson.Open()
            $reader = New-Object System.IO.StreamReader($stream)
            $json   = $reader.ReadToEnd()
            $reader.Close(); $stream.Close()
            try {
                $fd = $json | ConvertFrom-Json
                if ($fd.id)          { $modInfo.ModId   = $fd.id }
                if ($fd.name)        { $modInfo.Name    = $fd.name }
                if ($fd.version)     { $modInfo.Version = $fd.version }
                if ($fd.description) { $modInfo.Description = $fd.description }
                if ($fd.authors)     { $modInfo.Authors = if ($fd.authors -is [array]) { $fd.authors } else { @($fd.authors) } }
                if ($fd.license)     { $modInfo.License = $fd.license }
                if ($fd.contact)     { $modInfo.Contact = $fd.contact }
                if ($fd.environment) { $modInfo.Environment = $fd.environment }
                if ($fd.entrypoints) { $modInfo.Entrypoints = $fd.entrypoints }
                if ($fd.mixins)      { $modInfo.Mixins = if ($fd.mixins -is [array]) { $fd.mixins } else { @($fd.mixins) } }
                if ($fd.accessWidener){ $modInfo.AccessWidener = $fd.accessWidener }
                if ($fd.depends)     { $modInfo.Depends = $fd.depends }
                $modInfo.ModLoader = "Fabric"
                $zip.Dispose(); return $modInfo
            } catch {}
        }

        $modsToml = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/mods.toml' } | Select-Object -First 1
        if ($modsToml) {
            $stream = $modsToml.Open()
            $reader = New-Object System.IO.StreamReader($stream)
            $toml   = $reader.ReadToEnd()
            $reader.Close(); $stream.Close()
            if ($toml -match 'modId\s*=\s*"([^"]+)"')       { $modInfo.ModId   = $matches[1] }
            if ($toml -match 'displayName\s*=\s*"([^"]+)"') { $modInfo.Name    = $matches[1] }
            if ($toml -match 'version\s*=\s*"([^"]+)"')     { $modInfo.Version = $matches[1] }
            if ($toml -match 'authors\s*=\s*"([^"]+)"')     { $modInfo.Authors = @($matches[1]) }
            $modInfo.ModLoader = "Forge/NeoForge"
            $zip.Dispose(); return $modInfo
        }

        $manifest = $zip.Entries | Where-Object { $_.Name -eq 'MANIFEST.MF' } | Select-Object -First 1
        if ($manifest) {
            $stream = $manifest.Open()
            $reader = New-Object System.IO.StreamReader($stream)
            $mf     = $reader.ReadToEnd()
            $reader.Close(); $stream.Close()
            foreach ($line in ($mf -split "`n")) {
                if ($line -match 'Implementation-Title:\s*(.+)' -and -not $modInfo.Name)    { $modInfo.Name    = $matches[1].Trim() }
                if ($line -match 'Implementation-Version:\s*(.+)' -and -not $modInfo.Version){ $modInfo.Version = $matches[1].Trim() }
            }
        }
        $zip.Dispose()
    } catch {}
    return $modInfo
}

function Find-Closest-Version {
    param([string]$localVersion, [array]$availableVersions, [string]$preferredLoader="Fabric", [string]$minecraftVersion=$null)
    if (-not $localVersion -or -not $availableVersions -or $availableVersions.Count -eq 0) { return $null }
    $filtered = @()
    foreach ($v in $availableVersions) {
        $mL = ($v.loaders -contains $preferredLoader.ToLower())
        $mM = if ($minecraftVersion -and $v.game_versions) { ($v.game_versions -contains $minecraftVersion) } else { $true }
        if ($mL -and $mM) { $filtered += $v }
    }
    if ($filtered.Count -eq 0 -and $minecraftVersion) { foreach ($v in $availableVersions) { if ($v.game_versions -contains $minecraftVersion) { $filtered += $v } } }
    if ($filtered.Count -eq 0) { foreach ($v in $availableVersions) { if ($v.loaders -contains $preferredLoader.ToLower()) { $filtered += $v } } }
    if ($filtered.Count -eq 0) { $filtered = $availableVersions }
    foreach ($v in $filtered) { if ($v.version_number -eq $localVersion) { return $v } }
    try {
        if ($localVersion -match '(\d+)\.(\d+)\.(\d+)') {
            $maj=$([int]$matches[1]); $min=$([int]$matches[2]); $pat=$([int]$matches[3])
            $cl=$null; $cd=[double]::MaxValue
            foreach ($v in $filtered) {
                if ($v.version_number -match '(\d+)\.(\d+)\.(\d+)') {
                    $d=[math]::Sqrt([math]::Pow($maj-[int]$matches[1],2)*100+[math]::Pow($min-[int]$matches[2],2)*10+[math]::Pow($pat-[int]$matches[3],2))
                    if ($d -lt $cd) { $cd=$d; $cl=$v }
                }
            }
            if ($cl -and $cd -lt 10) { return $cl }
        }
        if ($localVersion -match '(\d+)\.(\d+)') {
            $maj=$([int]$matches[1]); $min=$([int]$matches[2])
            $cl=$null; $cd=[double]::MaxValue
            foreach ($v in $filtered) {
                if ($v.version_number -match '(\d+)\.(\d+)') {
                    $d=[math]::Sqrt([math]::Pow($maj-[int]$matches[1],2)*10+[math]::Pow($min-[int]$matches[2],2))
                    if ($d -lt $cd) { $cd=$d; $cl=$v }
                }
            }
            if ($cl -and $cd -lt 5) { return $cl }
        }
    } catch {}
    return $null
}

function Fetch-Modrinth-By-Hash {
    param([string]$hash)
    try {
        $r = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($r.project_id) {
            $p    = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($r.project_id)" -Method Get -UseBasicParsing -ErrorAction Stop
            $file = $r.files[0]
            return @{ Name=$p.title; Slug=$p.slug; ExpectedSize=$file.size; VersionNumber=$r.version_number; FileName=$file.filename
                      ModrinthUrl="https://modrinth.com/mod/$($p.slug)/version/$($r.id)"; FoundByHash=$true; ExactMatch=$true
                      IsLatestVersion=$false; MatchType="Exact Hash"
                      LoaderType=if($r.loaders -contains "fabric"){"Fabric"}elseif($r.loaders -contains "forge"){"Forge"}else{"Unknown"} }
        }
    } catch {}
    return @{ Name=""; Slug=""; ExpectedSize=0; VersionNumber=""; FileName=""; FoundByHash=$false; ExactMatch=$false; IsLatestVersion=$false; MatchType="No Match"; LoaderType="Unknown" }
}

function Fetch-Modrinth-By-ModId {
    param([string]$modId, [string]$version, [string]$preferredLoader="Fabric")
    try {
        try {
            $p = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$modId" -Method Get -UseBasicParsing -ErrorAction Stop
            if ($p.id) {
                $vers = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$modId/version" -Method Get -UseBasicParsing -ErrorAction Stop
                if ($vers.Count -gt 0) {
                    $mv = Find-Closest-Version -localVersion $version -availableVersions $vers -preferredLoader $preferredLoader -minecraftVersion $minecraftVersion
                    if ($mv) {
                        $f=$mv.files[0]; $ie=($mv.version_number -eq $version)
                        $ld=if($mv.loaders -contains "fabric"){"Fabric"}elseif($mv.loaders -contains "forge"){"Forge"}else{$mv.loaders[0]}
                        return @{ Name=$p.title; Slug=$p.slug; ExpectedSize=$f.size; VersionNumber=$mv.version_number; FileName=$f.filename
                                  ModrinthUrl="https://modrinth.com/mod/$($p.slug)/version/$($mv.id)"; FoundByHash=$false; ExactMatch=$ie
                                  IsLatestVersion=($vers[0].id -eq $mv.id); MatchType=if($ie){"Exact Version"}else{"Closest Version"}; LoaderType=$ld }
                    }
                    foreach ($v in $vers) {
                        $mL=($v.loaders -contains $preferredLoader.ToLower())
                        $mM=if($minecraftVersion -and $v.game_versions){($v.game_versions -contains $minecraftVersion)}else{$true}
                        if ($mL -and $mM) {
                            $lf=$v.files[0]; $ld=if($v.loaders -contains "fabric"){"Fabric"}elseif($v.loaders -contains "forge"){"Forge"}else{$v.loaders[0]}
                            return @{ Name=$p.title; Slug=$p.slug; ExpectedSize=$lf.size; VersionNumber=$v.version_number; FileName=$lf.filename
                                      ModrinthUrl="https://modrinth.com/mod/$($p.slug)/version/$($v.id)"; FoundByHash=$false; ExactMatch=$false
                                      IsLatestVersion=($vers[0].id -eq $v.id); MatchType="Latest Version ($ld)"; LoaderType=$ld }
                        }
                    }
                    $lv=$vers[0]; $lf=$lv.files[0]; $ld=if($lv.loaders -contains "fabric"){"Fabric"}elseif($lv.loaders -contains "forge"){"Forge"}else{$lv.loaders[0]}
                    return @{ Name=$p.title; Slug=$p.slug; ExpectedSize=$lf.size; VersionNumber=$lv.version_number; FileName=$lf.filename
                              ModrinthUrl="https://modrinth.com/mod/$($p.slug)/version/$($lv.id)"; FoundByHash=$false; ExactMatch=$false
                              IsLatestVersion=$true; MatchType="Latest Version ($ld)"; LoaderType=$ld }
                }
            }
        } catch {}
        $sd = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/search?query=`"$modId`"&facets=`"[[`"project_type:mod`"]]`"&limit=5" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($sd.hits -and $sd.hits.Count -gt 0) {
            $best=$null; $bestScore=0
            foreach ($h in $sd.hits) {
                $score=0
                if ($h.slug -eq $modId)     { $score+=100 }
                if ($h.project_id -eq $modId){ $score+=100 }
                if ($h.title -eq $modId)    { $score+=80  }
                if ($h.title -match $modId) { $score+=50  }
                if ($h.slug -match $modId)  { $score+=40  }
                if ($score -gt $bestScore)  { $bestScore=$score; $best=$h }
            }
            if ($best) {
                $vers = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($best.project_id)/version" -Method Get -UseBasicParsing -ErrorAction Stop
                if ($vers.Count -gt 0) {
                    $mv = Find-Closest-Version -localVersion $version -availableVersions $vers -preferredLoader $preferredLoader -minecraftVersion $minecraftVersion
                    if ($mv) {
                        $f=$mv.files[0]; $ie=($mv.version_number -eq $version)
                        $ld=if($mv.loaders -contains "fabric"){"Fabric"}elseif($mv.loaders -contains "forge"){"Forge"}else{$mv.loaders[0]}
                        return @{ Name=$best.title; Slug=$best.slug; ExpectedSize=$f.size; VersionNumber=$mv.version_number; FileName=$f.filename
                                  ModrinthUrl="https://modrinth.com/mod/$($best.slug)/version/$($mv.id)"; FoundByHash=$false; ExactMatch=$ie
                                  IsLatestVersion=($vers[0].id -eq $mv.id); MatchType=if($ie){"Exact Version"}else{"Closest Version"}; LoaderType=$ld }
                    }
                    $lv=$vers[0]; $lf=$lv.files[0]; $ld=if($lv.loaders -contains "fabric"){"Fabric"}elseif($lv.loaders -contains "forge"){"Forge"}else{$lv.loaders[0]}
                    return @{ Name=$best.title; Slug=$best.slug; ExpectedSize=$lf.size; VersionNumber=$lv.version_number; FileName=$lf.filename
                              ModrinthUrl="https://modrinth.com/mod/$($best.slug)/version/$($lv.id)"; FoundByHash=$false; ExactMatch=$false
                              IsLatestVersion=$true; MatchType="Latest Version ($ld)"; LoaderType=$ld }
                }
            }
        }
    } catch {}
    return @{ Name=""; Slug=""; ExpectedSize=0; VersionNumber=""; FileName=""; FoundByHash=$false; ExactMatch=$false; IsLatestVersion=$false; MatchType="No Match"; LoaderType="Unknown" }
}

function Fetch-Modrinth-By-Filename {
    param([string]$filename, [string]$preferredLoader="Fabric")
    try {
        $clean    = $filename -replace '\.temp\.jar$','.jar' -replace '\.tmp\.jar$','.jar' -replace '_1\.jar$','.jar'
        $noExt    = [System.IO.Path]::GetFileNameWithoutExtension($clean)
        $base     = $noExt
        if ($filename -match '(?i)fabric') { $preferredLoader="Fabric" }
        elseif ($filename -match '(?i)forge') { $preferredLoader="Forge" }
        $localVer = ""
        if ($noExt -match '[-_](v?[\d\.]+(?:-[a-zA-Z0-9]+)?)$') { $localVer=$matches[1]; $base=$noExt -replace '[-_](v?[\d\.]+(?:-[a-zA-Z0-9]+)?)$','' }
        $base = $base -replace '(?i)-fabric$','' -replace '(?i)-forge$',''
        foreach ($slug in @($base.ToLower(), $noExt.ToLower())) {
            try {
                $p = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$slug" -Method Get -UseBasicParsing -ErrorAction Stop
                if ($p.id) {
                    $vers = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$slug/version" -Method Get -UseBasicParsing -ErrorAction Stop
                    foreach ($v in $vers) {
                        foreach ($f in $v.files) {
                            if ($f.filename -eq $clean -or $f.filename -eq $filename) {
                                $ld=if($v.loaders -contains "fabric"){"Fabric"}elseif($v.loaders -contains "forge"){"Forge"}else{$v.loaders[0]}
                                return @{ Name=$p.title; Slug=$p.slug; ExpectedSize=$f.size; VersionNumber=$v.version_number; FileName=$f.filename
                                          ModrinthUrl="https://modrinth.com/mod/$($p.slug)/version/$($v.id)"; FoundByHash=$false; ExactMatch=$true
                                          IsLatestVersion=($vers[0].id -eq $v.id); MatchType="Exact Filename"; LoaderType=$ld }
                            }
                        }
                    }
                    if ($localVer -and $vers.Count -gt 0) {
                        $mv = Find-Closest-Version -localVersion $localVer -availableVersions $vers -preferredLoader $preferredLoader -minecraftVersion $minecraftVersion
                        if ($mv) {
                            $f=$mv.files[0]; $ie=($mv.version_number -eq $localVer)
                            $ld=if($mv.loaders -contains "fabric"){"Fabric"}elseif($mv.loaders -contains "forge"){"Forge"}else{$mv.loaders[0]}
                            return @{ Name=$p.title; Slug=$p.slug; ExpectedSize=$f.size; VersionNumber=$mv.version_number; FileName=$f.filename
                                      ModrinthUrl="https://modrinth.com/mod/$($p.slug)/version/$($mv.id)"; FoundByHash=$false; ExactMatch=$ie
                                      IsLatestVersion=($vers[0].id -eq $mv.id); MatchType=if($ie){"Exact Version"}else{"Closest Version"}; LoaderType=$ld }
                        }
                    }
                    foreach ($v in $vers) {
                        $mL=($v.loaders -contains $preferredLoader.ToLower())
                        $mM=if($minecraftVersion -and $v.game_versions){($v.game_versions -contains $minecraftVersion)}else{$true}
                        if ($mL -and $mM) {
                            $f=$v.files[0]; $ld=if($v.loaders -contains "fabric"){"Fabric"}elseif($v.loaders -contains "forge"){"Forge"}else{$v.loaders[0]}
                            return @{ Name=$p.title; Slug=$p.slug; ExpectedSize=$f.size; VersionNumber=$v.version_number; FileName=$f.filename
                                      ModrinthUrl="https://modrinth.com/mod/$($p.slug)/version/$($v.id)"; FoundByHash=$false; ExactMatch=$false
                                      IsLatestVersion=($vers[0].id -eq $v.id); MatchType="Latest Version ($ld)"; LoaderType=$ld }
                        }
                    }
                }
            } catch {}
        }
        $sd = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/search?query=`"$base`"&facets=`"[[`"project_type:mod`"]]`"&limit=5" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($sd.hits -and $sd.hits.Count -gt 0) {
            $h    = $sd.hits[0]
            $vers = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($h.project_id)/version" -Method Get -UseBasicParsing -ErrorAction Stop
            foreach ($v in $vers) {
                foreach ($f in $v.files) {
                    if ($f.filename -eq $clean -or $f.filename -eq $filename) {
                        $ld=if($v.loaders -contains "fabric"){"Fabric"}elseif($v.loaders -contains "forge"){"Forge"}else{$v.loaders[0]}
                        return @{ Name=$h.title; Slug=$h.slug; ExpectedSize=$f.size; VersionNumber=$v.version_number; FileName=$f.filename
                                  ModrinthUrl="https://modrinth.com/mod/$($h.slug)/version/$($v.id)"; FoundByHash=$false; ExactMatch=$true
                                  IsLatestVersion=($vers[0].id -eq $v.id); MatchType="Exact Filename"; LoaderType=$ld }
                    }
                }
            }
            foreach ($v in $vers) {
                $mL=($v.loaders -contains $preferredLoader.ToLower())
                $mM=if($minecraftVersion -and $v.game_versions){($v.game_versions -contains $minecraftVersion)}else{$true}
                if ($mL -and $mM) {
                    $f=$v.files[0]; $ld=if($v.loaders -contains "fabric"){"Fabric"}elseif($v.loaders -contains "forge"){"Forge"}else{$v.loaders[0]}
                    return @{ Name=$h.title; Slug=$h.slug; ExpectedSize=$f.size; VersionNumber=$v.version_number; FileName=$f.filename
                              ModrinthUrl="https://modrinth.com/mod/$($h.slug)/version/$($v.id)"; FoundByHash=$false; ExactMatch=$false
                              IsLatestVersion=($vers[0].id -eq $v.id); MatchType="Latest Version ($ld)"; LoaderType=$ld }
                }
            }
            if ($vers.Count -gt 0) {
                $lv=$vers[0]; $lf=$lv.files[0]; $ld=if($lv.loaders -contains "fabric"){"Fabric"}elseif($lv.loaders -contains "forge"){"Forge"}else{$lv.loaders[0]}
                return @{ Name=$h.title; Slug=$h.slug; ExpectedSize=$lf.size; VersionNumber=$lv.version_number; FileName=$lf.filename
                          ModrinthUrl="https://modrinth.com/mod/$($h.slug)/version/$($lv.id)"; FoundByHash=$false; ExactMatch=$false
                          IsLatestVersion=$true; MatchType="Latest Version ($ld)"; LoaderType=$ld }
            }
        }
    } catch {}
    return @{ Name=""; Slug=""; ExpectedSize=0; VersionNumber=""; FileName=""; FoundByHash=$false; ExactMatch=$false; IsLatestVersion=$false; MatchType="No Match"; LoaderType="Unknown" }
}

function Fetch-Megabase {
    param([string]$hash)
    try {
        $r = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$hash" -Method Get -UseBasicParsing -ErrorAction Stop
        if (-not $r.error) { return $r.data }
    } catch {}
    return $null
}

$cheatStrings = @(
    "autocrystal","auto crystal","cw crystal","autohitcrystal",
    "autoanchor","auto anchor","anchortweaks","anchor macro",
    "autototem","auto totem","legittotem","inventorytotem","hover totem",
    "autopot","auto pot","velocity",
    "autodoublehand","auto double hand",
    "autoarmor","auto armor",
    "automace",
    "aimassist","aim assist",
    "triggerbot","trigger bot",
    "shieldbreaker","shield breaker",
    "axespam","axe spam",
    "pingspoof","ping spoof",
    "webmacro","web macro",
    "selfdestruct","self destruct",
    "hitboxes",
    "lvstrng",
    "swapBackToOriginalSlot",
    "attackRegisteredThisClick",
    "findKnockbackSword"
)

function Check-CheatStrings {
    param([string]$filePath)
    $found = [System.Collections.Generic.HashSet[string]]::new()
    try {
        $stringsPath = $null
        foreach ($p in @("C:\Program Files\Git\usr\bin\strings.exe","C:\Program Files\Git\mingw64\bin\strings.exe","$env:ProgramFiles\Git\usr\bin\strings.exe","C:\msys64\usr\bin\strings.exe","C:\cygwin64\bin\strings.exe")) {
            if (Test-Path $p) { $stringsPath=$p; break }
        }
        if ($stringsPath) {
            $tmp = Join-Path $env:TEMP "yolegacy_str_$(Get-Random).txt"
            & $stringsPath $filePath 2>$null | Out-File $tmp -ErrorAction SilentlyContinue
            if (Test-Path $tmp) {
                $content = Get-Content $tmp -Raw
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                foreach ($s in $cheatStrings) { if ($content -match $s) { $found.Add($s)|Out-Null } }
            }
        } else {
            $bytes   = [System.IO.File]::ReadAllBytes($filePath)
            $content = [System.Text.Encoding]::ASCII.GetString($bytes).ToLower()
            foreach ($s in $cheatStrings) {
                if ($s -eq "velocity") {
                    if ($content -match "velocity(hack|module|cheat|bypass|packet|horizontal|vertical|amount|factor|setting)") { $found.Add($s)|Out-Null }
                } else {
                    if ($content -match $s) { $found.Add($s)|Out-Null }
                }
            }
        }
    } catch {}
    return $found
}

function Get-Minecraft-Version-From-Mods {
    param([string]$modsFolder)
    $versionCounts = @{}
    $jarFiles = Get-ChildItem -Path $modsFolder -Filter *.jar
    foreach ($f in $jarFiles) {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($f.FullName)
            $fmj = $zip.Entries | Where-Object { $_.Name -eq 'fabric.mod.json' } | Select-Object -First 1
            if ($fmj) {
                $s=$fmj.Open(); $r=New-Object System.IO.StreamReader($s); $j=$r.ReadToEnd(); $r.Close(); $s.Close()
                $fd=$j|ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($fd.depends -and $fd.depends.minecraft) {
                    $mcv=$fd.depends.minecraft -replace '^[><=~^]*\s*','' -replace '\s*$',''
                    if ($mcv -match '^\d+(\.\d+)+(\.\d+)?$') {
                        if ($versionCounts.ContainsKey($mcv)) { $versionCounts[$mcv]++ } else { $versionCounts[$mcv]=1 }
                    }
                }
            }
            $zip.Dispose()
        } catch {}
    }
    if ($versionCounts.Count -gt 0) {
        $mc = $versionCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
        Write-Host "Detected Minecraft version: $($mc.Key) (from $($mc.Value) mods)" -ForegroundColor Red
        return $mc.Key
    }
    $proc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $proc) { $proc = Get-Process java -ErrorAction SilentlyContinue }
    if ($proc) {
        try {
            $cmd = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
            if ($cmd -match '-Dfabric.gameVersion=(\d+(\.\d+)+)' -or $cmd -match '--version\s+(\d+(\.\d+)+)') {
                Write-Host "Detected Minecraft version from process: $($matches[1])" -ForegroundColor Red
                return $matches[1]
            }
        } catch {}
    }
    Write-Host "Could not auto-detect Minecraft version." -ForegroundColor Yellow
    $mcv = Read-Host "Enter your Minecraft version (e.g. 1.21) or press Enter to skip"
    return if ($mcv) { $mcv } else { $null }
}

# ── Mod Analyzer Main ─────────────────────────────────────────────
Write-Host "Enter path to mods folder: " -NoNewline
Write-Host "(press Enter for default)" -ForegroundColor DarkGray
$mods = Read-Host "PATH"
Write-Host ""

if (-not $mods) {
    $mods = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
    Write-Host "Using: $mods" -ForegroundColor White
    Write-Host ""
}

if (-not (Test-Path $mods -PathType Container)) {
    Write-Host "Invalid mods path! Skipping mod analyzer." -ForegroundColor Red
    Add-SSFinding -Category "Mod Analyzer" -Item "Mods Folder" -Detail "Mods folder not found at: $mods" -Severity "WARNING"
} else {
    # Minecraft uptime
    $proc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $proc) { $proc = Get-Process java -ErrorAction SilentlyContinue }
    if ($proc) {
        try {
            $st = $proc.StartTime; $el=(Get-Date)-$st
            Write-Host "{ Minecraft Uptime }" -ForegroundColor Red
            Write-Host "$($proc.Name) PID $($proc.Id) started $st | running $($el.Hours)h $($el.Minutes)m $($el.Seconds)s" -ForegroundColor White
            Write-Host ""
        } catch {}
    }

    $minecraftVersion = Get-Minecraft-Version-From-Mods -modsFolder $mods
    if ($minecraftVersion) {
        Write-Host "Using MC version: $minecraftVersion" -ForegroundColor Green
        Write-Host ""
    }

    $verifiedMods    = @()
    $unknownMods     = @()
    $cheatMods       = @()
    $sizeMismatchMods= @()
    $tamperedMods    = @()
    $allModsInfo     = @()
    $spinner         = @("|","/","-","\")
    $jarFiles        = Get-ChildItem -Path $mods -Filter *.jar
    $totalMods       = $jarFiles.Count
    $counter         = 0

    foreach ($file in $jarFiles) {
        $counter++
        $spin = $spinner[$counter % $spinner.Length]
        Write-Host "`r[$spin] Scanning mods: $counter / $totalMods" -ForegroundColor Magenta -NoNewline

        $hash        = Get-SHA1 -filePath $file.FullName
        $actualSize  = $file.Length
        $actualSizeKB= [math]::Round($actualSize/1KB,2)
        $zoneInfo    = Get-ZoneIdentifier $file.FullName
        $jarModInfo  = Get-Mod-Info-From-Jar -jarPath $file.FullName

        $preferredLoader = "Fabric"
        if     ($file.Name -match '(?i)fabric')        { $preferredLoader="Fabric" }
        elseif ($file.Name -match '(?i)forge')         { $preferredLoader="Forge"  }
        elseif ($jarModInfo.ModLoader -eq "Fabric")    { $preferredLoader="Fabric" }
        elseif ($jarModInfo.ModLoader -eq "Forge/NeoForge"){ $preferredLoader="Forge" }

        $modData = Fetch-Modrinth-By-Hash -hash $hash

        if ($modData.Name -and $modData.FoundByHash) {
            $sizeDiff = $actualSize - $modData.ExpectedSize
            $modEntry = [PSCustomObject]@{
                ModName=$modData.Name; FileName=$file.Name; Version=$modData.VersionNumber
                ExpectedSize=$modData.ExpectedSize; ExpectedSizeKB=[math]::Round($modData.ExpectedSize/1KB,2)
                ActualSize=$actualSize; ActualSizeKB=$actualSizeKB; SizeDiff=$sizeDiff
                SizeDiffKB=[math]::Round($sizeDiff/1KB,2); DownloadSource=$zoneInfo.Source
                SourceURL=$zoneInfo.URL; IsModrinthDownload=$zoneInfo.IsModrinth
                ModrinthUrl=$modData.ModrinthUrl; IsVerified=$true; MatchType=$modData.MatchType
                ExactMatch=$modData.ExactMatch; IsLatestVersion=$modData.IsLatestVersion
                LoaderType=$modData.LoaderType; PreferredLoader=$preferredLoader
                FilePath=$file.FullName; JarModId=$jarModInfo.ModId; JarName=$jarModInfo.Name
                JarVersion=$jarModInfo.Version; JarModLoader=$jarModInfo.ModLoader
            }
            $verifiedMods += $modEntry; $allModsInfo += $modEntry
            if ($modData.ExpectedSize -gt 0 -and $actualSize -ne $modData.ExpectedSize) {
                $sizeMismatchMods += $modEntry
                if ([math]::Abs($sizeDiff) -gt 1024) { $tamperedMods += $modEntry }
            }
            continue
        }

        $mrFromJar = $null
        if ($jarModInfo.ModId) { $mrFromJar = Fetch-Modrinth-By-ModId -modId $jarModInfo.ModId -version $jarModInfo.Version -preferredLoader $preferredLoader }

        if ($mrFromJar -and $mrFromJar.Name) {
            $sizeDiff = $actualSize - $mrFromJar.ExpectedSize
            $modEntry = [PSCustomObject]@{
                ModName=$mrFromJar.Name; FileName=$file.Name; Version=$mrFromJar.VersionNumber
                ExpectedSize=$mrFromJar.ExpectedSize; ExpectedSizeKB=if($mrFromJar.ExpectedSize-gt 0){[math]::Round($mrFromJar.ExpectedSize/1KB,2)}else{0}
                ActualSize=$actualSize; ActualSizeKB=$actualSizeKB; SizeDiff=$sizeDiff
                SizeDiffKB=[math]::Round($sizeDiff/1KB,2); DownloadSource=$zoneInfo.Source
                SourceURL=$zoneInfo.URL; IsModrinthDownload=$zoneInfo.IsModrinth
                ModrinthUrl=$mrFromJar.ModrinthUrl; IsVerified=$true; MatchType=$mrFromJar.MatchType
                ExactMatch=$mrFromJar.ExactMatch; IsLatestVersion=$mrFromJar.IsLatestVersion
                LoaderType=$mrFromJar.LoaderType; PreferredLoader=$preferredLoader
                FilePath=$file.FullName; JarModId=$jarModInfo.ModId; JarName=$jarModInfo.Name
                JarVersion=$jarModInfo.Version; JarModLoader=$jarModInfo.ModLoader
            }
            $verifiedMods += $modEntry; $allModsInfo += $modEntry
            if ($mrFromJar.ExpectedSize -gt 0 -and $actualSize -ne $mrFromJar.ExpectedSize) {
                $sizeMismatchMods += $modEntry
                if ([math]::Abs($sizeDiff) -gt 1024) { $tamperedMods += $modEntry }
            }
            continue
        }

        $mrInfo = Fetch-Modrinth-By-Filename -filename $file.Name -preferredLoader $preferredLoader
        if ($mrInfo.Name) {
            $sizeDiff = $actualSize - $mrInfo.ExpectedSize
            $modEntry = [PSCustomObject]@{
                ModName=$mrInfo.Name; FileName=$file.Name; Version=$mrInfo.VersionNumber
                ExpectedSize=$mrInfo.ExpectedSize; ExpectedSizeKB=if($mrInfo.ExpectedSize-gt 0){[math]::Round($mrInfo.ExpectedSize/1KB,2)}else{0}
                ActualSize=$actualSize; ActualSizeKB=$actualSizeKB; SizeDiff=$sizeDiff
                SizeDiffKB=[math]::Round($sizeDiff/1KB,2); DownloadSource=$zoneInfo.Source
                SourceURL=$zoneInfo.URL; IsModrinthDownload=$zoneInfo.IsModrinth
                ModrinthUrl=$mrInfo.ModrinthUrl; IsVerified=$true; MatchType=$mrInfo.MatchType
                ExactMatch=$mrInfo.ExactMatch; IsLatestVersion=$mrInfo.IsLatestVersion
                LoaderType=$mrInfo.LoaderType; PreferredLoader=$preferredLoader
                FilePath=$file.FullName; JarModId=$jarModInfo.ModId; JarName=$jarModInfo.Name
                JarVersion=$jarModInfo.Version; JarModLoader=$jarModInfo.ModLoader
            }
            $verifiedMods += $modEntry; $allModsInfo += $modEntry
            if ($mrInfo.ExpectedSize -gt 0 -and $actualSize -ne $mrInfo.ExpectedSize) {
                $sizeMismatchMods += $modEntry
                if ([math]::Abs($sizeDiff) -gt 1024) { $tamperedMods += $modEntry }
            }
            continue
        }

        $mbData = Fetch-Megabase -hash $hash
        if ($mbData -and $mbData.name) {
            $modEntry = [PSCustomObject]@{
                ModName=$mbData.name; FileName=$file.Name; Version="Unknown"
                ExpectedSize=0; ExpectedSizeKB=0; ActualSize=$actualSize; ActualSizeKB=$actualSizeKB
                SizeDiff=0; SizeDiffKB=0; DownloadSource=$zoneInfo.Source
                SourceURL=$zoneInfo.URL; IsModrinthDownload=$zoneInfo.IsModrinth
                IsVerified=$true; MatchType="Megabase"; ExactMatch=$false; IsLatestVersion=$false
                LoaderType="Unknown"; PreferredLoader=$preferredLoader; FilePath=$file.FullName
                JarModId=$jarModInfo.ModId; JarName=$jarModInfo.Name; JarVersion=$jarModInfo.Version; JarModLoader=$jarModInfo.ModLoader
            }
            $verifiedMods += $modEntry; $allModsInfo += $modEntry
            continue
        }

        $unknownEntry = [PSCustomObject]@{
            FileName=$file.Name; FilePath=$file.FullName; ZoneId=$zoneInfo.URL
            DownloadSource=$zoneInfo.Source; IsModrinthDownload=$zoneInfo.IsModrinth
            FileSize=$actualSize; FileSizeKB=$actualSizeKB; Hash=$hash
            ExpectedSize=0; ExpectedSizeKB=0; SizeDiff=0; SizeDiffKB=0
            ModrinthUrl=""; ModName=""; MatchType=""; ExactMatch=$false; IsLatestVersion=$false
            LoaderType="Unknown"; PreferredLoader=$preferredLoader
            JarModId=$jarModInfo.ModId; JarName=$jarModInfo.Name; JarVersion=$jarModInfo.Version; JarModLoader=$jarModInfo.ModLoader
        }
        $unknownMods += $unknownEntry; $allModsInfo += $unknownEntry
    }

    # Post-scan Modrinth lookup for unknown mods
    for ($i=0; $i -lt $unknownMods.Count; $i++) {
        $mod = $unknownMods[$i]
        $mrInfo = $null
        if ($mod.JarModId) { $mrInfo = Fetch-Modrinth-By-ModId -modId $mod.JarModId -version $mod.JarVersion -preferredLoader $mod.PreferredLoader }
        if (-not $mrInfo -or -not $mrInfo.Name) { $mrInfo = Fetch-Modrinth-By-Filename -filename $mod.FileName -preferredLoader $mod.PreferredLoader }
        if ($mrInfo -and $mrInfo.Name) {
            $mod.ModName      = $mrInfo.Name
            $mod.ExpectedSize = $mrInfo.ExpectedSize
            $mod.ExpectedSizeKB = if ($mrInfo.ExpectedSize -gt 0) { [math]::Round($mrInfo.ExpectedSize/1KB,2) } else { 0 }
            $mod.SizeDiff     = $mod.FileSize - $mrInfo.ExpectedSize
            $mod.SizeDiffKB   = [math]::Round(($mod.FileSize - $mrInfo.ExpectedSize)/1KB,2)
            $mod.ModrinthUrl  = $mrInfo.ModrinthUrl
            $mod.MatchType    = $mrInfo.MatchType
            $mod.ExactMatch   = $mrInfo.ExactMatch
            $mod.IsLatestVersion = $mrInfo.IsLatestVersion
            $mod.LoaderType   = $mrInfo.LoaderType
            for ($j=0; $j -lt $allModsInfo.Count; $j++) {
                if ($allModsInfo[$j].FileName -eq $mod.FileName) {
                    $allModsInfo[$j].ModName=$mrInfo.Name; $allModsInfo[$j].ExpectedSize=$mrInfo.ExpectedSize
                    $allModsInfo[$j].ExpectedSizeKB=$mod.ExpectedSizeKB; $allModsInfo[$j].SizeDiff=$mod.SizeDiff
                    $allModsInfo[$j].SizeDiffKB=$mod.SizeDiffKB; $allModsInfo[$j].ModrinthUrl=$mrInfo.ModrinthUrl
                    $allModsInfo[$j].MatchType=$mrInfo.MatchType; $allModsInfo[$j].ExactMatch=$mrInfo.ExactMatch
                    $allModsInfo[$j].IsLatestVersion=$mrInfo.IsLatestVersion; $allModsInfo[$j].LoaderType=$mrInfo.LoaderType
                    break
                }
            }
        }
    }

    # Cheat string scan
    $tempDir = Join-Path $env:TEMP "yolegacysstool"
    $counter = 0
    try {
        if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        foreach ($mod in $allModsInfo) {
            $counter++
            $spin = $spinner[$counter % $spinner.Length]
            Write-Host "`r[$spin] Scanning for cheat strings: $counter / $totalMods" -ForegroundColor Magenta -NoNewline
            $modStrings = Check-CheatStrings $mod.FilePath
            if ($modStrings.Count -gt 0) {
                $cheatMods += [PSCustomObject]@{
                    FileName=$mod.FileName; StringsFound=$modStrings
                    FileSizeKB=if($mod.PSObject.Properties['FileSizeKB']){$mod.FileSizeKB}else{$mod.ActualSizeKB}
                    DownloadSource=$mod.DownloadSource; SourceURL=$mod.ZoneId
                    ExpectedSizeKB=$mod.ExpectedSizeKB; SizeDiffKB=$mod.SizeDiffKB
                    IsVerifiedMod=($mod.PSObject.Properties['IsVerified'] -and $mod.IsVerified -eq $true)
                    ModName=$mod.ModName; ModrinthUrl=$mod.ModrinthUrl; FilePath=$mod.FilePath
                    HasSizeMismatch=($mod.SizeDiffKB -ne 0 -and [math]::Abs($mod.SizeDiffKB) -gt 1)
                    JarModId=$mod.JarModId; JarName=$mod.JarName; JarVersion=$mod.JarVersion
                    MatchType=$mod.MatchType; ExactMatch=$mod.ExactMatch; LoaderType=$mod.LoaderType
                }
            }
        }
    } catch { Write-Host "`nScan error: $($_.Exception.Message)" -ForegroundColor Red }
    finally { if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue } }

    Write-Host "`r$(' '*80)`r" -NoNewline

    # ── Mod Results Display ───────────────────────────────────────
    Write-Host "`n{ Mod Scan Results }" -ForegroundColor Red
    Write-Host ""

    if ($verifiedMods.Count -gt 0) {
        Write-Host "{ Verified Mods } — Total: $($verifiedMods.Count)" -ForegroundColor Red
        Write-Host ""
        foreach ($mod in $verifiedMods) {
            $isCheating = $cheatMods.FileName -contains $mod.FileName
            $isTampered = $tamperedMods.FileName -contains $mod.FileName
            $nameColor  = if ($isTampered -or $isCheating) { "Red" } else { "Green" }
            Write-Host "> $($mod.ModName)" -ForegroundColor $nameColor -NoNewline
            Write-Host " - $($mod.FileName)" -ForegroundColor $(if ($isCheating) {"Red"} else {"Gray"}) -NoNewline
            if ($mod.Version -and $mod.Version -ne "Unknown") { Write-Host " [$($mod.Version)]" -ForegroundColor DarkGray -NoNewline }
            $mi=""; $mc="DarkGray"
            if     ($mod.MatchType -match "Exact")   { $mi="✓"; $mc="Green"  }
            elseif ($mod.MatchType -eq "Closest Version") { $mi="≈"; $mc="Yellow" }
            elseif ($mod.MatchType -match "Latest")  { $mi="↑"; $mc="Red"   }
            if ($mi) { Write-Host " $mi" -ForegroundColor $mc -NoNewline }
            if ($mod.LoaderType -ne "Unknown") { Write-Host " ($($mod.LoaderType))" -ForegroundColor $(if($mod.LoaderType -eq "Fabric"){"Magenta"}else{"Yellow"}) -NoNewline }
            if ($mod.DownloadSource -ne "Unknown") { Write-Host " [$($mod.DownloadSource)]" -ForegroundColor $(if($mod.IsModrinthDownload){"Green"}else{"DarkYellow"}) }
            else { Write-Host "" }
            if ($mod.ExpectedSize -gt 0) {
                if ($mod.ActualSize -eq $mod.ExpectedSize) { Write-Host "  Size: $($mod.ActualSizeKB) KB ✓" -ForegroundColor Green }
                else {
                    $sign=if($mod.SizeDiffKB -gt 0){"+"}else{""}
                    $sc=if($isTampered){"Magenta"}else{"Yellow"}
                    Write-Host "  Size: $($mod.ActualSizeKB) KB (Expected: $($mod.ExpectedSizeKB) KB, Diff: $sign$($mod.SizeDiffKB) KB)" -ForegroundColor $sc
                }
            }
        }
        Write-Host ""
    }

    if ($unknownMods.Count -gt 0) {
        Write-Host "{ Unknown Mods } — Total: $($unknownMods.Count)" -ForegroundColor Yellow
        Write-Host ""
        foreach ($mod in $unknownMods) {
            Write-Host "> $($mod.FileName)" -ForegroundColor Yellow
            Write-Host "  Size: $($mod.FileSizeKB) KB" -ForegroundColor Gray
            if ($mod.ModName) {
                Write-Host "  Identified as: $($mod.ModName)" -ForegroundColor Red
                if ($mod.ExpectedSize -gt 0) {
                    if ($mod.FileSize -eq $mod.ExpectedSize) { Write-Host "  Size matches Modrinth ✓" -ForegroundColor Green }
                    else {
                        $sign=if($mod.SizeDiffKB -gt 0){"+"}else{""}
                        Write-Host "  Expected: $($mod.ExpectedSizeKB) KB  Diff: $sign$($mod.SizeDiffKB) KB" -ForegroundColor Yellow
                    }
                }
            }
            if ($mod.ZoneId) { Write-Host "  Source: $($mod.DownloadSource)" -ForegroundColor $(if($mod.IsModrinthDownload){"Green"}else{"DarkYellow"}) }
            Write-Host ""
            Add-SSFinding -Category "Mod Analyzer" -Item $mod.FileName -Detail "Unknown mod — not found on Modrinth or Megabase" -Severity "WARNING"
        }
    }

    if ($tamperedMods.Count -gt 0) {
        Write-Host "{ Potentially Tampered Mods } — Total: $($tamperedMods.Count) ⚠" -ForegroundColor Red
        Write-Host ""
        foreach ($mod in $tamperedMods) {
            $sign=if($mod.SizeDiffKB -gt 0){"+"}else{""}
            Write-Host "> $($mod.FileName)" -ForegroundColor Red
            Write-Host "  Mod: $($mod.ModName)" -ForegroundColor Magenta
            Write-Host "  Expected: $($mod.ExpectedSizeKB) KB | Actual: $($mod.ActualSizeKB) KB | Diff: $sign$($mod.SizeDiffKB) KB" -ForegroundColor Magenta
            Write-Host "  ⚠ File size differs significantly from Modrinth!" -ForegroundColor Red
            if ($mod.ModrinthUrl) { Write-Host "  Verify: $($mod.ModrinthUrl)" -ForegroundColor DarkGray }
            Write-Host ""
            Add-SSFinding -Category "Mod Analyzer" -Item $mod.FileName -Detail "TAMPERED — size differs $sign$($mod.SizeDiffKB) KB from Modrinth: $($mod.ModName)" -Severity "CRITICAL"
        }
    }

    if ($cheatMods.Count -gt 0) {
        Write-Host "{ Cheat Mods Detected } — Total: $($cheatMods.Count) ⚠" -ForegroundColor Red
        Write-Host ""
        foreach ($mod in $cheatMods) {
            Write-Host "> $($mod.FileName)" -ForegroundColor Red
            if ($mod.ModName) { Write-Host "  Mod: $($mod.ModName)" -ForegroundColor Gray }
            Write-Host "  Cheat Strings: $($mod.StringsFound -join ', ')" -ForegroundColor Magenta
            Write-Host "  Size: $($mod.FileSizeKB) KB" -ForegroundColor Gray
            if ($mod.IsVerifiedMod) {
                Write-Host "  ⚠ LEGITIMATE MOD CONTAINS CHEAT CODE — tampered version!" -ForegroundColor Red
            }
            if ($mod.ExpectedSizeKB -gt 0) {
                $sign=if($mod.SizeDiffKB -gt 0){"+"}else{""}
                if ($mod.SizeDiffKB -eq 0) { Write-Host "  Size matches Modrinth ✓" -ForegroundColor Green }
                else {
                    Write-Host "  Expected: $($mod.ExpectedSizeKB) KB | Diff: $sign$($mod.SizeDiffKB) KB" -ForegroundColor Yellow
                    if ([math]::Abs($mod.SizeDiffKB) -gt 1) { Write-Host "  ⚠ Size mismatch + cheat strings = likely injected cheat!" -ForegroundColor Red }
                }
            }
            if ($mod.DownloadSource -ne "Unknown") { Write-Host "  Source: $($mod.DownloadSource)" -ForegroundColor $(if($mod.DownloadSource -eq "Modrinth"){"Green"}else{"DarkYellow"}) }
            Write-Host ""
            Add-SSFinding -Category "Mod Analyzer" -Item $mod.FileName -Detail "CHEAT MOD — strings found: $($mod.StringsFound -join ', ')" -Severity "CRITICAL"
        }
    }

    Write-Host "`n  Credits to Habibi Mod Analyzer (original concept)" -ForegroundColor DarkGray
}

# ================================================================
# FINAL CONCLUSION
# ================================================================
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║              YOLEGACY SS TOOL — CONCLUSION          ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

$toolEndTime  = Get-Date
$toolDuration = $toolEndTime - $toolStartTime
Write-Host ("  Scan completed in {0}m {1}s  |  {2}" -f [int]$toolDuration.TotalMinutes, $toolDuration.Seconds, $toolEndTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor DarkGray
Write-Host ""

$criticals = $global:ssFindings | Where-Object { $_.Severity -eq "CRITICAL" }
$warnings  = $global:ssFindings | Where-Object { $_.Severity -eq "WARNING"  }
$infos     = $global:ssFindings | Where-Object { $_.Severity -eq "INFO"     }

if ($criticals.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Host "  ✅ No suspicious activity detected — looks clean!" -ForegroundColor Green
    Write-Host ""
} else {
    if ($criticals.Count -gt 0) {
        Write-Host ("  🔴 CRITICAL FINDINGS : {0}" -f $criticals.Count) -ForegroundColor Red
        Write-Host "  ─────────────────────────────────────────────────" -ForegroundColor DarkRed
        $catGroups = $criticals | Group-Object Category
        foreach ($group in $catGroups) {
            Write-Host ("  [ {0} ]" -f $group.Name.ToUpper()) -ForegroundColor Red
            foreach ($f in $group.Group) {
                Write-Host "    • $($f.Item)" -ForegroundColor White -NoNewline
                Write-Host " — $($f.Detail)" -ForegroundColor DarkRed
            }
            Write-Host ""
        }
    }

    if ($warnings.Count -gt 0) {
        Write-Host ("  🟡 WARNINGS          : {0}" -f $warnings.Count) -ForegroundColor Yellow
        Write-Host "  ─────────────────────────────────────────────────" -ForegroundColor DarkYellow
        $catGroups = $warnings | Group-Object Category
        foreach ($group in $catGroups) {
            Write-Host ("  [ {0} ]" -f $group.Name.ToUpper()) -ForegroundColor Yellow
            foreach ($f in $group.Group) {
                Write-Host "    • $($f.Item)" -ForegroundColor White -NoNewline
                Write-Host " — $($f.Detail)" -ForegroundColor DarkYellow
            }
            Write-Host ""
        }
    }
}

if ($infos.Count -gt 0) {
    Write-Host ("  ℹ INFO               : {0}" -f $infos.Count) -ForegroundColor Red
    Write-Host "  ─────────────────────────────────────────────────" -ForegroundColor DarkRed
    foreach ($f in $infos) {
        Write-Host "    • [$($f.Category)] $($f.Item) — $($f.Detail)" -ForegroundColor DarkRed
    }
    Write-Host ""
}

# Overall verdict
Write-Host "  ┌─────────────────────────────────────────────────┐" -ForegroundColor Red
if ($criticals.Count -ge 3) {
    Write-Host "  │  VERDICT:  🔴  HIGHLY SUSPICIOUS — BAN LIKELY  │" -ForegroundColor Red
} elseif ($criticals.Count -ge 1) {
    Write-Host "  │  VERDICT:  🟠  SUSPICIOUS — INVESTIGATE FURTHER │" -ForegroundColor DarkYellow
} elseif ($warnings.Count -ge 3) {
    Write-Host "  │  VERDICT:  🟡  MODERATE CONCERN — REVIEW NEEDED │" -ForegroundColor Yellow
} elseif ($warnings.Count -ge 1) {
    Write-Host "  │  VERDICT:  🟡  MINOR FLAGS — LIKELY CLEAN        │" -ForegroundColor Yellow
} else {
    Write-Host "  │  VERDICT:  🟢  CLEAN — NO ISSUES FOUND           │" -ForegroundColor Green
}
Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor Red
Write-Host ""
Write-Host "  Non-MS executable paths saved to: C:\YoLegacy\paths.txt" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Made by YoLegacy  |  YoLegacy SS TOOL v1.0" -ForegroundColor DarkRed
Write-Host ""

Write-Host "Press any key to exit..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
