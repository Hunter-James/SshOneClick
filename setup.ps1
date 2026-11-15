[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$root = Join-Path $env:ProgramData 'ssh'
$config = Join-Path $root 'sshd_config'
$keyFile = Join-Path $root 'ssh_one_click_authorized_keys'
$rule = 'SshOneClick-Local'
$port = 2222
$marker = '# Managed by SshOneClick'
$bin = Join-Path $env:SystemRoot 'System32\OpenSSH'

# Write plain text to the console and the Go launcher's report.
function Write-Status([string]$message) {
    [Console]::WriteLine($message)
}

# Return addresses that can be used to reach this adapter over IPv4.
function Get-LanIPv4($profile) {
    Get-NetIPAddress -InterfaceIndex $profile.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -ExpandProperty IPAddress
}

# Run the same OpenSSH binary in the foreground with a loopback-only configuration.
function Write-SshDebugReport {
    $debugConfig = Join-Path $root ("sshd_debug_{0}.conf" -f [guid]::NewGuid().ToString('N'))
    $process = New-Object Diagnostics.Process
    $launched = $false
    try {
        $debugLines = @(Get-Content -LiteralPath $config | Where-Object { $_ -notmatch '^ListenAddress\s' })
        $debugLines += 'ListenAddress 127.0.0.1'
        $debugLines | Set-Content -LiteralPath $debugConfig -Encoding ascii

        $process.StartInfo.FileName = Join-Path $bin 'sshd.exe'
        $process.StartInfo.Arguments = '-ddd -e -f "' + $debugConfig + '"'
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.CreateNoWindow = $true
        Write-Status 'OpenSSH foreground debug (127.0.0.1 only):'
        $launched = $process.Start()
        if (!$launched) { throw 'Could not start foreground sshd.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(8000)) {
            Write-Status 'Foreground sshd was still running after 8 seconds. Stopping it.'
            $process.Kill()
            [void]$process.WaitForExit(3000)
        } else {
            Write-Status ('Foreground sshd exit code: {0} (0x{0:X8})' -f $process.ExitCode)
        }
        foreach ($stream in $stdout, $stderr) {
            if ($stream.Wait(1000) -and $stream.Result) { Write-Status $stream.Result.TrimEnd() }
        }
    } finally {
        if ($launched -and !$process.HasExited) {
            try { $process.Kill() } catch { Write-Status "Could not stop foreground sshd: $($_.Exception.Message)" }
        }
        $process.Dispose()
        Remove-Item -LiteralPath $debugConfig -ErrorAction SilentlyContinue
    }
}

# Keep the fallback tied to this setup window and capture OpenSSH output on exit.
function Start-StandaloneSsh {
    $process = New-Object Diagnostics.Process
    $launched = $false
    try {
        $process.StartInfo.FileName = Join-Path $bin 'sshd.exe'
        $process.StartInfo.Arguments = '-D -e -f "' + $config + '"'
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        Write-Status 'Attempt 2: standalone OpenSSH.'
        $launched = $process.Start()
        if (!$launched) { throw 'Could not launch standalone OpenSSH.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            if ($process.HasExited) { throw "Standalone OpenSSH exited with code $($process.ExitCode)." }
            $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $port -OwningProcess $process.Id -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty LocalAddress)
            $reachable = @($addresses | Where-Object { $listeners -contains $_ })
            if ($reachable.Count) { break }
            Start-Sleep -Milliseconds 500
        } while ([DateTime]::UtcNow -lt $deadline)
        if (!$reachable.Count) { throw 'Standalone OpenSSH did not open a LAN listener.' }

        Write-ConnectionDetails $reachable
        Write-Status 'Standalone SSH is listening. Leave this window open while connecting.'
        Write-Status 'Press Enter to stop standalone SSH and remove its firewall rule.'
        [void][Console]::ReadLine()
    } finally {
        try {
            if ($launched) {
                if (!$process.HasExited) { $process.Kill() }
                [void]$process.WaitForExit(3000)
                foreach ($stream in $stdout, $stderr) {
                    if ($stream -and $stream.Wait(1000) -and $stream.Result) { Write-Status $stream.Result.TrimEnd() }
                }
            }
        } finally {
            $process.Dispose()
            Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
    }
}

function Write-ConnectionDetails($reachable) {
    foreach ($address in $reachable) {
        Write-Status "SSH address: ${address}:$port"
        Write-Status "Client command: ssh -i netbook_key -p $port $user@$address"
    }
    Write-Status 'Server fingerprint (ED25519):'
    & "$bin\ssh-keygen.exe" -lf (Join-Path $root 'ssh_host_ed25519_key.pub') | ForEach-Object { Write-Status $_ }
}

function Get-PrivateLanAddresses {
    $profiles = @(Get-NetConnectionProfile)
    $addresses = @(foreach ($profile in $profiles | Where-Object NetworkCategory -eq 'Private') {
        Get-LanIPv4 $profile
    })
    if ($addresses.Count) { return $addresses }

    foreach ($profile in $profiles | Where-Object NetworkCategory -eq 'Public') {
        $addresses = @(Get-LanIPv4 $profile)
        if (!$addresses.Count) { continue }

        Write-Status "Network: $($profile.Name) [$($profile.InterfaceAlias), $($addresses -join ', ')]"
        Write-Status 'Do you trust this network? Setting it to Private applies Windows private-network firewall rules.'
        [Console]::Write('Set this network to Private and continue SSH setup? [y/N]: ')
        $answer = [Console]::ReadLine()
        if ($null -eq $answer) { break }
        if ($answer.Trim() -ine 'y') { continue }

        $current = Get-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex
        if ($current.Name -ne $profile.Name -or $current.NetworkCategory -ne 'Public' -or
            (($addresses -join ",") -ne (@(Get-LanIPv4 $current) -join ","))) {
            throw 'The network changed while waiting for confirmation. Run SshOneClick again.'
        }

        Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Private
        $current = Get-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex
        if ($current.NetworkCategory -ne 'Private') { throw 'Windows did not apply the Private network profile.' }
        Write-Status "Network profile set to Private: $($current.Name)"
        return (Get-LanIPv4 $current)
    }
}

try {
    if ($action -eq 'SelfTest') {
        if ([Console]::ReadLine() -cne 'SshOneClick') { throw 'Console input self-test failed.' }
        Write-Status 'PowerShell setup script loaded and console input verified.'
        exit 0
    }
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required.'
    }
    $managed = (Test-Path -LiteralPath $config) -and ((Get-Content -LiteralPath $config -TotalCount 1) -eq $marker)
    if ($action -eq 'Stop') {
        if ($managed) {
            Set-Service sshd -StartupType Disabled
            Stop-Service sshd -Force
            Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
        Write-Status 'SshOneClick access is disabled.'
        exit 0
    }

    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($build -lt 17763) { throw 'Requires Windows 10 version 1809 (build 17763) or later.' }
    $account = $identity.Name.Split('\')
    if ($account.Count -ne 2 -or $account[0] -ine $env:COMPUTERNAME -or $account[1] -notmatch '^[a-zA-Z0-9_.-]+$') {
        throw 'Run under a local administrator account with a name using letters A-Z, digits, dots, hyphens or underscores.'
    }
    $user = $account[1].ToLowerInvariant()

    $firewall = Get-NetFirewallProfile -PolicyStore ActiveStore -Name Private
    if (!$firewall.Enabled -or $firewall.DefaultInboundAction -eq 'Allow' -or $firewall.AllowLocalFirewallRules -eq 'False') {
        throw 'The private firewall profile must be enabled, block inbound traffic by default and allow local rules.'
    }

    $service = Get-Service sshd -ErrorAction SilentlyContinue
    if (!$managed -and ($service -or (Test-Path -LiteralPath $config))) {
        throw 'An existing OpenSSH setup was found. Its configuration was left intact.'
    }

    $addresses = @(Get-PrivateLanAddresses)
    if (!$addresses.Count) { throw 'No trusted LAN with an active IPv4 address was selected.' }

    $configure = $false
    try {
        if (!$service) {
            $capability = 'OpenSSH.Server~~~~0.0.1.0'
            Write-Status 'Installing Windows OpenSSH Server. This can take several minutes.'
            $result = Add-WindowsCapability -Online -Name $capability
            if ($result.RestartNeeded) { throw 'Windows requires a reboot. Run SshOneClick again after restarting.' }
        }

        $configure = $true
        Set-Service sshd -StartupType Disabled
        Stop-Service sshd -Force
        Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
        Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule

        if (!(Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root | Out-Null }
        $key | Set-Content -LiteralPath $keyFile -Encoding ascii
        & "$env:SystemRoot\System32\icacls.exe" $keyFile '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-String -Stream | ForEach-Object { Write-Status $_ }
        if ($LASTEXITCODE -ne 0) { throw 'Could not set SSH public key permissions.' }

        $lines = @(
            $marker
            "Port $port"
            'AddressFamily inet'
            'SyslogFacility LOCAL0'
            'LogLevel VERBOSE'
            'ListenAddress 127.0.0.1'
            foreach ($address in $addresses) { "ListenAddress $address" }
            'PubkeyAuthentication yes'
            'AuthenticationMethods publickey'
            'PasswordAuthentication no'
            'AllowTcpForwarding no'
            'AllowAgentForwarding no'
            'AuthorizedKeysFile __PROGRAMDATA__/ssh/ssh_one_click_authorized_keys'
            "AllowUsers $user"
        )
        $lines | Set-Content -LiteralPath $config -Encoding ascii
        & "$bin\ssh-keygen.exe" -A | Out-String -Stream | ForEach-Object { Write-Status $_ }
        if ($LASTEXITCODE -ne 0) { throw 'Could not generate SSH host keys.' }
        & "$bin\sshd.exe" -t -f $config
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSH rejected the configuration.' }

        New-NetFirewallRule -Name $rule -DisplayName 'SshOneClick (private LAN)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Private -RemoteAddress LocalSubnet4 -Program "$bin\sshd.exe" | Out-Null
        Set-Service sshd -StartupType Manual
        $startedAt = Get-Date
        $serviceControl = Join-Path $env:SystemRoot 'System32\sc.exe'
        try {
            Write-Status 'Attempt 1: Windows OpenSSH service.'
            & $serviceControl start sshd | ForEach-Object { Write-Status $_ }
            $startCode = $LASTEXITCODE
            Write-Status "sc.exe start sshd exit code: $startCode"
            if ($startCode -ne 0 -and $startCode -ne 1056) {
                throw "Windows could not start sshd (sc.exe exit code $startCode)."
            }
            Write-Status 'Waiting for OpenSSH to accept connections...'
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            do {
                $client = New-Object Net.Sockets.TcpClient
                try {
                    $client.Connect('127.0.0.1', $port)
                    $client.ReceiveTimeout = 2000
                    $reader = New-Object IO.StreamReader($client.GetStream())
                    if ($reader.ReadLine() -like 'SSH-2.0-*') { break }
                    $problem = 'The port did not return an SSH banner.'
                } catch {
                    $problem = $_.Exception.GetBaseException().Message
                } finally {
                    $client.Dispose()
                }
                if ((Get-Service sshd).Status -eq 'Stopped' -or [DateTime]::UtcNow -ge $deadline) {
                    throw "OpenSSH did not become ready on 127.0.0.1:${port}. $problem"
                }
                Start-Sleep -Milliseconds 500
            } while ($true)
        } catch {
            Write-Status "sshd service status: $((Get-Service sshd -ErrorAction SilentlyContinue).Status)"
            foreach ($command in 'queryex', 'qc') {
                Write-Status "sc.exe $command sshd"
                & $serviceControl $command sshd | ForEach-Object { Write-Status $_ }
            }
            $serviceName = (Get-Service sshd -ErrorAction SilentlyContinue).DisplayName
            $events = @(Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Service Control Manager'
                StartTime = $startedAt.AddSeconds(-5)
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Properties.Value -contains 'sshd' -or
                    ($serviceName -and $_.Properties.Value -contains $serviceName) -or
                    $_.Message -match '\bsshd\b|OpenSSH'
            } | Select-Object -First 8)
            Write-Status "Service Control Manager events for sshd: $($events.Count)"
            foreach ($event in $events) {
                Write-Status "$($event.TimeCreated.ToString('s')) [$($event.Id)] $($event.Message)"
            }
            Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
                Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize | Out-String -Stream | ForEach-Object { Write-Status $_ }
            foreach ($log in 'OpenSSH/Admin', 'OpenSSH/Operational') {
                Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$startedAt} -MaxEvents 8 -ErrorAction SilentlyContinue |
                    ForEach-Object { Write-Status "$log [$($_.Id)] $($_.Message)" }
            }
            $serviceLog = Join-Path $root 'logs\sshd.log'
            $logFile = Get-Item -LiteralPath $serviceLog -ErrorAction SilentlyContinue
            if ($logFile -and $logFile.LastWriteTime -ge $startedAt.AddSeconds(-2)) {
                Write-Status 'Recent sshd file log:'
                Get-Content -LiteralPath $serviceLog -Tail 60 -ErrorAction SilentlyContinue |
                    ForEach-Object { Write-Status $_ }
            } else {
                Write-Status 'The service did not write a fresh sshd.log.'
            }
            Write-Status 'OpenSSH file permissions:'
            foreach ($path in @($root, $config, $keyFile, (Join-Path $root 'logs')) + @(Get-ChildItem -LiteralPath $root -Filter 'ssh_host_*_key' -Name | ForEach-Object { Join-Path $root $_ })) {
                if (Test-Path -LiteralPath $path) {
                    & "$env:SystemRoot\System32\icacls.exe" $path | ForEach-Object { Write-Status $_ }
                }
            }
            if ((Get-Service sshd).Status -eq 'Stopped') {
                try { Write-SshDebugReport } catch { Write-Status "Foreground diagnostics failed: $($_.Exception.Message)" }
            }
            $crashes = @(Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                Id = 1000, 1001
                StartTime = $startedAt.AddSeconds(-5)
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -match '\bsshd\.exe\b' -or $_.Properties.Value -contains 'sshd.exe'
            } | Select-Object -First 8)
            Write-Status "Application crash events for sshd: $($crashes.Count)"
            foreach ($event in $crashes) {
                Write-Status "$($event.TimeCreated.ToString('s')) [$($event.Id)] $($event.Message)"
            }
            Write-Status "Service attempt failed: $($_.Exception.Message)"
            Set-Service sshd -StartupType Disabled
            Stop-Service sshd -Force
            Start-StandaloneSsh
            Write-Status 'Standalone SSH session ended.'
            exit 0
        }
        Write-ConnectionDetails $addresses
        Write-Status 'SSH remains available until disabled or Windows restarts.'
    } catch {
        if ($configure) {
            Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service sshd -Force -ErrorAction SilentlyContinue
        }
        throw
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
