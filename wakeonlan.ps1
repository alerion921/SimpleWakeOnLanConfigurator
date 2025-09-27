#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Advanced Wake-on-LAN Configurator & Manager
.DESCRIPTION
    Comprehensive tool for configuring, testing, and managing Wake-on-LAN functionality
    across network adapters with full GUI interface and advanced features.
.AUTHOR
    Enhanced WoL Configurator v2.0
.VERSION
    2.0.0
#>

param(
    [switch]$Debug,
    [string]$ConfigFile = "$env:USERPROFILE\Documents\WoLConfig.json"
)

# Assembly imports
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Drawing.Design

# Global variables
$global:Config = @{}
$global:LogEntries = @()
$global:CurrentAdapter = $null
$global:Adapters = @()
$global:DiscoveredDevices = @()
$global:WoLProfiles = @()

# Constants
$Script:AppTitle = "Advanced Wake-on-LAN Configurator v2.0"
$Script:ConfigPath = $ConfigFile
$Script:LogPath = "$env:TEMP\WoL_Debug.log"

#region Utility Functions

function Write-WoLLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $global:LogEntries += @{
        Timestamp = $timestamp
        Level = $Level  
        Message = $Message
        Entry = $logEntry
    }
    
    if ($Debug) {
        $logEntry | Out-File -FilePath $Script:LogPath -Append -Encoding UTF8
    }
    
    # Keep only last 1000 entries
    if ($global:LogEntries.Count -gt 1000) {
        $global:LogEntries = $global:LogEntries[-1000..-1]
    }
}

function Show-MessageBox {
    param(
        [string]$Message,
        [string]$Title = $Script:AppTitle,
        [System.Windows.Forms.MessageBoxButtons]$Buttons = 'OK',
        [System.Windows.Forms.MessageBoxIcon]$Icon = 'Information'
    )
    
    Write-WoLLog -Message "MessageBox: $Title - $Message" -Level 'Info'
    return [System.Windows.Forms.MessageBox]::Show($Message, $Title, $Buttons, $Icon)
}

function Ensure-RunAsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $result = Show-MessageBox -Message "This application requires Administrator privileges to modify network adapter settings. Would you like to restart as Administrator?" -Title "Administrator Required" -Buttons 'YesNo' -Icon 'Warning'
        
        if ($result -eq 'Yes') {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
            if ($Debug) { $psi.Arguments += " -Debug" }
            $psi.Verb = "runas"
            try {
                [System.Diagnostics.Process]::Start($psi) | Out-Null
            } catch {
                Show-MessageBox -Message "Failed to restart as Administrator: $($_.Exception.Message)" -Title "Error" -Icon 'Error'
            }
        }
        Exit
    }
}

# Run admin check
Ensure-RunAsAdmin
Write-WoLLog -Message "Application started with Administrator privileges" -Level 'Info'

function Test-MacAddress {
    param([string]$MacAddress)
    
    if ([string]::IsNullOrWhiteSpace($MacAddress)) {
        return $false
    }
    
    # Remove common separators and whitespace
    $clean = $MacAddress -replace '[:\-\s]', ''
    
    # Check if it's exactly 12 hex characters
    if ($clean.Length -ne 12) {
        return $false
    }
    
    # Check if all characters are valid hex
    return $clean -match '^[0-9A-Fa-f]{12}$'
}

function Format-MacAddress {
    param(
        [string]$MacAddress,
        [ValidateSet('Colon', 'Dash', 'None')]
        [string]$Format = 'Colon'
    )
    
    if (-not (Test-MacAddress $MacAddress)) {
        throw "Invalid MAC address format: $MacAddress"
    }
    
    $clean = $MacAddress -replace '[:\-\s]', ''
    
    switch ($Format) {
        'Colon' { 
            return ($clean -replace '(.{2})', '$1:').TrimEnd(':')
        }
        'Dash' { 
            return ($clean -replace '(.{2})', '$1-').TrimEnd('-')
        }
        'None' { 
            return $clean.ToUpper()
        }
    }
}

function Parse-MacAddress {
    param([string]$MacAddress)
    
    if (-not (Test-MacAddress $MacAddress)) {
        throw "Invalid MAC address format: $MacAddress. Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX"
    }
    
    $clean = $MacAddress -replace '[:\-\s]', ''
    $bytes = for ($i = 0; $i -lt 12; $i += 2) { 
        [byte]::Parse($clean.Substring($i, 2), 'AllowHexSpecifier') 
    }
    return ,$bytes
}

function Send-MagicPacket {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MacAddress,
        [string]$BroadcastAddress = '255.255.255.255',
        [ValidateRange(1, 65535)]
        [int]$Port = 9,
        [string]$Interface = $null,
        [int]$Count = 1,
        [int]$DelayMs = 1000
    )
    
    Write-WoLLog -Message "Preparing to send magic packet to MAC: $MacAddress, Broadcast: $BroadcastAddress, Port: $Port" -Level 'Info'
    
    try {
        # Validate and parse MAC address
        $macBytes = Parse-MacAddress -MacAddress $MacAddress
        
        # Create magic packet (6 bytes of 0xFF followed by 16 repetitions of MAC)
        $payload = [byte[]](,0xFF * 6)
        for ($i = 0; $i -lt 16; $i++) { 
            $payload += $macBytes 
        }
        
        Write-WoLLog -Message "Magic packet payload created: $($payload.Length) bytes" -Level 'Debug'
        
        $results = @()
        
        for ($attempt = 1; $attempt -le $Count; $attempt++) {
            try {
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $udpClient.EnableBroadcast = $true
                
                # Bind to specific interface if specified
                if ($Interface) {
                    $localEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($Interface), 0)
                    $udpClient.Client.Bind($localEndpoint)
                }
                
                $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($BroadcastAddress), $Port)
                $bytesSent = $udpClient.Send($payload, $payload.Length, $endpoint)
                $udpClient.Close()
                
                $result = @{
                    Attempt = $attempt
                    Success = $true
                    BytesSent = $bytesSent
                    Timestamp = Get-Date
                    Error = $null
                }
                
                Write-WoLLog -Message "Magic packet sent successfully (attempt $attempt): $bytesSent bytes to $BroadcastAddress`:$Port" -Level 'Info'
                
            } catch {
                $result = @{
                    Attempt = $attempt
                    Success = $false
                    BytesSent = 0
                    Timestamp = Get-Date
                    Error = $_.Exception.Message
                }
                
                Write-WoLLog -Message "Failed to send magic packet (attempt $attempt): $($_.Exception.Message)" -Level 'Error'
                
                if ($udpClient) {
                    $udpClient.Close()
                }
            }
            
            $results += $result
            
            # Delay between attempts (except for last attempt)
            if ($attempt -lt $Count -and $DelayMs -gt 0) {
                Start-Sleep -Milliseconds $DelayMs
            }
        }
        
        return $results
        
    } catch {
        Write-WoLLog -Message "Magic packet send failed: $($_.Exception.Message)" -Level 'Error'
        throw
    }
}

function Test-NetworkConnectivity {
    param(
        [string]$Target,
        [int]$Port = 80,
        [int]$TimeoutMs = 5000
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($Target, $Port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        
        if ($wait) {
            $tcpClient.EndConnect($asyncResult)
            $tcpClient.Close()
            return $true
        } else {
            $tcpClient.Close()
            return $false
        }
    } catch {
        return $false
    }
}

function Get-NetworkInterfaces {
    try {
        Write-WoLLog -Message "Enumerating network adapters" -Level 'Debug'
        
        $adapters = Get-NetAdapter -Physical | Where-Object { 
            $_.Status -ne $null -and $_.InterfaceType -eq 6  # Ethernet interfaces
        } | Sort-Object Name
        
        $enhancedAdapters = foreach ($adapter in $adapters) {
            try {
                # Get additional network information
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                $ipAddresses = $ipConfig.IPv4Address.IPAddress -join ', '
                
                # Get power management info
                $powerMgmt = $null
                try {
                    $powerMgmt = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction Stop
                } catch {
                    Write-WoLLog -Message "Could not get power management info for $($adapter.Name): $($_.Exception.Message)" -Level 'Debug'
                }
                
                # Get PnP device info
                $pnpDevice = Get-PnpDevice -Class Net -Status OK | Where-Object {
                    $_.FriendlyName -like "*$($adapter.InterfaceDescription.Split(',')[0])*"
                } | Select-Object -First 1
                
                [PSCustomObject]@{
                    Adapter = $adapter
                    Name = $adapter.Name
                    Description = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    MacAddress = $adapter.MacAddress
                    LinkSpeed = $adapter.LinkSpeed
                    IPAddresses = $ipAddresses
                    PowerManagement = $powerMgmt
                    PnPDevice = $pnpDevice
                    DriverDate = $adapter.DriverDate
                    DriverVersion = $adapter.DriverVersion
                    InterfaceIndex = $adapter.InterfaceIndex
                }
            } catch {
                Write-WoLLog -Message "Error processing adapter $($adapter.Name): $($_.Exception.Message)" -Level 'Warning'
                $null
            }
        }
        
        return $enhancedAdapters | Where-Object { $_ -ne $null }
        
    } catch {
        Write-WoLLog -Message "Failed to enumerate network adapters: $($_.Exception.Message)" -Level 'Error'
        return @()
    }
}

function Save-Configuration {
    param([string]$Path = $Script:ConfigPath)
    
    try {
        $config = @{
            Version = "2.0.0"
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            WoLProfiles = $global:WoLProfiles
            Settings = $global:Config
        }
        
        $json = $config | ConvertTo-Json -Depth 10 -Compress
        $json | Out-File -FilePath $Path -Encoding UTF8 -Force
        
        Write-WoLLog -Message "Configuration saved to: $Path" -Level 'Info'
        return $true
        
    } catch {
        Write-WoLLog -Message "Failed to save configuration: $($_.Exception.Message)" -Level 'Error'
        return $false
    }
}

function Load-Configuration {
    param([string]$Path = $Script:ConfigPath)
    
    if (-not (Test-Path $Path)) {
        Write-WoLLog -Message "Configuration file not found, using defaults: $Path" -Level 'Info'
        Initialize-DefaultConfiguration
        return
    }
    
    try {
        $json = Get-Content -Path $Path -Raw -Encoding UTF8
        $config = $json | ConvertFrom-Json
        
        if ($config.WoLProfiles) {
            $global:WoLProfiles = @($config.WoLProfiles)
        }
        
        if ($config.Settings) {
            $global:Config = @{}
            $config.Settings.PSObject.Properties | ForEach-Object {
                $global:Config[$_.Name] = $_.Value
            }
        }
        
        Write-WoLLog -Message "Configuration loaded from: $Path" -Level 'Info'
        
    } catch {
        Write-WoLLog -Message "Failed to load configuration, using defaults: $($_.Exception.Message)" -Level 'Warning'
        Initialize-DefaultConfiguration
    }
}

function Initialize-DefaultConfiguration {
    $global:Config = @{
        DefaultPort = 9
        DefaultBroadcast = '255.255.255.255'
        MagicPacketCount = 3
        MagicPacketDelay = 1000
        AutoSaveProfiles = $true
        EnableLogging = $false
        Theme = 'System'
        WindowState = 'Normal'
        WindowSize = @{ Width = 1200; Height = 900 }
    }
    
    $global:WoLProfiles = @()
    Write-WoLLog -Message "Default configuration initialized" -Level 'Info'
}

function New-WoLProfile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$MacAddress,
        [string]$IPAddress = '',
        [string]$BroadcastAddress = '255.255.255.255',
        [int]$Port = 9,
        [string]$Description = '',
        [string]$Group = 'Default'
    )
    
    if (-not (Test-MacAddress $MacAddress)) {
        throw "Invalid MAC address: $MacAddress"
    }
    
    $profile = @{
        Id = [System.Guid]::NewGuid().ToString()
        Name = $Name
        MacAddress = Format-MacAddress $MacAddress -Format 'Colon'
        IPAddress = $IPAddress
        BroadcastAddress = $BroadcastAddress
        Port = $Port
        Description = $Description
        Group = $Group
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        LastUsed = $null
        UseCount = 0
    }
    
    return $profile
}

function Add-WoLProfile {
    param($Profile)
    
    # Check for duplicate names
    if ($global:WoLProfiles | Where-Object { $_.Name -eq $Profile.Name }) {
        throw "A profile with the name '$($Profile.Name)' already exists"
    }
    
    $global:WoLProfiles += $Profile
    
    if ($global:Config.AutoSaveProfiles) {
        Save-Configuration
    }
    
    Write-WoLLog -Message "Added WoL profile: $($Profile.Name)" -Level 'Info'
}

function Remove-WoLProfile {
    param([string]$ProfileId)
    
    $profile = $global:WoLProfiles | Where-Object { $_.Id -eq $ProfileId } | Select-Object -First 1
    if ($profile) {
        $global:WoLProfiles = $global:WoLProfiles | Where-Object { $_.Id -ne $ProfileId }
        
        if ($global:Config.AutoSaveProfiles) {
            Save-Configuration
        }
        
        Write-WoLLog -Message "Removed WoL profile: $($profile.Name)" -Level 'Info'
        return $true
    }
    
    return $false
}

function Update-WoLProfileUsage {
    param([string]$ProfileId)
    
    $profile = $global:WoLProfiles | Where-Object { $_.Id -eq $ProfileId } | Select-Object -First 1
    if ($profile) {
        $profile.LastUsed = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $profile.UseCount++
        
        if ($global:Config.AutoSaveProfiles) {
            Save-Configuration
        }
    }
}

function Discover-NetworkDevices {
    param(
        [string]$NetworkRange = $null,
        [int]$TimeoutMs = 2000,
        [switch]$IncludeOfflineDevices
    )
    
    Write-WoLLog -Message "Starting network device discovery" -Level 'Info'
    
    try {
        $devices = @()
        
        # Get current network configuration
        $netConfigs = Get-NetIPConfiguration | Where-Object { 
            $_.NetAdapter.Status -eq 'Up' -and 
            $_.IPv4Address.Count -gt 0 
        }
        
        foreach ($config in $netConfigs) {
            $adapter = $config.NetAdapter
            $ipAddress = $config.IPv4Address[0].IPAddress
            $prefixLength = $config.IPv4Address[0].PrefixLength
            
            # Calculate network range if not specified
            if (-not $NetworkRange) {
                $network = Get-NetworkRange -IPAddress $ipAddress -PrefixLength $prefixLength
            } else {
                $network = $NetworkRange
            }
            
            Write-WoLLog -Message "Scanning network range: $network for adapter: $($adapter.Name)" -Level 'Debug'
            
            # Scan ARP table first (faster)
            $arpEntries = Get-NetNeighbor -AddressFamily IPv4 -State Reachable, Stale, Permanent -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' }
            
            foreach ($arp in $arpEntries) {
                if ($arp.LinkLayerAddress -and $arp.LinkLayerAddress -ne '00-00-00-00-00-00') {
                    $hostname = 'Unknown'
                    try {
                        $hostname = [System.Net.Dns]::GetHostEntry($arp.IPAddress).HostName
                    } catch { }
                    
                    $devices += @{
                        IPAddress = $arp.IPAddress
                        MacAddress = $arp.LinkLayerAddress
                        Hostname = $hostname
                        Status = 'Online'
                        Adapter = $adapter.Name
                        DiscoveryMethod = 'ARP'
                        LastSeen = Get-Date
                    }
                }
            }
        }
        
        # Deduplicate devices by MAC address
        $uniqueDevices = $devices | Group-Object MacAddress | ForEach-Object {
            $_.Group | Sort-Object LastSeen | Select-Object -Last 1
        }
        
        $global:DiscoveredDevices = $uniqueDevices | Sort-Object IPAddress
        
        Write-WoLLog -Message "Network discovery completed: $($global:DiscoveredDevices.Count) devices found" -Level 'Info'
        
        return $global:DiscoveredDevices
        
    } catch {
        Write-WoLLog -Message "Network discovery failed: $($_.Exception.Message)" -Level 'Error'
        return @()
    }
}

function Get-NetworkRange {
    param(
        [string]$IPAddress,
        [int]$PrefixLength
    )
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        $mask = [System.Net.IPAddress]::Parse((Convert-PrefixLengthToSubnetMask $PrefixLength))
        
        $networkBytes = @()
        for ($i = 0; $i -lt 4; $i++) {
            $networkBytes += $ip.GetAddressBytes()[$i] -band $mask.GetAddressBytes()[$i]
        }
        
        $network = ($networkBytes -join '.') + "/$PrefixLength"
        return $network
        
    } catch {
        return '192.168.1.0/24'  # Default fallback
    }
}

function Convert-PrefixLengthToSubnetMask {
    param([int]$PrefixLength)
    
    $mask = 0
    for ($i = 0; $i -lt $PrefixLength; $i++) {
        $mask = $mask -bor (1 -shl (31 - $i))
    }
    
    $bytes = @(
        ($mask -shr 24) -band 0xFF,
        ($mask -shr 16) -band 0xFF,
        ($mask -shr 8) -band 0xFF,
        $mask -band 0xFF
    )
    
    return $bytes -join '.'
}

#endregion

#region Power Management Functions

function Get-AdapterPowerManagement {
    param([object]$Adapter)
    
    try {
        $powerMgmt = Get-NetAdapterPowerManagement -Name $Adapter.Name -ErrorAction Stop
        $advanced = Get-NetAdapterAdvancedProperty -Name $Adapter.Name -ErrorAction SilentlyContinue
        
        # Get WoL specific advanced properties
        $wolProperties = @{}
        $commonWoLKeywords = @(
            'WakeOnMagicPacket', 'WakeOnPattern', 'WakeOnLink', 'WakeFromShutdown',
            'EnablePME', 'PMEEnable', 'WakeUpCapabilities', 'PowerManagement'
        )
        
        foreach ($prop in $advanced) {
            if ($commonWoLKeywords -contains $prop.RegistryKeyword) {
                $wolProperties[$prop.RegistryKeyword] = @{
                    DisplayName = $prop.DisplayName
                    Value = $prop.DisplayValue
                    RegistryKeyword = $prop.RegistryKeyword
                    ValidDisplayValues = $prop.ValidDisplayValues
                }
            }
        }
        
        return @{
            PowerManagement = $powerMgmt
            WoLProperties = $wolProperties
            AdvancedProperties = $advanced
        }
        
    } catch {
        Write-WoLLog -Message "Failed to get power management for adapter $($Adapter.Name): $($_.Exception.Message)" -Level 'Warning'
        return @{
            PowerManagement = $null
            WoLProperties = @{}
            AdvancedProperties = @()
        }
    }
}

function Set-AdapterWakeOnLAN {
    param(
        [object]$Adapter,
        [bool]$EnableMagicPacket = $true,
        [bool]$EnablePatternMatch = $false,
        [hashtable]$AdvancedSettings = @{}
    )
    
    try {
        Write-WoLLog -Message "Configuring Wake-on-LAN for adapter: $($Adapter.Name)" -Level 'Info'
        
        # Set basic power management
        $magicPacketSetting = if ($EnableMagicPacket) { 'Enabled' } else { 'Disabled' }
        $patternSetting = if ($EnablePatternMatch) { 'Enabled' } else { 'Disabled' }
        
        Set-NetAdapterPowerManagement -Name $Adapter.Name -WakeOnMagicPacket $magicPacketSetting -WakeOnPattern $patternSetting -ErrorAction Stop
        Write-WoLLog -Message "Basic power management configured successfully" -Level 'Debug'
        
        # Apply advanced settings if provided
        foreach ($setting in $AdvancedSettings.GetEnumerator()) {
            try {
                Set-NetAdapterAdvancedProperty -Name $Adapter.Name -RegistryKeyword $setting.Key -RegistryValue $setting.Value -ErrorAction Stop
                Write-WoLLog -Message "Advanced setting applied: $($setting.Key) = $($setting.Value)" -Level 'Debug'
            } catch {
                Write-WoLLog -Message "Failed to apply advanced setting $($setting.Key): $($_.Exception.Message)" -Level 'Warning'
            }
        }
        
        # Enable device wake using powercfg
        try {
            $pnpDevice = Get-PnpDevice -Class Net -Status OK | Where-Object {
                $_.FriendlyName -like "*$($Adapter.InterfaceDescription.Split(',')[0])*"
            } | Select-Object -First 1
            
            if ($pnpDevice) {
                & powercfg /deviceenablewake "$($pnpDevice.FriendlyName)" 2>$null
                Write-WoLLog -Message "Device wake enabled via powercfg" -Level 'Debug'
            }
        } catch {
            Write-WoLLog -Message "Failed to enable device wake via powercfg: $($_.Exception.Message)" -Level 'Warning'
        }
        
        return $true
        
    } catch {
        Write-WoLLog -Message "Failed to configure Wake-on-LAN for adapter $($Adapter.Name): $($_.Exception.Message)" -Level 'Error'
        throw
    }
}

function Test-WakeOnLANSupport {
    param([object]$Adapter)
    
    $support = @{
        AdapterSupported = $false
        PowerManagementSupported = $false
        MagicPacketSupported = $false
        PatternMatchSupported = $false
        BIOSRequired = $true
        Issues = @()
        Recommendations = @()
    }
    
    try {
        # Check if adapter is physical Ethernet
        if ($Adapter.Adapter.InterfaceType -ne 6) {
            $support.Issues += "Adapter is not Ethernet (InterfaceType: $($Adapter.Adapter.InterfaceType))"
            return $support
        }
        
        $support.AdapterSupported = $true
        
        # Check power management support
        if ($Adapter.PowerManagement) {
            $support.PowerManagementSupported = $true
            $support.MagicPacketSupported = $true  # Assume supported if PowerManagement exists
            
            if ($Adapter.PowerManagement.WakeOnMagicPacket -eq 'Disabled') {
                $support.Recommendations += "Enable Wake on Magic Packet"
            }
        } else {
            $support.Issues += "PowerManagement cmdlets not supported"
        }
        
        # Check for common WoL advanced properties
        $wolProps = $Adapter.PowerManagement.WoLProperties
        if ($wolProps.Count -eq 0) {
            $support.Issues += "No Wake-on-LAN advanced properties found"
        }
        
        # Check if adapter is connected and has valid speed
        if ($Adapter.Status -ne 'Up') {
            $support.Issues += "Adapter is not connected (Status: $($Adapter.Status))"
        }
        
        if (-not $Adapter.LinkSpeed -or $Adapter.LinkSpeed -eq '0 bps') {
            $support.Issues += "No active network connection"
        }
        
        # General recommendations
        $support.Recommendations += "Verify BIOS/UEFI settings enable Wake-on-LAN"
        $support.Recommendations += "Ensure power supply to network adapter in sleep/shutdown states"
        $support.Recommendations += "Consider disabling Windows Fast Startup if WoL fails from shutdown"
        
        return $support
        
    } catch {
        $support.Issues += "Error analyzing Wake-on-LAN support: $($_.Exception.Message)"
        return $support
    }
}

#endregion

# Load configuration on startup
Load-Configuration
#region UI Creation

function Create-MainForm {
    Write-WoLLog -Message "Creating main application window" -Level 'Debug'
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Script:AppTitle
    $form.Size = New-Object System.Drawing.Size($global:Config.WindowSize.Width, $global:Config.WindowSize.Height)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $form.AutoScaleMode = 'Font'
    $form.MinimumSize = New-Object System.Drawing.Size(1000, 700)
    $form.Icon = [System.Drawing.SystemIcons]::Network
    
    # Create menu bar
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    
    # File menu
    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&File")
    $exportProfilesItem = New-Object System.Windows.Forms.ToolStripMenuItem("&Export Profiles...")
    $importProfilesItem = New-Object System.Windows.Forms.ToolStripMenuItem("&Import Profiles...")
    $fileMenu.DropDownItems.AddRange(@($exportProfilesItem, (New-Object System.Windows.Forms.ToolStripSeparator), $importProfilesItem))
    
    $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem("E&xit")
    $fileMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    $fileMenu.DropDownItems.Add($exitItem)
    
    # Tools menu
    $toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Tools")
    $refreshAdaptersItem = New-Object System.Windows.Forms.ToolStripMenuItem("&Refresh Adapters")
    $discoverDevicesItem = New-Object System.Windows.Forms.ToolStripMenuItem("&Discover Devices")
    $viewLogsItem = New-Object System.Windows.Forms.ToolStripMenuItem("View &Logs")
    $toolsMenu.DropDownItems.AddRange(@($refreshAdaptersItem, $discoverDevicesItem, (New-Object System.Windows.Forms.ToolStripSeparator), $viewLogsItem))
    
    # Help menu
    $helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Help")
    $troubleshootingItem = New-Object System.Windows.Forms.ToolStripMenuItem("&Troubleshooting Guide")
    $aboutItem = New-Object System.Windows.Forms.ToolStripMenuItem("&About")
    $helpMenu.DropDownItems.AddRange(@($troubleshootingItem, (New-Object System.Windows.Forms.ToolStripSeparator), $aboutItem))
    
    $menuStrip.Items.AddRange(@($fileMenu, $toolsMenu, $helpMenu))
    $form.Controls.Add($menuStrip)
    $form.MainMenuStrip = $menuStrip
    
    # Create tab control
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Location = New-Object System.Drawing.Point(10, 35)
    $tabControl.Size = New-Object System.Drawing.Size(($form.Width - 40), ($form.Height - 80))
    $tabControl.Anchor = 'Top,Left,Right,Bottom'
    $form.Controls.Add($tabControl)
    
    # Create tabs
    $adaptersTab = Create-AdaptersTab
    $profilesTab = Create-ProfilesTab  
    $discoveryTab = Create-DiscoveryTab
    $testingTab = Create-TestingTab
    $settingsTab = Create-SettingsTab
    
    $tabControl.TabPages.AddRange(@($adaptersTab, $profilesTab, $discoveryTab, $testingTab, $settingsTab))
    
    # Store references for event handlers
    $form.Tag = @{
        TabControl = $tabControl
        MenuStrip = $menuStrip
        AdaptersTab = $adaptersTab
        ProfilesTab = $profilesTab
        DiscoveryTab = $discoveryTab
        TestingTab = $testingTab
        SettingsTab = $settingsTab
    }
    
    # Event handlers
    $exitItem.Add_Click({ $form.Close() })
    $refreshAdaptersItem.Add_Click({ Refresh-AdaptersList -Tab $adaptersTab })
    $discoverDevicesItem.Add_Click({ Start-DeviceDiscovery -Tab $discoveryTab })
    $viewLogsItem.Add_Click({ Show-LogViewer })
    $troubleshootingItem.Add_Click({ Show-TroubleshootingGuide })
    $aboutItem.Add_Click({ Show-AboutDialog })
    
    $form.Add_FormClosing({
        param($sender, $e)
        
        # Save window state
        if ($sender.WindowState -eq 'Normal') {
            $global:Config.WindowSize.Width = $sender.Width
            $global:Config.WindowSize.Height = $sender.Height
        }
        $global:Config.WindowState = $sender.WindowState
        
        Save-Configuration
        Write-WoLLog -Message "Application closing" -Level 'Info'
    })
    
    return $form
}

function Create-AdaptersTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Network Adapters"
    $tab.UseVisualStyleBackColor = $true
    
    # Splitter for adapters list and details
    $splitter = New-Object System.Windows.Forms.SplitContainer
    $splitter.Dock = 'Fill'
    $splitter.SplitterDistance = 400
    $splitter.FixedPanel = 'Panel1'
    $tab.Controls.Add($splitter)
    
    # Left panel - Adapters list
    $leftPanel = $splitter.Panel1
    
    $adaptersLabel = New-Object System.Windows.Forms.Label
    $adaptersLabel.Text = "Physical Network Adapters:"
    $adaptersLabel.Location = New-Object System.Drawing.Point(10, 10)
    $adaptersLabel.Size = New-Object System.Drawing.Size(300, 20)
    $adaptersLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $leftPanel.Controls.Add($adaptersLabel)
    
    $adaptersListView = New-Object System.Windows.Forms.ListView
    $adaptersListView.Location = New-Object System.Drawing.Point(10, 35)
    $adaptersListView.Size = New-Object System.Drawing.Size(375, 300)
    $adaptersListView.Anchor = 'Top,Left,Bottom,Right'
    $adaptersListView.View = 'Details'
    $adaptersListView.FullRowSelect = $true
    $adaptersListView.GridLines = $true
    $adaptersListView.MultiSelect = $false
    
    # Add columns
    $adaptersListView.Columns.Add("Name", 100) | Out-Null
    $adaptersListView.Columns.Add("Status", 60) | Out-Null
    $adaptersListView.Columns.Add("Speed", 80) | Out-Null
    $adaptersListView.Columns.Add("MAC Address", 130) | Out-Null
    
    $leftPanel.Controls.Add($adaptersListView)
    
    $refreshButton = New-Object System.Windows.Forms.Button
    $refreshButton.Text = "Refresh List"
    $refreshButton.Location = New-Object System.Drawing.Point(10, 345)
    $refreshButton.Size = New-Object System.Drawing.Size(100, 30)
    $refreshButton.Anchor = 'Bottom,Left'
    $leftPanel.Controls.Add($refreshButton)
    
    # Right panel - Adapter details and configuration
    $rightPanel = $splitter.Panel2
    
    $detailsGroupBox = New-Object System.Windows.Forms.GroupBox
    $detailsGroupBox.Text = "Adapter Details"
    $detailsGroupBox.Location = New-Object System.Drawing.Point(10, 10)
    $detailsGroupBox.Size = New-Object System.Drawing.Size(($rightPanel.Width - 30), 200)
    $detailsGroupBox.Anchor = 'Top,Left,Right'
    $rightPanel.Controls.Add($detailsGroupBox)
    
    $detailsTextBox = New-Object System.Windows.Forms.TextBox
    $detailsTextBox.Multiline = $true
    $detailsTextBox.ReadOnly = $true
    $detailsTextBox.ScrollBars = 'Vertical'
    $detailsTextBox.Location = New-Object System.Drawing.Point(10, 20)
    $detailsTextBox.Size = New-Object System.Drawing.Size(($detailsGroupBox.Width - 30), 170)
    $detailsTextBox.Anchor = 'Top,Left,Right'
    $detailsTextBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    $detailsGroupBox.Controls.Add($detailsTextBox)
    
    # WoL Configuration Group
    $wolConfigGroupBox = New-Object System.Windows.Forms.GroupBox
    $wolConfigGroupBox.Text = "Wake-on-LAN Configuration"
    $wolConfigGroupBox.Location = New-Object System.Drawing.Point(10, 220)
    $wolConfigGroupBox.Size = New-Object System.Drawing.Size(($rightPanel.Width - 30), 200)
    $wolConfigGroupBox.Anchor = 'Top,Left,Right'
    $rightPanel.Controls.Add($wolConfigGroupBox)
    
    $enableWoLCheckBox = New-Object System.Windows.Forms.CheckBox
    $enableWoLCheckBox.Text = "Enable Wake on Magic Packet"
    $enableWoLCheckBox.Location = New-Object System.Drawing.Point(15, 25)
    $enableWoLCheckBox.Size = New-Object System.Drawing.Size(250, 22)
    $wolConfigGroupBox.Controls.Add($enableWoLCheckBox)
    
    $enablePatternCheckBox = New-Object System.Windows.Forms.CheckBox
    $enablePatternCheckBox.Text = "Enable Wake on Pattern Match"
    $enablePatternCheckBox.Location = New-Object System.Drawing.Point(15, 50)
    $enablePatternCheckBox.Size = New-Object System.Drawing.Size(250, 22)
    $wolConfigGroupBox.Controls.Add($enablePatternCheckBox)
    
    $applyWoLButton = New-Object System.Windows.Forms.Button
    $applyWoLButton.Text = "Apply WoL Settings"
    $applyWoLButton.Location = New-Object System.Drawing.Point(15, 85)
    $applyWoLButton.Size = New-Object System.Drawing.Size(150, 30)
    $wolConfigGroupBox.Controls.Add($applyWoLButton)
    
    $testWoLButton = New-Object System.Windows.Forms.Button
    $testWoLButton.Text = "Test WoL Support"
    $testWoLButton.Location = New-Object System.Drawing.Point(180, 85)
    $testWoLButton.Size = New-Object System.Drawing.Size(130, 30)
    $wolConfigGroupBox.Controls.Add($testWoLButton)
    
    # Advanced Properties ListView
    $advPropsLabel = New-Object System.Windows.Forms.Label
    $advPropsLabel.Text = "Advanced Properties:"
    $advPropsLabel.Location = New-Object System.Drawing.Point(15, 125)
    $advPropsLabel.Size = New-Object System.Drawing.Size(200, 20)
    $wolConfigGroupBox.Controls.Add($advPropsLabel)
    
    $advPropsListView = New-Object System.Windows.Forms.ListView
    $advPropsListView.Location = New-Object System.Drawing.Point(15, 145)
    $advPropsListView.Size = New-Object System.Drawing.Size(($wolConfigGroupBox.Width - 40), 45)
    $advPropsListView.Anchor = 'Top,Left,Right'
    $advPropsListView.View = 'Details'
    $advPropsListView.FullRowSelect = $true
    $advPropsListView.GridLines = $true
    $advPropsListView.Columns.Add("Property", 200) | Out-Null
    $advPropsListView.Columns.Add("Value", 100) | Out-Null
    $wolConfigGroupBox.Controls.Add($advPropsListView)
    
    # Store references in tab tag
    $tab.Tag = @{
        AdaptersListView = $adaptersListView
        RefreshButton = $refreshButton
        DetailsTextBox = $detailsTextBox
        EnableWoLCheckBox = $enableWoLCheckBox
        EnablePatternCheckBox = $enablePatternCheckBox
        ApplyWoLButton = $applyWoLButton
        TestWoLButton = $testWoLButton
        AdvPropsListView = $advPropsListView
    }
    
    # Event handlers
    $refreshButton.Add_Click({ Refresh-AdaptersList -Tab $tab })
    $adaptersListView.Add_SelectedIndexChanged({ Update-AdapterDetails -Tab $tab })
    $applyWoLButton.Add_Click({ Apply-WoLConfiguration -Tab $tab })
    $testWoLButton.Add_Click({ Test-AdapterWoLSupport -Tab $tab })
    
    return $tab
}

function Create-ProfilesTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "WoL Profiles"
    $tab.UseVisualStyleBackColor = $true
    
    # Profiles management UI
    $profilesGroupBox = New-Object System.Windows.Forms.GroupBox
    $profilesGroupBox.Text = "Saved WoL Profiles"
    $profilesGroupBox.Location = New-Object System.Drawing.Point(10, 10)
    $profilesGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 350)
    $profilesGroupBox.Anchor = 'Top,Left,Right'
    $tab.Controls.Add($profilesGroupBox)
    
    $profilesListView = New-Object System.Windows.Forms.ListView
    $profilesListView.Location = New-Object System.Drawing.Point(10, 25)
    $profilesListView.Size = New-Object System.Drawing.Size(($profilesGroupBox.Width - 30), 280)
    $profilesListView.Anchor = 'Top,Left,Right'
    $profilesListView.View = 'Details'
    $profilesListView.FullRowSelect = $true
    $profilesListView.GridLines = $true
    $profilesListView.MultiSelect = $false
    
    $profilesListView.Columns.Add("Name", 150) | Out-Null
    $profilesListView.Columns.Add("MAC Address", 130) | Out-Null
    $profilesListView.Columns.Add("IP Address", 100) | Out-Null
    $profilesListView.Columns.Add("Group", 80) | Out-Null
    $profilesListView.Columns.Add("Last Used", 120) | Out-Null
    $profilesListView.Columns.Add("Use Count", 70) | Out-Null
    
    $profilesGroupBox.Controls.Add($profilesListView)
    
    # Profile management buttons
    $addProfileButton = New-Object System.Windows.Forms.Button
    $addProfileButton.Text = "Add Profile"
    $addProfileButton.Location = New-Object System.Drawing.Point(10, 315)
    $addProfileButton.Size = New-Object System.Drawing.Size(100, 25)
    $profilesGroupBox.Controls.Add($addProfileButton)
    
    $editProfileButton = New-Object System.Windows.Forms.Button
    $editProfileButton.Text = "Edit Profile"
    $editProfileButton.Location = New-Object System.Drawing.Point(120, 315)
    $editProfileButton.Size = New-Object System.Drawing.Size(100, 25)
    $profilesGroupBox.Controls.Add($editProfileButton)
    
    $deleteProfileButton = New-Object System.Windows.Forms.Button
    $deleteProfileButton.Text = "Delete Profile"
    $deleteProfileButton.Location = New-Object System.Drawing.Point(230, 315)
    $deleteProfileButton.Size = New-Object System.Drawing.Size(100, 25)
    $profilesGroupBox.Controls.Add($deleteProfileButton)
    
    $wakeProfileButton = New-Object System.Windows.Forms.Button
    $wakeProfileButton.Text = "Wake Device"
    $wakeProfileButton.Location = New-Object System.Drawing.Point(350, 315)
    $wakeProfileButton.Size = New-Object System.Drawing.Size(100, 25)
    $wakeProfileButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $wakeProfileButton.BackColor = [System.Drawing.Color]::LightGreen
    $profilesGroupBox.Controls.Add($wakeProfileButton)
    
    # Quick Wake section
    $quickWakeGroupBox = New-Object System.Windows.Forms.GroupBox
    $quickWakeGroupBox.Text = "Quick Wake"
    $quickWakeGroupBox.Location = New-Object System.Drawing.Point(10, 370)
    $quickWakeGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 120)
    $quickWakeGroupBox.Anchor = 'Top,Left,Right'
    $tab.Controls.Add($quickWakeGroupBox)
    
    $macLabel = New-Object System.Windows.Forms.Label
    $macLabel.Text = "MAC Address:"
    $macLabel.Location = New-Object System.Drawing.Point(10, 25)
    $macLabel.Size = New-Object System.Drawing.Size(80, 20)
    $quickWakeGroupBox.Controls.Add($macLabel)
    
    $macTextBox = New-Object System.Windows.Forms.TextBox
    $macTextBox.Location = New-Object System.Drawing.Point(95, 22)
    $macTextBox.Size = New-Object System.Drawing.Size(150, 22)
    $macTextBox.PlaceholderText = "XX:XX:XX:XX:XX:XX"
    $quickWakeGroupBox.Controls.Add($macTextBox)
    
    $broadcastLabel = New-Object System.Windows.Forms.Label
    $broadcastLabel.Text = "Broadcast:"
    $broadcastLabel.Location = New-Object System.Drawing.Point(260, 25)
    $broadcastLabel.Size = New-Object System.Drawing.Size(70, 20)
    $quickWakeGroupBox.Controls.Add($broadcastLabel)
    
    $broadcastTextBox = New-Object System.Windows.Forms.TextBox
    $broadcastTextBox.Location = New-Object System.Drawing.Point(335, 22)
    $broadcastTextBox.Size = New-Object System.Drawing.Size(120, 22)
    $broadcastTextBox.Text = $global:Config.DefaultBroadcast
    $quickWakeGroupBox.Controls.Add($broadcastTextBox)
    
    $portLabel = New-Object System.Windows.Forms.Label
    $portLabel.Text = "Port:"
    $portLabel.Location = New-Object System.Drawing.Point(470, 25)
    $portLabel.Size = New-Object System.Drawing.Size(35, 20)
    $quickWakeGroupBox.Controls.Add($portLabel)
    
    $portTextBox = New-Object System.Windows.Forms.TextBox
    $portTextBox.Location = New-Object System.Drawing.Point(510, 22)
    $portTextBox.Size = New-Object System.Drawing.Size(50, 22)
    $portTextBox.Text = $global:Config.DefaultPort.ToString()
    $quickWakeGroupBox.Controls.Add($portTextBox)
    
    $quickWakeButton = New-Object System.Windows.Forms.Button
    $quickWakeButton.Text = "Send Magic Packet"
    $quickWakeButton.Location = New-Object System.Drawing.Point(10, 55)
    $quickWakeButton.Size = New-Object System.Drawing.Size(140, 30)
    $quickWakeButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $quickWakeButton.BackColor = [System.Drawing.Color]::LightBlue
    $quickWakeGroupBox.Controls.Add($quickWakeButton)
    
    $resultLabel = New-Object System.Windows.Forms.Label
    $resultLabel.Location = New-Object System.Drawing.Point(160, 62)
    $resultLabel.Size = New-Object System.Drawing.Size(400, 20)
    $resultLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $quickWakeGroupBox.Controls.Add($resultLabel)
    
    # Store references
    $tab.Tag = @{
        ProfilesListView = $profilesListView
        AddProfileButton = $addProfileButton
        EditProfileButton = $editProfileButton
        DeleteProfileButton = $deleteProfileButton
        WakeProfileButton = $wakeProfileButton
        MacTextBox = $macTextBox
        BroadcastTextBox = $broadcastTextBox
        PortTextBox = $portTextBox
        QuickWakeButton = $quickWakeButton
        ResultLabel = $resultLabel
    }
    
    # Event handlers
    $addProfileButton.Add_Click({ Show-ProfileEditor -Tab $tab })
    $editProfileButton.Add_Click({ Show-ProfileEditor -Tab $tab -Edit })
    $deleteProfileButton.Add_Click({ Remove-SelectedProfile -Tab $tab })
    $wakeProfileButton.Add_Click({ Wake-SelectedProfile -Tab $tab })
    $quickWakeButton.Add_Click({ Send-QuickWake -Tab $tab })
    
    return $tab
}

function Create-DiscoveryTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Device Discovery"  
    $tab.UseVisualStyleBackColor = $true
    
    # Discovery controls
    $discoveryGroupBox = New-Object System.Windows.Forms.GroupBox
    $discoveryGroupBox.Text = "Network Device Discovery"
    $discoveryGroupBox.Location = New-Object System.Drawing.Point(10, 10)
    $discoveryGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 100)
    $discoveryGroupBox.Anchor = 'Top,Left,Right'
    $tab.Controls.Add($discoveryGroupBox)
    
    $scanButton = New-Object System.Windows.Forms.Button
    $scanButton.Text = "Scan Network"
    $scanButton.Location = New-Object System.Drawing.Point(15, 25)
    $scanButton.Size = New-Object System.Drawing.Size(120, 30)
    $scanButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $discoveryGroupBox.Controls.Add($scanButton)
    
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(150, 30)
    $progressBar.Size = New-Object System.Drawing.Size(200, 20)
    $progressBar.Style = 'Marquee'
    $progressBar.Visible = $false
    $discoveryGroupBox.Controls.Add($progressBar)
    
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(15, 65)
    $statusLabel.Size = New-Object System.Drawing.Size(400, 20)
    $statusLabel.Text = "Click 'Scan Network' to discover devices"
    $discoveryGroupBox.Controls.Add($statusLabel)
    
    # Discovered devices list
    $devicesGroupBox = New-Object System.Windows.Forms.GroupBox
    $devicesGroupBox.Text = "Discovered Devices"
    $devicesGroupBox.Location = New-Object System.Drawing.Point(10, 120)
    $devicesGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 350)
    $devicesGroupBox.Anchor = 'Top,Left,Right,Bottom'
    $tab.Controls.Add($devicesGroupBox)
    
    $devicesListView = New-Object System.Windows.Forms.ListView
    $devicesListView.Location = New-Object System.Drawing.Point(10, 25)
    $devicesListView.Size = New-Object System.Drawing.Size(($devicesGroupBox.Width - 30), 280)
    $devicesListView.Anchor = 'Top,Left,Right,Bottom'
    $devicesListView.View = 'Details'
    $devicesListView.FullRowSelect = $true
    $devicesListView.GridLines = $true
    $devicesListView.MultiSelect = $true
    
    $devicesListView.Columns.Add("IP Address", 100) | Out-Null
    $devicesListView.Columns.Add("MAC Address", 130) | Out-Null
    $devicesListView.Columns.Add("Hostname", 150) | Out-Null
    $devicesListView.Columns.Add("Status", 70) | Out-Null
    $devicesListView.Columns.Add("Adapter", 100) | Out-Null
    $devicesListView.Columns.Add("Last Seen", 120) | Out-Null
    
    $devicesGroupBox.Controls.Add($devicesListView)
    
    # Device action buttons
    $addToProfilesButton = New-Object System.Windows.Forms.Button
    $addToProfilesButton.Text = "Add to Profiles"
    $addToProfilesButton.Location = New-Object System.Drawing.Point(10, 315)
    $addToProfilesButton.Size = New-Object System.Drawing.Size(120, 25)
    $addToProfilesButton.Anchor = 'Bottom,Left'
    $devicesGroupBox.Controls.Add($addToProfilesButton)
    
    $wakeDeviceButton = New-Object System.Windows.Forms.Button
    $wakeDeviceButton.Text = "Wake Selected"
    $wakeDeviceButton.Location = New-Object System.Drawing.Point(140, 315)
    $wakeDeviceButton.Size = New-Object System.Drawing.Size(120, 25)
    $wakeDeviceButton.Anchor = 'Bottom,Left'
    $wakeDeviceButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $wakeDeviceButton.BackColor = [System.Drawing.Color]::LightGreen
    $devicesGroupBox.Controls.Add($wakeDeviceButton)
    
    # Store references
    $tab.Tag = @{
        ScanButton = $scanButton
        ProgressBar = $progressBar
        StatusLabel = $statusLabel
        DevicesListView = $devicesListView
        AddToProfilesButton = $addToProfilesButton
        WakeDeviceButton = $wakeDeviceButton
    }
    
    # Event handlers  
    $scanButton.Add_Click({ Start-DeviceDiscovery -Tab $tab })
    $addToProfilesButton.Add_Click({ Add-DiscoveredToProfiles -Tab $tab })
    $wakeDeviceButton.Add_Click({ Wake-DiscoveredDevices -Tab $tab })
    
    return $tab
}

function Create-TestingTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Testing & Diagnostics"
    $tab.UseVisualStyleBackColor = $true
    
    # Magic packet testing
    $magicPacketGroupBox = New-Object System.Windows.Forms.GroupBox
    $magicPacketGroupBox.Text = "Magic Packet Testing"
    $magicPacketGroupBox.Location = New-Object System.Drawing.Point(10, 10)
    $magicPacketGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 180)
    $magicPacketGroupBox.Anchor = 'Top,Left,Right'
    $tab.Controls.Add($magicPacketGroupBox)
    
    $testMacLabel = New-Object System.Windows.Forms.Label
    $testMacLabel.Text = "Target MAC Address:"
    $testMacLabel.Location = New-Object System.Drawing.Point(15, 25)
    $testMacLabel.Size = New-Object System.Drawing.Size(120, 20)
    $magicPacketGroupBox.Controls.Add($testMacLabel)
    
    $testMacTextBox = New-Object System.Windows.Forms.TextBox
    $testMacTextBox.Location = New-Object System.Drawing.Point(140, 22)
    $testMacTextBox.Size = New-Object System.Drawing.Size(150, 22)
    $testMacTextBox.PlaceholderText = "XX:XX:XX:XX:XX:XX"
    $magicPacketGroupBox.Controls.Add($testMacTextBox)
    
    $testBroadcastLabel = New-Object System.Windows.Forms.Label
    $testBroadcastLabel.Text = "Broadcast Address:"
    $testBroadcastLabel.Location = New-Object System.Drawing.Point(15, 55)
    $testBroadcastLabel.Size = New-Object System.Drawing.Size(120, 20)
    $magicPacketGroupBox.Controls.Add($testBroadcastLabel)
    
    $testBroadcastTextBox = New-Object System.Windows.Forms.TextBox
    $testBroadcastTextBox.Location = New-Object System.Drawing.Point(140, 52)
    $testBroadcastTextBox.Size = New-Object System.Drawing.Size(120, 22)
    $testBroadcastTextBox.Text = $global:Config.DefaultBroadcast
    $magicPacketGroupBox.Controls.Add($testBroadcastTextBox)
    
    $testPortLabel = New-Object System.Windows.Forms.Label
    $testPortLabel.Text = "Port:"
    $testPortLabel.Location = New-Object System.Drawing.Point(280, 55)
    $testPortLabel.Size = New-Object System.Drawing.Size(35, 20)
    $magicPacketGroupBox.Controls.Add($testPortLabel)
    
    $testPortTextBox = New-Object System.Windows.Forms.TextBox
    $testPortTextBox.Location = New-Object System.Drawing.Point(320, 52)
    $testPortTextBox.Size = New-Object System.Drawing.Size(50, 22)
    $testPortTextBox.Text = $global:Config.DefaultPort.ToString()
    $magicPacketGroupBox.Controls.Add($testPortTextBox)
    
    $packetCountLabel = New-Object System.Windows.Forms.Label
    $packetCountLabel.Text = "Packet Count:"
    $packetCountLabel.Location = New-Object System.Drawing.Point(15, 85)
    $packetCountLabel.Size = New-Object System.Drawing.Size(80, 20)
    $magicPacketGroupBox.Controls.Add($packetCountLabel)
    
    $packetCountNumeric = New-Object System.Windows.Forms.NumericUpDown
    $packetCountNumeric.Location = New-Object System.Drawing.Point(140, 82)
    $packetCountNumeric.Size = New-Object System.Drawing.Size(60, 22)
    $packetCountNumeric.Minimum = 1
    $packetCountNumeric.Maximum = 10
    $packetCountNumeric.Value = $global:Config.MagicPacketCount
    $magicPacketGroupBox.Controls.Add($packetCountNumeric)
    
    $delayLabel = New-Object System.Windows.Forms.Label
    $delayLabel.Text = "Delay (ms):"
    $delayLabel.Location = New-Object System.Drawing.Point(220, 85)
    $delayLabel.Size = New-Object System.Drawing.Size(65, 20)
    $magicPacketGroupBox.Controls.Add($delayLabel)
    
    $delayNumeric = New-Object System.Windows.Forms.NumericUpDown
    $delayNumeric.Location = New-Object System.Drawing.Point(290, 82)
    $delayNumeric.Size = New-Object System.Drawing.Size(80, 22)
    $delayNumeric.Minimum = 100
    $delayNumeric.Maximum = 10000
    $delayNumeric.Increment = 100
    $delayNumeric.Value = $global:Config.MagicPacketDelay
    $magicPacketGroupBox.Controls.Add($delayNumeric)
    
    $sendTestButton = New-Object System.Windows.Forms.Button
    $sendTestButton.Text = "Send Test Packets"
    $sendTestButton.Location = New-Object System.Drawing.Point(15, 115)
    $sendTestButton.Size = New-Object System.Drawing.Size(130, 30)
    $sendTestButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $sendTestButton.BackColor = [System.Drawing.Color]::LightCoral
    $magicPacketGroupBox.Controls.Add($sendTestButton)
    
    $testResultLabel = New-Object System.Windows.Forms.Label
    $testResultLabel.Location = New-Object System.Drawing.Point(155, 122)
    $testResultLabel.Size = New-Object System.Drawing.Size(350, 20)
    $testResultLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $magicPacketGroupBox.Controls.Add($testResultLabel)
    
    # Diagnostics section
    $diagnosticsGroupBox = New-Object System.Windows.Forms.GroupBox
    $diagnosticsGroupBox.Text = "System Diagnostics"
    $diagnosticsGroupBox.Location = New-Object System.Drawing.Point(10, 200)
    $diagnosticsGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 280)
    $diagnosticsGroupBox.Anchor = 'Top,Left,Right,Bottom'
    $tab.Controls.Add($diagnosticsGroupBox)
    
    $diagnosticsTextBox = New-Object System.Windows.Forms.TextBox
    $diagnosticsTextBox.Multiline = $true
    $diagnosticsTextBox.ReadOnly = $true
    $diagnosticsTextBox.ScrollBars = 'Vertical'
    $diagnosticsTextBox.Location = New-Object System.Drawing.Point(10, 50)
    $diagnosticsTextBox.Size = New-Object System.Drawing.Size(($diagnosticsGroupBox.Width - 30), 220)
    $diagnosticsTextBox.Anchor = 'Top,Left,Right,Bottom'
    $diagnosticsTextBox.Font = New-Object System.Drawing.Font('Consolas', 8)
    $diagnosticsGroupBox.Controls.Add($diagnosticsTextBox)
    
    $runDiagnosticsButton = New-Object System.Windows.Forms.Button
    $runDiagnosticsButton.Text = "Run Diagnostics"
    $runDiagnosticsButton.Location = New-Object System.Drawing.Point(10, 20)
    $runDiagnosticsButton.Size = New-Object System.Drawing.Size(120, 25)
    $diagnosticsGroupBox.Controls.Add($runDiagnosticsButton)
    
    $exportDiagnosticsButton = New-Object System.Windows.Forms.Button
    $exportDiagnosticsButton.Text = "Export Report"
    $exportDiagnosticsButton.Location = New-Object System.Drawing.Point(140, 20)
    $exportDiagnosticsButton.Size = New-Object System.Drawing.Size(100, 25)
    $diagnosticsGroupBox.Controls.Add($exportDiagnosticsButton)
    
    # Store references
    $tab.Tag = @{
        TestMacTextBox = $testMacTextBox
        TestBroadcastTextBox = $testBroadcastTextBox
        TestPortTextBox = $testPortTextBox
        PacketCountNumeric = $packetCountNumeric
        DelayNumeric = $delayNumeric
        SendTestButton = $sendTestButton
        TestResultLabel = $testResultLabel
        DiagnosticsTextBox = $diagnosticsTextBox
        RunDiagnosticsButton = $runDiagnosticsButton
        ExportDiagnosticsButton = $exportDiagnosticsButton
    }
    
    # Event handlers
    $sendTestButton.Add_Click({ Send-TestMagicPackets -Tab $tab })
    $runDiagnosticsButton.Add_Click({ Run-SystemDiagnostics -Tab $tab })
    $exportDiagnosticsButton.Add_Click({ Export-DiagnosticsReport -Tab $tab })
    
    return $tab
}

function Create-SettingsTab {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "Settings"
    $tab.UseVisualStyleBackColor = $true
    
    # Application settings
    $appSettingsGroupBox = New-Object System.Windows.Forms.GroupBox
    $appSettingsGroupBox.Text = "Application Settings"
    $appSettingsGroupBox.Location = New-Object System.Drawing.Point(10, 10)
    $appSettingsGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 200)
    $appSettingsGroupBox.Anchor = 'Top,Left,Right'
    $tab.Controls.Add($appSettingsGroupBox)
    
    $autoSaveCheckBox = New-Object System.Windows.Forms.CheckBox
    $autoSaveCheckBox.Text = "Auto-save profiles and settings"
    $autoSaveCheckBox.Location = New-Object System.Drawing.Point(15, 25)
    $autoSaveCheckBox.Size = New-Object System.Drawing.Size(250, 22)
    $autoSaveCheckBox.Checked = $global:Config.AutoSaveProfiles
    $appSettingsGroupBox.Controls.Add($autoSaveCheckBox)
    
    $enableLoggingCheckBox = New-Object System.Windows.Forms.CheckBox  
    $enableLoggingCheckBox.Text = "Enable debug logging"
    $enableLoggingCheckBox.Location = New-Object System.Drawing.Point(15, 50)
    $enableLoggingCheckBox.Size = New-Object System.Drawing.Size(250, 22)
    $enableLoggingCheckBox.Checked = $global:Config.EnableLogging
    $appSettingsGroupBox.Controls.Add($enableLoggingCheckBox)
    
    # Default values
    $defaultsLabel = New-Object System.Windows.Forms.Label
    $defaultsLabel.Text = "Default Values:"
    $defaultsLabel.Location = New-Object System.Drawing.Point(15, 85)
    $defaultsLabel.Size = New-Object System.Drawing.Size(100, 20)
    $defaultsLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $appSettingsGroupBox.Controls.Add($defaultsLabel)
    
    $defaultPortLabel = New-Object System.Windows.Forms.Label
    $defaultPortLabel.Text = "Port:"
    $defaultPortLabel.Location = New-Object System.Drawing.Point(25, 110)
    $defaultPortLabel.Size = New-Object System.Drawing.Size(40, 20)
    $appSettingsGroupBox.Controls.Add($defaultPortLabel)
    
    $defaultPortNumeric = New-Object System.Windows.Forms.NumericUpDown
    $defaultPortNumeric.Location = New-Object System.Drawing.Point(70, 107)
    $defaultPortNumeric.Size = New-Object System.Drawing.Size(70, 22)
    $defaultPortNumeric.Minimum = 1
    $defaultPortNumeric.Maximum = 65535
    $defaultPortNumeric.Value = $global:Config.DefaultPort
    $appSettingsGroupBox.Controls.Add($defaultPortNumeric)
    
    $defaultBroadcastLabel = New-Object System.Windows.Forms.Label
    $defaultBroadcastLabel.Text = "Broadcast:"
    $defaultBroadcastLabel.Location = New-Object System.Drawing.Point(160, 110)
    $defaultBroadcastLabel.Size = New-Object System.Drawing.Size(70, 20)
    $appSettingsGroupBox.Controls.Add($defaultBroadcastLabel)
    
    $defaultBroadcastTextBox = New-Object System.Windows.Forms.TextBox
    $defaultBroadcastTextBox.Location = New-Object System.Drawing.Point(235, 107)
    $defaultBroadcastTextBox.Size = New-Object System.Drawing.Size(120, 22)
    $defaultBroadcastTextBox.Text = $global:Config.DefaultBroadcast
    $appSettingsGroupBox.Controls.Add($defaultBroadcastTextBox)
    
    $applySettingsButton = New-Object System.Windows.Forms.Button
    $applySettingsButton.Text = "Apply Settings"
    $applySettingsButton.Location = New-Object System.Drawing.Point(15, 145)
    $applySettingsButton.Size = New-Object System.Drawing.Size(120, 30)
    $appSettingsGroupBox.Controls.Add($applySettingsButton)
    
    $resetSettingsButton = New-Object System.Windows.Forms.Button
    $resetSettingsButton.Text = "Reset to Defaults"
    $resetSettingsButton.Location = New-Object System.Drawing.Point(150, 145)
    $resetSettingsButton.Size = New-Object System.Drawing.Size(130, 30)
    $appSettingsGroupBox.Controls.Add($resetSettingsButton)
    
    # About section
    $aboutGroupBox = New-Object System.Windows.Forms.GroupBox
    $aboutGroupBox.Text = "About"
    $aboutGroupBox.Location = New-Object System.Drawing.Point(10, 220)
    $aboutGroupBox.Size = New-Object System.Drawing.Size(($tab.Width - 30), 150)
    $aboutGroupBox.Anchor = 'Top,Left,Right'
    $tab.Controls.Add($aboutGroupBox)
    
    $aboutTextBox = New-Object System.Windows.Forms.TextBox
    $aboutTextBox.Multiline = $true
    $aboutTextBox.ReadOnly = $true
    $aboutTextBox.ScrollBars = 'Vertical'
    $aboutTextBox.Location = New-Object System.Drawing.Point(10, 20)
    $aboutTextBox.Size = New-Object System.Drawing.Size(($aboutGroupBox.Width - 30), 120)
    $aboutTextBox.Anchor = 'Top,Left,Right'
    $aboutTextBox.Text = @"
Advanced Wake-on-LAN Configurator v2.0

A comprehensive tool for configuring and managing Wake-on-LAN functionality across network adapters.

Features:
• Complete WoL adapter configuration and testing
• Profile management for commonly used devices  
• Network device discovery and automatic profiling
• Comprehensive diagnostics and troubleshooting
• Magic packet testing with multiple broadcast options
• Advanced power management settings control

Author: Enhanced WoL Configurator
Version: 2.0.0
Requirements: Windows PowerShell 5.1+, Administrator privileges

For troubleshooting and support, use the built-in diagnostics tools and log viewer.
"@
    $aboutGroupBox.Controls.Add($aboutTextBox)
    
    # Store references
    $tab.Tag = @{
        AutoSaveCheckBox = $autoSaveCheckBox
        EnableLoggingCheckBox = $enableLoggingCheckBox
        DefaultPortNumeric = $defaultPortNumeric
        DefaultBroadcastTextBox = $defaultBroadcastTextBox
        ApplySettingsButton = $applySettingsButton
        ResetSettingsButton = $resetSettingsButton
        AboutTextBox = $aboutTextBox
    }
    
    # Event handlers
    $applySettingsButton.Add_Click({ Apply-Settings -Tab $tab })
    $resetSettingsButton.Add_Click({ Reset-Settings -Tab $tab })
    
    return $tab
}

#endregion
#region Event Handler Functions

function Refresh-AdaptersList {
    param($Tab)
    
    Write-WoLLog -Message "Refreshing network adapters list" -Level 'Info'
    
    $controls = $Tab.Tag
    $listView = $controls.AdaptersListView
    
    try {
        $listView.Items.Clear()
        $global:Adapters = Get-NetworkInterfaces
        
        foreach ($adapter in $global:Adapters) {
            $item = New-Object System.Windows.Forms.ListViewItem($adapter.Name)
            $item.SubItems.Add($adapter.Status) | Out-Null
            $item.SubItems.Add($adapter.LinkSpeed) | Out-Null
            $item.SubItems.Add($adapter.MacAddress) | Out-Null
            $item.Tag = $adapter
            $listView.Items.Add($item) | Out-Null
        }
        
        Write-WoLLog -Message "Found $($global:Adapters.Count) network adapters" -Level 'Info'
        
    } catch {
        Show-MessageBox -Message "Failed to refresh adapters list: $($_.Exception.Message)" -Title "Error" -Icon 'Error'
        Write-WoLLog -Message "Failed to refresh adapters: $($_.Exception.Message)" -Level 'Error'
    }
}

function Update-AdapterDetails {
    param($Tab)
    
    $controls = $Tab.Tag
    $listView = $controls.AdaptersListView
    $detailsTextBox = $controls.DetailsTextBox
    $enableWoLCheckBox = $controls.EnableWoLCheckBox
    $enablePatternCheckBox = $controls.EnablePatternCheckBox
    $advPropsListView = $controls.AdvPropsListView
    
    if ($listView.SelectedItems.Count -eq 0) {
        $global:CurrentAdapter = $null
        $detailsTextBox.Text = ""
        $advPropsListView.Items.Clear()
        return
    }
    
    $selectedAdapter = $listView.SelectedItems[0].Tag
    $global:CurrentAdapter = $selectedAdapter
    
    try {
        # Update details text
        $details = @"
Name: $($selectedAdapter.Name)
Description: $($selectedAdapter.Description)
Status: $($selectedAdapter.Status)
MAC Address: $($selectedAdapter.MacAddress)
Link Speed: $($selectedAdapter.LinkSpeed)
IP Addresses: $($selectedAdapter.IPAddresses)
Driver Version: $($selectedAdapter.DriverVersion)
Driver Date: $($selectedAdapter.DriverDate)

Power Management Status:
"@
        
        # Add power management details
        if ($selectedAdapter.PowerManagement) {
            $pm = $selectedAdapter.PowerManagement
            $details += "`nWake on Magic Packet: $($pm.WakeOnMagicPacket)"
            $details += "`nWake on Pattern: $($pm.WakeOnPattern)"
            
            $enableWoLCheckBox.Checked = ($pm.WakeOnMagicPacket -eq 'Enabled')
            $enablePatternCheckBox.Checked = ($pm.WakeOnPattern -eq 'Enabled')
        } else {
            $details += "`nPower Management: Not Available"
            $enableWoLCheckBox.Checked = $false
            $enablePatternCheckBox.Checked = $false
        }
        
        $detailsTextBox.Text = $details
        
        # Update advanced properties
        $advPropsListView.Items.Clear()
        $powerMgmtDetails = Get-AdapterPowerManagement -Adapter $selectedAdapter.Adapter
        
        foreach ($prop in $powerMgmtDetails.WoLProperties.GetEnumerator()) {
            $item = New-Object System.Windows.Forms.ListViewItem($prop.Value.DisplayName)
            $item.SubItems.Add($prop.Value.Value) | Out-Null
            $item.Tag = $prop
            $advPropsListView.Items.Add($item) | Out-Null
        }
        
        Write-WoLLog -Message "Updated details for adapter: $($selectedAdapter.Name)" -Level 'Debug'
        
    } catch {
        $detailsTextBox.Text = "Error loading adapter details: $($_.Exception.Message)"
        Write-WoLLog -Message "Error updating adapter details: $($_.Exception.Message)" -Level 'Error'
    }
}

function Apply-WoLConfiguration {
    param($Tab)
    
    if (-not $global:CurrentAdapter) {
        Show-MessageBox -Message "Please select a network adapter first." -Title "No Adapter Selected" -Icon 'Warning'
        return
    }
    
    $controls = $Tab.Tag
    $enableMagic = $controls.EnableWoLCheckBox.Checked
    $enablePattern = $controls.EnablePatternCheckBox.Checked
    
    try {
        Write-WoLLog -Message "Applying WoL configuration to $($global:CurrentAdapter.Name)" -Level 'Info'
        
        $result = Set-AdapterWakeOnLAN -Adapter $global:CurrentAdapter.Adapter -EnableMagicPacket $enableMagic -EnablePatternMatch $enablePattern
        
        if ($result) {
            Show-MessageBox -Message "Wake-on-LAN settings have been applied successfully." -Title "Configuration Applied" -Icon 'Information'
            Update-AdapterDetails -Tab $Tab
        }
        
    } catch {
        Show-MessageBox -Message "Failed to apply WoL configuration: $($_.Exception.Message)" -Title "Configuration Error" -Icon 'Error'
    }
}

function Test-AdapterWoLSupport {
    param($Tab)
    
    if (-not $global:CurrentAdapter) {
        Show-MessageBox -Message "Please select a network adapter first." -Title "No Adapter Selected" -Icon 'Warning'
        return
    }
    
    try {
        Write-WoLLog -Message "Testing WoL support for $($global:CurrentAdapter.Name)" -Level 'Info'
        
        $support = Test-WakeOnLANSupport -Adapter $global:CurrentAdapter
        
        $message = "Wake-on-LAN Support Analysis:`n`n"
        $message += "Adapter Supported: $($support.AdapterSupported)`n"
        $message += "Power Management: $($support.PowerManagementSupported)`n"
        $message += "Magic Packet: $($support.MagicPacketSupported)`n"
        $message += "Pattern Match: $($support.PatternMatchSupported)`n"
        $message += "BIOS Config Required: $($support.BIOSRequired)`n`n"
        
        if ($support.Issues.Count -gt 0) {
            $message += "Issues Found:`n"
            foreach ($issue in $support.Issues) {
                $message += "• $issue`n"
            }
            $message += "`n"
        }
        
        if ($support.Recommendations.Count -gt 0) {
            $message += "Recommendations:`n"
            foreach ($rec in $support.Recommendations) {
                $message += "• $rec`n"
            }
        }
        
        Show-MessageBox -Message $message -Title "WoL Support Analysis" -Icon 'Information'
        
    } catch {
        Show-MessageBox -Message "Failed to test WoL support: $($_.Exception.Message)" -Title "Test Error" -Icon 'Error'
    }
}

function Refresh-ProfilesList {
    param($Tab)
    
    $controls = $Tab.Tag
    $listView = $controls.ProfilesListView
    
    $listView.Items.Clear()
    
    foreach ($profile in $global:WoLProfiles) {
        $item = New-Object System.Windows.Forms.ListViewItem($profile.Name)
        $item.SubItems.Add($profile.MacAddress) | Out-Null
        $item.SubItems.Add($profile.IPAddress) | Out-Null
        $item.SubItems.Add($profile.Group) | Out-Null
        $item.SubItems.Add($profile.LastUsed) | Out-Null
        $item.SubItems.Add($profile.UseCount.ToString()) | Out-Null
        $item.Tag = $profile
        $listView.Items.Add($item) | Out-Null
    }
}

function Show-ProfileEditor {
    param($Tab, [switch]$Edit)
    
    $profile = $null
    if ($Edit) {
        $controls = $Tab.Tag
        $listView = $controls.ProfilesListView
        if ($listView.SelectedItems.Count -eq 0) {
            Show-MessageBox -Message "Please select a profile to edit." -Title "No Profile Selected" -Icon 'Warning'
            return
        }
        $profile = $listView.SelectedItems[0].Tag
    }
    
    $editorForm = New-Object System.Windows.Forms.Form
    $editorForm.Text = if ($Edit) { "Edit Profile" } else { "Add Profile" }
    $editorForm.Size = New-Object System.Drawing.Size(400, 350)
    $editorForm.StartPosition = 'CenterParent'
    $editorForm.FormBorderStyle = 'FixedDialog'
    $editorForm.MaximizeBox = $false
    $editorForm.MinimizeBox = $false
    
    # Name
    $nameLabel = New-Object System.Windows.Forms.Label
    $nameLabel.Text = "Profile Name:"
    $nameLabel.Location = New-Object System.Drawing.Point(20, 20)
    $nameLabel.Size = New-Object System.Drawing.Size(100, 20)
    $editorForm.Controls.Add($nameLabel)
    
    $nameTextBox = New-Object System.Windows.Forms.TextBox
    $nameTextBox.Location = New-Object System.Drawing.Point(130, 17)
    $nameTextBox.Size = New-Object System.Drawing.Size(220, 22)
    if ($profile) { $nameTextBox.Text = $profile.Name }
    $editorForm.Controls.Add($nameTextBox)
    
    # MAC Address
    $macLabel = New-Object System.Windows.Forms.Label
    $macLabel.Text = "MAC Address:"
    $macLabel.Location = New-Object System.Drawing.Point(20, 50)
    $macLabel.Size = New-Object System.Drawing.Size(100, 20)
    $editorForm.Controls.Add($macLabel)
    
    $macTextBox = New-Object System.Windows.Forms.TextBox
    $macTextBox.Location = New-Object System.Drawing.Point(130, 47)
    $macTextBox.Size = New-Object System.Drawing.Size(220, 22)
    $macTextBox.PlaceholderText = "XX:XX:XX:XX:XX:XX"
    if ($profile) { $macTextBox.Text = $profile.MacAddress }
    $editorForm.Controls.Add($macTextBox)
    
    # IP Address
    $ipLabel = New-Object System.Windows.Forms.Label
    $ipLabel.Text = "IP Address:"
    $ipLabel.Location = New-Object System.Drawing.Point(20, 80)
    $ipLabel.Size = New-Object System.Drawing.Size(100, 20)
    $editorForm.Controls.Add($ipLabel)
    
    $ipTextBox = New-Object System.Windows.Forms.TextBox
    $ipTextBox.Location = New-Object System.Drawing.Point(130, 77)
    $ipTextBox.Size = New-Object System.Drawing.Size(220, 22)
    $ipTextBox.PlaceholderText = "192.168.1.100 (optional)"
    if ($profile) { $ipTextBox.Text = $profile.IPAddress }
    $editorForm.Controls.Add($ipTextBox)
    
    # Broadcast Address
    $broadcastLabel = New-Object System.Windows.Forms.Label
    $broadcastLabel.Text = "Broadcast:"
    $broadcastLabel.Location = New-Object System.Drawing.Point(20, 110)
    $broadcastLabel.Size = New-Object System.Drawing.Size(100, 20)
    $editorForm.Controls.Add($broadcastLabel)
    
    $broadcastTextBox = New-Object System.Windows.Forms.TextBox
    $broadcastTextBox.Location = New-Object System.Drawing.Point(130, 107)
    $broadcastTextBox.Size = New-Object System.Drawing.Size(220, 22)
    $broadcastTextBox.Text = if ($profile) { $profile.BroadcastAddress } else { $global:Config.DefaultBroadcast }
    $editorForm.Controls.Add($broadcastTextBox)
    
    # Port
    $portLabel = New-Object System.Windows.Forms.Label
    $portLabel.Text = "Port:"
    $portLabel.Location = New-Object System.Drawing.Point(20, 140)
    $portLabel.Size = New-Object System.Drawing.Size(100, 20)
    $editorForm.Controls.Add($portLabel)
    
    $portNumeric = New-Object System.Windows.Forms.NumericUpDown
    $portNumeric.Location = New-Object System.Drawing.Point(130, 137)
    $portNumeric.Size = New-Object System.Drawing.Size(80, 22)
    $portNumeric.Minimum = 1
    $portNumeric.Maximum = 65535
    $portNumeric.Value = if ($profile) { $profile.Port } else { $global:Config.DefaultPort }
    $editorForm.Controls.Add($portNumeric)
    
    # Group
    $groupLabel = New-Object System.Windows.Forms.Label
    $groupLabel.Text = "Group:"
    $groupLabel.Location = New-Object System.Drawing.Point(20, 170)
    $groupLabel.Size = New-Object System.Drawing.Size(100, 20)
    $editorForm.Controls.Add($groupLabel)
    
    $groupTextBox = New-Object System.Windows.Forms.TextBox
    $groupTextBox.Location = New-Object System.Drawing.Point(130, 167)
    $groupTextBox.Size = New-Object System.Drawing.Size(220, 22)
    $groupTextBox.Text = if ($profile) { $profile.Group } else { "Default" }
    $editorForm.Controls.Add($groupTextBox)
    
    # Description
    $descLabel = New-Object System.Windows.Forms.Label
    $descLabel.Text = "Description:"
    $descLabel.Location = New-Object System.Drawing.Point(20, 200)
    $descLabel.Size = New-Object System.Drawing.Size(100, 20)
    $editorForm.Controls.Add($descLabel)
    
    $descTextBox = New-Object System.Windows.Forms.TextBox
    $descTextBox.Multiline = $true
    $descTextBox.Location = New-Object System.Drawing.Point(130, 200)
    $descTextBox.Size = New-Object System.Drawing.Size(220, 60)
    if ($profile) { $descTextBox.Text = $profile.Description }
    $editorForm.Controls.Add($descTextBox)
    
    # Buttons
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(195, 280)
    $okButton.Size = New-Object System.Drawing.Size(75, 25)
    $okButton.DialogResult = 'OK'
    $editorForm.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(275, 280)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 25)
    $cancelButton.DialogResult = 'Cancel'
    $editorForm.Controls.Add($cancelButton)
    
    $editorForm.AcceptButton = $okButton
    $editorForm.CancelButton = $cancelButton
    
    # Validation and save
    $okButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($nameTextBox.Text)) {
            Show-MessageBox -Message "Profile name is required." -Title "Validation Error" -Icon 'Warning'
            return
        }
        
        if (-not (Test-MacAddress $macTextBox.Text)) {
            Show-MessageBox -Message "Please enter a valid MAC address." -Title "Validation Error" -Icon 'Warning'
            return
        }
        
        try {
            if ($Edit) {
                # Update existing profile
                $profile.Name = $nameTextBox.Text.Trim()
                $profile.MacAddress = Format-MacAddress $macTextBox.Text.Trim()
                $profile.IPAddress = $ipTextBox.Text.Trim()
                $profile.BroadcastAddress = $broadcastTextBox.Text.Trim()
                $profile.Port = [int]$portNumeric.Value
                $profile.Group = $groupTextBox.Text.Trim()
                $profile.Description = $descTextBox.Text.Trim()
                
                Write-WoLLog -Message "Updated profile: $($profile.Name)" -Level 'Info'
            } else {
                # Create new profile
                $newProfile = New-WoLProfile -Name $nameTextBox.Text.Trim() -MacAddress $macTextBox.Text.Trim() -IPAddress $ipTextBox.Text.Trim() -BroadcastAddress $broadcastTextBox.Text.Trim() -Port ([int]$portNumeric.Value) -Group $groupTextBox.Text.Trim() -Description $descTextBox.Text.Trim()
                Add-WoLProfile -Profile $newProfile
                
                Write-WoLLog -Message "Created new profile: $($newProfile.Name)" -Level 'Info'
            }
            
            Refresh-ProfilesList -Tab $Tab
            
        } catch {
            Show-MessageBox -Message "Failed to save profile: $($_.Exception.Message)" -Title "Save Error" -Icon 'Error'
            return
        }
    })
    
    $editorForm.ShowDialog() | Out-Null
}

function Remove-SelectedProfile {
    param($Tab)
    
    $controls = $Tab.Tag
    $listView = $controls.ProfilesListView
    
    if ($listView.SelectedItems.Count -eq 0) {
        Show-MessageBox -Message "Please select a profile to delete." -Title "No Profile Selected" -Icon 'Warning'
        return
    }
    
    $profile = $listView.SelectedItems[0].Tag
    $result = Show-MessageBox -Message "Are you sure you want to delete the profile '$($profile.Name)'?" -Title "Confirm Delete" -Buttons 'YesNo' -Icon 'Question'
    
    if ($result -eq 'Yes') {
        Remove-WoLProfile -ProfileId $profile.Id
        Refresh-ProfilesList -Tab $Tab
    }
}

function Wake-SelectedProfile {
    param($Tab)
    
    $controls = $Tab.Tag
    $listView = $controls.ProfilesListView
    
    if ($listView.SelectedItems.Count -eq 0) {
        Show-MessageBox -Message "Please select a profile to wake." -Title "No Profile Selected" -Icon 'Warning'
        return
    }
    
    $profile = $listView.SelectedItems[0].Tag
    
    try {
        Write-WoLLog -Message "Waking device from profile: $($profile.Name)" -Level 'Info'
        
        $results = Send-MagicPacket -MacAddress $profile.MacAddress -BroadcastAddress $profile.BroadcastAddress -Port $profile.Port -Count $global:Config.MagicPacketCount -DelayMs $global:Config.MagicPacketDelay
        
        $successCount = ($results | Where-Object { $_.Success }).Count
        $totalCount = $results.Count
        
        if ($successCount -eq $totalCount) {
            Show-MessageBox -Message "Magic packets sent successfully to '$($profile.Name)' ($successCount/$totalCount packets)" -Title "Wake Sent" -Icon 'Information'
            Update-WoLProfileUsage -ProfileId $profile.Id
            Refresh-ProfilesList -Tab $Tab
        } else {
            Show-MessageBox -Message "Partial success: $successCount/$totalCount packets sent to '$($profile.Name)'" -Title "Wake Partially Sent" -Icon 'Warning'
        }
        
    } catch {
        Show-MessageBox -Message "Failed to wake device '$($profile.Name)': $($_.Exception.Message)" -Title "Wake Error" -Icon 'Error'
    }
}

function Send-QuickWake {
    param($Tab)
    
    $controls = $Tab.Tag
    $macTextBox = $controls.MacTextBox
    $broadcastTextBox = $controls.BroadcastTextBox
    $portTextBox = $controls.PortTextBox
    $resultLabel = $controls.ResultLabel
    
    $mac = $macTextBox.Text.Trim()
    if ([string]::IsNullOrEmpty($mac)) {
        Show-MessageBox -Message "Please enter a MAC address." -Title "MAC Address Required" -Icon 'Warning'
        return
    }
    
    if (-not (Test-MacAddress $mac)) {
        Show-MessageBox -Message "Please enter a valid MAC address." -Title "Invalid MAC Address" -Icon 'Warning'
        return
    }
    
    $broadcast = $broadcastTextBox.Text.Trim()
    if ([string]::IsNullOrEmpty($broadcast)) {
        $broadcast = $global:Config.DefaultBroadcast
    }
    
    $port = $global:Config.DefaultPort
    if (-not [string]::IsNullOrEmpty($portTextBox.Text.Trim())) {
        [int]::TryParse($portTextBox.Text.Trim(), [ref]$port) | Out-Null
    }
    
    try {
        Write-WoLLog -Message "Sending quick wake to MAC: $mac" -Level 'Info'
        
        $results = Send-MagicPacket -MacAddress $mac -BroadcastAddress $broadcast -Port $port -Count $global:Config.MagicPacketCount -DelayMs $global:Config.MagicPacketDelay
        
        $successCount = ($results | Where-Object { $_.Success }).Count
        $totalCount = $results.Count
        
        if ($successCount -eq $totalCount) {
            $resultLabel.Text = "SUCCESS: $successCount/$totalCount packets sent to $broadcast`:$port"
            $resultLabel.ForeColor = [System.Drawing.Color]::Green
        } else {
            $resultLabel.Text = "PARTIAL: $successCount/$totalCount packets sent to $broadcast`:$port"
            $resultLabel.ForeColor = [System.Drawing.Color]::Orange
        }
        
    } catch {
        $resultLabel.Text = "ERROR: $($_.Exception.Message)"
        $resultLabel.ForeColor = [System.Drawing.Color]::Red
        Write-WoLLog -Message "Quick wake failed: $($_.Exception.Message)" -Level 'Error'
    }
}

function Start-DeviceDiscovery {
    param($Tab)
    
    $controls = $Tab.Tag
    $scanButton = $controls.ScanButton
    $progressBar = $controls.ProgressBar
    $statusLabel = $controls.StatusLabel
    $devicesListView = $controls.DevicesListView
    
    try {
        Write-WoLLog -Message "Starting network device discovery" -Level 'Info'
        
        $scanButton.Enabled = $false
        $progressBar.Visible = $true
        $statusLabel.Text = "Scanning network for devices..."
        $devicesListView.Items.Clear()
        
        # Run discovery in background
        $devices = Discover-NetworkDevices
        
        # Update UI with results
        foreach ($device in $devices) {
            $item = New-Object System.Windows.Forms.ListViewItem($device.IPAddress)
            $item.SubItems.Add($device.MacAddress) | Out-Null
            $item.SubItems.Add($device.Hostname) | Out-Null
            $item.SubItems.Add($device.Status) | Out-Null
            $item.SubItems.Add($device.Adapter) | Out-Null
            $item.SubItems.Add($device.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")) | Out-Null
            $item.Tag = $device
            $devicesListView.Items.Add($item) | Out-Null
        }
        
        $statusLabel.Text = "Discovery completed: $($devices.Count) devices found"
        Write-WoLLog -Message "Device discovery completed: $($devices.Count) devices found" -Level 'Info'
        
    } catch {
        $statusLabel.Text = "Discovery failed: $($_.Exception.Message)"
        Write-WoLLog -Message "Device discovery failed: $($_.Exception.Message)" -Level 'Error'
        
    } finally {
        $scanButton.Enabled = $true
        $progressBar.Visible = $false
    }
}

function Add-DiscoveredToProfiles {
    param($Tab)
    
    $controls = $Tab.Tag
    $devicesListView = $controls.DevicesListView
    
    if ($devicesListView.SelectedItems.Count -eq 0) {
        Show-MessageBox -Message "Please select one or more devices to add to profiles." -Title "No Devices Selected" -Icon 'Warning'
        return
    }
    
    $addedCount = 0
    foreach ($selectedItem in $devicesListView.SelectedItems) {
        $device = $selectedItem.Tag
        
        try {
            $profileName = if ($device.Hostname -ne 'Unknown') { $device.Hostname } else { $device.IPAddress }
            $newProfile = New-WoLProfile -Name $profileName -MacAddress $device.MacAddress -IPAddress $device.IPAddress -Description "Auto-discovered device"
            Add-WoLProfile -Profile $newProfile
            $addedCount++
            
        } catch {
            Write-WoLLog -Message "Failed to add device $($device.IPAddress) to profiles: $($_.Exception.Message)" -Level 'Warning'
        }
    }
    
    if ($addedCount -gt 0) {
        Show-MessageBox -Message "$addedCount device(s) added to profiles successfully." -Title "Profiles Added" -Icon 'Information'
    } else {
        Show-MessageBox -Message "No devices were added to profiles." -Title "No Profiles Added" -Icon 'Warning'
    }
}

function Wake-DiscoveredDevices {
    param($Tab)
    
    $controls = $Tab.Tag
    $devicesListView = $controls.DevicesListView
    
    if ($devicesListView.SelectedItems.Count -eq 0) {
        Show-MessageBox -Message "Please select one or more devices to wake." -Title "No Devices Selected" -Icon 'Warning'
        return
    }
    
    $wakeCount = 0
    $failCount = 0
    
    foreach ($selectedItem in $devicesListView.SelectedItems) {
        $device = $selectedItem.Tag
        
        try {
            $results = Send-MagicPacket -MacAddress $device.MacAddress -BroadcastAddress $global:Config.DefaultBroadcast -Port $global:Config.DefaultPort
            
            if ($results[0].Success) {
                $wakeCount++
                Write-WoLLog -Message "Wake packet sent to $($device.IPAddress) ($($device.MacAddress))" -Level 'Info'
            } else {
                $failCount++
            }
            
        } catch {
            $failCount++
            Write-WoLLog -Message "Failed to wake $($device.IPAddress): $($_.Exception.Message)" -Level 'Error'
        }
    }
    
    $message = "Wake operation completed:`n$wakeCount devices woken successfully"
    if ($failCount -gt 0) {
        $message += "`n$failCount devices failed to wake"
    }
    
    Show-MessageBox -Message $message -Title "Wake Operation Result" -Icon 'Information'
}

function Send-TestMagicPackets {
    param($Tab)
    
    $controls = $Tab.Tag
    $macTextBox = $controls.TestMacTextBox
    $broadcastTextBox = $controls.TestBroadcastTextBox
    $portTextBox = $controls.TestPortTextBox
    $countNumeric = $controls.PacketCountNumeric
    $delayNumeric = $controls.DelayNumeric
    $resultLabel = $controls.TestResultLabel
    
    $mac = $macTextBox.Text.Trim()
    if ([string]::IsNullOrEmpty($mac)) {
        Show-MessageBox -Message "Please enter a MAC address to test." -Title "MAC Address Required" -Icon 'Warning'
        return
    }
    
    if (-not (Test-MacAddress $mac)) {
        Show-MessageBox -Message "Please enter a valid MAC address." -Title "Invalid MAC Address" -Icon 'Warning'
        return
    }
    
    $broadcast = $broadcastTextBox.Text.Trim()
    $port = [int]::Parse($portTextBox.Text)
    $count = [int]$countNumeric.Value
    $delay = [int]$delayNumeric.Value
    
    try {
        Write-WoLLog -Message "Sending test magic packets: MAC=$mac, Count=$count, Delay=$delay" -Level 'Info'
        
        $results = Send-MagicPacket -MacAddress $mac -BroadcastAddress $broadcast -Port $port -Count $count -DelayMs $delay
        
        $successCount = ($results | Where-Object { $_.Success }).Count
        $totalBytes = ($results | Where-Object { $_.Success } | Measure-Object -Property BytesSent -Sum).Sum
        
        if ($successCount -eq $count) {
            $resultLabel.Text = "SUCCESS: All $count packets sent ($totalBytes bytes total)"
            $resultLabel.ForeColor = [System.Drawing.Color]::Green
        } else {
            $resultLabel.Text = "PARTIAL: $successCount/$count packets sent"
            $resultLabel.ForeColor = [System.Drawing.Color]::Orange
        }
        
        Write-WoLLog -Message "Test magic packets result: $successCount/$count successful" -Level 'Info'
        
    } catch {
        $resultLabel.Text = "ERROR: $($_.Exception.Message)"
        $resultLabel.ForeColor = [System.Drawing.Color]::Red
        Write-WoLLog -Message "Test magic packets failed: $($_.Exception.Message)" -Level 'Error'
    }
}

function Run-SystemDiagnostics {
    param($Tab)
    
    $controls = $Tab.Tag
    $diagnosticsTextBox = $controls.DiagnosticsTextBox
    $runButton = $controls.RunDiagnosticsButton
    
    try {
        $runButton.Enabled = $false
        $diagnosticsTextBox.Text = "Running diagnostics, please wait..."
        
        Write-WoLLog -Message "Running system diagnostics" -Level 'Info'
        
        $report = @()
        $report += "=== Wake-on-LAN System Diagnostics ==="
        $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $report += ""
        
        # System Information
        $report += "=== SYSTEM INFORMATION ==="
        $report += "Computer Name: $env:COMPUTERNAME"
        $report += "OS Version: $((Get-CimInstance Win32_OperatingSystem).Caption)"
        $report += "PowerShell Version: $($PSVersionTable.PSVersion)"
        $report += "Administrator: $([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
        $report += ""
        
        # Network Adapters
        $report += "=== NETWORK ADAPTERS ==="
        foreach ($adapter in $global:Adapters) {
            $report += "Adapter: $($adapter.Name)"
            $report += "  Description: $($adapter.Description)"
            $report += "  Status: $($adapter.Status)"
            $report += "  MAC: $($adapter.MacAddress)"
            $report += "  Speed: $($adapter.LinkSpeed)"
            
            if ($adapter.PowerManagement) {
                $report += "  WoL Magic Packet: $($adapter.PowerManagement.WakeOnMagicPacket)"
                $report += "  WoL Pattern: $($adapter.PowerManagement.WakeOnPattern)"
            } else {
                $report += "  WoL Status: Not Available"
            }
            
            # Test WoL Support
            try {
                $support = Test-WakeOnLANSupport -Adapter $adapter
                $report += "  WoL Support: $($support.AdapterSupported)"
                if ($support.Issues.Count -gt 0) {
                    $report += "  Issues: $($support.Issues -join '; ')"
                }
            } catch {
                $report += "  WoL Support: Error testing"
            }
            
            $report += ""
        }
        
        # Power Settings
        $report += "=== POWER SETTINGS ==="
        try {
            $powerSettings = & powercfg /query SCHEME_CURRENT SUB_SLEEP 2>$null | Out-String
            $report += "Current Power Scheme: $((& powercfg /getactivescheme) -split '\s+')[3]"
            
            # Check for Fast Startup
            $fastStartup = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
            if ($fastStartup) {
                $report += "Fast Startup: $($fastStartup.HiberbootEnabled -eq 1)"
            }
        } catch {
            $report += "Power Settings: Unable to query"
        }
        $report += ""
        
        # Wake-enabled devices
        $report += "=== WAKE-ENABLED DEVICES ==="
        try {
            $wakeDevices = & powercfg /devicequery wake_armed 2>$null
            if ($wakeDevices) {
                foreach ($device in $wakeDevices) {
                    $report += "  $device"
                }
            } else {
                $report += "  No devices are currently wake-enabled"
            }
        } catch {
            $report += "  Unable to query wake-enabled devices"
        }
        $report += ""
        
        # Network Configuration
        $report += "=== NETWORK CONFIGURATION ==="
        $netConfigs = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' }
        foreach ($config in $netConfigs) {
            $report += "Interface: $($config.InterfaceAlias)"
            if ($config.IPv4Address) {
                $report += "  IPv4: $($config.IPv4Address.IPAddress)/$($config.IPv4Address.PrefixLength)"
            }
            if ($config.IPv4DefaultGateway) {
                $report += "  Gateway: $($config.IPv4DefaultGateway.NextHop)"
            }
            $report += ""
        }
        
        # Log Summary
        $report += "=== LOG SUMMARY ==="
        $report += "Total Log Entries: $($global:LogEntries.Count)"
        $errorCount = ($global:LogEntries | Where-Object { $_.Level -eq 'Error' }).Count
        $warningCount = ($global:LogEntries | Where-Object { $_.Level -eq 'Warning' }).Count
        $report += "Errors: $errorCount"
        $report += "Warnings: $warningCount"
        
        if ($errorCount -gt 0) {
            $report += ""
            $report += "Recent Errors:"
            $recentErrors = $global:LogEntries | Where-Object { $_.Level -eq 'Error' } | Select-Object -Last 5
            foreach ($error in $recentErrors) {
                $report += "  $($error.Entry)"
            }
        }
        
        $diagnosticsTextBox.Text = $report -join "`r`n"
        
        Write-WoLLog -Message "System diagnostics completed successfully" -Level 'Info'
        
    } catch {
        $diagnosticsTextBox.Text = "Failed to run diagnostics: $($_.Exception.Message)"
        Write-WoLLog -Message "System diagnostics failed: $($_.Exception.Message)" -Level 'Error'
        
    } finally {
        $runButton.Enabled = $true
    }
}

function Export-DiagnosticsReport {
    param($Tab)
    
    $controls = $Tab.Tag
    $diagnosticsTextBox = $controls.DiagnosticsTextBox
    
    if ([string]::IsNullOrWhiteSpace($diagnosticsTextBox.Text)) {
        Show-MessageBox -Message "Please run diagnostics first before exporting." -Title "No Report Available" -Icon 'Warning'
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Title = "Export Diagnostics Report"
    $saveDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
    $saveDialog.FileName = "WoL_Diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    
    if ($saveDialog.ShowDialog() -eq 'OK') {
        try {
            $diagnosticsTextBox.Text | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            Show-MessageBox -Message "Diagnostics report exported successfully to:`n$($saveDialog.FileName)" -Title "Export Successful" -Icon 'Information'
            Write-WoLLog -Message "Diagnostics report exported to: $($saveDialog.FileName)" -Level 'Info'
            
        } catch {
            Show-MessageBox -Message "Failed to export diagnostics report: $($_.Exception.Message)" -Title "Export Error" -Icon 'Error'
        }
    }
}

function Apply-Settings {
    param($Tab)
    
    $controls = $Tab.Tag
    
    try {
        # Update global configuration
        $global:Config.AutoSaveProfiles = $controls.AutoSaveCheckBox.Checked
        $global:Config.EnableLogging = $controls.EnableLoggingCheckBox.Checked
        $global:Config.DefaultPort = [int]$controls.DefaultPortNumeric.Value
        $global:Config.DefaultBroadcast = $controls.DefaultBroadcastTextBox.Text.Trim()
        
        # Save configuration
        Save-Configuration
        
        Show-MessageBox -Message "Settings have been applied and saved successfully." -Title "Settings Applied" -Icon 'Information'
        Write-WoLLog -Message "Application settings updated" -Level 'Info'
        
    } catch {
        Show-MessageBox -Message "Failed to apply settings: $($_.Exception.Message)" -Title "Settings Error" -Icon 'Error'
    }
}

function Reset-Settings {
    param($Tab)
    
    $result = Show-MessageBox -Message "Are you sure you want to reset all settings to defaults? This cannot be undone." -Title "Reset Settings" -Buttons 'YesNo' -Icon 'Question'
    
    if ($result -eq 'Yes') {
        try {
            Initialize-DefaultConfiguration
            Save-Configuration
            
            # Update UI controls
            $controls = $Tab.Tag
            $controls.AutoSaveCheckBox.Checked = $global:Config.AutoSaveProfiles
            $controls.EnableLoggingCheckBox.Checked = $global:Config.EnableLogging
            $controls.DefaultPortNumeric.Value = $global:Config.DefaultPort
            $controls.DefaultBroadcastTextBox.Text = $global:Config.DefaultBroadcast
            
            Show-MessageBox -Message "Settings have been reset to defaults." -Title "Settings Reset" -Icon 'Information'
            Write-WoLLog -Message "Application settings reset to defaults" -Level 'Info'
            
        } catch {
            Show-MessageBox -Message "Failed to reset settings: $($_.Exception.Message)" -Title "Reset Error" -Icon 'Error'
        }
    }
}

function Show-LogViewer {
    $logForm = New-Object System.Windows.Forms.Form
    $logForm.Text = "Application Log Viewer"
    $logForm.Size = New-Object System.Drawing.Size(800, 600)
    $logForm.StartPosition = 'CenterParent'
    
    $logListView = New-Object System.Windows.Forms.ListView
    $logListView.Dock = 'Fill'
    $logListView.View = 'Details'
    $logListView.FullRowSelect = $true
    $logListView.GridLines = $true
    
    $logListView.Columns.Add("Timestamp", 150) | Out-Null
    $logListView.Columns.Add("Level", 80) | Out-Null
    $logListView.Columns.Add("Message", 550) | Out-Null
    
    foreach ($logEntry in $global:LogEntries) {
        $item = New-Object System.Windows.Forms.ListViewItem($logEntry.Timestamp)
        $item.SubItems.Add($logEntry.Level) | Out-Null
        $item.SubItems.Add($logEntry.Message) | Out-Null
        
        switch ($logEntry.Level) {
            'Error' { $item.BackColor = [System.Drawing.Color]::LightPink }
            'Warning' { $item.BackColor = [System.Drawing.Color]::LightYellow }
            'Debug' { $item.ForeColor = [System.Drawing.Color]::Gray }
        }
        
        $logListView.Items.Add($item) | Out-Null
    }
    
    $logForm.Controls.Add($logListView)
    $logForm.ShowDialog() | Out-Null
}

function Show-TroubleshootingGuide {
    $helpForm = New-Object System.Windows.Forms.Form
    $helpForm.Text = "Wake-on-LAN Troubleshooting Guide"
    $helpForm.Size = New-Object System.Drawing.Size(700, 500)
    $helpForm.StartPosition = 'CenterParent'
    
    $helpTextBox = New-Object System.Windows.Forms.TextBox
    $helpTextBox.Multiline = $true
    $helpTextBox.ReadOnly = $true
    $helpTextBox.ScrollBars = 'Vertical'
    $helpTextBox.Dock = 'Fill'
    $helpTextBox.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    
    $helpText = @"
WAKE-ON-LAN TROUBLESHOOTING GUIDE

1. HARDWARE REQUIREMENTS
• Ethernet adapter with WoL support (check manufacturer specs)
• Motherboard with WoL support
• Adequate power supply to network adapter during sleep/shutdown
• Physical network connection (cables, switches must remain powered)

2. BIOS/UEFI SETTINGS (CRITICAL)
• Enable "Wake on LAN" or "Power on by PCI-E" 
• Enable "PME (Power Management Event)"
• Disable "Deep Sleep" or "ErP Ready" modes
• Some systems: Enable "AC Power Recovery" 
• Location varies by manufacturer (Power, Advanced, or Integrated Peripherals)

3. WINDOWS CONFIGURATION
• Run this tool as Administrator
• Enable "Wake on Magic Packet" in adapter power management
• Ensure adapter drivers are up to date
• Consider disabling "Fast Startup" (Power Options > Choose what power buttons do)

4. NETWORK CONFIGURATION
• Use correct broadcast address for your network
• Common ports: 7, 9 (try both)
• Ensure switches/routers forward broadcast packets
• For remote WoL: configure router port forwarding

5. POWER STATE CONSIDERATIONS
• Sleep (S3): Usually works if properly configured
• Hibernate (S4): May work depending on hardware
• Shutdown (S5): Requires "Wake from S5" BIOS setting and PSU support

6. COMMON ISSUES & SOLUTIONS

Issue: WoL works from sleep but not shutdown
Solution: Enable "Wake from S5" in BIOS, check PSU capability

Issue: Magic packets sent but device doesn't wake
Solution: Verify BIOS settings, check power to network adapter

Issue: Works sometimes but not consistently  
Solution: Update network drivers, disable power saving on adapter

Issue: WoL doesn't work after Windows updates
Solution: Check if driver was updated, reconfigure power management

Issue: Can't enable Wake on Magic Packet option
Solution: Update network adapter drivers, verify hardware support

7. TESTING STEPS
1. Test WoL from same network segment first
2. Use this tool's diagnostics to check configuration
3. Verify magic packets are being sent (use packet capture)
4. Test from different power states (sleep, then shutdown)
5. Check Windows Event Log for power/wake events

8. ADVANCED TROUBLESHOOTING
• Use 'powercfg /devicequery wake_armed' to see wake-enabled devices
• Use 'powercfg /waketimers' to check for wake timers
• Monitor network traffic with Wireshark during WoL attempts
• Check manufacturer documentation for specific WoL requirements

9. SECURITY CONSIDERATIONS
• WoL magic packets are unencrypted
• Consider SecureOn (password-protected) WoL if supported
• Limit WoL to trusted networks only
• Some corporate networks block broadcast traffic

For additional help, use the built-in diagnostics tool and check the application logs.
"@

    $helpTextBox.Text = $helpText
    $helpForm.Controls.Add($helpTextBox)
    $helpForm.ShowDialog() | Out-Null
}

function Show-AboutDialog {
    $aboutForm = New-Object System.Windows.Forms.Form
    $aboutForm.Text = "About"
    $aboutForm.Size = New-Object System.Drawing.Size(400, 300)
    $aboutForm.StartPosition = 'CenterParent'
    $aboutForm.FormBorderStyle = 'FixedDialog'
    $aboutForm.MaximizeBox = $false
    $aboutForm.MinimizeBox = $false
    
    $aboutLabel = New-Object System.Windows.Forms.Label
    $aboutLabel.Text = @"
Advanced Wake-on-LAN Configurator
Version 2.0.0

A comprehensive tool for configuring and managing 
Wake-on-LAN functionality across network adapters.

Enhanced from the original Simple WoL Configurator 
with modern interface, advanced features, and 
comprehensive diagnostics.

Requires Windows PowerShell 5.1+ and 
Administrator privileges.

© 2024 Enhanced WoL Configurator
"@
    $aboutLabel.Location = New-Object System.Drawing.Point(20, 20)
    $aboutLabel.Size = New-Object System.Drawing.Size(350, 200)
    $aboutLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $aboutForm.Controls.Add($aboutLabel)
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(160, 230)
    $okButton.Size = New-Object System.Drawing.Size(75, 25)
    $okButton.DialogResult = 'OK'
    $aboutForm.Controls.Add($okButton)
    $aboutForm.AcceptButton = $okButton
    
    $aboutForm.ShowDialog() | Out-Null
}

#endregion

#region Application Startup

try {
    Write-WoLLog -Message "Starting $Script:AppTitle" -Level 'Info'
    
    # Create and show main form
    $mainForm = Create-MainForm
    
    # Initialize data on startup
    $adaptersTab = $mainForm.Tag.AdaptersTab
    $profilesTab = $mainForm.Tag.ProfilesTab
    
    # Load initial data
    Refresh-AdaptersList -Tab $adaptersTab
    Refresh-ProfilesList -Tab $profilesTab
    
    Write-WoLLog -Message "Application initialized successfully" -Level 'Info'
    
    # Show the form
    [System.Windows.Forms.Application]::EnableVisualStyles()
    [void]$mainForm.ShowDialog()
    
} catch {
    $errorMessage = "Failed to start application: $($_.Exception.Message)"
    Write-WoLLog -Message $errorMessage -Level 'Error'
    Show-MessageBox -Message $errorMessage -Title "Startup Error" -Icon 'Error'
}

Write-WoLLog -Message "Application terminated" -Level 'Info'

#endregion
