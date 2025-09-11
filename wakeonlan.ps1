Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Ensure-RunAsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Get-Process -Id $PID).Path
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
        $psi.Verb = "runas"
        try {
            [System.Diagnostics.Process]::Start($psi) | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("This tool needs to run as Administrator. Restart canceled.", "Elevation Required", 'OK', 'Warning') | Out-Null
        }
        Exit
    }
}

# Ensure script is elevated because many operations require admin
Ensure-RunAsAdmin

# Helper: format MAC to bytes
function Parse-MacAddress {
    param([string]$mac)
    $clean = $mac -replace '[:-]', '' -replace '\s+', ''
    if ($clean.Length -ne 12) { throw 'MAC must be 12 hex digits (e.g. 00:11:22:AA:BB:CC)' }
    $bytes = for ($i=0; $i -lt 12; $i += 2) { [byte]::Parse($clean.Substring($i,2), 'AllowHexSpecifier') }
    return ,$bytes
}

# Send magic packet
function Send-MagicPacket {
    param(
        [Parameter(Mandatory=$true)][string]$Mac,
        [string]$Broadcast = '255.255.255.255',
        [int]$Port = 9
    )
    try {
        $payload = [byte[]](,0xFF * 6)
        $macBytes = Parse-MacAddress -mac $Mac
        for ($i=0; $i -lt 16; $i++) { $payload += $macBytes }

        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.EnableBroadcast = $true
        $end = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($Broadcast), $Port)
        $bytesSent = $udp.Send($payload, $payload.Length, $end)
        $udp.Close()
        return $bytesSent
    } catch {
        throw $_
    }
}

# Build UI
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Wake-on-LAN Configurator'
$form.Size = New-Object System.Drawing.Size(920,640)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI',9)

# Left: Adapter list
$lblAdapters = New-Object System.Windows.Forms.Label
$lblAdapters.Text = 'Network Adapters:'
$lblAdapters.Location = New-Object System.Drawing.Point(10,10)
$lblAdapters.Size = New-Object System.Drawing.Size(200,20)
$form.Controls.Add($lblAdapters)

$lstAdapters = New-Object System.Windows.Forms.ListBox
$lstAdapters.Location = New-Object System.Drawing.Point(10,35)
$lstAdapters.Size = New-Object System.Drawing.Size(330,220)
$lstAdapters.ScrollAlwaysVisible = $true
$form.Controls.Add($lstAdapters)

# Buttons to refresh and show details
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = 'Refresh Adapters'
$btnRefresh.Location = New-Object System.Drawing.Point(10,265)
$btnRefresh.Size = New-Object System.Drawing.Size(160,28)
$form.Controls.Add($btnRefresh)

$btnRescanAdv = New-Object System.Windows.Forms.Button
$btnRescanAdv.Text = 'Load Advanced Props'
$btnRescanAdv.Location = New-Object System.Drawing.Point(180,265)
$btnRescanAdv.Size = New-Object System.Drawing.Size(160,28)
$form.Controls.Add($btnRescanAdv)

# Right: details group
$grpDetails = New-Object System.Windows.Forms.GroupBox
$grpDetails.Text = 'Adapter Details & Controls'
$grpDetails.Location = New-Object System.Drawing.Point(350,10)
$grpDetails.Size = New-Object System.Drawing.Size(540,300)
$form.Controls.Add($grpDetails)

$txtDetails = New-Object System.Windows.Forms.TextBox
$txtDetails.Multiline = $true
$txtDetails.ScrollBars = 'Vertical'
$txtDetails.Location = New-Object System.Drawing.Point(10,20)
$txtDetails.Size = New-Object System.Drawing.Size(520,120)
$txtDetails.ReadOnly = $true
$grpDetails.Controls.Add($txtDetails)

# Power management checkboxes
$chkWakeMagic = New-Object System.Windows.Forms.CheckBox
$chkWakeMagic.Text = 'Enable Wake on Magic Packet (Set-NetAdapterPowerManagement)'
$chkWakeMagic.Location = New-Object System.Drawing.Point(10,150)
$chkWakeMagic.Size = New-Object System.Drawing.Size(520,20)
$grpDetails.Controls.Add($chkWakeMagic)

$chkWakePattern = New-Object System.Windows.Forms.CheckBox
$chkWakePattern.Text = 'Enable Wake on Pattern'
$chkWakePattern.Location = New-Object System.Drawing.Point(10,175)
$chkWakePattern.Size = New-Object System.Drawing.Size(520,20)
$grpDetails.Controls.Add($chkWakePattern)

$btnApplyPowerMgmt = New-Object System.Windows.Forms.Button
$btnApplyPowerMgmt.Text = 'Apply Power Management'
$btnApplyPowerMgmt.Location = New-Object System.Drawing.Point(10,205)
$btnApplyPowerMgmt.Size = New-Object System.Drawing.Size(200,30)
$grpDetails.Controls.Add($btnApplyPowerMgmt)

# Advanced properties list and editor
$lblAdv = New-Object System.Windows.Forms.Label
$lblAdv.Text = 'Advanced Properties (driver-specific)'
$lblAdv.Location = New-Object System.Drawing.Point(10,240)
$lblAdv.Size = New-Object System.Drawing.Size(300,20)
$grpDetails.Controls.Add($lblAdv)

$lstAdv = New-Object System.Windows.Forms.ListView
$lstAdv.Location = New-Object System.Drawing.Point(10,265)
$lstAdv.Size = New-Object System.Drawing.Size(520,120)
$lstAdv.View = 'Details'
$lstAdv.FullRowSelect = $true
$lstAdv.Columns.Add('DisplayName',220) | Out-Null
$lstAdv.Columns.Add('DisplayValue',150) | Out-Null
$lstAdv.Columns.Add('RegistryKeyword',120) | Out-Null
$grpDetails.Controls.Add($lstAdv)

$lblAdvValue = New-Object System.Windows.Forms.Label
$lblAdvValue.Text = 'Set Value:'
$lblAdvValue.Location = New-Object System.Drawing.Point(10,392)
$lblAdvValue.Size = New-Object System.Drawing.Size(80,20)
$grpDetails.Controls.Add($lblAdvValue)

$txtAdvValue = New-Object System.Windows.Forms.TextBox
$txtAdvValue.Location = New-Object System.Drawing.Point(90,390)
$txtAdvValue.Size = New-Object System.Drawing.Size(210,22)
$grpDetails.Controls.Add($txtAdvValue)

$btnSetAdv = New-Object System.Windows.Forms.Button
$btnSetAdv.Text = 'Set Selected Property'
$btnSetAdv.Location = New-Object System.Drawing.Point(310,388)
$btnSetAdv.Size = New-Object System.Drawing.Size(220,26)
$grpDetails.Controls.Add($btnSetAdv)

# Powercfg device wake controls (enable/disable)
$lblPowercfg = New-Object System.Windows.Forms.Label
$lblPowercfg.Text = 'powercfg Device Wake Controls:'
$lblPowercfg.Location = New-Object System.Drawing.Point(10,420)
$lblPowercfg.Size = New-Object System.Drawing.Size(300,20)
$form.Controls.Add($lblPowercfg)

$btnEnableDeviceWake = New-Object System.Windows.Forms.Button
$btnEnableDeviceWake.Text = 'Enable Device Wake (powercfg)'
$btnEnableDeviceWake.Location = New-Object System.Drawing.Point(10,445)
$btnEnableDeviceWake.Size = New-Object System.Drawing.Size(200,30)
$form.Controls.Add($btnEnableDeviceWake)

$btnDisableDeviceWake = New-Object System.Windows.Forms.Button
$btnDisableDeviceWake.Text = 'Disable Device Wake (powercfg)'
$btnDisableDeviceWake.Location = New-Object System.Drawing.Point(220,445)
$btnDisableDeviceWake.Size = New-Object System.Drawing.Size(200,30)
$form.Controls.Add($btnDisableDeviceWake)

# Magic packet test section
$grpTest = New-Object System.Windows.Forms.GroupBox
$grpTest.Text = 'Test: Send Magic Packet'
$grpTest.Location = New-Object System.Drawing.Point(350,320)
$grpTest.Size = New-Object System.Drawing.Size(540,170)
$form.Controls.Add($grpTest)

$lblMac = New-Object System.Windows.Forms.Label
$lblMac.Text = 'Target MAC (e.g. 00:11:22:AA:BB:CC):'
$lblMac.Location = New-Object System.Drawing.Point(10,25)
$lblMac.Size = New-Object System.Drawing.Size(220,20)
$grpTest.Controls.Add($lblMac)

$txtMac = New-Object System.Windows.Forms.TextBox
$txtMac.Location = New-Object System.Drawing.Point(10,45)
$txtMac.Size = New-Object System.Drawing.Size(200,22)
$grpTest.Controls.Add($txtMac)

$lblBroadcast = New-Object System.Windows.Forms.Label
$lblBroadcast.Text = 'Broadcast IP (default 255.255.255.255):'
$lblBroadcast.Location = New-Object System.Drawing.Point(220,25)
$lblBroadcast.Size = New-Object System.Drawing.Size(260,20)
$grpTest.Controls.Add($lblBroadcast)

$txtBroadcast = New-Object System.Windows.Forms.TextBox
$txtBroadcast.Location = New-Object System.Drawing.Point(220,45)
$txtBroadcast.Size = New-Object System.Drawing.Size(140,22)
$grpTest.Controls.Add($txtBroadcast)

$lblPort = New-Object System.Windows.Forms.Label
$lblPort.Text = 'Port (7 or 9):'
$lblPort.Location = New-Object System.Drawing.Point(370,25)
$lblPort.Size = New-Object System.Drawing.Size(80,20)
$grpTest.Controls.Add($lblPort)

$txtPort = New-Object System.Windows.Forms.TextBox
$txtPort.Location = New-Object System.Drawing.Point(370,45)
$txtPort.Size = New-Object System.Drawing.Size(60,22)
$grpTest.Controls.Add($txtPort)

$btnSendMagic = New-Object System.Windows.Forms.Button
$btnSendMagic.Text = 'Send Magic Packet'
$btnSendMagic.Location = New-Object System.Drawing.Point(10,75)
$btnSendMagic.Size = New-Object System.Drawing.Size(150,30)
$grpTest.Controls.Add($btnSendMagic)

$lblTestResult = New-Object System.Windows.Forms.Label
$lblTestResult.Text = ''
$lblTestResult.Location = New-Object System.Drawing.Point(170,80)
$lblTestResult.Size = New-Object System.Drawing.Size(350,20)
$grpTest.Controls.Add($lblTestResult)

# Bottom: BIOS notes and help
$grpNotes = New-Object System.Windows.Forms.GroupBox
$grpNotes.Text = 'Notes & BIOS/UEFI steps (cannot change from OS)'
$grpNotes.Location = New-Object System.Drawing.Point(10,500)
$grpNotes.Size = New-Object System.Drawing.Size(880,100)
$form.Controls.Add($grpNotes)

$txtNotes = New-Object System.Windows.Forms.TextBox
$txtNotes.Multiline = $true
$txtNotes.ReadOnly = $true
$txtNotes.ScrollBars = 'Vertical'
$txtNotes.Location = New-Object System.Drawing.Point(10,20)
$txtNotes.Size = New-Object System.Drawing.Size(860,70)
$txtNotes.Text = "Important:
 - Enabling Wake-on-LAN often requires enabling the option in the BIOS/UEFI (look for 'Wake on LAN', 'Power on by PCI-E', or similar). The script cannot modify firmware settings.
 - Ensure adapter drivers support Wake-on-LAN and that the adapter stays powered in S3/S5 if desired.
 - Some systems disable WOL when Fast Startup (Windows) is enabled; consider disabling Fast Startup if WOL fails for power-off state.
 - Use the 'Advanced Properties' list to set driver-specific options (names differ by vendor)."
$grpNotes.Controls.Add($txtNotes)

# Global variables to hold adapter objects
$global:Adapters = @()
$global:CurrentAdapter = $null

function Load-Adapters {
    $lstAdapters.Items.Clear()
    $global:Adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -ne $null }
    foreach ($a in $global:Adapters) {
        $display = "{0} - {1}" -f $a.Name, $a.InterfaceDescription
        $lstAdapters.Items.Add($display) | Out-Null
    }
    if ($global:Adapters.Count -eq 0) { $lstAdapters.Items.Add('No physical adapters found or NetAdapter module missing') | Out-Null }
}

function Show-AdapterDetails {
    param($adapter)
    if (-not $adapter) { $txtDetails.Text = ''; return }
    $out = "Name: $($adapter.Name)`r`nDescription: $($adapter.InterfaceDescription)`r`nStatus: $($adapter.Status)`r`nMAC: $($adapter.MacAddress)`r`nLink Speed: $($adapter.LinkSpeed)"
    # Power management query
    try {
        $pm = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction Stop
        $out += "`r`nPowerManagement:`r`n  WakeOnMagicPacket: $($pm.WakeOnMagicPacket)  WakeOnPattern: $($pm.WakeOnPattern)  NoPowerSave: $($pm.NoPowerSave)"
        $chkWakeMagic.Checked = [bool]$pm.WakeOnMagicPacket
        $chkWakePattern.Checked = [bool]$pm.WakeOnPattern
    } catch {
        $out += "`r`nPowerManagement: (could not query - driver may not support Get-NetAdapterPowerManagement)"
        $chkWakeMagic.Checked = $false
        $chkWakePattern.Checked = $false
    }

    $txtDetails.Text = $out
}

function Load-AdvancedProperties {
    $lstAdv.Items.Clear()
    if (-not $global:CurrentAdapter) { return }
    try {
        $props = Get-NetAdapterAdvancedProperty -Name $global:CurrentAdapter.Name -ErrorAction Stop
        foreach ($p in $props) {
            $item = New-Object System.Windows.Forms.ListViewItem($p.DisplayName)
            $item.SubItems.Add([string]$p.DisplayValue)   # <-- fixed line
            $item.SubItems.Add($p.RegistryKeyword)
            $item.Tag = $p
            $lstAdv.Items.Add($item) | Out-Null
        }
    } catch {
        $item = New-Object System.Windows.Forms.ListViewItem('No advanced properties found or access denied')
        $lstAdv.Items.Add($item) | Out-Null
    }
}

# Event handlers
$btnRefresh.Add_Click({ Load-Adapters })
$btnRescanAdv.Add_Click({ Load-AdvancedProperties })

$lstAdapters.Add_SelectedIndexChanged({
    if ($lstAdapters.SelectedIndex -lt 0) { return }
    $global:CurrentAdapter = $global:Adapters[$lstAdapters.SelectedIndex]
    Show-AdapterDetails -adapter $global:CurrentAdapter
    Load-AdvancedProperties
})

$btnApplyPowerMgmt.Add_Click({
    if (-not $global:CurrentAdapter) { [System.Windows.Forms.MessageBox]::Show('Select an adapter first','Error') | Out-Null; return }
    try {
        Set-NetAdapterPowerManagement -Name $global:CurrentAdapter.Name -WakeOnMagicPacket:$chkWakeMagic.Checked -WakeOnPattern:$chkWakePattern.Checked -ErrorAction Stop
        [System.Windows.Forms.MessageBox]::Show('Power management settings applied.','Success') | Out-Null
        Show-AdapterDetails -adapter $global:CurrentAdapter
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to apply power management: $($_.Exception.Message)", 'Error') | Out-Null
    }
})

$btnSetAdv.Add_Click({
    if (-not $global:CurrentAdapter) { [System.Windows.Forms.MessageBox]::Show('Select an adapter first','Error') | Out-Null; return }
    if ($lstAdv.SelectedItems.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Select a property to change','Error') | Out-Null; return }
    $p = $lstAdv.SelectedItems[0].Tag
    $newVal = $txtAdvValue.Text.Trim()
    if ([string]::IsNullOrEmpty($newVal)) { [System.Windows.Forms.MessageBox]::Show('Enter a new value','Error') | Out-Null; return }
    try {
        Set-NetAdapterAdvancedProperty -Name $global:CurrentAdapter.Name -DisplayName $p.DisplayName -DisplayValue $newVal -ErrorAction Stop
        [System.Windows.Forms.MessageBox]::Show('Advanced property set.','Success') | Out-Null
        Load-AdvancedProperties
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to set advanced property: $($_.Exception.Message)", 'Error') | Out-Null
    }
})

$btnEnableDeviceWake.Add_Click({
    if (-not $global:CurrentAdapter) { [System.Windows.Forms.MessageBox]::Show('Select an adapter first','Error') | Out-Null; return }
    # Try to find corresponding PnPDevice name. Use Get-PnpDevice and match by InstanceId containing adapter name or description
    try {
        $devs = Get-PnpDevice -Class Net -Status OK | Where-Object { $_.FriendlyName -like "*$($global:CurrentAdapter.InterfaceDescription.Split(',')[0])*" -or $_.InstanceId -like "*$($global:CurrentAdapter.Name)*" }
        if ($devs.Count -gt 0) {
            foreach ($d in $devs) { powercfg -deviceenablewake $d.FriendlyName | Out-Null }
            [System.Windows.Forms.MessageBox]::Show('Enabled wake for matching PnP device(s).','Success') | Out-Null
        } else {
            # fallback: try with InterfaceDescription
            powercfg -deviceenablewake "$($global:CurrentAdapter.InterfaceDescription)" | Out-Null
            [System.Windows.Forms.MessageBox]::Show('Enabled wake for adapter (fallback try).','Success') | Out-Null
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to enable device wake: $($_.Exception.Message)", 'Error') | Out-Null
    }
})

$btnDisableDeviceWake.Add_Click({
    if (-not $global:CurrentAdapter) { [System.Windows.Forms.MessageBox]::Show('Select an adapter first','Error') | Out-Null; return }
    try {
        $devs = Get-PnpDevice -Class Net -Status OK | Where-Object { $_.FriendlyName -like "*$($global:CurrentAdapter.InterfaceDescription.Split(',')[0])*" -or $_.InstanceId -like "*$($global:CurrentAdapter.Name)*" }
        if ($devs.Count -gt 0) {
            foreach ($d in $devs) { powercfg -devicedisablewake $d.FriendlyName | Out-Null }
            [System.Windows.Forms.MessageBox]::Show('Disabled wake for matching PnP device(s).','Success') | Out-Null
        } else {
            powercfg -devicedisablewake "$($global:CurrentAdapter.InterfaceDescription)" | Out-Null
            [System.Windows.Forms.MessageBox]::Show('Disabled wake for adapter (fallback try).','Success') | Out-Null
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to disable device wake: $($_.Exception.Message)", 'Error') | Out-Null
    }
})

$btnSendMagic.Add_Click({
    $mac = $txtMac.Text.Trim()
    if ([string]::IsNullOrEmpty($mac)) { [System.Windows.Forms.MessageBox]::Show('Enter a MAC address first','Error') | Out-Null; return }
    $bcast = $txtBroadcast.Text.Trim()
    if ([string]::IsNullOrEmpty($bcast)) { $bcast = '255.255.255.255' }
    $port = 9
    if (-not [string]::IsNullOrEmpty($txtPort.Text.Trim())) { [int]::TryParse($txtPort.Text.Trim(), [ref]$port) | Out-Null }
    try {
        $sent = Send-MagicPacket -Mac $mac -Broadcast $bcast -Port $port
        $lblTestResult.Text = "Sent $sent bytes to ${bcast}:${port} (MAC $mac)"
    } catch {
        $lblTestResult.Text = "Error sending packet: $($_.Exception.Message)"
    }
})

# Auto-load on start
Load-Adapters

# Show form
[void]$form.ShowDialog()
