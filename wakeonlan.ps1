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
$form.Size = New-Object System.Drawing.Size(1100,800)   # increased overall form size
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI',9)
$form.AutoScaleMode = 'Font'

# Left: Adapter list
$lblAdapters = New-Object System.Windows.Forms.Label
$lblAdapters.Text = 'Network Adapters:'
$lblAdapters.Location = New-Object System.Drawing.Point(10,10)
$lblAdapters.Size = New-Object System.Drawing.Size(220,20)
$lblAdapters.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$form.Controls.Add($lblAdapters)

$lstAdapters = New-Object System.Windows.Forms.ListBox
$lstAdapters.Location = New-Object System.Drawing.Point(10,35)
$lstAdapters.Size = New-Object System.Drawing.Size(340,320)    # taller to show more items
$lstAdapters.ScrollAlwaysVisible = $true
# Anchor so it expands vertically with the form
$lstAdapters.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Bottom
$form.Controls.Add($lstAdapters)

# Buttons to refresh and show details
$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = 'Refresh Adapters'
$btnRefresh.Location = New-Object System.Drawing.Point(10,365)
$btnRefresh.Size = New-Object System.Drawing.Size(160,32)
$btnRefresh.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Top
$form.Controls.Add($btnRefresh)

$btnRescanAdv = New-Object System.Windows.Forms.Button
$btnRescanAdv.Text = 'Load Advanced Props'
$btnRescanAdv.Location = New-Object System.Drawing.Point(180,365)
$btnRescanAdv.Size = New-Object System.Drawing.Size(170,32)
$btnRescanAdv.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Top
$form.Controls.Add($btnRescanAdv)

# Right: details group (expanded)
$grpDetails = New-Object System.Windows.Forms.GroupBox
$grpDetails.Text = 'Adapter Details & Controls'
$grpDetails.Location = New-Object System.Drawing.Point(360,10)
$grpDetails.Size = New-Object System.Drawing.Size(720,360)   # wider & taller
$grpDetails.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$form.Controls.Add($grpDetails)

$txtDetails = New-Object System.Windows.Forms.TextBox
$txtDetails.Multiline = $true
$txtDetails.ScrollBars = 'Vertical'
$txtDetails.Location = New-Object System.Drawing.Point(10,20)
$txtDetails.Size = New-Object System.Drawing.Size(700,120)  # wider details area
$txtDetails.ReadOnly = $true
$txtDetails.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$grpDetails.Controls.Add($txtDetails)

# Power management checkboxes
$chkWakeMagic = New-Object System.Windows.Forms.CheckBox
$chkWakeMagic.Text = 'Enable Wake on Magic Packet (Set-NetAdapterPowerManagement)'
$chkWakeMagic.Location = New-Object System.Drawing.Point(10,150)
$chkWakeMagic.Size = New-Object System.Drawing.Size(700,22)
$chkWakeMagic.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$grpDetails.Controls.Add($chkWakeMagic)

$chkWakePattern = New-Object System.Windows.Forms.CheckBox
$chkWakePattern.Text = 'Enable Wake on Pattern'
$chkWakePattern.Location = New-Object System.Drawing.Point(10,175)
$chkWakePattern.Size = New-Object System.Drawing.Size(700,22)
$chkWakePattern.Anchor = $chkWakeMagic.Anchor
$grpDetails.Controls.Add($chkWakePattern)

$btnApplyPowerMgmt = New-Object System.Windows.Forms.Button
$btnApplyPowerMgmt.Text = 'Apply Power Management'
$btnApplyPowerMgmt.Location = New-Object System.Drawing.Point(10,205)
$btnApplyPowerMgmt.Size = New-Object System.Drawing.Size(220,34)
$btnApplyPowerMgmt.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpDetails.Controls.Add($btnApplyPowerMgmt)

# Advanced properties list and editor
$lblAdv = New-Object System.Windows.Forms.Label
$lblAdv.Text = 'Advanced Properties (driver-specific)'
$lblAdv.Location = New-Object System.Drawing.Point(10,245)
$lblAdv.Size = New-Object System.Drawing.Size(350,20)
$lblAdv.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpDetails.Controls.Add($lblAdv)

$lstAdv = New-Object System.Windows.Forms.ListView
$lstAdv.Location = New-Object System.Drawing.Point(10,270)
$lstAdv.Size = New-Object System.Drawing.Size(700,100)   # larger to show more rows
$lstAdv.View = 'Details'
$lstAdv.FullRowSelect = $true
$lstAdv.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
# wider columns to avoid clipping
$lstAdv.Columns.Add('DisplayName',320) | Out-Null
$lstAdv.Columns.Add('DisplayValue',220) | Out-Null
$lstAdv.Columns.Add('RegistryKeyword',160) | Out-Null
$grpDetails.Controls.Add($lstAdv)

$lblAdvValue = New-Object System.Windows.Forms.Label
$lblAdvValue.Text = 'Set Value:'
$lblAdvValue.Location = New-Object System.Drawing.Point(10,380)
$lblAdvValue.Size = New-Object System.Drawing.Size(80,20)
$lblAdvValue.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpDetails.Controls.Add($lblAdvValue)

$txtAdvValue = New-Object System.Windows.Forms.TextBox
$txtAdvValue.Location = New-Object System.Drawing.Point(90,378)
$txtAdvValue.Size = New-Object System.Drawing.Size(260,24)
$txtAdvValue.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$grpDetails.Controls.Add($txtAdvValue)

$btnSetAdv = New-Object System.Windows.Forms.Button
$btnSetAdv.Text = 'Set Selected Property'
$btnSetAdv.Location = New-Object System.Drawing.Point(360,376)
$btnSetAdv.Size = New-Object System.Drawing.Size(220,28)
$btnSetAdv.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$grpDetails.Controls.Add($btnSetAdv)

# Powercfg device wake controls (enable/disable)
$lblPowercfg = New-Object System.Windows.Forms.Label
$lblPowercfg.Text = 'powercfg Device Wake Controls:'
$lblPowercfg.Location = New-Object System.Drawing.Point(10,420)
$lblPowercfg.Size = New-Object System.Drawing.Size(300,20)
$lblPowercfg.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Bottom
$form.Controls.Add($lblPowercfg)

$btnEnableDeviceWake = New-Object System.Windows.Forms.Button
$btnEnableDeviceWake.Text = 'Enable Device Wake (powercfg)'
$btnEnableDeviceWake.Location = New-Object System.Drawing.Point(10,450)
$btnEnableDeviceWake.Size = New-Object System.Drawing.Size(240,34)
$btnEnableDeviceWake.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Bottom
$form.Controls.Add($btnEnableDeviceWake)

$btnDisableDeviceWake = New-Object System.Windows.Forms.Button
$btnDisableDeviceWake.Text = 'Disable Device Wake (powercfg)'
$btnDisableDeviceWake.Location = New-Object System.Drawing.Point(10,490)
$btnDisableDeviceWake.Size = New-Object System.Drawing.Size(240,34)
$btnDisableDeviceWake.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Bottom
$form.Controls.Add($btnDisableDeviceWake)

# Magic packet test section (moved and enlarged)
$grpTest = New-Object System.Windows.Forms.GroupBox
$grpTest.Text = 'Test: Send Magic Packet'
$grpTest.Location = New-Object System.Drawing.Point(360,380)
$grpTest.Size = New-Object System.Drawing.Size(720,200)   # moved below details group
$grpTest.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
$form.Controls.Add($grpTest)

$lblMac = New-Object System.Windows.Forms.Label
$lblMac.Text = 'Target MAC:'
$lblMac.Location = New-Object System.Drawing.Point(10,25)
$lblMac.Size = New-Object System.Drawing.Size(200,20)
$lblMac.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpTest.Controls.Add($lblMac)

$txtMac = New-Object System.Windows.Forms.TextBox
$txtMac.Location = New-Object System.Drawing.Point(10,45)
$txtMac.Size = New-Object System.Drawing.Size(260,24)
$txtMac.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$grpTest.Controls.Add($txtMac)

$lblBroadcast = New-Object System.Windows.Forms.Label
$lblBroadcast.Text = 'Broadcast IP:'
$lblBroadcast.Location = New-Object System.Drawing.Point(290,25)
$lblBroadcast.Size = New-Object System.Drawing.Size(150,20)
$lblBroadcast.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpTest.Controls.Add($lblBroadcast)

$txtBroadcast = New-Object System.Windows.Forms.TextBox
$txtBroadcast.Location = New-Object System.Drawing.Point(290,45)
$txtBroadcast.Size = New-Object System.Drawing.Size(180,24)
$txtBroadcast.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpTest.Controls.Add($txtBroadcast)

$lblPort = New-Object System.Windows.Forms.Label
$lblPort.Text = 'Port (7 or 9):'
$lblPort.Location = New-Object System.Drawing.Point(480,25)
$lblPort.Size = New-Object System.Drawing.Size(80,20)
$lblPort.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpTest.Controls.Add($lblPort)

$txtPort = New-Object System.Windows.Forms.TextBox
$txtPort.Location = New-Object System.Drawing.Point(480,45)
$txtPort.Size = New-Object System.Drawing.Size(80,24)
$txtPort.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpTest.Controls.Add($txtPort)

$btnSendMagic = New-Object System.Windows.Forms.Button
$btnSendMagic.Text = 'Send Magic Packet'
$btnSendMagic.Location = New-Object System.Drawing.Point(10,80)
$btnSendMagic.Size = New-Object System.Drawing.Size(160,34)
$btnSendMagic.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$grpTest.Controls.Add($btnSendMagic)

$lblTestResult = New-Object System.Windows.Forms.Label
$lblTestResult.Text = ''
$lblTestResult.Location = New-Object System.Drawing.Point(180,88)
$lblTestResult.Size = New-Object System.Drawing.Size(520,20)   # larger so messages don't wrap awkwardly
$lblTestResult.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$grpTest.Controls.Add($lblTestResult)

# Bottom: BIOS notes and help (wider and taller)
$grpNotes = New-Object System.Windows.Forms.GroupBox
$grpNotes.Text = 'Notes & BIOS/UEFI steps (cannot change from OS)'
$grpNotes.Location = New-Object System.Drawing.Point(10,600)
$grpNotes.Size = New-Object System.Drawing.Size(1070,170)
$grpNotes.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
$form.Controls.Add($grpNotes)

$txtNotes = New-Object System.Windows.Forms.TextBox
$txtNotes.Multiline = $true
$txtNotes.ReadOnly = $true
$txtNotes.ScrollBars = 'Vertical'
$txtNotes.Location = New-Object System.Drawing.Point(10,20)
$txtNotes.Size = New-Object System.Drawing.Size(1048,140)
$txtNotes.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
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

    # Map checkbox booleans to the string values expected by Set-NetAdapterPowerManagement
    $wakeMagicVal = if ($chkWakeMagic.Checked) { 'Enabled' } else { 'Disabled' }
    $wakePatternVal = if ($chkWakePattern.Checked) { 'Enabled' } else { 'Disabled' }

    try {
        Set-NetAdapterPowerManagement -Name $global:CurrentAdapter.Name -WakeOnMagicPacket $wakeMagicVal -WakeOnPattern $wakePatternVal -ErrorAction Stop
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
