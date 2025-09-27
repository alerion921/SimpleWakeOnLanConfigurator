# Advanced Wake-on-LAN Configurator v2.0

A comprehensive PowerShell GUI application for configuring, testing, and managing Wake-on-LAN functionality across network adapters with advanced features and professional interface.

## 🚀 Features

### Core Functionality
- **Complete WoL Configuration**: Configure all aspects of Wake-on-LAN on network adapters
- **Advanced Power Management**: Full control over adapter power settings and WoL properties  
- **Magic Packet Testing**: Send and test magic packets with multiple broadcast options
- **Device Discovery**: Automatically discover devices on your network for easy WoL setup

### Modern Interface
- **Tabbed Interface**: Organized tabs for Adapters, Profiles, Discovery, Testing, and Settings
- **Professional Design**: Modern Windows Forms UI with proper anchoring and scaling
- **Comprehensive Menus**: Full menu system with File, Tools, and Help options
- **Responsive Layout**: Resizable interface that adapts to different screen sizes

### Profile Management
- **Save WoL Profiles**: Create and manage profiles for commonly used devices
- **Import/Export**: Backup and restore your WoL profiles
- **Usage Tracking**: Track when and how often profiles are used
- **Group Organization**: Organize profiles by groups/categories

### Diagnostics & Troubleshooting
- **System Diagnostics**: Comprehensive analysis of WoL support and configuration
- **Built-in Help**: Complete troubleshooting guide covering hardware, BIOS, and network issues
- **Activity Logging**: Debug logging for troubleshooting problems
- **Export Reports**: Save diagnostic reports for support or reference

### Network Discovery
- **ARP Table Scanning**: Discover active devices using ARP table entries
- **Hostname Resolution**: Attempt to resolve device hostnames
- **Multi-Adapter Support**: Discover devices across multiple network interfaces
- **Add to Profiles**: Easy conversion of discovered devices to WoL profiles

## 📋 Requirements

- **Windows**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Windows PowerShell 5.1 or later
- **Privileges**: Administrator rights (required for network adapter configuration)
- **Network**: Physical Ethernet adapters with WoL support

## 🛠️ Installation & Usage

1. **Download**: Clone or download the repository
2. **Run as Administrator**: Right-click `wakeonlan.ps1` → "Run with PowerShell" (as Administrator)
3. **Allow Execution**: If prompted about execution policy, choose to allow the script

### First Time Setup
1. The application will automatically request Administrator privileges
2. Navigate to the **Adapters** tab to see your network adapters
3. Select an adapter and configure Wake-on-LAN settings
4. Test WoL support using the built-in diagnostics

### Creating WoL Profiles
1. Go to the **Profiles** tab
2. Click "Add Profile" to create a new device profile
3. Enter device name, MAC address, and network settings
4. Use "Wake Device" to send magic packets to saved profiles

### Network Discovery
1. Open the **Discovery** tab  
2. Click "Scan Network" to find devices on your network
3. Select discovered devices and add them to your profiles
4. Wake devices directly from the discovery list

## 📖 Configuration Guide

### BIOS/UEFI Settings (Critical)
Wake-on-LAN requires proper BIOS configuration:

- Enable "Wake on LAN" or "Power on by PCI-E"
- Enable "PME (Power Management Event)"  
- Disable "Deep Sleep" or "ErP Ready" modes
- Set "AC Power Recovery" (some systems)

### Windows Configuration  
- Ensure network adapter drivers are current
- Configure power management through the application
- Consider disabling "Fast Startup" for shutdown WoL
- Verify Windows Firewall allows WoL traffic

### Network Requirements
- Use appropriate broadcast address for your network
- Standard WoL ports are 7 and 9 (try both)
- Ensure switches/routers forward broadcast packets
- For remote WoL, configure router port forwarding

## 🔧 Advanced Features

### Magic Packet Testing
- **Multiple Packets**: Send multiple magic packets with configurable delays
- **Custom Broadcast**: Use subnet-specific broadcast addresses  
- **Port Options**: Test different UDP ports (7, 9, custom)
- **Validation**: MAC address format validation and correction

### Power Management
- **Driver Integration**: Direct integration with Windows network adapter drivers
- **Advanced Properties**: Access to vendor-specific WoL settings
- **Powercfg Integration**: Automatic device wake enablement
- **Support Analysis**: Comprehensive analysis of WoL compatibility

### Diagnostics
- **System Analysis**: Complete analysis of hardware and software WoL support
- **Configuration Validation**: Verify all settings are properly configured  
- **Power State Testing**: Test WoL from different power states
- **Network Validation**: Verify network configuration for WoL

## 🚨 Troubleshooting

### Common Issues

**WoL works from sleep but not shutdown:**
- Enable "Wake from S5" in BIOS
- Verify power supply supports network adapter power in S5

**Magic packets sent but device doesn't wake:**
- Check BIOS WoL settings
- Verify network adapter receives power when system is off
- Update network adapter drivers

**Inconsistent WoL behavior:**
- Disable Windows Fast Startup
- Update network drivers  
- Check for power management conflicts

### Getting Help
1. Use the built-in **Troubleshooting Guide** (Help menu)
2. Run **System Diagnostics** (Testing tab) 
3. Check the **Log Viewer** (Tools menu) for detailed error information
4. Export diagnostic reports for support

## 📝 Configuration Files

The application stores configuration in:
- **Profiles**: `%USERPROFILE%\Documents\WoLConfig.json`
- **Debug Logs**: `%TEMP%\WoL_Debug.log` (when debug mode enabled)

Configuration includes:
- Saved WoL profiles with usage statistics
- Application settings and preferences
- Default values for ports and broadcast addresses

## 🔐 Security Considerations

- **Unencrypted Packets**: Standard WoL magic packets are unencrypted
- **Network Security**: Limit WoL to trusted networks only  
- **SecureOn**: Use password-protected WoL if supported by hardware
- **Corporate Networks**: Some networks block broadcast traffic required for WoL

## 📄 Version History

### v2.0.0 (Current)
- Complete application rewrite with modern tabbed interface
- Added comprehensive device discovery and profile management
- Enhanced diagnostics and troubleshooting tools
- Improved power management configuration
- Added configuration import/export functionality
- Built-in help system and troubleshooting guide

### v1.0.0 (Original)
- Basic Wake-on-LAN configuration
- Simple magic packet sending
- Basic adapter power management

## 📃 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

**Note**: This tool requires Administrator privileges to modify network adapter settings. Always ensure you understand the implications of Wake-on-LAN configuration in your environment.
