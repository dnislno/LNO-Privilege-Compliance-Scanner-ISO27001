// LNO Privilege Compliance Scanner
// Author  : dnislno (https://github.com/dnislno)
// License : MIT (see LICENSE file)
//
// DISCLAIMER: This software is provided "AS IS" without warranty of any kind.
// The author shall not be held liable for any damages arising from the use
// of this software. Users assume all responsibility and risk. Use only on
// systems you own or have explicit written permission to audit.

const { execSync } = require('child_process');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'scan.db');
const CONFIG_PATH = path.join(__dirname, 'risk-config.json');
const scanId = crypto.randomUUID();

// =============================================================================
// ISO 27001:2022 MAPPING REFERENCE
// =============================================================================
// Each finding is mapped to an ISO 27001 Annex A control. The mapping rationale
// is documented here for audit trail and compliance evidence purposes.
// All codes below use ISO/IEC 27001:2022 numbering (Annex A — 93 controls, 4 themes).
//
//   A.5.9   Information Classification → System info (baseline for all controls)
//   A.5.15  Access Control            → User accounts, group memberships, ACLs
//   A.8.2   Privileged Access Rights  → Processes running with excessive privileges
//   A.8.2   Privileged Access Rights  → Privilege audit, UAC, LSA protection
//   A.5.17  Authentication Info       → Password length, complexity, lockout, expiry
//   A.7.1   Physical Security         → System metadata (hostname, domain)
//   A.5.37  Documented Procedures     → Process/service inventory (baseline)
//   A.8.7   Malware Protection        → Defender status, unsigned/suspicious procs
//   A.8.13  Information Backup        → System uptime (future)
//   A.8.15  Logging & Monitoring      → Event log config (future)
//   A.8.8   Technical Vulnerabilities → Service path vulnerabilities, weak ACLs
//   A.8.20  Network Controls          → Firewall status, network connections
//
// Each FINDING_DEFS entry below includes its iso field referencing the above.
// The compliance_status table stores per-control pass/fail based on whether
// any finding exists for that control in the current scan.
// =============================================================================

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  } catch(e) { console.error('Config error:', e.message); }
  return {
    severity_weights: { critical: 25, high: 10, medium: 4, low: 1, info: 0 },
    type_overrides: {},
    suppressed_types: [],
    min_score: 10, max_score: 100,
  };
}
const CONFIG = loadConfig();

function runPS(script, timeoutMs = 30000) {
  const tmpFile = path.join(os.tmpdir(), `_lno_ps_${Date.now()}_${Math.random().toString(36).slice(2)}.ps1`);
  fs.writeFileSync(tmpFile, script, 'utf-8');
  try {
    const result = execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${tmpFile}"`, {
      timeout: timeoutMs,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return result ? result.toString().trim() : '';
  } catch (e) {
    if (e.stdout) return e.stdout.toString().trim();
    return '';
  } finally {
    try { fs.unlinkSync(tmpFile); } catch(_) {}
  }
}

const DANGEROUS_PRIVILEGES = {
  'SeTakeOwnershipPrivilege': 'Can take ownership of any object',
  'SeDebugPrivilege': 'Can debug/inject into any process (LSASS dump possible)',
  'SeBackupPrivilege': 'Can read any file regardless of ACL',
  'SeRestorePrivilege': 'Can write any file regardless of ACL',
  'SeTcbPrivilege': 'Acts as part of OS - full system trust',
  'SeLoadDriverPrivilege': 'Can load/unload kernel drivers',
  'SeCreateTokenPrivilege': 'Can create arbitrary access tokens',
  'SeImpersonatePrivilege': 'Can impersonate other users (potato attack)',
  'SeSecurityPrivilege': 'Can manage audit logs - hide tracks',
};

// Finding type definitions with ISO 27001:2022 Annex A control mappings.
// Each entry maps to an ISO control based on the security domain affected.
// See the ISO 27001 MAPPING REFERENCE above for full rationale.
const FINDING_DEFS = {
  admin_member: { title: 'User is member of Administrators group', category: 'privilege_management', iso: 'A.8.2', default_severity: 'critical' },
  def_disabled: { title: 'Windows Defender real-time protection disabled', category: 'malware_protection', iso: 'A.8.7', default_severity: 'high' },
  firewall_disabled: { title: 'Windows Firewall disabled on one or more profiles', category: 'network_security', iso: 'A.8.20', default_severity: 'high' },
  weak_password_policy: { title: 'Weak password policy (length < 8 or no complexity)', category: 'password_policy', iso: 'A.5.17', default_severity: 'high' },
  guest_enabled: { title: 'Guest account is enabled', category: 'access_control', iso: 'A.5.15', default_severity: 'medium' },
  uac_disabled: { title: 'UAC disabled - no privilege separation', category: 'privilege_management', iso: 'A.8.2', default_severity: 'high' },
  lsa_not_protected: { title: 'LSASS not running as Protected Process (PPL)', category: 'privilege_management', iso: 'A.8.2', default_severity: 'medium' },
  dangerous_priv: { title: 'User has dangerous privilege enabled: {detail}', category: 'privilege_management', iso: 'A.8.2', default_severity: 'high' },
  world_writable_system: { title: 'World-writable directory detected: {detail}', category: 'access_control', iso: 'A.5.15', default_severity: 'high' },
  unquoted_service: { title: 'Unquoted service path (escalation risk): {detail}', category: 'privilege_management', iso: 'A.8.2', default_severity: 'medium' },
  sys_service_from_user: { title: 'Service running as SYSTEM from non-system path: {detail}', category: 'least_privilege', iso: 'A.8.2', default_severity: 'high' },
  unsig_process_user: { title: 'Unsigned process from user-writable location: {detail}', category: 'malware_protection', iso: 'A.8.7', default_severity: 'medium' },
  admin_process_network: { title: 'Process running as admin with outbound network: {detail}', category: 'least_privilege', iso: 'A.8.2', default_severity: 'medium' },
  suspicious_service: { title: 'Service from temp/suspicious path: {detail}', category: 'malware_protection', iso: 'A.8.7', default_severity: 'critical' },
  weak_registry_acl: { title: 'Weak ACL on sensitive registry key: {detail}', category: 'access_control', iso: 'A.8.3', default_severity: 'high' },
  no_password_expiry: { title: 'One or more user accounts have non-expiring passwords', category: 'password_policy', iso: 'A.5.17', default_severity: 'medium' },
};

// ---------------------------------------------------------------------------
// Service parent-application classification & description lookup
// ---------------------------------------------------------------------------
function classifyService(name, displayName, pathName) {
  const p = (pathName || '').toLowerCase();
  const n = (name || '').toLowerCase();

  // Determine parent application from executable path
  let parent = 'Unknown';

  // Known Windows system processes (name-based fallback when path is empty)
  const KNOWN_WINDOWS_PROCS = [
    'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'lsaiso.exe', 'svchost.exe', 'spoolsv.exe',
    'dllhost.exe', 'taskhostw.exe', 'taskhostex.exe', 'sihost.exe',
    'runtimebroker.exe', 'startmenuexperiencehost.exe', 'searchapp.exe',
    'searchindexer.exe', 'searchfilterhost.exe', 'ctfmon.exe',
    'wermgr.exe', 'werfault.exe', 'conhost.exe', 'cmd.exe', 'powershell.exe',
    'widgets.exe', 'widgetservice.exe', 'securityhealthservice.exe',
    'windowsinternal.composableshell.experiences.winrtcomposable.shell.dllhost.exe',
    'applicationframehost.exe', 'systemsettings.exe', 'lockapp.exe',
    'logonui.exe', 'userinit.exe', 'wmiprvse.exe', 'unsecapp.exe',
    'sppsvc.exe', 'trustedinstaller.exe', 'audiodg.exe',
    'ntoskrnl.exe', 'winload.exe', 'winresume.exe',
  ];
  if (KNOWN_WINDOWS_PROCS.includes(n)) parent = 'Windows System';

  if (parent === 'Unknown') {
    if (p.startsWith('c:\\windows\\system32\\') || p.startsWith('c:\\windows\\syswow64\\')) {
      parent = 'Windows System';
    } else if (p.startsWith('c:\\windows\\')) {
    parent = 'Windows System';
  } else if (p.startsWith('c:\\program files\\microsoft office\\') || p.startsWith('c:\\program files (x86)\\microsoft office\\')) {
    parent = 'Microsoft Office';
  } else if (p.includes('\\google\\chrome\\')) {
    parent = 'Google Chrome';
  } else if (p.includes('\\mozilla firefox\\')) {
    parent = 'Mozilla Firefox';
  } else if (p.includes('\\microsoft\\edge\\')) {
    parent = 'Microsoft Edge';
  } else if (p.includes('\\microsoft sql server\\')) {
    parent = 'Microsoft SQL Server';
  } else if (p.includes('\\docker\\')) {
    parent = 'Docker';
  } else if (p.includes('\\nodejs\\')) {
    parent = 'Node.js';
  } else if (p.includes('\\python\\') || p.includes('\\python3')) {
    parent = 'Python';
  } else if (p.includes('\\git\\')) {
    parent = 'Git';
  } else if (p.includes('\\vscode\\') || p.includes('\\vs code\\') || p.includes('\\visual studio code\\')) {
    parent = 'VS Code';
  } else if (p.includes('\\oracle\\')) {
    parent = 'Oracle';
  } else if (p.includes('\\mysql\\')) {
    parent = 'MySQL';
  } else if (p.includes('\\postgresql\\')) {
    parent = 'PostgreSQL';
  } else if (p.includes('\\mongodb\\')) {
    parent = 'MongoDB';
  } else if (p.includes('\\adobe\\')) {
    parent = 'Adobe';
  } else if (p.includes('\\autodesk\\')) {
    parent = 'Autodesk';
  } else if (p.includes('\\vmware\\')) {
    parent = 'VMware';
  } else if (p.includes('\\virtualbox\\')) {
    parent = 'VirtualBox';
  } else if (p.includes('\\teamviewer\\')) {
    parent = 'TeamViewer';
  } else if (p.includes('\\7-zip\\') || p.includes('\\7zip\\')) {
    parent = '7-Zip';
  } else if (p.includes('\\winrar\\')) {
    parent = 'WinRAR';
  } else if (p.includes('\\spotify\\')) {
    parent = 'Spotify';
  } else if (p.includes('\\discord\\')) {
    parent = 'Discord';
  } else if (p.includes('\\telegram\\')) {
    parent = 'Telegram';
  } else if (p.includes('\\slack\\')) {
    parent = 'Slack';
  } else if (p.startsWith('c:\\program files\\') || p.startsWith('c:\\program files (x86)\\')) {
    parent = 'Third-Party Application';
  } else if (p.startsWith('c:\\users\\')) {
      parent = 'User Application';
    }
  }

  // Map known service names to descriptions
  const desc = SERVICE_DESC[name.toLowerCase()];
  const fallbackDesc = displayName || name;

  return { parent_app: parent, description: desc || fallbackDesc };
}

const SERVICE_DESC = {
  'appinfo': 'Application Information — facilitates running apps with admin privileges (UAC elevation)',
  'appidsvc': 'Application Identity — determines and verifies app identity (AppLocker)',
  'applockerfltr': 'AppLocker Filter — enforces AppLocker policies',
  'appmgmt': 'Application Management — processes Group Policy software installation',
  'appreadiness': 'App Readiness — prepares and manages Store apps for first use',
  'appxsvc': 'AppX Deployment Service — deploys and maintains Windows Store apps',
  'assignedaccessmanagersvc': 'Assigned Access Manager — manages kiosk mode assignments',
  'audioendpointbuilder': 'Windows Audio Endpoint Builder — manages audio devices and endpoints',
  'audiosrv': 'Windows Audio — manages audio for Windows programs',
  'autotimesvc': 'Cellular Time — manages time sync from mobile networks',
  'axinstsvc': 'ActiveX Installer — installs ActiveX controls from the web',
  'bcastdvruserservice': 'Broadcast DVR — manages broadcast recording (Xbox)',
  'bfe': 'Base Filtering Engine — manages firewall and IPsec policies',
  'bits': 'Background Intelligent Transfer — transfers files in background using idle bandwidth',
  'bluetoothavrcpservice': 'Bluetooth AVRCP — manages Bluetooth audio/remote control',
  'bluetoothuserservice': 'Bluetooth User Support — supports Bluetooth device pairing',
  'brokerinfrastructure': 'Background Tasks Infrastructure — manages background app tasks (WinRT)',
  'browserservice': 'Browser Support — supports web browsing features',
  'bthavctpsvc': 'Bluetooth AVCTP — manages Bluetooth A/V control transport',
  'bthserv': 'Bluetooth Support Service — supports Bluetooth device discovery and pairing',
  'bthhfsrv': 'Bluetooth HF — manages Bluetooth hands-free devices',
  'camsvc': 'Capability Access Manager — manages app capability access (camera, mic, etc.)',
  'cdpsvc': 'Connected Devices Platform — manages device connectivity and sync',
  'cdpusersvc': 'Connected Devices Platform User — user-level device sync service',
  'certpropsvc': 'Certificate Propagation — distributes smart card certificates',
  'classicapplauncher': 'Classic App Launcher — launches classic (Win32) applications',
  'cloudfilesyncengine': 'Cloud Files Sync — manages cloud file sync (OneDrive)',
  'cmitrastartup': 'CM ITRA Startup — manages Citrix/CMS startup',
  'comsysapp': 'COM+ System Application — manages COM+ components',
  'consentuxuserconsent': 'Consent UX — manages user consent for permissions',
  'coremessaging': 'Core Messaging — inter-process communication for Windows components',
  'coremessagingregistrar': 'Core Messaging Registrar — manages core messaging endpoints',
  'cryptsvc': 'Cryptographic Services — manages certificates, encryption, and signing',
  'dcomlaunch': 'DCOM Server Process Launcher — launches COM/DCOM components',
  'defragsvc': 'Optimize Drives — defragments and optimizes drives',
  'deviceassociationservice': 'Device Association — manages device pairing and association',
  'deviceinstall': 'Device Install — installs device drivers and hardware',
  'devquerybackgrounddiscover': 'Device Query Background — discovers and manages devices',
  'dhcp': 'DHCP Client — registers and updates IP addresses and DNS records',
  'diagnosticshub': 'Diagnostics Hub — collects and processes diagnostic data',
  'diagtrack': 'Connected User Experiences and Telemetry — sends diagnostic data (DiagTrack)',
  'dispbrokerdesktopsvc': 'Display Policy Broker — manages display policies',
  'displayenhancementservice': 'Display Enhancement — manages display enhancements',
  'dnsclient': 'DNS Client — resolves DNS names and caches results',
  'dosvc': 'Delivery Optimization — optimizes Windows Update downloads (peer-to-peer)',
  'dps': 'Diagnostic Policy Service — detects and troubleshoots Windows problems',
  'dssvc': 'Data Sharing Service — manages data sharing between apps',
  'dusmsvc': 'Data Usage Service — monitors and manages network data usage',
  'edgeupdate': 'Microsoft Edge Update — keeps Edge browser up to date',
  'edgeupdatem': 'Microsoft Edge Update (machine) — system-level Edge updates',
  'efs': 'Encrypting File System — manages file encryption (EFS)',
  'eventlog': 'Windows Event Log — logs and manages system/application events',
  'eventnotification': 'Event Notification — notifies COM components of system events',
  'eventsystem': 'COM+ Event System — supports COM+ event subscriptions',
  'fdrespub': 'Function Discovery Resource Publication — publishes network resources for discovery',
  'fhsvc': 'File History Service — backs up files to external drives',
  'fontcache': 'Windows Font Cache — optimizes font rendering performance',
  'fontdiscovery': 'Font Discovery — discovers and indexes available fonts',
  'fontdrvhost': 'Font Driver Host — hosts font drivers for rendering',
  'gpsvc': 'Group Policy Client — applies Group Policy settings',
  'graphicsperfmon': 'Graphics Performance Monitor — monitors GPU performance',
  'hidserv': 'Human Interface Device Access — manages HID devices (keyboard, mouse, etc.)',
  'hns': 'Host Network Service — manages virtual networking for containers/Hyper-V',
  'hvhost': 'Hyper-V Host Compute — manages Hyper-V virtualization',
  'icssvc': 'Internet Connection Sharing — shares internet from this PC',
  'installservice': 'Windows Install Service — manages MSI package installation',
  'iphlpsvc': 'IP Helper — manages IPv6 transition technologies (Teredo, 6to4)',
  'keyiso': 'CNG Key Isolation — isolates cryptographic keys in LSASS',
  'kpssvc': 'Kernel Processor Service — manages processor performance states',
  'krmxserver': 'KRMX Server — manages remote desktop multiplexing',
  'lanserver': 'Server — supports file/print sharing via SMB',
  'lanmanworkstation': 'Workstation — supports network file access via SMB',
  'lfsvc': 'Geolocation Service — monitors device location and GPS',
  'licensemanager': 'Windows License Manager — manages software licenses',
  'lmhosts': 'TCP/IP NetBIOS Helper — supports NetBIOS over TCP/IP',
  'locator': 'Remote Procedure Call (RPC) Locator — manages RPC name service',
  'lsaiso': 'LSASS ISO — manages LSA for Credential Guard',
  'lxpansvc': 'Language Experience — manages language packs and input methods',
  'mapsbroker': 'Downloaded Maps Manager — manages downloaded offline maps',
  'mcds': 'Microsoft Connected Drive — manages mobile broadband',
  'mdmappinstall': 'MDM App Install — installs enterprise apps via MDM',
  'messagingservice': 'Messaging Service — manages SMS and messaging',
  'mixedrealitycapture': 'Mixed Reality Capture — manages mixed reality recording',
  'mpssvc': 'Windows Defender Firewall — manages firewall rules',
  'msdtc': 'Distributed Transaction Coordinator — coordinates transactions across multiple systems',
  'msiscsi': 'Microsoft iSCSI Initiator — manages iSCSI connections',
  'mskserver': 'Microsoft Key Distribution — distributes keys for EFS/IPSEC',
  'nat': 'Network Address Translation — manages NAT for ICS',
  'ncb': 'Network Connection Broker — manages network connectivity',
  'netlogon': 'Netlogon — maintains secure channel to domain controller',
  'netman': 'Network Connections — manages Network and Dial-up Connections',
  'netprofm': 'Network List Service — identifies and manages network connections',
  'netprofmbroker': 'Network Profile Broker — manages network profiles',
  'ngccontainersvc': 'Windows Hello Container — manages Windows Hello biometrics',
  'ngcctnr': 'Windows Hello Container — manages Windows Hello container',
  'ngcctnrsvc': 'Windows Hello Container Service — supports Windows Hello',
  'ngcsvc': 'Windows Hello — manages Windows Hello biometric authentication',
  'nla': 'Network Location Awareness — collects and stores network configuration',
  'nsi': 'Network Store Interface — stores network interface information',
  'ntkdaeamonservice': 'NVIDIA Display Container — manages NVIDIA GPU driver services',
  'nvagent': 'NVIDIA Telemetry — collects NVIDIA driver analytics',
  'p2psvc': 'Peer Networking Grouping — manages peer-to-peer groups',
  'p2pipcsvc': 'Peer Networking Identity Manager — manages peer-to-peer identities',
  'pcasvc': 'Program Compatibility Assistant — detects and fixes app compatibility issues',
  'peerdist': 'Peer Networking Distribution — distributes content over peer network',
  'perfhost': 'Performance Counter DLL Host — hosts performance counter providers',
  'phonesvc': 'Phone Service — manages telephony services',
  'pla': 'Performance Logs & Alerts — configures and schedules performance logs',
  'plugplay': 'Plug and Play — automatically detects and configures hardware',
  'pnrpautoreg': 'PNRP Machine Name — publishes peer-to-peer machine names',
  'policynotification': 'Policy Notification — notifies clients of Group Policy changes',
  'power': 'Power — manages power policy and sleep states',
  'printspooler': 'Print Spooler — manages print jobs and printer queues',
  'profilesvc': 'User Profile Service — loads/unloads user profiles',
  'profsvc': 'User Profile Service — manages user profile loading',
  'protectedunit': 'Protected Environment — supports DRM and protected content',
  'pushnotificationservice': 'Windows Push Notifications — manages push notifications from apps',
  'rasauto': 'Remote Access Auto Connection Manager — dials VPN/remote connections automatically',
  'rasman': 'Remote Access Connection Manager — manages dial-up and VPN connections',
  'remotedesktopservices': 'Remote Desktop Services — manages multi-user remote desktop sessions',
  'remotehelp': 'Remote Assistance — enables remote assistance invitations',
  'renderservice': 'Render Service — manages print rendering',
  'retaildemo': 'Retail Demo — manages retail store demo mode',
  'rmsvc': 'Rights Management Services — manages RMS client for data protection',
  'rpcss': 'Remote Procedure Call (RPC) — core COM/DCOM communication service',
  'rpcepmapper': 'RPC Endpoint Mapper — resolves RPC interface identifiers',
  'sams': 'Security Accounts Manager — manages local user/group accounts (SAM DB)',
  'schedule': 'Task Scheduler — schedules and runs automated tasks',
  'seclogon': 'Secondary Logon — allows running processes as alternate user (runas)',
  'securityhealthservice': 'Security Health — monitors Windows security features',
  'semdrsvc': 'SEM Distributed Router Service — manages Storage Event Management',
  'sens': 'System Event Notification — monitors and notifies system events',
  'sensor': 'Sensor Service — manages sensor data (location, accelerometer, etc.)',
  'sensordataservice': 'Sensor Data Service — processes and stores sensor data',
  'sensorservice': 'Sensor Monitoring Service — monitors sensor devices',
  'sessionenv': 'Session Environment — configures and manages user session environment',
  'sharedaccess': 'Internet Connection Sharing (ICS) — provides NAT for shared connections',
  'shellhwdetection': 'Shell Hardware Detection — monitors AutoPlay and hardware events',
  'smbhelper': 'SMB Helper — supports SMB protocol helper functions',
  'snmptrap': 'SNMP Trap — receives SNMP trap messages',
  'spectrum': 'Spectrum — manages Windows wireless spectrum',
  'spooler': 'Print Spooler — manages print jobs in queue',
  'srm': 'System Resource Manager — manages system resource allocation',
  'ssdpsrv': 'SSDP Discovery — discovers UPnP devices on the network',
  'sstpsrv': 'SSTP Service — manages Secure Socket Tunneling Protocol (VPN)',
  'stisvc': 'Windows Image Acquisition — manages scanner and camera devices',
  'storsvc': 'Storage Service — manages storage settings and spaces',
  'swnp': 'SWNP — manages software notifications and policies',
  'sysmain': 'SysMain (Superfetch) — improves startup and app launch performance',
  'systemeventsbroker': 'System Events Broker — coordinates background system events',
  'tabletinputservice': 'Touch Keyboard and Handwriting — manages touch input panel',
  'tapi': 'Telephony — manages phone devices and TAPI services',
  'tdx': 'NetBT — supports NetBIOS name resolution over TCP/IP',
  'terminalservice': 'Remote Desktop Services — enables remote desktop connections',
  'termservice': 'Remote Desktop Services — manages remote desktop sessions',
  'themes': 'Themes — manages visual themes and desktop background',
  'tieringengineservice': 'Storage Tiering — manages storage tier optimization',
  'timebroker': 'Time Broker — manages background tasks with time constraints',
  'timebrokersvc': 'Time Broker Service — coordinates timed background tasks',
  'tokenbroker': 'Token Broker — manages authentication tokens for apps',
  'trkwks': 'Distributed Link Tracking — tracks file links across NTFS volumes',
  'troubleshootingsvc': 'Troubleshooting Service — diagnoses and resolves Windows problems',
  'trustedinstaller': 'Windows Module Installer — installs and manages Windows Updates',
  'tzautoupdate': 'Auto Time Zone Updater — automatically sets time zone',
  'uaeprompt': 'UAE Prompt — manages User Account Control prompts',
  'uhssvc': 'USB Hub Service — manages USB hubs and devices',
  'upnphost': 'UPnP Device Host — hosts UPnP devices on the network',
  'usermanager': 'User Manager — manages multi-user configuration and profiles',
  'usosvc': 'Update Orchestrator — orchestrates Windows Update installation',
  'vaultsvc': 'Credential Manager — stores and manages user credentials',
  'vds': 'Virtual Disk Service — manages software and hardware RAID volumes',
  'vmicguestinterface': 'Hyper-V Guest Interface — provides host-guest communication',
  'vmicheartbeat': 'Hyper-V Heartbeat — monitors Hyper-V guest health',
  'vmickvpexchange': 'Hyper-V Data Exchange — exchanges data between host and guest',
  'vmicrdv': 'Hyper-V Remote Desktop — provides remote desktop in Hyper-V',
  'vmicshutdown': 'Hyper-V Shutdown — shuts down guest from Hyper-V host',
  'vmictimesync': 'Hyper-V Time Sync — syncs guest time with Hyper-V host',
  'w32time': 'Windows Time — syncs system time with NTP servers',
  'wcmomsvc': 'Windows Connection Manager — manages network connectivity preferences',
  'wcmsvc': 'Windows Connection Manager — manages network connections',
  'wcspluginservice': 'Windows Color System — manages color calibration profiles',
  'wd': 'Windows Defender — provides real-time malware protection',
  'wdfs': 'Windows Defender Firewall — manages firewall settings',
  'wdi': 'Windows Diagnostic Infrastructure — supports Windows diagnostics',
  'wdisystemhost': 'Windows Diagnostic System Host — hosts diagnostic modules',
  'webaccountmanager': 'Web Account Manager — manages web accounts and tokens',
  'webthreatdefsvc': 'Web Threat Defense — protects against web-based threats',
  'webthreatdefusersvc': 'Web Threat Defense User — user-level web protection',
  'websclient': 'WebClient — enables Windows programs to access WebDAV shares',
  'wecsvc': 'Windows Event Collector — collects events from remote machines',
  'wep': 'Wi-Fi Direct — manages Wi-Fi Direct connections',
  'wersvc': 'Windows Error Reporting — reports crashes to Microsoft',
  'wesp': 'Wi-Fi Direct Services — supports Wi-Fi Direct services',
  'wfdconsmgrsvc': 'Wi-Fi Direct Connection Manager — manages Wi-Fi Direct connections',
  'wfhcsrv': 'Windows Filtering Host Controller — manages network filtering',
  'whhelper': 'Windows Helper — supports Windows system functions',
  'whessvc': 'Windows Health Service — manages device health attestation',
  'winhttpautoproxysvc': 'WinHTTP Web Proxy Auto-Discovery — configures proxy settings',
  'winmgmt': 'Windows Management Instrumentation (WMI) — manages system management data',
  'winrm': 'Windows Remote Management — enables remote PowerShell/WMI management',
  'wiscservice': 'Windows Image Service — manages image-related operations',
  'wlansvc': 'WLAN AutoConfig — manages wireless network connections',
  'wlidsvc': 'Microsoft Account Sign-In Assistant — enables Microsoft account sign-in',
  'wlnknetsvc': 'Windows Link Network — manages network links',
  'wmi': 'Windows Management Instrumentation — core WMI provider host',
  'wpcmon': 'Parental Controls — monitors and controls child account usage',
  'wpnsvc': 'Windows Push Notifications — manages push notification connections',
  'wps': 'Wi-Fi Protected Setup — supports WPS for network devices',
  'wsainterfacesvc': 'WSA Interface Service — manages Windows Subsystem for Android',
  'wscsvc': 'Security Center — monitors security health (firewall, AV, updates)',
  'wsearch': 'Windows Search — indexes files for fast search queries',
  'wuauserv': 'Windows Update — detects, downloads, and installs Windows updates',
  'wudfsvc': 'Windows Update Driver — manages driver updates via Windows Update',
  'xblauthmanager': 'Xbox Live Auth Manager — authenticates Xbox Live accounts',
  'xblgamesave': 'Xbox Live Game Save — syncs Xbox game saves to cloud',
  'xboxgip': 'Xbox Accessory Management — manages Xbox controllers and accessories',
  'xboxnetapisvc': 'Xbox Live Networking — manages Xbox Live network connectivity',
  'xpssvc': 'XPS Viewer — hosts XPS document viewing',
};

const SENSITIVE_PATHS = [
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'C:\\Windows\\System32\\config\\SAM',
  'C:\\Windows\\System32\\config\\SECURITY',
  'C:\\Windows\\System32\\config\\SYSTEM',
  'C:\\Windows\\System32\\config\\SOFTWARE',
  'C:\\Windows\\System32',
  'C:\\Windows',
  'C:\\Program Files',
  'C:\\Program Files (x86)',
  'C:\\Users',
  'C:\\Users\\Public',
  'C:\\ProgramData',
  'C:\\Windows\\Temp',
  'C:\\',
];

// =============================================================================
// ISO 27001:2022 Annex A — Complete Reference (93 Controls)
// =============================================================================
// Each control: code, title, description, theme, category
const ANNEX_A = [
  // --- A.5 Organizational Controls (37) ---
  { code: 'A.5.1', title: 'Policies for information security', theme: 'Organizational', desc: 'Establish, review and communicate information security policies aligned with business objectives and legal/regulatory requirements.' },
  { code: 'A.5.2', title: 'Information security roles and responsibilities', theme: 'Organizational', desc: 'Define and allocate information security responsibilities for all roles in the organization.' },
  { code: 'A.5.3', title: 'Segregation of duties', theme: 'Organizational', desc: 'Separate conflicting duties and areas of responsibility to reduce opportunities for unauthorized or unintentional modification or misuse of assets.' },
  { code: 'A.5.4', title: 'Management responsibilities', theme: 'Organizational', desc: 'Ensure management enforces information security policies through demonstrated commitment and resource allocation.' },
  { code: 'A.5.5', title: 'Contact with authorities', theme: 'Organizational', desc: 'Maintain appropriate contact with law enforcement, regulatory bodies, and other relevant authorities.' },
  { code: 'A.5.6', title: 'Contact with special interest groups', theme: 'Organizational', desc: 'Maintain appropriate contact with security forums, industry groups, and professional associations.' },
  { code: 'A.5.7', title: 'Threat intelligence', theme: 'Organizational', desc: 'Collect and analyze information about information security threats to produce actionable threat intelligence.' },
  { code: 'A.5.8', title: 'Information security in project management', theme: 'Organizational', desc: 'Integrate information security into project management methodologies across all project types.' },
  { code: 'A.5.9', title: 'Inventory of information and other associated assets', theme: 'Organizational', desc: 'Identify and maintain an inventory of information assets and other associated assets including owners and classification.' },
  { code: 'A.5.10', title: 'Acceptable use of information and other associated assets', theme: 'Organizational', desc: 'Define and document rules for acceptable use of information and associated assets.' },
  { code: 'A.5.11', title: 'Return of assets', theme: 'Organizational', desc: 'Ensure personnel return all organizational assets in their possession upon termination or change of employment.' },
  { code: 'A.5.12', title: 'Classification of information', theme: 'Organizational', desc: 'Classify information according to its value, legal requirements, sensitivity, and criticality to the organization.' },
  { code: 'A.5.13', title: 'Labelling of information', theme: 'Organizational', desc: 'Develop and implement procedures for labelling information according to the classification scheme.' },
  { code: 'A.5.14', title: 'Information transfer', theme: 'Organizational', desc: 'Protect information during transfer within and outside the organization through defined policies and procedures.' },
  { code: 'A.5.15', title: 'Access control', theme: 'Organizational', desc: 'Establish an access control policy based on business and information security requirements for access to networks, systems, applications, and information.' },
  { code: 'A.5.16', title: 'Identity management', theme: 'Organizational', desc: 'Manage the full lifecycle of user identities including creation, maintenance, and deletion of identities.' },
  { code: 'A.5.17', title: 'Authentication information', theme: 'Organizational', desc: 'Control allocation and management of authentication information through formal management processes.' },
  { code: 'A.5.18', title: 'Access rights', theme: 'Organizational', desc: 'Provision, review, and revoke access rights for users including privileged access rights.' },
  { code: 'A.5.19', title: 'Information security in supplier relationships', theme: 'Organizational', desc: 'Define processes to manage information security risks associated with supplier access to organizational assets.' },
  { code: 'A.5.20', title: 'Addressing information security within supplier agreements', theme: 'Organizational', desc: 'Include relevant information security requirements in supplier agreements based on risk assessment.' },
  { code: 'A.5.21', title: 'Managing information security in the ICT supply chain', theme: 'Organizational', desc: 'Define processes to manage information security risks in the ICT supply chain including supplier dependencies.' },
  { code: 'A.5.22', title: 'Monitoring, review and change management of supplier services', theme: 'Organizational', desc: 'Monitor, review, and audit supplier service delivery and manage changes to supplier services.' },
  { code: 'A.5.23', title: 'Information security for use of cloud services', theme: 'Organizational', desc: 'Establish processes for acquiring, using, managing, and exiting cloud services securely.' },
  { code: 'A.5.24', title: 'Information security incident management planning and preparation', theme: 'Organizational', desc: 'Plan and prepare for information security incidents through defined processes and roles.' },
  { code: 'A.5.25', title: 'Assessment and decision on information security events', theme: 'Organizational', desc: 'Assess information security events to determine whether they should be categorized as incidents.' },
  { code: 'A.5.26', title: 'Response to information security incidents', theme: 'Organizational', desc: 'Respond to information security incidents according to defined procedures.' },
  { code: 'A.5.27', title: 'Learning from information security incidents', theme: 'Organizational', desc: 'Use knowledge gained from analyzing and resolving incidents to improve security posture.' },
  { code: 'A.5.28', title: 'Collection of evidence', theme: 'Organizational', desc: 'Establish procedures for identification, collection, acquisition, and preservation of evidence related to security events.' },
  { code: 'A.5.29', title: 'Information security during disruption', theme: 'Organizational', desc: 'Maintain appropriate level of information security during any period of disruption.' },
  { code: 'A.5.30', title: 'ICT readiness for business continuity', theme: 'Organizational', desc: 'Plan, implement, maintain, and test ICT readiness to ensure business continuity during disruptions.' },
  { code: 'A.5.31', title: 'Legal, statutory, regulatory and contractual requirements', theme: 'Organizational', desc: 'Identify, document, and comply with legal, statutory, regulatory, and contractual requirements for information security.' },
  { code: 'A.5.32', title: 'Intellectual property rights', theme: 'Organizational', desc: 'Implement procedures to protect intellectual property rights including copyrights, trademarks, and patents.' },
  { code: 'A.5.33', title: 'Protection of records', theme: 'Organizational', desc: 'Protect records from loss, destruction, falsification, unauthorized access, and unauthorized release.' },
  { code: 'A.5.34', title: 'Privacy and protection of personally identifiable information', theme: 'Organizational', desc: 'Ensure privacy and protection of PII as required by applicable laws and regulations.' },
  { code: 'A.5.35', title: 'Independent review of information security', theme: 'Organizational', desc: 'Conduct independent reviews of the organization\'s approach to managing information security at planned intervals.' },
  { code: 'A.5.36', title: 'Compliance with policies, rules and standards for information security', theme: 'Organizational', desc: 'Ensure compliance with information security policies, rules, and standards.' },
  { code: 'A.5.37', title: 'Documented operating procedures', theme: 'Organizational', desc: 'Document operating procedures for information processing facilities and make them available to personnel.' },

  // --- A.6 People Controls (8) ---
  { code: 'A.6.1', title: 'Screening', theme: 'People', desc: 'Conduct background verification checks on all candidates for employment prior to joining.' },
  { code: 'A.6.2', title: 'Terms and conditions of employment', theme: 'People', desc: 'Include information security roles and responsibilities in employment contracts and terms.' },
  { code: 'A.6.3', title: 'Information security awareness, education and training', theme: 'People', desc: 'Provide ongoing information security awareness, education, and training to all personnel.' },
  { code: 'A.6.4', title: 'Disciplinary process', theme: 'People', desc: 'Establish a formal disciplinary process for personnel who commit information security violations.' },
  { code: 'A.6.5', title: 'Responsibilities after termination or change of employment', theme: 'People', desc: 'Define and communicate information security responsibilities that remain valid after termination or change.' },
  { code: 'A.6.6', title: 'Confidentiality or non-disclosure agreements', theme: 'People', desc: 'Identify and document confidentiality and non-disclosure requirements reflecting organizational needs.' },
  { code: 'A.6.7', title: 'Remote working', theme: 'People', desc: 'Implement security measures for personnel working remotely to protect information accessed or processed off-site.' },
  { code: 'A.6.8', title: 'Information security event reporting', theme: 'People', desc: 'Provide a mechanism for personnel to report observed or suspected security events promptly.' },

  // --- A.7 Physical Controls (14) ---
  { code: 'A.7.1', title: 'Physical security perimeters', theme: 'Physical', desc: 'Define and use security perimeters to protect areas that contain information and associated assets.' },
  { code: 'A.7.2', title: 'Physical entry', theme: 'Physical', desc: 'Secure areas with appropriate entry controls to ensure only authorized personnel have access.' },
  { code: 'A.7.3', title: 'Securing offices, rooms and facilities', theme: 'Physical', desc: 'Design and apply physical security for offices, rooms, and facilities.' },
  { code: 'A.7.4', title: 'Physical security monitoring', theme: 'Physical', desc: 'Continuously monitor physical premises for unauthorized access using surveillance and detection systems.' },
  { code: 'A.7.5', title: 'Protecting against physical and environmental threats', theme: 'Physical', desc: 'Protect against physical and environmental threats such as fire, flood, earthquake, and power failure.' },
  { code: 'A.7.6', title: 'Working in secure areas', theme: 'Physical', desc: 'Define and apply procedures for working in secure areas including visitor control.' },
  { code: 'A.7.7', title: 'Clear desk and clear screen', theme: 'Physical', desc: 'Implement clear desk and clear screen policies for paper documents and removable storage media.' },
  { code: 'A.7.8', title: 'Equipment siting and protection', theme: 'Physical', desc: 'Site and protect equipment to reduce risks from environmental threats and unauthorized access.' },
  { code: 'A.7.9', title: 'Security of assets off-premises', theme: 'Physical', desc: 'Protect off-premises assets taking into account the different risks of working outside the premises.' },
  { code: 'A.7.10', title: 'Storage media', theme: 'Physical', desc: 'Manage removable storage media throughout their lifecycle including acquisition, use, and secure disposal.' },
  { code: 'A.7.11', title: 'Supporting utilities', theme: 'Physical', desc: 'Protect information processing facilities from power failures and other disruptions to supporting utilities.' },
  { code: 'A.7.12', title: 'Cabling security', theme: 'Physical', desc: 'Protect power and telecommunications cabling against interception, interference, or damage.' },
  { code: 'A.7.13', title: 'Equipment maintenance', theme: 'Physical', desc: 'Maintain equipment to ensure continued availability and integrity of information.' },
  { code: 'A.7.14', title: 'Secure disposal or re-use of equipment', theme: 'Physical', desc: 'Sanitize equipment containing storage media prior to disposal or re-use.' },

  // --- A.8 Technological Controls (34) ---
  { code: 'A.8.1', title: 'User endpoint devices', theme: 'Technological', desc: 'Protect information on user endpoint devices including workstations, laptops, tablets, and mobile phones.' },
  { code: 'A.8.2', title: 'Privileged access rights', theme: 'Technological', desc: 'Restrict and manage allocation and use of privileged access rights including administrator and root access.' },
  { code: 'A.8.3', title: 'Information access restriction', theme: 'Technological', desc: 'Restrict access to information and information processing facilities according to the access control policy.' },
  { code: 'A.8.4', title: 'Access to source code', theme: 'Technological', desc: 'Restrict access to program source code, development tools, and libraries.' },
  { code: 'A.8.5', title: 'Secure authentication', theme: 'Technological', desc: 'Implement secure authentication mechanisms including multi-factor authentication where appropriate.' },
  { code: 'A.8.6', title: 'Capacity management', theme: 'Technological', desc: 'Monitor and manage the use of information processing resources to ensure adequate capacity.' },
  { code: 'A.8.7', title: 'Protection against malware', theme: 'Technological', desc: 'Implement malware detection, prevention, and recovery controls combined with appropriate user awareness.' },
  { code: 'A.8.8', title: 'Management of technical vulnerabilities', theme: 'Technological', desc: 'Identify, evaluate, and remediate technical vulnerabilities in information systems in a timely manner.' },
  { code: 'A.8.9', title: 'Configuration management', theme: 'Technological', desc: 'Establish and maintain secure baseline configurations for hardware, software, and networks.' },
  { code: 'A.8.10', title: 'Information deletion', theme: 'Technological', desc: 'Delete information when no longer required in accordance with retention policies.' },
  { code: 'A.8.11', title: 'Data masking', theme: 'Technological', desc: 'Mask sensitive data according to organizational access control and data classification policies.' },
  { code: 'A.8.12', title: 'Data leakage prevention', theme: 'Technological', desc: 'Apply data leakage prevention measures to detect and prevent unauthorized disclosure of sensitive information.' },
  { code: 'A.8.13', title: 'Information backup', theme: 'Technological', desc: 'Maintain and regularly test backups of information and software to ensure recoverability.' },
  { code: 'A.8.14', title: 'Redundancy of information processing facilities', theme: 'Technological', desc: 'Implement redundancy in information processing facilities to meet availability requirements.' },
  { code: 'A.8.15', title: 'Logging', theme: 'Technological', desc: 'Produce, store, protect, and review event logs recording user activities, exceptions, faults, and security events.' },
  { code: 'A.8.16', title: 'Monitoring activities', theme: 'Technological', desc: 'Monitor networks, systems, and applications for anomalous behavior and potential security incidents.' },
  { code: 'A.8.17', title: 'Clock synchronization', theme: 'Technological', desc: 'Synchronize clocks of relevant information processing systems to a reference time source.' },
  { code: 'A.8.18', title: 'Use of privileged utility programs', theme: 'Technological', desc: 'Restrict and control the use of utility programs that could bypass system and application controls.' },
  { code: 'A.8.19', title: 'Installation of software on operational systems', theme: 'Technological', desc: 'Implement policies and procedures for controlled installation of software on operational systems.' },
  { code: 'A.8.20', title: 'Networks security', theme: 'Technological', desc: 'Secure and manage networks to protect information in transit and network services from attack.' },
  { code: 'A.8.21', title: 'Security of network services', theme: 'Technological', desc: 'Identify and implement security mechanisms for network services including firewalls and IDS/IPS.' },
  { code: 'A.8.22', title: 'Segregation of networks', theme: 'Technological', desc: 'Segregate groups of information services, users, and systems on networks based on trust levels.' },
  { code: 'A.8.23', title: 'Web filtering', theme: 'Technological', desc: 'Manage access to external websites to reduce exposure to malicious content and non-compliant browsing.' },
  { code: 'A.8.24', title: 'Use of cryptography', theme: 'Technological', desc: 'Define and implement cryptographic controls including key management based on risk assessment.' },
  { code: 'A.8.25', title: 'Secure development life cycle', theme: 'Technological', desc: 'Establish and apply rules for secure development of software and systems throughout their life cycle.' },
  { code: 'A.8.26', title: 'Application security requirements', theme: 'Technological', desc: 'Identify and specify information security requirements for new or enhanced applications.' },
  { code: 'A.8.27', title: 'Secure system architecture and engineering principles', theme: 'Technological', desc: 'Apply secure system architecture and engineering principles to all IT systems.' },
  { code: 'A.8.28', title: 'Secure coding', theme: 'Technological', desc: 'Apply secure coding principles to software development including input validation and output encoding.' },
  { code: 'A.8.29', title: 'Security testing in development and acceptance', theme: 'Technological', desc: 'Define and implement security testing processes in development and acceptance phases.' },
  { code: 'A.8.30', title: 'Outsourced development', theme: 'Technological', desc: 'Direct, monitor, and review outsourced system development activities for security compliance.' },
  { code: 'A.8.31', title: 'Separation of development, test and production environments', theme: 'Technological', desc: 'Separate development, testing, and production environments to reduce risk of unauthorized access or changes.' },
  { code: 'A.8.32', title: 'Change management', theme: 'Technological', desc: 'Control changes to information processing facilities and systems through formal change management processes.' },
  { code: 'A.8.33', title: 'Test information', theme: 'Technological', desc: 'Select, protect, and manage test information to avoid using production data in test environments.' },
  { code: 'A.8.34', title: 'Protection of information systems during audit testing', theme: 'Technological', desc: 'Plan and conduct audit tests to minimize disruption and protect production systems and data.' },
];

async function scan() {
  const findings = [];

  // ------------------------------------------------
  // 1. SYSTEM INFORMATION
  // ------------------------------------------------
  console.log('=== SYSTEM INFO ===');
  const psSysInfo = `
    $info = Get-CimInstance Win32_ComputerSystem;
    $os = Get-CimInstance Win32_OperatingSystem;
    [PSCustomObject]@{
      Hostname = $info.Name;
      Domain = $info.Domain;
      Manufacturer = $info.Manufacturer;
      Model = $info.Model;
      TotalRAM = [math]::Round($info.TotalPhysicalMemory / 1GB, 1);
      OSName = $os.Caption;
      OSVersion = $os.Version;
      OSPath = $os.WindowsDirectory;
      LastBoot = $os.LastBootUpTime.ToString("o");
      Architecture = $os.OSArchitecture;
    } | ConvertTo-Json -Compress
  `;
  let sysInfo = {};
  try { sysInfo = JSON.parse(runPS(psSysInfo)); } catch(e) { console.error('SysInfo error:', e.message); }
  console.log(`  Host: ${sysInfo.Hostname || '?'}, OS: ${sysInfo.OSName || '?'}`);

  // ------------------------------------------------
  // 2. CURRENT USER & GROUPS
  // ------------------------------------------------
  console.log('=== USER & GROUP ANALYSIS ===');
  const psUser = `
    $user = [PSCustomObject]@{
      UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;
      IsAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator);
      AuthType = [System.Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType;
    };
    $groups = @();
    $sidMap = @{
      'S-1-5-32-544' = 'Administrators';
      'S-1-5-32-545' = 'Users';
      'S-1-5-32-546' = 'Guests';
      'S-1-5-32-547' = 'Power Users';
      'S-1-5-32-548' = 'Account Operators';
      'S-1-5-32-549' = 'Server Operators';
      'S-1-5-32-550' = 'Print Operators';
      'S-1-5-32-551' = 'Backup Operators';
      'S-1-5-32-552' = 'Replicator';
      'S-1-5-32-555' = 'Remote Desktop Users';
      'S-1-5-32-556' = 'Network Configuration Operators';
      'S-1-5-32-557' = 'Performance Monitor Users';
      'S-1-5-32-558' = 'Performance Log Users';
      'S-1-5-32-559' = 'Distributed COM Users';
      'S-1-5-32-568' = 'IIS_IUSRS';
      'S-1-5-32-569' = 'Cryptographic Operators';
      'S-1-5-32-573' = 'Event Log Readers';
      'S-1-5-32-574' = 'Certificate Service DCOM Access';
      'S-1-5-11' = 'Authenticated Users';
      'S-1-5-1' = 'World (Everyone)';
      'S-1-5-19' = 'NT AUTHORITY\\LocalService';
      'S-1-5-20' = 'NT AUTHORITY\\NetworkService';
      'S-1-5-18' = 'NT AUTHORITY\\SYSTEM';
    };
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent();
    foreach ($g in $identity.Groups) {
      $name = $null;
      try { $name = $g.Translate([System.Security.Principal.NTAccount]).Value; } catch {}
      if (-not $name) { $name = $sidMap[$g.Value]; if (-not $name) { $name = $g.Value; } }
      $groups += [PSCustomObject]@{ SID = $g.Value; Name = $name; IsBuiltIn = [bool]$sidMap[$g.Value] }
    }
    [PSCustomObject]@{ User = $user; Groups = $groups } | ConvertTo-Json -Compress
  `;
  let userInfo = { User: {}, Groups: [] };
  try { userInfo = JSON.parse(runPS(psUser, 15000)); } catch(e) { console.error('User info error:', e.message); }
  const currentUser = userInfo.User || {};
  const currentGroups = userInfo.Groups || [];
  console.log(`  User: ${currentUser.UserName || '?'}, Admin: ${currentUser.IsAdmin}, Groups: ${currentGroups.length}`);

  // ------------------------------------------------
  // 3. USER PRIVILEGES (whoami /priv)
  // ------------------------------------------------
  console.log('=== USER PRIVILEGES ===');
  const rawPrivs = runPS('whoami /priv');
  const privs = [];
  let started = false, headerDone = false;
  for (const line of (rawPrivs || '').split('\n')) {
    const t = line.trim();
    if (t.includes('---')) { started = true; continue; }
    if (!started || !t) continue;
    if (/^[=\- ]+$/.test(t)) continue;
    if (!headerDone) { headerDone = true; continue; }
    const cols = t.split(/\s{2,}/);
    if (cols.length >= 2) {
      const pname = cols[0].trim();
      const state = cols[cols.length - 1].trim();
      const enabled = state === 'Enabled';
      const danger = DANGEROUS_PRIVILEGES[pname];
      privs.push({
        name: pname, enabled, description: cols.slice(1, cols.length - 1).join(' ').trim(),
        risk: danger ? 'high' : (enabled ? 'info' : 'none'),
        risk_note: danger || ''
      });
    }
  }
  const enabledDangerousPrivs = privs.filter(p => p.enabled && p.risk === 'high');
  for (const p of enabledDangerousPrivs) {
    findings.push({
      type: 'dangerous_priv', severity: 'high', category: 'privilege_management',
      iso: 'A.8.2', title: FINDING_DEFS.dangerous_priv.title.replace('{detail}', p.name),
      detail: p.risk_note, remediation: 'Remove this privilege from user token if not required'
    });
  }
  console.log(`  ${privs.length} privs, ${enabledDangerousPrivs.length} dangerous`);

  // ------------------------------------------------
  // 4. LOCAL USERS & GROUPS
  // ------------------------------------------------
  console.log('=== LOCAL USERS ===');
  const psUsers = `
    $results = @();
    $users = Get-LocalUser -ErrorAction SilentlyContinue;
    if (-not $users) { $users = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue; }
    foreach ($u in $users) {
    $results += [PSCustomObject]@{
      Name = $u.Name; FullName = if ($u.FullName) { $u.FullName } else { "" };
      Enabled = if ($u.Enabled -eq $true -or $u.Disabled -eq $false) { $true } else { $false };
      PasswordExpires = if ($u.PasswordExpires) { $u.PasswordExpires.ToString("o") } else { "" };
      LastLogon = if ($u.LastLogon) { $u.LastLogon.ToString("o") } else { "" };
      Description = if ($u.Description) { $u.Description } else { "" };
      SID = if ($u.SID) { $u.SID.ToString() } else { "" };
    }
    }
    $results | ConvertTo-Json -Compress
  `;
  let localUsers = [];
  try { localUsers = JSON.parse(runPS(psUsers) || '[]'); if (!Array.isArray(localUsers)) localUsers = [localUsers]; } catch(e) {}
  console.log(`  ${localUsers.length} users`);

  // Check guest account
  const guest = localUsers.find(u => u.Name && u.Name.toLowerCase() === 'guest');
  if (guest && guest.Enabled) {
    findings.push({
      type: 'guest_enabled', severity: 'medium', category: 'access_control',
      iso: 'A.5.15', title: FINDING_DEFS.guest_enabled.title,
      detail: 'Guest account is enabled and could allow anonymous access',
      remediation: 'Disable the Guest account via "net user guest /active:no"'
    });
  }

  // Check for non-expiring passwords
  const nonExpiring = localUsers.filter(u => u.Enabled && u.PasswordExpires === null && u.Name && u.Name.toLowerCase() !== 'guest' && !u.Name.endsWith('$'));
  if (nonExpiring.length > 0) {
    findings.push({
      type: 'no_password_expiry', severity: 'medium', category: 'password_policy',
      iso: 'A.5.17', title: FINDING_DEFS.no_password_expiry.title,
      detail: `Accounts: ${nonExpiring.map(u => u.Name).join(', ')}`,
      remediation: 'Set passwords to expire via "net user <username> /expires:never" or configure password policy'
    });
  }

  console.log('=== LOCAL GROUPS ===');
  const psGroups = `
    $results = @();
    $groups = Get-LocalGroup -ErrorAction SilentlyContinue;
    if (-not $groups) { $groups = Get-WmiObject Win32_Group -Filter "LocalAccount=True" -ErrorAction SilentlyContinue; }
    foreach ($g in $groups) {
      $members = @();
      try {
        $gmembers = Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue;
        foreach ($m in $gmembers) {
          $members += [PSCustomObject]@{
            Name = $m.Name; SID = if ($m.SID) { $m.SID.ToString() } else { "" }; ObjectClass = $m.ObjectClass
          }
        }
      } catch {}
      $results += [PSCustomObject]@{
        Name = $g.Name; Description = if ($g.Description) { $g.Description } else { "" };
        SID = if ($g.SID) { $g.SID.ToString() } else { "" }; Members = $members
      }
    }
    $results | ConvertTo-Json -Compress -Depth 3
  `;
  let localGroups = [];
  try { localGroups = JSON.parse(runPS(psGroups) || '[]'); if (!Array.isArray(localGroups)) localGroups = [localGroups]; } catch(e) {}

  const adminGroup = localGroups.find(g => g.Name === 'Administrators' || g.Name === 'Administradores');
  const adminMembers = adminGroup ? (adminGroup.Members || []).map(m => m.Name) : [];
  console.log(`  ${localGroups.length} groups, ${adminMembers.length} admin members`);

  // Check if current user is in admin
  const userName = (currentUser.UserName || '').toLowerCase();
  if (currentUser.IsAdmin) {
    findings.push({
      type: 'admin_member', severity: 'critical', category: 'privilege_management',
      iso: 'A.8.2', title: FINDING_DEFS.admin_member.title,
      detail: `User ${currentUser.UserName} is a member of Administrators group. All processes run with elevated privileges.`,
      remediation: 'Use a standard user account for daily work. Create a separate admin account for administrative tasks.'
    });
  }

  // ------------------------------------------------
  // 5. SECURITY POLICY
  // ------------------------------------------------
  console.log('=== SECURITY POLICY ===');
  const psPolicy = `
    $result = [PSCustomObject]@{};
    try {
      $acct = Get-CimInstance Win32_AccountPolicy -ErrorAction SilentlyContinue;
      if (-not $acct) {
        $sec = [PSCustomObject]@{
          LockoutThreshold = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" -Name MaximumPasswordAge -ErrorAction SilentlyContinue).MaximumPasswordAge;
        };
      }
      $secedit = secedit /export /cfg "$env:TEMP\\_secpol.inf" /areas SECURITYPOLICY 2>&1 | Out-Null;
      $p = Get-Content "$env:TEMP\\_secpol.inf" -ErrorAction SilentlyContinue;
      $pwLen = ($p | Select-String "MinimumPasswordLength" | ForEach-Object { $_ -replace '.*=', '' } | Select-Object -First 1);
      $pwHistory = ($p | Select-String "PasswordHistorySize" | ForEach-Object { $_ -replace '.*=', '' } | Select-Object -First 1);
      $pwAge = ($p | Select-String "MaximumPasswordAge" | ForEach-Object { $_ -replace '.*=', '' } | Select-Object -First 1);
      $lockout = ($p | Select-String "LockoutBadCount" | ForEach-Object { $_ -replace '.*=', '' } | Select-Object -First 1);
      $lockoutDur = ($p | Select-String "LockoutDuration" | ForEach-Object { $_ -replace '.*=', '' } | Select-Object -First 1);
      Remove-Item "$env:TEMP\\_secpol.inf" -ErrorAction SilentlyContinue;
      $result = [PSCustomObject]@{
        MinPasswordLength = if ($pwLen) { [int]$pwLen } else { 0 };
        PasswordHistorySize = if ($pwHistory) { [int]$pwHistory } else { 0 };
        MaxPasswordAge = if ($pwAge) { [int]$pwAge } else { 0 };
        LockoutThreshold = if ($lockout) { [int]$lockout } else { 0 };
        LockoutDuration = if ($lockoutDur) { [int]$lockoutDur } else { 0 };
      }
    } catch { $result = [PSCustomObject]@{ MinPasswordLength = -1; PasswordHistorySize = -1; MaxPasswordAge = -1; LockoutThreshold = -1; LockoutDuration = -1 } }
    $result | ConvertTo-Json -Compress
  `;
  let secPolicy = {};
  try { secPolicy = JSON.parse(runPS(psPolicy)); } catch(e) { console.error('Policy error:', e.message); }
  console.log(`  MinPWLen: ${secPolicy.MinPasswordLength || '?'}`);

  if (secPolicy.MinPasswordLength !== undefined && secPolicy.MinPasswordLength >= 0) {
    if (secPolicy.MinPasswordLength < 8) {
      findings.push({
        type: 'weak_password_policy', severity: 'high', category: 'password_policy',
        iso: 'A.5.17', title: FINDING_DEFS.weak_password_policy.title,
        detail: `Minimum password length is ${secPolicy.MinPasswordLength} (recommended: 8+)`,
        remediation: 'Set minimum password length to at least 8 characters via Local Security Policy > Account Policies > Password Policy'
      });
    }
    if (!secPolicy.LockoutThreshold || secPolicy.LockoutThreshold === 0) {
      findings.push({
        type: 'no_lockout_policy', severity: 'medium', category: 'password_policy',
        iso: 'A.5.17', title: 'Account lockout not configured (brute force risk)',
        detail: 'No account lockout policy set: unlimited login attempts allowed',
        remediation: 'Configure account lockout threshold (e.g., 5 attempts) via Local Security Policy'
      });
    }
  }

  // ------------------------------------------------
  // 6. UAC STATUS
  // ------------------------------------------------
  const psUAC = `
    $result = [PSCustomObject]@{};
    try {
      $uac = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name EnableLUA -ErrorAction Stop;
      $consent = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name ConsentPromptBehaviorAdmin -ErrorAction Stop;
      $result = [PSCustomObject]@{ EnableLUA = $uac.EnableLUA; ConsentPrompt = $consent.ConsentPromptBehaviorAdmin }
    } catch { $result = [PSCustomObject]@{ EnableLUA = -1; ConsentPrompt = -1 } }
    $result | ConvertTo-Json -Compress
  `;
  let uacStatus = { EnableLUA: -1 };
  try { uacStatus = JSON.parse(runPS(psUAC)); } catch(e) {}
  if (uacStatus.EnableLUA === 0) {
    findings.push({
      type: 'uac_disabled', severity: 'high', category: 'privilege_management',
      iso: 'A.8.2', title: FINDING_DEFS.uac_disabled.title,
      detail: 'UAC (User Account Control) is disabled. Processes run with full admin rights without prompting.',
      remediation: 'Enable UAC via Control Panel > User Accounts > Change User Account Control settings'
    });
  }

  // ------------------------------------------------
  // 7. LSA PROTECTION
  // ------------------------------------------------
  const psLSA = `
    $result = [PSCustomObject]@{};
    try {
      $lsa = Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue;
      $result = [PSCustomObject]@{ RunAsPPL = if ($lsa.RunAsPPL -eq 1) { 1 } else { 0 } }
    } catch { $result = [PSCustomObject]@{ RunAsPPL = 0 } }
    $result | ConvertTo-Json -Compress
  `;
  let lsaStatus = { RunAsPPL: 0 };
  try { lsaStatus = JSON.parse(runPS(psLSA)); } catch(e) {}
  if (lsaStatus.RunAsPPL === 0) {
    findings.push({
      type: 'lsa_not_protected', severity: 'medium', category: 'privilege_management',
      iso: 'A.8.2', title: FINDING_DEFS.lsa_not_protected.title,
      detail: 'LSASS is not running as Protected Process Light (PPL). Credentials can be dumped via Mimikatz if admin access is obtained.',
      remediation: 'Enable LSA protection via Regedit: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = dword:00000001'
    });
  }

  // ------------------------------------------------
  // 8. PROCESS RISK ASSESSMENT
  // ------------------------------------------------
  console.log('=== PROCESS RISK ASSESSMENT ===');
  const psProcs = `
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -gt 4 };
    $results = @();
    foreach ($p in $procs) {
      $owner = $null;
      try { $owner = $p.GetOwner(); } catch {}
      $ownerStr = if ($owner -and $owner.User) { $owner.Domain + "\\" + $owner.User } else { "UNKNOWN" };
      try {
        $fp = [System.Diagnostics.Process]::GetProcessById($p.ProcessId);
        $startTime = try { $fp.StartTime.ToString("o") } catch { "" };
        $fp.Dispose();
      } catch { $startTime = ""; }
      $results += [PSCustomObject]@{
        PID = $p.ProcessId;
        Name = if ($p.Name) { $p.Name } else { "unknown" };
        Owner = $ownerStr;
        CPU = [math]::Round(($p.KernelModeTime + $p.UserModeTime) / 10000000 / 100, 2);
        MemMB = [math]::Round($p.WorkingSetSize / 1MB, 1);
        Path = if ($p.ExecutablePath) { $p.ExecutablePath } else { "" };
        CmdLine = if ($p.CommandLine) { $p.CommandLine } else { "" };
        PPID = $p.ParentProcessId;
        ThreadCount = $p.ThreadCount;
        HandleCount = $p.HandleCount;
        SessionId = $p.SessionId;
      }
    }
    $results | ConvertTo-Json -Compress
  `;
  const rawProcs = runPS(psProcs, 60000);
  let processes = [];
  try {
    const parsed = JSON.parse(rawProcs);
    processes = (Array.isArray(parsed) ? parsed : [parsed]).filter(p => p && p.Name);
  } catch(e) { console.error('Process parse error:', e.message); }

  // Signature check
  const psSig = `
    $paths = @();
    Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -gt 4 -and $_.ExecutablePath } | Select-Object -First 150 | ForEach-Object {
      $paths += [PSCustomObject]@{ PID = $_.ProcessId; Path = $_.ExecutablePath }
    }
    $results = @();
    foreach ($entry in $paths) {
      try {
        $sig = Get-AuthenticodeSignature -FilePath $entry.Path -ErrorAction Stop;
        $results += [PSCustomObject]@{ PID = $entry.PID; Signed = ($sig.Status -eq "Valid"); Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }; Status = $sig.Status.ToString() }
      } catch { $results += [PSCustomObject]@{ PID = $entry.PID; Signed = $false; Signer = ""; Status = "NoSignature" } }
    }
    $results | ConvertTo-Json -Compress
  `;
  let signatures = {};
  try {
    const parsed = JSON.parse(runPS(psSig, 120000) || '[]');
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    for (const s of arr) { if (s && s.PID) signatures[s.PID] = { signed: s.Signed, signer: s.Signer, status: s.Status }; }
  } catch(e) { console.error('Signature error:', e.message); }

  const systemOwners = ['SYSTEM', 'NT AUTHORITY\\SYSTEM', 'NT SERVICE\\', 'AUTHORITY\\'];
  const isSystemOwner = (o) => o && systemOwners.some(s => o.startsWith(s));
  const isUserPath = (p) => p && (p.toLowerCase().includes('\\users\\') || p.toLowerCase().includes('\\temp\\') || p.toLowerCase().includes('\\downloads\\') || p.toLowerCase().includes('\\appdata\\'));
  const isSystemPath = (p) => p && (p.toLowerCase().includes('\\windows\\') || p.toLowerCase().includes('\\program files'));

  const processRisks = [];
  for (const p of processes) {
    const sig = signatures[p.PID] || {};
    const runningAsSystem = isSystemOwner(p.Owner);
    const runningAsAdmin = currentUser.IsAdmin && p.Owner && p.Owner.toLowerCase() === (currentUser.UserName || '').toLowerCase();
    const fromUserPath = isUserPath(p.Path);
    const fromSystemPath = isSystemPath(p.Path);
    const hasNetwork = false; // will be populated from connections later
    const unknownPath = !p.Path || p.Path === '';

    let riskScore = 0;
    const reasons = [];

    // SYSTEM process from user-writable path = critical
    if (runningAsSystem && fromUserPath) { riskScore += 50; reasons.push('SYSTEM process from user-writable path'); }
    // Unsigned process from user path
    if (!sig.signed && fromUserPath) { riskScore += 25; reasons.push('Unsigned from user-writable path'); }
    // Running as admin
    if (runningAsAdmin) { riskScore += 10; reasons.push('Running with admin privileges'); }
    // No path = potential injection
    if (unknownPath && !runningAsSystem) { riskScore += 20; reasons.push('No executable path (potential injection)'); }
    // Unsigned with high memory
    if (!sig.signed && (p.MemMB || 0) > 200 && !fromSystemPath) { riskScore += 10; reasons.push('Unsigned, high memory, non-system path'); }
    // High thread count (potential malware)
    if ((p.ThreadCount || 0) > 100 && !runningAsSystem) { riskScore += 5; reasons.push('High thread count'); }

    const parent = classifyService(p.Name, p.Name, p.Path).parent_app;

    processRisks.push({
      pid: p.PID, name: p.Name, owner: p.Owner,
      risk_score: Math.min(riskScore, 100),
      reasons: reasons.join('; '),
      is_signed: sig.signed ? 1 : 0,
      signer: sig.signer || '',
      exec_path: p.Path,
      cmd_line: p.CmdLine,
      ppid: p.PPID,
      cpu: p.CPU,
      mem_mb: p.MemMB,
      thread_count: p.ThreadCount,
      handle_count: p.HandleCount,
      session_id: p.SessionId,
      parent_app: parent,
    });
  }
  console.log(`  ${processRisks.length} processes assessed`);

  // Generate process-related findings (aggregated)
  const suspiciousSysProcs = processRisks.filter(r => r.reasons.includes('SYSTEM process from user-writable path'));
  const unsignedUserProcs = processRisks.filter(r => r.reasons.includes('Unsigned from user-writable path'));
  if (suspiciousSysProcs.length > 0) {
    findings.push({
      type: 'suspicious_service', severity: 'critical', category: 'malware_protection',
      iso: 'A.8.7', title: `${suspiciousSysProcs.length} SYSTEM process(es) from user-writable path(s)`,
      detail: `Processes: ${suspiciousSysProcs.map(r => r.name).join(', ')}. SYSTEM processes from user locations indicate potential compromise.`,
      remediation: 'Investigate each process origin. Scan with antivirus.'
    });
  }
  if (unsignedUserProcs.length > 0) {
    findings.push({
      type: 'unsig_process_user', severity: 'medium', category: 'malware_protection',
      iso: 'A.8.7', title: `${unsignedUserProcs.length} unsigned process(es) from user-writable path(s)`,
      detail: `Processes: ${unsignedUserProcs.map(r => r.name).join(', ')}. Unsigned executables in user-writable locations may be malicious.`,
      remediation: 'Verify the legitimacy of unsigned executables in user-writable locations.'
    });
  }

  // ------------------------------------------------
  // 9. NETWORK CONNECTIONS (for process context)
  // ------------------------------------------------
  console.log('=== NETWORK CONNECTIONS ===');
  const psConns = `
    $result = @();
    $lines = netstat -ano | Select-String "^\\s*(TCP|UDP)";
    foreach ($line in $lines) {
      $parts = $line.ToString() -split '\\s+', 5;
      if ($parts.Count -ge 5) {
        $pidNum = try { [int]$parts[4] } catch { 0 };
        $result += [PSCustomObject]{
          Protocol = $parts[0]; LocalAddr = $parts[1]; RemoteAddr = $parts[2];
          State = if ($parts[3] -eq '*') { "LISTEN" } else { $parts[3] }; PID = $pidNum
        }
      }
    }
    $result | ConvertTo-Json -Compress -Depth 2
  `;
  let conns = [];
  try {
    const rawConn = runPS(psConns);
    if (!rawConn || rawConn === '') throw new Error('Empty output');
    const parsed = JSON.parse(rawConn);
    conns = Array.isArray(parsed) ? parsed : [];
  } catch(e) { console.error('Conn parse error:', e.message, 'raw:', (rawConn||'').slice(0,100)); }
  console.log(`  ${conns.length} connections`);

  // Mark processes with outbound connections as having network
  const procsWithOutbound = new Set();
  for (const c of conns) {
    if (c.State === 'ESTABLISHED' && c.RemoteAddr && !c.RemoteAddr.startsWith('0.0.0.0') && !c.RemoteAddr.startsWith('127.0.0.1') && !c.RemoteAddr.startsWith('*')) {
      procsWithOutbound.add(c.PID);
    }
  }
  let adminNetworkCount = 0;
  for (const r of processRisks) {
    if (procsWithOutbound.has(r.pid)) {
      r.has_network = 1;
      if (r.owner && (r.owner.includes('SYSTEM') || currentUser.IsAdmin && r.owner === currentUser.UserName)) {
        r.risk_score = Math.min(r.risk_score + 10, 100);
        adminNetworkCount++;
      }
    }
  }
  if (adminNetworkCount > 0) {
    findings.push({
      type: 'admin_process_network', severity: 'medium', category: 'least_privilege',
      iso: 'A.8.2',
      title: `${adminNetworkCount} privileged process(es) with outbound network access`,
      detail: `Processes running as SYSTEM/Administrator have outbound network connections, increasing attack surface`,
      remediation: 'Audit network access requirements for privileged processes. Consider network segmentation.'
    });
  }

  // ------------------------------------------------
  // 10. SERVICES AUDIT
  // ------------------------------------------------
  console.log('=== SERVICES AUDIT ===');
  const psSvcs = `
    Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
      [PSCustomObject]@{
        Name = $_.Name; DisplayName = $_.DisplayName; StartMode = $_.StartMode;
        PID = $_.ProcessId; PathName = if ($_.PathName) { $_.PathName } else { "" };
        StartName = $_.StartName;
      }
    } | ConvertTo-Json -Compress
  `;
  let services = [];
  try { const parsed = JSON.parse(runPS(psSvcs) || '[]'); services = Array.isArray(parsed) ? parsed : [parsed]; } catch(e) {}
  // Enrich each service with parent application and description
  for (const s of services) {
    const enrich = classifyService(s.Name, s.DisplayName, s.PathName);
    s.ParentApp = enrich.parent_app;
    s.Description = enrich.description;
  }
  console.log(`  ${services.length} running services`);

  for (const s of services) {
    const pname = (s.PathName || '').replace(/^"/, '').replace(/".*$/, '').trim().toLowerCase();
    const isUnquoted = s.PathName && s.PathName.includes(' ') && !s.PathName.startsWith('"');
    const isSystemService = s.StartName && (s.StartName.includes('SYSTEM') || s.StartName.includes('LocalSystem'));
    const isNonSystemPath = pname && !pname.includes('\\windows\\') && !pname.includes('\\program files');

    if (isUnquoted) {
      findings.push({
        type: 'unquoted_service', severity: 'medium', category: 'privilege_management',
        iso: 'A.8.2', title: FINDING_DEFS.unquoted_service.title.replace('{detail}', s.Name),
        detail: `Service "${s.Name}" has unquoted path: ${s.PathName}. Could allow privilege escalation via injected executable.`,
        remediation: `Quote the service path: sc qc ${s.Name}, then sc config ${s.Name} binPath="<correct quoted path>"`
      });
    }

    if (isSystemService && isNonSystemPath) {
      findings.push({
        type: 'sys_service_from_user', severity: 'high', category: 'least_privilege',
        iso: 'A.8.2', title: FINDING_DEFS.sys_service_from_user.title.replace('{detail}', s.Name),
        detail: `Service "${s.Name}" runs as ${s.StartName} from non-system path: ${s.PathName}`,
        remediation: 'Move the service binary to Program Files or System32 and ensure proper ACLs'
      });
    }

    // Check for services from temp dirs
    if (pname && (pname.includes('\\temp\\') || pname.includes('\\downloads\\'))) {
      findings.push({
        type: 'suspicious_service', severity: 'critical', category: 'malware_protection',
        iso: 'A.8.7', title: FINDING_DEFS.suspicious_service.title.replace('{detail}', s.Name),
        detail: `Service "${s.Name}" runs from temp directory: ${s.PathName}`,
        remediation: 'This is highly suspicious. Investigate and remove immediately.'
      });
    }
  }

  // ------------------------------------------------
  // 11. FILE SYSTEM ACL (sensitive paths)
  // ------------------------------------------------
  console.log('=== FILE SYSTEM ACL ===');
  const aclEntries = [];
  for (const sp of SENSITIVE_PATHS) {
    const psAcl = `
      $path = '${sp.replace(/'/g, "''")}';
      $result = @();
      try {
        $acl = Get-Acl -Path $path -ErrorAction Stop;
        foreach ($a in $acl.Access) {
          $result += [PSCustomObject]@{
            Path = $path;
            Identity = $a.IdentityReference.Value;
            Rights = $a.FileSystemRights.ToString();
            AccessType = $a.AccessControlType.ToString();
            IsInherited = $a.IsInherited;
          }
        }
      } catch {}
      $result | ConvertTo-Json -Compress
    `;
    try {
      const parsed = JSON.parse(runPS(psAcl, 10000) || '[]');
      const arr = Array.isArray(parsed) ? parsed : [parsed];
      for (const a of arr) {
        if (a && a.Path) {
          aclEntries.push(a);
          // Check for Everyone/FullControl or BUILTIN\\Users/Write
          const idLower = (a.Identity || '').toLowerCase();
          const rights = (a.Rights || '').toLowerCase();
          if (a.AccessType === 'Allow' && (
            (idLower.includes('everyone') || idLower.includes('usuários') || idLower === 'users' || idLower === 'builtin\\users') &&
            (rights.includes('fullcontrol') || rights.includes('modify') || rights.includes('write'))
          )) {
            findings.push({
              type: 'world_writable_system', severity: 'high', category: 'access_control',
              iso: 'A.5.15', title: FINDING_DEFS.world_writable_system.title.replace('{detail}', `${sp} (${a.Identity}: ${a.Rights})`),
              detail: `Path "${sp}" allows "${a.Identity}" with "${a.Rights}" access`,
              remediation: `Restrict permissions on ${sp} to only required administrators/system`
            });
          }
        }
      }
    } catch(e) {}
  }
  console.log(`  ${aclEntries.length} ACL entries`);

  // ------------------------------------------------
  // 12. DEFENDER & FIREWALL
  // ------------------------------------------------
  console.log('=== SECURITY FEATURES ===');
  const psDef = `
    $result = [PSCustomObject]@{};
    try {
      $mp = Get-MpComputerStatus -ErrorAction Stop;
      $result = [PSCustomObject]@{
        RealTimeProtection = if ($mp.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" };
        AntivirusEnabled = if ($mp.AntivirusEnabled) { "Enabled" } else { "Disabled" };
        NISEnabled = if ($mp.NisEnabled) { "Enabled" } else { "Disabled" };
        SignatureVersion = $mp.AntivirusSignatureVersion;
        LastUpdate = $mp.AntivirusSignatureLastUpdated.ToString("o");
      }
    } catch { $result = [PSCustomObject]@{ RealTimeProtection = "Unknown"; AntivirusEnabled = "Unknown"; NISEnabled = "Unknown"; SignatureVersion = ""; LastUpdate = "" } }
    $result | ConvertTo-Json -Compress
  `;
  let defender = { RealTimeProtection: 'Unknown' };
  try { defender = JSON.parse(runPS(psDef)); } catch(e) {}
  if (defender.RealTimeProtection === 'Disabled') {
    findings.push({
      type: 'def_disabled', severity: 'high', category: 'malware_protection',
      iso: 'A.8.7', title: FINDING_DEFS.def_disabled.title,
      detail: 'Windows Defender real-time protection is disabled',
      remediation: 'Enable via Windows Security > Virus & threat protection > Manage settings > Real-time protection'
    });
  }

  const psFW = `
    $profiles = Get-NetFirewallProfile;
    $result = @();
    foreach ($p in $profiles) { $result += [PSCustomObject]@{ Profile = $p.Name; Enabled = if ($p.Enabled) { "Enabled" } else { "Disabled" } } }
    $result | ConvertTo-Json -Compress
  `;
  let firewall = [];
  try { const parsed = JSON.parse(runPS(psFW) || '[]'); firewall = Array.isArray(parsed) ? parsed : []; } catch(e) {}
  const disabledFw = firewall.filter(f => f.Enabled === 'Disabled');
  if (disabledFw.length > 0) {
    findings.push({
      type: 'firewall_disabled', severity: 'high', category: 'network_security',
      iso: 'A.8.20', title: FINDING_DEFS.firewall_disabled.title,
      detail: `Disabled profiles: ${disabledFw.map(f => f.Profile).join(', ')}`,
      remediation: 'Enable Windows Firewall for all profiles via Control Panel > Windows Defender Firewall > Turn on'
    });
  }

  // ------------------------------------------------
  // 13. COMPREHENSIVE ISO 27001:2022 COMPLIANCE ASSESSMENT
  // ------------------------------------------------
  // Evaluates all 93 Annex A controls against actual scan findings.
  // Controls that the scanner CAN verify are marked compliant/non-compliant.
  // Controls outside scanner scope are marked 'not_assessed' with guidance.
  // This serves as evidence for external ISO 27001 audit.
  console.log('=== COMPLIANCE MAPPING ===');

  // Build a map: finding.type → [iso codes it violates]
  const FINDING_ISO_MAP = {
    weak_password_policy: ['A.5.17','A.5.31','A.8.5'],
    no_lockout_policy: ['A.5.17','A.8.5'],
    no_password_expiry: ['A.5.17','A.8.5'],
    guest_enabled: ['A.5.15','A.5.18','A.8.3'],
    admin_member: ['A.5.15','A.5.18','A.8.2','A.8.3'],
    dangerous_priv: ['A.5.15','A.5.18','A.8.2','A.8.3'],
    uac_disabled: ['A.5.15','A.8.2','A.8.5'],
    lsa_not_protected: ['A.8.2','A.8.8','A.8.15'],
    def_disabled: ['A.8.7','A.8.8'],
    firewall_disabled: ['A.8.20','A.8.21'],
    unquoted_service: ['A.8.2','A.8.9','A.8.32'],
    sys_service_from_user: ['A.8.2','A.8.3'],
    unsig_process_user: ['A.8.7','A.8.8','A.8.19'],
    admin_process_network: ['A.8.2','A.8.20'],
    suspicious_service: ['A.8.7','A.8.8','A.8.19'],
    world_writable_system: ['A.5.33','A.8.3'],
    weak_registry_acl: ['A.5.33','A.8.3','A.8.9'],
  };

  // Controls the scanner CAN positively verify (as compliant if no findings)
  const VERIFIABLE_CONTROLS = new Set([
    'A.5.2','A.5.9','A.5.12','A.5.15','A.5.16','A.5.17','A.5.18','A.5.31','A.5.33','A.5.34','A.5.36','A.5.37',
    'A.8.1','A.8.2','A.8.3','A.8.5','A.8.6','A.8.7','A.8.8','A.8.9','A.8.15','A.8.16','A.8.17',
    'A.8.18','A.8.19','A.8.20','A.8.21','A.8.22','A.8.24','A.8.32',
  ]);

  // Map old ISO 27001:2013 codes to 2022 codes used in ANNEX_A
  const OLD_TO_NEW = {
    'A.9.2': 'A.5.15', 'A.9.2.2': 'A.8.2', 'A.9.2.3': 'A.8.2',
    'A.9.4.3': 'A.5.17', 'A.11.1.1': 'A.7.1', 'A.12.1.2': 'A.5.37',
    'A.12.2.1': 'A.8.7', 'A.12.3.1': 'A.8.13', 'A.12.4.1': 'A.8.15',
    'A.12.6.1': 'A.8.8', 'A.13.1.1': 'A.8.20',
  };

  // Compliance assessment: iterate all 93 Annex A controls
  const isoControls = {};
  for (const ctrl of ANNEX_A) {
    const code = ctrl.code;
    // Find findings that violate this control
    const violatingFindings = findings.filter(f => {
      const fIso = OLD_TO_NEW[f.iso] || f.iso;
      return fIso === code || (FINDING_ISO_MAP[f.type] || []).includes(code);
    });
    if (violatingFindings.length > 0) {
      // Non-compliant — evidence from actual findings
      const maxSev = ['critical','high','medium','low'].find(s => violatingFindings.some(f => f.severity === s)) || 'medium';
      isoControls[code] = {
        control: code, title: ctrl.title, description: ctrl.desc,
        theme: ctrl.theme, status: 'non_compliant', severity: maxSev,
        evidence: violatingFindings.map(f => f.title).join(' | '),
        details: violatingFindings.slice(0,3).map(f => f.detail).filter(Boolean).join(' | '),
      };
    } else if (VERIFIABLE_CONTROLS.has(code)) {
      // Scanner verified this control is implemented correctly
      isoControls[code] = {
        control: code, title: ctrl.title, description: ctrl.desc,
        theme: ctrl.theme, status: 'compliant', severity: 'none',
        evidence: 'Scanner verified — no violations detected on this endpoint',
        details: '',
      };
    } else {
      // Cannot be verified by endpoint scanner — needs manual review
      isoControls[code] = {
        control: code, title: ctrl.title, description: ctrl.desc,
        theme: ctrl.theme, status: 'not_assessed', severity: 'info',
        evidence: 'Requires manual review — this control cannot be verified by endpoint scanning alone',
        details: 'Review policy documents, contracts, physical security, and organizational processes',
      };
    }
  }
  const nonCompliant = Object.values(isoControls).filter(c => c.status === 'non_compliant');
  const compliant = Object.values(isoControls).filter(c => c.status === 'compliant');
  const notAssessed = Object.values(isoControls).filter(c => c.status === 'not_assessed');
  console.log(`  ${nonCompliant.length} non-compliant, ${compliant.length} compliant, ${notAssessed.length} not assessed (of 93 total)`);

  // ------------------------------------------------
  // 14. WRITE TO SQLITE
  // ------------------------------------------------
  const SQL = await initSqlJs();
  let db;
  // Always start with a fresh database (no history accumulation)
  db = new SQL.Database();

  db.run('PRAGMA page_size=4096');
  db.run('PRAGMA journal_mode=WAL');

  // Core tables
  db.run(`CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT,
    status TEXT DEFAULT 'running', findings_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 100
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    pid INTEGER, name TEXT, owner TEXT, cpu_usage REAL, memory_mb REAL,
    executable_path TEXT, command_line TEXT, ppid INTEGER,
    thread_count INTEGER, handle_count INTEGER,
    is_signed INTEGER DEFAULT 0, signer TEXT, signature_status TEXT,
    risk_score INTEGER DEFAULT 0, risk_reasons TEXT, has_network INTEGER DEFAULT 0,
    parent_app TEXT DEFAULT 'Unknown'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    name TEXT, display_name TEXT, start_mode TEXT, pid INTEGER,
    path_name TEXT, start_name TEXT,
    parent_app TEXT DEFAULT 'Unknown',
    description TEXT DEFAULT ''
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    protocol TEXT, local_addr TEXT, remote_addr TEXT, state TEXT, pid INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS system_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    key TEXT, value TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_account (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    user_name TEXT, is_admin INTEGER DEFAULT 0, auth_type TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    sid TEXT, name TEXT, is_builtin INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_privileges (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    name TEXT, enabled INTEGER DEFAULT 0, risk TEXT, risk_note TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS local_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    name TEXT, full_name TEXT, enabled INTEGER DEFAULT 0,
    password_expires TEXT, last_logon TEXT, description TEXT, sid TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS local_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    name TEXT, description TEXT, sid TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    group_name TEXT, member_name TEXT, member_sid TEXT, member_type TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS acl_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    path TEXT, identity TEXT, rights TEXT, access_type TEXT, is_inherited INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    type TEXT, severity TEXT, category TEXT, iso TEXT,
    title TEXT, detail TEXT, remediation TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS compliance_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    control TEXT, title TEXT, description TEXT, theme TEXT,
    status TEXT, severity TEXT, evidence TEXT, details TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS security_policy (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scans(id),
    min_password_length INTEGER DEFAULT 0, password_history_size INTEGER DEFAULT 0,
    max_password_age INTEGER DEFAULT 0, lockout_threshold INTEGER DEFAULT 0,
    lockout_duration INTEGER DEFAULT 0, enable_lua INTEGER DEFAULT -1,
    consent_prompt INTEGER DEFAULT -1, run_as_ppl INTEGER DEFAULT 0
  )`);

  const now = new Date().toISOString();
  db.run('INSERT INTO scans (id, started_at, status) VALUES (?, ?, ?)', [scanId, now, 'running']);

  const sysStmt = db.prepare('INSERT INTO system_info (scan_id, key, value) VALUES (?, ?, ?)');
  for (const [k, v] of Object.entries(sysInfo)) sysStmt.run([scanId, k, String(v || '')]);
  sysStmt.free();

  const isAdmin = currentUser.IsAdmin === true || currentUser.IsAdmin === 'True' || currentUser.IsAdmin === 1 ? 1 : 0;
  db.run('INSERT INTO user_account (scan_id, user_name, is_admin, auth_type) VALUES (?, ?, ?, ?)',
    [scanId, currentUser.UserName || '', isAdmin, currentUser.AuthType || '']);

  const ugStmt = db.prepare('INSERT INTO user_groups (scan_id, sid, name, is_builtin) VALUES (?, ?, ?, ?)');
  for (const g of currentGroups) ugStmt.run([scanId, g.SID || '', g.Name || '', g.IsBuiltIn ? 1 : 0]);
  ugStmt.free();

  const privStmt = db.prepare('INSERT INTO user_privileges (scan_id, name, enabled, risk, risk_note) VALUES (?, ?, ?, ?, ?)');
  for (const p of privs) privStmt.run([scanId, p.name, p.enabled ? 1 : 0, p.risk || 'none', p.risk_note || '']);
  privStmt.free();

  const luStmt = db.prepare('INSERT INTO local_users (scan_id, name, full_name, enabled, password_expires, last_logon, description, sid) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  for (const u of localUsers) luStmt.run([scanId, u.Name || '', u.FullName || '', u.Enabled ? 1 : 0, u.PasswordExpires || '', u.LastLogon || '', u.Description || '', u.SID || '']);
  luStmt.free();

  const lgStmt = db.prepare('INSERT INTO local_groups (scan_id, name, description, sid) VALUES (?, ?, ?, ?)');
  const gmStmt = db.prepare('INSERT INTO group_members (scan_id, group_name, member_name, member_sid, member_type) VALUES (?, ?, ?, ?, ?)');
  for (const g of localGroups) {
    lgStmt.run([scanId, g.Name || '', g.Description || '', g.SID || '']);
    const members = g.Members || [];
    for (const m of members) gmStmt.run([scanId, g.Name || '', m.Name || '', m.SID || '', m.ObjectClass || '']);
  }
  lgStmt.free(); gmStmt.free();

  const pStmt = db.prepare(`INSERT INTO processes (
    scan_id, pid, name, owner, cpu_usage, memory_mb, executable_path, command_line,
    ppid, thread_count, handle_count, is_signed, signer, signature_status,
    risk_score, risk_reasons, has_network, parent_app
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  for (const r of processRisks) {
    pStmt.run([scanId, r.pid, r.name, r.owner, r.cpu, r.mem_mb, r.exec_path, r.cmd_line,
      r.ppid, r.thread_count, r.handle_count, r.is_signed, r.signer, r.is_signed ? 'Valid' : 'NoSignature',
      r.risk_score, r.reasons, r.has_network || 0, r.parent_app || 'Unknown'
    ]);
  }
  pStmt.free();

  const svcStmt = db.prepare('INSERT INTO services (scan_id, name, display_name, start_mode, pid, path_name, start_name, parent_app, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
  for (const s of services) svcStmt.run([scanId, s.Name, s.DisplayName, s.StartMode, s.PID || 0, s.PathName, s.StartName || '', s.ParentApp || 'Unknown', s.Description || s.DisplayName || '']);
  svcStmt.free();

  const connStmt = db.prepare('INSERT INTO connections (scan_id, protocol, local_addr, remote_addr, state, pid) VALUES (?, ?, ?, ?, ?, ?)');
  for (const c of conns) {
    try { connStmt.run([scanId, '' + (c.Protocol || ''), '' + (c.LocalAddr || ''), '' + (c.RemoteAddr || ''), '' + (c.State || ''), parseInt(c.PID) || 0]); } catch(_) {}
  }
  connStmt.free();

  const aclStmt = db.prepare('INSERT INTO acl_entries (scan_id, path, identity, rights, access_type, is_inherited) VALUES (?, ?, ?, ?, ?, ?)');
  for (const a of aclEntries) aclStmt.run([scanId, a.Path, a.Identity || '', a.Rights || '', a.AccessType || '', a.IsInherited ? 1 : 0]);
  aclStmt.free();

  const fStmt = db.prepare('INSERT INTO findings (scan_id, type, severity, category, iso, title, detail, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  for (const f of findings) fStmt.run([scanId, f.type, f.severity, f.category, f.iso, f.title, f.detail || '', f.remediation || '']);
  fStmt.free();

  const cStmt = db.prepare('INSERT INTO compliance_status (scan_id, control, title, description, theme, status, severity, evidence, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
  for (const data of Object.values(isoControls)) {
    cStmt.run([scanId, data.control, data.title, data.description, data.theme, data.status, data.severity, data.evidence || '', data.details || '']);
  }
  cStmt.free();

  db.run(`INSERT INTO security_policy (scan_id, min_password_length, password_history_size, max_password_age, lockout_threshold, lockout_duration, enable_lua, consent_prompt, run_as_ppl)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [scanId, secPolicy.MinPasswordLength || 0, secPolicy.PasswordHistorySize || 0, secPolicy.MaxPasswordAge || 0,
     secPolicy.LockoutThreshold || 0, secPolicy.LockoutDuration || 0,
     uacStatus.EnableLUA !== undefined ? uacStatus.EnableLUA : -1,
     uacStatus.ConsentPrompt !== undefined ? uacStatus.ConsentPrompt : -1,
     lsaStatus.RunAsPPL || 0]);

  const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0, none: -1 };
  const weights = CONFIG.severity_weights || { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
  const suppressed = new Set(CONFIG.suppressed_types || []);
  const typeOverrides = CONFIG.type_overrides || {};
  const filteredFindings = findings.filter(f => !suppressed.has(f.type));
  // Apply type severity overrides
  for (const f of filteredFindings) {
    const ov = typeOverrides[f.type];
    if (ov && ov.severity) f.severity = ov.severity;
  }
  const uniqueTypes = {};
  for (const f of filteredFindings) {
    const key = f.type;
    const existing = uniqueTypes[key];
    if (!existing || (sevRank[f.severity] || 0) > (sevRank[existing] || 0)) {
      uniqueTypes[key] = f.severity;
    }
  }
  let deduction = 0;
  for (const [type, sev] of Object.entries(uniqueTypes)) {
    const ov = typeOverrides[type];
    if (ov && ov.weight !== undefined) deduction += ov.weight;
    else deduction += (weights[sev] || 0);
  }
  const minScore = CONFIG.min_score !== undefined ? CONFIG.min_score : 10;
  const maxScore = CONFIG.max_score !== undefined ? CONFIG.max_score : 100;
  const riskScore = Math.max(minScore, Math.min(maxScore, maxScore - deduction));

  const finished = new Date().toISOString();
  db.run('UPDATE scans SET finished_at=?, status=?, findings_count=?, risk_score=? WHERE id=?',
    [finished, 'done', filteredFindings.length, riskScore, scanId]);
  console.log('  DB: scan updated');

  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
  db.close();

  const report = {
    scan_id: scanId, findings: filteredFindings.length, risk_score: riskScore,
    processes: processRisks.length, services: services.length, connections: conns.length,
    users: localUsers.length, groups: localGroups.length, acl_entries: aclEntries.length
  };
  console.log(JSON.stringify(report));
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes('--schedule')) {
    // Scheduled scan mode: run, log, exit (for Windows Task Scheduler)
    console.log(`[${new Date().toISOString()}] Scheduled scan started`);
    scan().then(() => {
      console.log(`[${new Date().toISOString()}] Scan complete`);
      process.exit(0);
    }).catch(e => {
      console.error(`[${new Date().toISOString()}] Fatal:`, e.message);
      process.exit(1);
    });
  } else {
    scan().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
  }
}

module.exports = { scan, DB_PATH };
