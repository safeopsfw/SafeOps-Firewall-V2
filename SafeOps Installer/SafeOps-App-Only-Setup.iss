; ═══════════════════════════════════════════════════════════════════════════
;  SafeOps Application Installer (App Only)
;  Installs SafeOps binaries, web UI, backend, shortcuts, scheduled task
;
;  Prerequisites: Run SafeOps-Dependencies-Setup.exe FIRST
;  (PostgreSQL, Node.js, WinPkFilter, ES, Kibana must already be installed)
;
;  Build: ISCC "SafeOps-App-Only-Setup.iss"
; ═══════════════════════════════════════════════════════════════════════════

#define AppName       "SafeOps"
#define AppVersion    "1.0.0"
#define AppPublisher  "SafeOps"
#define AppURL        "https://safeops.local"
#define DefaultDir    "C:\Program Files\SafeOps"
#define PSHelper      "SafeOps-Install-Helper.ps1"

[Setup]
AppId={{C0FFEE01-SAFE-0PS0-SECU-RITY00000001}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
DefaultDirName={#DefaultDir}
DefaultGroupName={#AppName}
DisableProgramGroupPage=no
OutputDir=..\release
OutputBaseFilename=SafeOps-App-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=SafeOps Network Security Platform
VersionInfoCopyright=Copyright 2026 SafeOps
UninstallDisplayName={#AppName} Network Security Platform
UninstallDisplayIcon={app}\bin\SafeOps.exe
CreateUninstallRegKey=yes
ChangesEnvironment=yes
ChangesAssociations=no

; Icon and wizard branding
SetupIconFile=safeops.ico
WizardImageFile=wizard-sidebar.bmp
WizardSmallImageFile=wizard-small.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ── Tasks ────────────────────────────────────────────────────────────────
[Tasks]
Name: "desktopicon";  Description: "Create Desktop shortcut for SafeOps Launcher"; \
    GroupDescription: "Shortcuts:"
Name: "startmenu";   Description: "Create Start Menu shortcuts"; \
    GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "autolaunch";  Description: "Launch SafeOps after installation finishes"; \
    GroupDescription: "After install:"; Flags: checkedonce
Name: "openreadme";  Description: "Open Getting Started guide after installation"; \
    GroupDescription: "After install:"; Flags: checkedonce

; ── Files ────────────────────────────────────────────────────────────────
[Files]
Source: "{#PSHelper}"; DestDir: "{tmp}"; Flags: deleteafterinstall

; ─── SafeOps GUI Launcher ───────────────────────────────────────────────
Source: "..\bin\SafeOps.exe"; DestDir: "{app}\bin"; \
    Flags: ignoreversion
Source: "..\bin\icon.ico"; DestDir: "{app}\bin"; \
    Flags: ignoreversion skipifsourcedoesntexist

; ─── SafeOps CLI Launcher ───────────────────────────────────────────────
Source: "..\bin\SafeOps-Launcher.exe"; DestDir: "{app}\bin"; \
    Flags: ignoreversion skipifsourcedoesntexist

; ─── SafeOps Engine (NDIS packet capture) ───────────────────────────────
Source: "..\bin\safeops-engine\*"; DestDir: "{app}\bin\safeops-engine"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Firewall Engine ────────────────────────────────────────────────────
Source: "..\bin\firewall-engine\*"; DestDir: "{app}\bin\firewall-engine"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── NIC Management ─────────────────────────────────────────────────────
Source: "..\bin\nic_management\*"; DestDir: "{app}\bin\nic_management"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── DHCP Monitor ───────────────────────────────────────────────────────
Source: "..\bin\dhcp_monitor\*"; DestDir: "{app}\bin\dhcp_monitor"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Step CA (certificate authority) ────────────────────────────────────
Source: "..\bin\step-ca\*"; DestDir: "{app}\bin\step-ca"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "db\*.vlog"

; ─── Captive Portal ─────────────────────────────────────────────────────
Source: "..\bin\captive_portal\*"; DestDir: "{app}\bin\captive_portal"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── Network Logger ─────────────────────────────────────────────────────
Source: "..\bin\network-logger\*"; DestDir: "{app}\bin\network-logger"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── SIEM Forwarder ─────────────────────────────────────────────────────
Source: "..\bin\siem-forwarder\*"; DestDir: "{app}\bin\siem-forwarder"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Threat Intel ───────────────────────────────────────────────────────
Source: "..\bin\threat_intel\*"; DestDir: "{app}\bin\threat_intel"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── SIEM scripts ───────────────────────────────────────────────────────
Source: "..\bin\siem\*"; DestDir: "{app}\bin\siem"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── Database schemas ───────────────────────────────────────────────────
Source: "..\database\*"; DestDir: "{app}\database"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Web UI source (React + Vite) ──────────────────────────────────────
Source: "..\src\ui\dev\*"; DestDir: "{app}\src\ui\dev"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "node_modules\*,dist\*,.cache\*"

; ─── Node.js backend ────────────────────────────────────────────────────
Source: "..\backend\*"; DestDir: "{app}\backend"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "node_modules\*"

; ── Shortcuts ────────────────────────────────────────────────────────────
[Icons]
Name: "{autodesktop}\SafeOps Launcher"; \
    Filename: "{app}\bin\SafeOps.exe"; \
    WorkingDir: "{app}\bin"; \
    IconFilename: "{app}\bin\SafeOps.exe"; \
    Comment: "SafeOps Network Security Platform"; \
    Tasks: desktopicon

Name: "{group}\SafeOps Launcher"; \
    Filename: "{app}\bin\SafeOps.exe"; \
    WorkingDir: "{app}\bin"; \
    Comment: "Open SafeOps management interface"; \
    Tasks: startmenu

Name: "{group}\SafeOps Web Console"; \
    Filename: "http://localhost:3001"; \
    Comment: "Open web dashboard (launch SafeOps first)"; \
    Tasks: startmenu

Name: "{group}\Getting Started Guide"; \
    Filename: "{app}\IMPORTANT-README.txt"; \
    Comment: "How to use SafeOps"; \
    Tasks: startmenu

Name: "{group}\Uninstall SafeOps"; \
    Filename: "{uninstallexe}"; \
    Tasks: startmenu

; ── Registry ─────────────────────────────────────────────────────────────
[Registry]
Root: HKLM; Subkey: "Software\SafeOps"; \
    ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; \
    Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\SafeOps"; \
    ValueType: string; ValueName: "BinDir"; ValueData: "{app}\bin"; \
    Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\SafeOps"; \
    ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"; \
    Flags: uninsdeletekey

; ── Installation steps (app setup: npm + env/paths) ─────────────────────
[Run]
; Step 9: Install npm dependencies
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 9 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing Node.js dependencies for web UI and backend..."; \
    Flags: runhidden waituntilterminated

; Step 10: Set env vars, paths, scheduled task, README
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 10 -InstallDir ""{app}"" -BinDir ""{app}\bin"" -Username ""admin"" -Password ""safeops123"""; \
    StatusMsg: "Finalizing installation and writing configuration..."; \
    Flags: runhidden waituntilterminated

; Post-install: open README
Filename: "notepad.exe"; \
    Parameters: "{app}\IMPORTANT-README.txt"; \
    Description: "View Getting Started guide"; \
    Flags: nowait postinstall skipifsilent; \
    Tasks: openreadme

; Post-install: launch SafeOps
Filename: "{app}\bin\SafeOps.exe"; \
    Description: "Launch SafeOps now"; \
    Flags: nowait postinstall skipifsilent runascurrentuser; \
    Tasks: autolaunch

; ── Uninstaller ──────────────────────────────────────────────────────────
[UninstallRun]
Filename: "taskkill"; Parameters: "/IM SafeOps.exe /F /T";              Flags: runhidden; RunOnceId: "KillMain"
Filename: "taskkill"; Parameters: "/IM firewall-engine.exe /F /T";      Flags: runhidden; RunOnceId: "KillFW"
Filename: "taskkill"; Parameters: "/IM safeops-engine.exe /F /T";       Flags: runhidden; RunOnceId: "KillEngine"
Filename: "taskkill"; Parameters: "/IM step-ca.exe /F /T";              Flags: runhidden; RunOnceId: "KillCA"
Filename: "taskkill"; Parameters: "/IM nic_management.exe /F /T";       Flags: runhidden; RunOnceId: "KillNIC"
Filename: "taskkill"; Parameters: "/IM dhcp_monitor.exe /F /T";         Flags: runhidden; RunOnceId: "KillDHCP"
Filename: "taskkill"; Parameters: "/IM captive_portal.exe /F /T";       Flags: runhidden; RunOnceId: "KillPortal"
Filename: "taskkill"; Parameters: "/IM network-logger.exe /F /T";       Flags: runhidden; RunOnceId: "KillLogger"
Filename: "taskkill"; Parameters: "/IM siem-forwarder.exe /F /T";       Flags: runhidden; RunOnceId: "KillSIEM"

Filename: "powershell.exe"; \
    Parameters: "-Command ""Unregister-ScheduledTask -TaskName 'SafeOps Launcher' -TaskPath '\SafeOps\' -Confirm:$false -ErrorAction SilentlyContinue"""; \
    Flags: runhidden; RunOnceId: "RemoveTask"

Filename: "powershell.exe"; \
    Parameters: "-Command ""[System.Environment]::SetEnvironmentVariable('SAFEOPS_HOME', $null, 'Machine')"""; \
    Flags: runhidden; RunOnceId: "RemoveEnv"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\SafeOps"
Type: filesandordirs; Name: "{app}"

; ── Custom wizard pages ──────────────────────────────────────────────────
[Code]
procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'SafeOps Application Installer v{#AppVersion}' + #13#10 + #13#10 +
    'This installs all SafeOps components:' + #13#10 +
    '  - SafeOps Desktop Launcher (system tray)' + #13#10 +
    '  - SafeOps Engine (NDIS packet capture)' + #13#10 +
    '  - Firewall Engine (8-stage detection pipeline)' + #13#10 +
    '  - Web Dashboard (React + Node.js backend)' + #13#10 +
    '  - NIC Management, DHCP Monitor, Captive Portal' + #13#10 +
    '  - Step-CA (certificate authority)' + #13#10 +
    '  - Network Logger, SIEM Forwarder, Threat Intel' + #13#10 + #13#10 +
    'PREREQUISITES (install these first):' + #13#10 +
    '  - PostgreSQL 16' + #13#10 +
    '  - Node.js 20 LTS' + #13#10 +
    '  - WinPkFilter driver' + #13#10 + #13#10 +
    'Made by Arjun Mishra, Hari Krishan & Raghav SOM';
end;
