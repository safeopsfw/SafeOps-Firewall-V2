; ═══════════════════════════════════════════════════════════════════════════
;  SafeOps Network Security Platform — Complete Installer
;  Inno Setup 6.x
;
;  This is the SINGLE installer for all SafeOps components:
;    1. PostgreSQL 16 (database server)
;    2. Node.js 20 LTS (JavaScript runtime)
;    3. WinPkFilter driver (NDIS packet capture — required for SafeOps Engine)
;    4. PostgreSQL databases + users
;    5. Database schemas (15 SQL files across 3 databases)
;    6. Default admin user (admin/safeops123)
;    7. Elasticsearch 8.11 (SIEM log store)
;    8. Kibana 8.11 (SIEM dashboard)
;    9. Node.js UI + backend dependencies
;   10. SAFEOPS_HOME env var, system PATH, install-paths.json, README
;
;  ALL SafeOps executables are bundled inside this installer.
;
;  Build:
;    1. Install Inno Setup 6 from https://jrsoftware.org/isinfo.php
;    2. Open this file in Inno Setup
;    3. Press F9 (or Build → Compile)
;    4. Output: output\SafeOps-Setup.exe
;
;  Requirements:
;    • Internet connection (downloads PostgreSQL, Node.js, WinPkFilter, ES, Kibana)
;    • Windows 10/11 x64
;    • 4 GB free disk space minimum (ES + Kibana are large)
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
OutputBaseFilename=SafeOps-Complete-Setup-Uncompressed
Compression=none
SolidCompression=no
WizardStyle=modern

; Always require admin
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline

; Metadata (shown in Add/Remove Programs)
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

; ── Tasks (optional user choices) ──────────────────────────────────────────
[Tasks]
Name: "desktopicon";  Description: "Create Desktop shortcut for SafeOps Launcher"; \
    GroupDescription: "Shortcuts:"
Name: "startmenu";   Description: "Create Start Menu shortcuts"; \
    GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "autolaunch";  Description: "Launch SafeOps after installation finishes"; \
    GroupDescription: "After install:"; Flags: checkedonce
Name: "openreadme";  Description: "Open Getting Started guide after installation"; \
    GroupDescription: "After install:"; Flags: checkedonce

; ── Files: PowerShell helper (temp, auto-deleted) ──────────────────────────
[Files]
Source: "{#PSHelper}"; DestDir: "{tmp}"; Flags: deleteafterinstall

; ─── SafeOps GUI Launcher ──────────────────────────────────────────────────
Source: "..\bin\SafeOps.exe"; DestDir: "{app}\bin"; \
    Flags: ignoreversion

; ─── SafeOps CLI Launcher ──────────────────────────────────────────────────
Source: "..\bin\SafeOps-Launcher.exe"; DestDir: "{app}\bin"; \
    Flags: ignoreversion skipifsourcedoesntexist

; ─── SafeOps Engine (NDIS packet capture) ──────────────────────────────────
Source: "..\bin\safeops-engine\*"; DestDir: "{app}\bin\safeops-engine"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Firewall Engine ───────────────────────────────────────────────────────
Source: "..\bin\firewall-engine\*"; DestDir: "{app}\bin\firewall-engine"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── NIC Management ────────────────────────────────────────────────────────
Source: "..\bin\nic_management\*"; DestDir: "{app}\bin\nic_management"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── DHCP Monitor ──────────────────────────────────────────────────────────
Source: "..\bin\dhcp_monitor\*"; DestDir: "{app}\bin\dhcp_monitor"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Step CA (certificate authority) ──────────────────────────────────────
; Exclude BadgerDB vlog (2GB dev data) — Step-CA creates fresh DB on first run
Source: "..\bin\step-ca\*"; DestDir: "{app}\bin\step-ca"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "db\*.vlog"

; ─── Captive Portal ────────────────────────────────────────────────────────
Source: "..\bin\captive_portal\*"; DestDir: "{app}\bin\captive_portal"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── Network Logger ────────────────────────────────────────────────────────
Source: "..\bin\network-logger\*"; DestDir: "{app}\bin\network-logger"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── SIEM Forwarder ────────────────────────────────────────────────────────
Source: "..\bin\siem-forwarder\*"; DestDir: "{app}\bin\siem-forwarder"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Threat Intel ──────────────────────────────────────────────────────────
Source: "..\bin\threat_intel\*"; DestDir: "{app}\bin\threat_intel"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── SIEM scripts (Elasticsearch + Kibana launchers) ──────────────────────
Source: "..\bin\siem\*"; DestDir: "{app}\bin\siem"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ─── Database schemas ──────────────────────────────────────────────────────
Source: "..\database\*"; DestDir: "{app}\database"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ─── Web UI source (React + Vite) ─────────────────────────────────────────
Source: "..\src\ui\dev\*"; DestDir: "{app}\src\ui\dev"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "node_modules\*,dist\*,.cache\*"

; ─── Node.js backend ───────────────────────────────────────────────────────
Source: "..\backend\*"; DestDir: "{app}\backend"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "node_modules\*"

; ── Shortcuts ──────────────────────────────────────────────────────────────
[Icons]
; Desktop — SafeOps Launcher (exe has requireAdministrator manifest, auto-elevates)
Name: "{autodesktop}\SafeOps Launcher"; \
    Filename: "{app}\bin\SafeOps.exe"; \
    WorkingDir: "{app}\bin"; \
    IconFilename: "{app}\bin\SafeOps.exe"; \
    Comment: "SafeOps Network Security Platform"; \
    Tasks: desktopicon

; Start Menu
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
    Comment: "How to use SafeOps — read this first!"; \
    Tasks: startmenu

Name: "{group}\Uninstall SafeOps"; \
    Filename: "{uninstallexe}"; \
    Tasks: startmenu

; ── Registry ───────────────────────────────────────────────────────────────
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

; ── Installation steps ─────────────────────────────────────────────────────
[Run]
; Step 1: Install PostgreSQL 16
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 1 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing PostgreSQL 16 (downloading ~200MB)..."; \
    Flags: runhidden waituntilterminated

; Step 2: Install Node.js 20 LTS
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 2 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing Node.js 20 LTS..."; \
    Flags: runhidden waituntilterminated

; Step 3: Install WinPkFilter driver
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 3 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing WinPkFilter NDIS driver (required for packet capture)..."; \
    Flags: runhidden waituntilterminated

; Step 4: Configure PostgreSQL databases + users
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 4 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Configuring PostgreSQL databases and users..."; \
    Flags: runhidden waituntilterminated

; Step 5: Run all database schema files
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 5 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Creating database schemas (15 SQL files)..."; \
    Flags: runhidden waituntilterminated

; Step 6: Create default admin user
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 6 -InstallDir ""{app}"" -BinDir ""{app}\bin"" -Username ""admin"" -Password ""safeops123"""; \
    StatusMsg: "Creating default admin user (admin / safeops123)..."; \
    Flags: runhidden waituntilterminated

; Step 7: Install Elasticsearch 8.11
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 7 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Downloading and extracting Elasticsearch 8.11 (~700MB, may take several minutes)..."; \
    Flags: runhidden waituntilterminated

; Step 8: Install Kibana 8.11
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 8 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Downloading and extracting Kibana 8.11 (~700MB, may take several minutes)..."; \
    Flags: runhidden waituntilterminated

; Step 9: Install npm dependencies (React UI + Node backend)
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 9 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing Node.js dependencies for web UI and backend..."; \
    Flags: runhidden waituntilterminated

; Step 10: Set env vars, write install-paths.json, verify, write README
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 10 -InstallDir ""{app}"" -BinDir ""{app}\bin"" -Username ""admin"" -Password ""safeops123"""; \
    StatusMsg: "Finalizing installation and writing configuration..."; \
    Flags: runhidden waituntilterminated

; Post-install: open README (optional)
Filename: "notepad.exe"; \
    Parameters: "{app}\IMPORTANT-README.txt"; \
    Description: "View Getting Started guide"; \
    Flags: nowait postinstall skipifsilent; \
    Tasks: openreadme

; Post-install: launch SafeOps (optional)
Filename: "{app}\bin\SafeOps.exe"; \
    Description: "Launch SafeOps now"; \
    Flags: nowait postinstall skipifsilent runascurrentuser; \
    Tasks: autolaunch

; ── Uninstaller ────────────────────────────────────────────────────────────
[UninstallRun]
; Kill all SafeOps processes first
Filename: "taskkill"; Parameters: "/IM SafeOps.exe /F /T";              Flags: runhidden; RunOnceId: "KillMain"
Filename: "taskkill"; Parameters: "/IM firewall-engine.exe /F /T";      Flags: runhidden; RunOnceId: "KillFW"
Filename: "taskkill"; Parameters: "/IM safeops-engine.exe /F /T";       Flags: runhidden; RunOnceId: "KillEngine"
Filename: "taskkill"; Parameters: "/IM step-ca.exe /F /T";              Flags: runhidden; RunOnceId: "KillCA"
Filename: "taskkill"; Parameters: "/IM nic_management.exe /F /T";       Flags: runhidden; RunOnceId: "KillNIC"
Filename: "taskkill"; Parameters: "/IM dhcp_monitor.exe /F /T";         Flags: runhidden; RunOnceId: "KillDHCP"
Filename: "taskkill"; Parameters: "/IM captive_portal.exe /F /T";       Flags: runhidden; RunOnceId: "KillPortal"
Filename: "taskkill"; Parameters: "/IM network-logger.exe /F /T";       Flags: runhidden; RunOnceId: "KillLogger"
Filename: "taskkill"; Parameters: "/IM siem-forwarder.exe /F /T";       Flags: runhidden; RunOnceId: "KillSIEM"

; Remove startup scheduled task
Filename: "powershell.exe"; \
    Parameters: "-Command ""Unregister-ScheduledTask -TaskName 'SafeOps Launcher' -TaskPath '\SafeOps\' -Confirm:$false -ErrorAction SilentlyContinue"""; \
    Flags: runhidden; RunOnceId: "RemoveTask"

; Remove SAFEOPS_HOME env var
Filename: "powershell.exe"; \
    Parameters: "-Command ""[System.Environment]::SetEnvironmentVariable('SAFEOPS_HOME', $null, 'Machine')"""; \
    Flags: runhidden; RunOnceId: "RemoveEnv"

[UninstallDelete]
; Remove install data directory
Type: filesandordirs; Name: "{commonappdata}\SafeOps"
; Remove install directory (app was installed here)
Type: filesandordirs; Name: "{app}"

; ── Custom wizard pages ────────────────────────────────────────────────────
[Code]

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'SafeOps Network Security Platform v{#AppVersion}' + #13#10 + #13#10 +
    'This installer will:' + #13#10 +
    '  1. Install PostgreSQL 16 (database server)' + #13#10 +
    '  2. Install Node.js 20 LTS (JavaScript runtime)' + #13#10 +
    '  3. Install WinPkFilter driver (packet capture)' + #13#10 +
    '  4. Set up databases + schemas (3 databases, 15 SQL files)' + #13#10 +
    '  5. Create admin user: admin / safeops123' + #13#10 +
    '  6. Download Elasticsearch 8.11 (SIEM)' + #13#10 +
    '  7. Download Kibana 8.11 (SIEM dashboard)' + #13#10 +
    '  8. Install all SafeOps executables and web UI' + #13#10 + #13#10 +
    '⚠ REQUIREMENTS:' + #13#10 +
    '  • Internet connection required (downloads ~2GB)' + #13#10 +
    '  • Windows 10/11 x64' + #13#10 +
    '  • ~4 GB free disk space' + #13#10 +
    '  • Administrator account' + #13#10 + #13#10 +
    'Total installation time: 15-30 minutes';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if CurPageID = wpWelcome then begin
    if MsgBox(
      'SafeOps will download PostgreSQL, Node.js, WinPkFilter, Elasticsearch, and Kibana.' + #13#10 +
      'This requires an active internet connection and may take 15-30 minutes.' + #13#10 + #13#10 +
      'Continue with installation?',
      mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then begin
    // Nothing extra needed — all setup is handled by PowerShell steps
  end;
end;
