; ═══════════════════════════════════════════════════════════════════════════
;  SafeOps Dependencies Installer
;  Downloads and installs: PostgreSQL 16, Node.js 20, WinPkFilter,
;  Elasticsearch 8.11, Kibana 8.11, DB schemas + admin user
;
;  Run this FIRST on a fresh machine, then run SafeOps-App-Setup.exe
;
;  Build: ISCC "SafeOps-Dependencies-Setup.iss"
; ═══════════════════════════════════════════════════════════════════════════

#define AppName       "SafeOps Dependencies"
#define AppVersion    "1.0.0"
#define AppPublisher  "SafeOps"
#define AppURL        "https://safeops.local"
#define DefaultDir    "C:\Program Files\SafeOps"
#define PSHelper      "SafeOps-Install-Helper.ps1"

[Setup]
AppId={{C0FFEE01-SAFE-0PS0-DEPS-000000000001}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
DefaultDirName={#DefaultDir}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\release
OutputBaseFilename=SafeOps-Dependencies-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=SafeOps Dependencies Installer
VersionInfoCopyright=Copyright 2026 SafeOps
UninstallDisplayName={#AppName}
CreateUninstallRegKey=no
ChangesEnvironment=yes

; Icon and wizard branding
SetupIconFile=safeops.ico
WizardImageFile=wizard-sidebar.bmp
WizardSmallImageFile=wizard-small.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ── Files ────────────────────────────────────────────────────────────────
[Files]
Source: "{#PSHelper}"; DestDir: "{tmp}"; Flags: deleteafterinstall

; ─── Database schemas (needed for Step 5) ────────────────────────────────
Source: "..\database\*"; DestDir: "{app}\database"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ── Installation steps (dependencies only: 1-8) ─────────────────────────
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
    StatusMsg: "Downloading and extracting Elasticsearch 8.11 (~700MB)..."; \
    Flags: runhidden waituntilterminated

; Step 8: Install Kibana 8.11
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#PSHelper}"" -Step 8 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Downloading and extracting Kibana 8.11 (~700MB)..."; \
    Flags: runhidden waituntilterminated

; ── Custom wizard pages ──────────────────────────────────────────────────
[Code]
procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'SafeOps Dependencies Installer v{#AppVersion}' + #13#10 + #13#10 +
    'This installer downloads and sets up:' + #13#10 +
    '  1. PostgreSQL 16 (database server)' + #13#10 +
    '  2. Node.js 20 LTS (JavaScript runtime)' + #13#10 +
    '  3. WinPkFilter driver (packet capture)' + #13#10 +
    '  4. Databases + schemas (3 databases, 15 SQL files)' + #13#10 +
    '  5. Default admin user: admin / safeops123' + #13#10 +
    '  6. Elasticsearch 8.11 (SIEM)' + #13#10 +
    '  7. Kibana 8.11 (SIEM dashboard)' + #13#10 + #13#10 +
    'REQUIREMENTS:' + #13#10 +
    '  - Internet connection (~2GB downloads)' + #13#10 +
    '  - Windows 10/11 x64' + #13#10 +
    '  - ~4 GB free disk space' + #13#10 +
    '  - Administrator account' + #13#10 + #13#10 +
    'Run SafeOps-App-Setup.exe AFTER this completes.';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpWelcome then begin
    if MsgBox(
      'This will download PostgreSQL, Node.js, WinPkFilter, Elasticsearch, and Kibana.' + #13#10 +
      'Requires internet connection. May take 15-30 minutes.' + #13#10 + #13#10 +
      'Continue?',
      mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
    end;
  end;
end;
