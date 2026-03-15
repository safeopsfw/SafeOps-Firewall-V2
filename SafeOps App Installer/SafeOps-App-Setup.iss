; SafeOps Application Installer (EXE 2)
; Inno Setup 6.x Script
;
; This is the MAIN SafeOps installer. It:
;   1. Optionally runs the Dependencies Installer first (EXE 1)
;   2. Installs all SafeOps bin/ executables to C:\Program Files\SafeOps\
;   3. Installs source (UI, backend) for npm-based components
;   4. Creates Desktop + Start Menu shortcuts (all run as Admin)
;   5. Sets SAFEOPS_HOME environment variable
;   6. Writes install-paths.json
;   7. Creates a full uninstaller
;
; Build: Open in Inno Setup 6, press F9.
; IMPORTANT: Run the Dependencies Installer (SafeOps-Dependencies-Setup.exe) FIRST.

#define MyAppName      "SafeOps"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "SafeOps"
#define MyAppURL       "https://safeops.local"
#define MyInstallDir   "C:\Program Files\SafeOps"

[Setup]
AppId={{F9E8D7C6-B5A4-3210-FEDC-BA9876543210}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={#MyInstallDir}
DefaultGroupName=SafeOps
DisableProgramGroupPage=no
OutputDir=..\release
OutputBaseFilename=SafeOps-App-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
VersionInfoVersion=1.0.0.0
VersionInfoCompany=SafeOps
VersionInfoDescription=SafeOps Network Security Platform
VersionInfoCopyright=Copyright 2025 SafeOps
SetupIconFile=safeops.ico
WizardImageFile=wizard-sidebar.bmp
WizardSmallImageFile=wizard-small.bmp
UninstallDisplayIcon={app}\bin\SafeOps.exe
UninstallDisplayName=SafeOps Network Security Platform
CreateUninstallRegKey=yes
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";    Description: "Create SafeOps Launcher shortcut on desktop"; GroupDescription: "Shortcuts:"
Name: "startmenu";      Description: "Create Start Menu shortcuts"; GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "rundepsinst";    Description: "Run Dependencies Installer first (recommended for fresh install)"; GroupDescription: "Setup:"; Flags: unchecked

[Files]
; ── PowerShell post-install helper ────────────────────────────────────────────
Source: "SafeOps-App-Setup-Helper.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall

; ── Main launcher executable ──────────────────────────────────────────────────
Source: "..\bin\SafeOps.exe"; DestDir: "{app}\bin"; Flags: ignoreversion

; ── SafeOps CLI Launcher ──────────────────────────────────────────────────────
Source: "..\bin\SafeOps-Launcher.exe"; DestDir: "{app}\bin"; Flags: ignoreversion

; ── SafeOps Engine ────────────────────────────────────────────────────────────
Source: "..\bin\safeops-engine\*"; DestDir: "{app}\bin\safeops-engine"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ── Firewall Engine (exclude runtime logs) ────────────────────────────────────
Source: "..\bin\firewall-engine\*"; DestDir: "{app}\bin\firewall-engine"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "data\logs\*,data\data\*"

; ── NIC Management ────────────────────────────────────────────────────────────
Source: "..\bin\nic_management\*"; DestDir: "{app}\bin\nic_management"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ── DHCP Monitor ──────────────────────────────────────────────────────────────
Source: "..\bin\dhcp_monitor\*"; DestDir: "{app}\bin\dhcp_monitor"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ── Step CA (exclude 2GB BadgerDB vlog — fresh DB created on first run) ───────
Source: "..\bin\step-ca\*"; DestDir: "{app}\bin\step-ca"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "db\*.vlog"

; ── Captive Portal ────────────────────────────────────────────────────────────
Source: "..\bin\captive_portal\*"; DestDir: "{app}\bin\captive_portal"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ── Network Logger ────────────────────────────────────────────────────────────
Source: "..\bin\network-logger\*"; DestDir: "{app}\bin\network-logger"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ── SIEM Forwarder ────────────────────────────────────────────────────────────
Source: "..\bin\siem-forwarder\*"; DestDir: "{app}\bin\siem-forwarder"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ── Threat Intel (exclude runtime data cache) ─────────────────────────────────
Source: "..\bin\threat_intel\*"; DestDir: "{app}\bin\threat_intel"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "data\fetch\*,data\logs\*,data\processed\*,data\tmp\*"

; ── SIEM scripts ──────────────────────────────────────────────────────────────
Source: "..\bin\siem\*"; DestDir: "{app}\bin\siem"; \
    Flags: recursesubdirs createallsubdirs ignoreversion skipifsourcedoesntexist

; ── Database schemas ──────────────────────────────────────────────────────────
Source: "..\database\*"; DestDir: "{app}\database"; \
    Flags: recursesubdirs createallsubdirs ignoreversion

; ── Web UI source (React) ─────────────────────────────────────────────────────
Source: "..\src\ui\dev\*"; DestDir: "{app}\src\ui\dev"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "node_modules\*,dist\*,.cache\*"

; ── Node.js backend ───────────────────────────────────────────────────────────
Source: "..\backend\*"; DestDir: "{app}\backend"; \
    Flags: recursesubdirs createallsubdirs ignoreversion; \
    Excludes: "node_modules\*"

; ── Dependencies installer (bundled, optional first run) ──────────────────────
Source: "..\SafeOps Dependencies Installer\output\SafeOps-Dependencies-Setup.exe"; \
    DestDir: "{tmp}"; Flags: skipifsourcedoesntexist deleteafterinstall

[Icons]
; Desktop shortcut (always run as admin)
Name: "{autodesktop}\SafeOps Launcher"; \
    Filename: "{app}\bin\SafeOps.exe"; \
    WorkingDir: "{app}\bin"; \
    Comment: "SafeOps Network Security Platform"; \
    Tasks: desktopicon

; Start Menu shortcuts
Name: "{group}\SafeOps Launcher"; \
    Filename: "{app}\bin\SafeOps.exe"; \
    WorkingDir: "{app}\bin"; \
    Comment: "Launch SafeOps management interface"

Name: "{group}\SafeOps Web Console"; \
    Filename: "http://localhost:3001"; \
    Comment: "Open SafeOps web dashboard (requires launcher to be running)"

Name: "{group}\Uninstall SafeOps"; \
    Filename: "{uninstallexe}"

[Registry]
; Register as installed application
Root: HKLM; Subkey: "Software\SafeOps"; ValueType: string; \
    ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\SafeOps"; ValueType: string; \
    ValueName: "BinDir"; ValueData: "{app}\bin"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\SafeOps"; ValueType: string; \
    ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey

[Run]
; Optional: run Dependencies Installer first
Filename: "{tmp}\SafeOps-Dependencies-Setup.exe"; \
    Parameters: "/SILENT"; \
    StatusMsg: "Installing SafeOps dependencies (PostgreSQL, Node.js, ES, Kibana)..."; \
    Check: ShouldRunDepsInstaller; \
    Flags: waituntilterminated

; Post-install setup
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\SafeOps-App-Setup-Helper.ps1"" -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Configuring SafeOps..."; \
    Flags: runhidden waituntilterminated

; Launch SafeOps after install
Filename: "{app}\bin\SafeOps.exe"; \
    Description: "Launch SafeOps Launcher now"; \
    Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; Kill running SafeOps processes before uninstall
Filename: "taskkill"; Parameters: "/IM SafeOps.exe /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillSafeOps"
Filename: "taskkill"; Parameters: "/IM firewall-engine.exe /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillFirewall"
Filename: "taskkill"; Parameters: "/IM safeops-engine.exe /F"; Flags: runhidden waituntilterminated; RunOnceId: "KillEngine"
; Remove startup scheduled task
Filename: "powershell.exe"; \
    Parameters: "-Command ""Unregister-ScheduledTask -TaskName 'SafeOps Launcher' -TaskPath '\SafeOps\' -Confirm:$false -ErrorAction SilentlyContinue"""; \
    Flags: runhidden; RunOnceId: "RemoveTask"

[UninstallDelete]
; Remove the data directory created during install
Type: filesandordirs; Name: "{app}"

[Code]
var
  SIEMDirPage: TInputDirWizardPage;
  SIEMDir: String;

function ShouldRunDepsInstaller: Boolean;
begin
  Result := IsTaskSelected('rundepsinst') and
            FileExists(ExpandConstant('{tmp}\SafeOps-Dependencies-Setup.exe'));
end;

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'SafeOps Network Security Platform v{#MyAppVersion}' + #13#10 + #13#10 +
    'This installer will:' + #13#10 +
    '  • Install SafeOps executables to C:\Program Files\SafeOps\' + #13#10 +
    '  • Create Desktop and Start Menu shortcuts' + #13#10 +
    '  • Set SAFEOPS_HOME environment variable' + #13#10 +
    '  • Install Node.js UI dependencies' + #13#10 + #13#10 +
    'IMPORTANT: Run SafeOps-Dependencies-Setup.exe FIRST' + #13#10 +
    'if you have not already installed PostgreSQL and Node.js.' + #13#10 + #13#10 +
    'SafeOps requires Administrator privileges to run.';

  // Create SIEM scripts directory selection page (appears after install dir page)
  SIEMDirPage := CreateInputDirPage(wpSelectDir,
    'SIEM Scripts Location',
    'Where are the Elasticsearch and Kibana startup scripts?',
    'SafeOps needs to know where your SIEM scripts are located. ' +
    'This folder should contain files like:' + #13#10 +
    '  1-start-elasticsearch.bat' + #13#10 +
    '  2-start-kibana.bat' + #13#10 + #13#10 +
    'If you installed dependencies with SafeOps-Dependencies-Setup.exe, ' +
    'this is typically C:\Program Files\SafeOps\bin\siem\',
    False, '');
  SIEMDirPage.Add('');

  // Try to pre-fill with default or previously saved value
  SIEMDir := ExpandConstant('{pf}\SafeOps\bin\siem');
  SIEMDirPage.Values[0] := SIEMDir;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpSelectDir then begin
    if not IsAdminLoggedOn then begin
      MsgBox('SafeOps requires Administrator privileges. Please run as Administrator.',
             mbError, MB_OK);
      Result := False;
    end;
  end;
  if CurPageID = SIEMDirPage.ID then begin
    SIEMDir := SIEMDirPage.Values[0];
    // Warn if scripts not found, but don't block (user can change later in app)
    if not FileExists(SIEMDir + '\1-start-elasticsearch.bat') then begin
      if MsgBox('Elasticsearch start script not found in the selected folder.' + #13#10 +
                'Path: ' + SIEMDir + #13#10 + #13#10 +
                'Continue anyway? You can change this later in the SafeOps launcher.',
                mbConfirmation, MB_YESNO) = IDNO then
        Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  PathsFile: String;
  InstDir: String;
  DataDir: String;
  RC: Integer;
begin
  if CurStep = ssPostInstall then begin
    // Write siem_dir to install-paths.json so the launcher can find it
    InstDir := ExpandConstant('{app}');
    DataDir := ExpandConstant('{commonappdata}\SafeOps');

    if SIEMDir <> '' then begin
      PathsFile := DataDir + '\install-paths.json';
      // Append/update siem_dir using PowerShell (reads existing JSON, updates field)
      Exec('powershell.exe',
        '-ExecutionPolicy Bypass -Command "' +
        '$f=''' + PathsFile + '''; ' +
        'if (Test-Path $f) { $j=Get-Content $f|ConvertFrom-Json } else { $j=@{} }; ' +
        '$j | Add-Member -Force -NotePropertyName siem_dir -NotePropertyValue ''' + SIEMDir + '''; ' +
        '$j | ConvertTo-Json -Depth 3 | Set-Content $f -Encoding UTF8"',
        '', SW_HIDE, ewWaitUntilTerminated, RC);
    end;
  end;
end;
