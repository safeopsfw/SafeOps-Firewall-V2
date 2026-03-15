; SafeOps Dependencies Installer
; Inno Setup 6.x Script
; This installer downloads and installs all SafeOps dependencies:
;   PostgreSQL 16, Node.js 20 LTS, Elasticsearch 8.11, Kibana 8.11
;   Runs all database schemas and writes install-paths.json
;
; Build: Open this file in Inno Setup 6, press F9 to compile.

#define MyAppName      "SafeOps Dependencies"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "SafeOps"
#define MyAppURL       "https://safeops.local"
#define MyInstallDir   "C:\Program Files\SafeOps"
#define HelperScript   "SafeOps-Setup-Helper.ps1"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={#MyInstallDir}
DefaultGroupName=SafeOps
DisableProgramGroupPage=yes
OutputBaseFilename=SafeOps-Dependencies-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline
VersionInfoVersion=1.0.0.0
VersionInfoCompany=SafeOps
VersionInfoDescription=SafeOps Dependencies Installer
VersionInfoCopyright=Copyright 2025 SafeOps
SetupIconFile=safeops-icon.ico
UninstallDisplayName=SafeOps Dependencies

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; PowerShell helper script
Source: "{#HelperScript}"; DestDir: "{tmp}"; Flags: deleteafterinstall

; Database schema files
Source: "..\database\schemas\*"; DestDir: "{app}\database\schemas"; Flags: recursesubdirs createallsubdirs

; Database patches
Source: "..\database\patches\*"; DestDir: "{app}\database\patches"; Flags: recursesubdirs createallsubdirs skipifsourcedoesntexist

; Database seeds
Source: "..\database\seeds\*"; DestDir: "{app}\database\seeds"; Flags: recursesubdirs createallsubdirs skipifsourcedoesntexist

; UI Source (for npm install)
Source: "..\src\ui\dev\*"; DestDir: "{app}\src\ui\dev"; \
    Flags: recursesubdirs createallsubdirs; \
    Excludes: "node_modules\*,dist\*,.cache\*"

; Backend source
Source: "..\backend\*"; DestDir: "{app}\backend"; \
    Flags: recursesubdirs createallsubdirs; \
    Excludes: "node_modules\*"

; SIEM scripts
Source: "..\bin\siem\*"; DestDir: "{app}\bin\siem"; \
    Flags: recursesubdirs createallsubdirs skipifsourcedoesntexist

; README for manual steps
Source: "IMPORTANT-README.txt"; DestDir: "{app}"; Flags: skipifsourcedoesntexist

[Icons]
Name: "{group}\SafeOps Dependencies Setup"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SafeOps Dependencies Setup"; Filename: "{uninstallexe}"; Tasks: desktopicon

[Run]
; Step 1: Install PostgreSQL + Node.js
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 1 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing PostgreSQL 16 and Node.js 20..."; \
    Flags: runhidden waituntilterminated

; Step 2: Configure PostgreSQL databases
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 2 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Configuring databases..."; \
    Flags: runhidden waituntilterminated

; Step 3: Run schema files
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 3 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Creating database schemas..."; \
    Flags: runhidden waituntilterminated

; Step 4: Install Elasticsearch
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 4 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing Elasticsearch 8.11..."; \
    Flags: runhidden waituntilterminated

; Step 5: Install Kibana
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 5 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing Kibana 8.11..."; \
    Flags: runhidden waituntilterminated

; Step 6: Install npm dependencies
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 6 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Installing Node.js dependencies for UI..."; \
    Flags: runhidden waituntilterminated

; Step 7: Write install-paths.json
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 7 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Writing install paths..."; \
    Flags: runhidden waituntilterminated

; Step 8: Verify installation
Filename: "powershell.exe"; \
    Parameters: "-ExecutionPolicy Bypass -File ""{tmp}\{#HelperScript}"" -Step 8 -InstallDir ""{app}"" -BinDir ""{app}\bin"""; \
    StatusMsg: "Verifying installation..."; \
    Flags: runhidden waituntilterminated

; Open log file at end
Filename: "notepad.exe"; \
    Parameters: "{userdocs}\..\Desktop\SafeOps-Install-{code:GetDate}.log"; \
    Description: "View installation log"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; \
    Parameters: "-Command ""Remove-Item -Recurse -Force '$env:ProgramData\SafeOps' -ErrorAction SilentlyContinue"""; \
    Flags: runhidden waituntilterminated

[Code]
function GetDate(Param: String): String;
begin
  Result := GetDateTimeString('yyyy-mm-dd', '-', ':');
end;

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel2.Caption :=
    'This will install all SafeOps dependencies:' + #13#10 +
    '  • PostgreSQL 16 (database server)' + #13#10 +
    '  • Node.js 20 LTS (JavaScript runtime)' + #13#10 +
    '  • Elasticsearch 8.11 (SIEM data store)' + #13#10 +
    '  • Kibana 8.11 (SIEM visualization)' + #13#10 +
    '  • SafeOps database schemas (14 SQL files)' + #13#10 + #13#10 +
    'An internet connection is required to download installers.' + #13#10 +
    'Installation may take 10-20 minutes.';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpWelcome then begin
    if MsgBox('This installer requires an internet connection to download' + #13#10 +
              'PostgreSQL, Node.js, Elasticsearch, and Kibana.' + #13#10 + #13#10 +
              'Continue with installation?',
              mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;
