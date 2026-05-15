#define MyAppName "Tscan License"
#define MyAppVersion "0.2.1-beta"
#define MyAppPublisher "T-Space Scan contributors"
#define MyAppExeName "TscanLicense.exe"

[Setup]
AppId={{C4438B4E-49F7-4F0E-82E9-A84542A9FB6E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Tscan License
DefaultGroupName=Tscan License
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=TscanLicenseSetup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\PRIVACY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\DISCLAIMER.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Tscan License"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall Tscan License"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Tscan License"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Tscan License"; Flags: nowait postinstall skipifsilent
