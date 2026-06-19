[Setup]
AppName=BinaryHammer
AppVersion=1.0.0
AppPublisher=Harry Corcoran
AppPublisherURL=https://github.com/harryc295/Binary-slammer
AppSupportURL=https://github.com/harryc295/Binary-slammer/issues
AppUpdatesURL=https://github.com/harryc295/Binary-slammer/releases
DefaultDirName={autopf}\BinaryHammer
DefaultGroupName=BinaryHammer
OutputDir=..\dist
OutputBaseFilename=BinaryHammerSetup
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\binaryslammer.exe
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce

[Files]
Source: "..\build\Release\binaryslammer.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\BinaryHammer"; Filename: "{app}\binaryslammer.exe"; Tasks: startmenuicon
Name: "{group}\Uninstall BinaryHammer"; Filename: "{uninstallexe}"; Tasks: startmenuicon
Name: "{commondesktop}\BinaryHammer"; Filename: "{app}\binaryslammer.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\binaryslammer.exe"; Description: "Launch BinaryHammer"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up the AppData folder on uninstall
Type: filesandordirs; Name: "{userappdata}\BinaryHammer"
