#ifndef MyAppVersion
  #error MyAppVersion must be provided by the build script.
#endif
#ifndef MyArchitecture
  #error MyArchitecture must be provided by the build script.
#endif
#ifndef MySourceDir
  #error MySourceDir must be provided by the build script.
#endif
#ifndef MyOutputDir
  #error MyOutputDir must be provided by the build script.
#endif
#ifndef MyRepoRoot
  #error MyRepoRoot must be provided by the build script.
#endif

#if MyArchitecture == "x64"
  #define MyArchitecturesAllowed "x64compatible and not arm64"
#elif MyArchitecture == "arm64"
  #define MyArchitecturesAllowed "arm64"
#else
  #error Unsupported architecture. Expected x64 or arm64.
#endif

[Setup]
AppId={{8D72DC5E-7BBE-4CF4-9D8B-A76F06C2A614}
AppName=WinSight
AppVersion={#MyAppVersion}
AppVerName=WinSight {#MyAppVersion}
AppPublisher=WinSight contributors
AppPublisherURL=https://github.com/ClementG91/winsight
AppSupportURL=https://github.com/ClementG91/winsight/issues
AppUpdatesURL=https://github.com/ClementG91/winsight/releases
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany=WinSight contributors
VersionInfoDescription=WinSight security visibility suite installer
VersionInfoProductName=WinSight
VersionInfoProductVersion={#MyAppVersion}
DefaultDirName={autopf}\WinSight
DefaultGroupName=WinSight
DisableProgramGroupPage=yes
LicenseFile={#MyRepoRoot}\LICENSE
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed={#MyArchitecturesAllowed}
ArchitecturesInstallIn64BitMode={#MyArchitecturesAllowed}
MinVersion=10.0.19045
OutputDir={#MyOutputDir}
OutputBaseFilename=winsight-v{#MyAppVersion}-win-{#MyArchitecture}-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern dynamic
SetupLogging=yes
SetupIconFile={#MyRepoRoot}\assets\branding\winsight.ico
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\winsight-dashboard.exe
UninstallDisplayName=WinSight {#MyAppVersion} ({#MyArchitecture})
UsePreviousAppDir=yes
UsePreviousLanguage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[CustomMessages]
english.DesktopIcon=Create a desktop shortcut
french.DesktopIcon=Créer un raccourci sur le bureau
spanish.DesktopIcon=Crear un acceso directo en el escritorio
english.LaunchDashboard=Launch WinSight
french.LaunchDashboard=Lancer WinSight
spanish.LaunchDashboard=Iniciar WinSight

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\WinSight"; Filename: "{app}\winsight-dashboard.exe"; WorkingDir: "{app}"
Name: "{group}\WinSight command line"; Filename: "{sys}\cmd.exe"; Parameters: "/K ""{app}\winsight.exe"" --help"; WorkingDir: "{app}"
Name: "{autodesktop}\WinSight"; Filename: "{app}\winsight-dashboard.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\winsight-dashboard.exe"; Parameters: "--language {code:GetDashboardLanguage}"; Description: "{cm:LaunchDashboard}"; Flags: nowait postinstall skipifsilent

[Code]
function GetDashboardLanguage(Param: String): String;
begin
  if ActiveLanguage = 'french' then
    Result := 'fr'
  else if ActiveLanguage = 'spanish' then
    Result := 'es'
  else
    Result := 'en';
end;
