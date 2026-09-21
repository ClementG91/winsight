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
english.SignatureVerb=Add "Check signature with WinSight" to File Explorer
french.SignatureVerb=Ajouter « Vérifier la signature avec WinSight » à l'Explorateur de fichiers
spanish.SignatureVerb=Añadir "Comprobar la firma con WinSight" al Explorador de archivos
english.SignatureVerbMenu=Check signature with WinSight
french.SignatureVerbMenu=Vérifier la signature avec WinSight
spanish.SignatureVerbMenu=Comprobar la firma con WinSight

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "signatureverb"; Description: "{cm:SignatureVerb}"

[Files]
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\WinSight"; Filename: "{app}\winsight-dashboard.exe"; WorkingDir: "{app}"
Name: "{group}\WinSight command line"; Filename: "{sys}\cmd.exe"; Parameters: "/K ""{app}\winsight.exe"" --help"; WorkingDir: "{app}"
Name: "{autodesktop}\WinSight"; Filename: "{app}\winsight-dashboard.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
; HKA is HKCU in current-user mode and HKLM in all-users mode. Declaring the Explorer verb here,
; instead of invoking a HKCU-only helper, gives it the same scope and lifetime as the installation.
; Inno then removes the exact key from the same hive during elevated all-users uninstall; an
; [UninstallRun] command cannot use runasoriginaluser (that flag is valid only in [Run]).
Root: HKA; Subkey: "Software\Classes\*\shell\WinSight.Signature"; ValueType: string; ValueName: ""; ValueData: "{cm:SignatureVerbMenu}"; Flags: uninsdeletekey; Tasks: signatureverb
Root: HKA; Subkey: "Software\Classes\*\shell\WinSight.Signature"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\winsight-dashboard.exe"",0"; Tasks: signatureverb
Root: HKA; Subkey: "Software\Classes\*\shell\WinSight.Signature\command"; ValueType: string; ValueName: ""; ValueData: """{app}\winsight-dashboard.exe"" --signature ""%1"""; Tasks: signatureverb

[Run]
Filename: "{app}\winsight-dashboard.exe"; Parameters: "--language {code:GetDashboardLanguage}"; Description: "{cm:LaunchDashboard}"; Flags: nowait postinstall skipifsilent

; Uninstall removed the installation directory and left the ransomware decoys where they were
; planted: up to eighteen files across Documents, Desktop, Pictures, Videos, Music and Downloads,
; deliberately named to be unrecognisable. That property is what makes them work as decoys and what
; makes them impossible for the user to pick out afterwards - and because those folders follow the
; OneDrive redirection, they had synchronised to the cloud as well.
;
; This runs the sweep the product already performs at startup. runhidden because an uninstall should
; not flash a console; skipifdoesntexist because a partially removed install must still uninstall.
[UninstallRun]
Filename: "{app}\winsight.exe"; Parameters: "remove-decoys"; Flags: runhidden skipifdoesntexist; RunOnceId: "RemoveDecoys"

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
