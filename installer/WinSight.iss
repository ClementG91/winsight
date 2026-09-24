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
english.FirewallServiceNotRemoved=The WinSight firewall service of this installation could not be removed, so the uninstall stopped before removing anything: deleting its program would leave a service pointing at a file that no longer exists. From an elevated console, run:%n%n"%1" uninstall%n%nor, if that fails: sc stop WinSightFirewall, then sc delete WinSightFirewall (its filters are dynamic and end with the service). Then run the uninstall again.
french.FirewallServiceNotRemoved=Le service pare-feu WinSight de cette installation n'a pas pu être retiré ; la désinstallation s'est donc arrêtée avant de supprimer quoi que ce soit : supprimer son programme laisserait un service pointant vers un fichier inexistant. Depuis une console élevée, exécutez :%n%n"%1" uninstall%n%nou, en cas d'échec : sc stop WinSightFirewall, puis sc delete WinSightFirewall (ses filtres sont dynamiques et disparaissent avec le service). Relancez ensuite la désinstallation.
spanish.FirewallServiceNotRemoved=No se pudo quitar el servicio de firewall de WinSight de esta instalación, así que la desinstalación se detuvo antes de quitar nada: borrar su programa dejaría un servicio que apunta a un archivo inexistente. Desde una consola con privilegios elevados, ejecute:%n%n"%1" uninstall%n%no, si falla: sc stop WinSightFirewall y luego sc delete WinSightFirewall (sus filtros son dinámicos y terminan con el servicio). Después vuelva a ejecutar la desinstalación.

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
const
  FirewallServiceKey = 'SYSTEM\CurrentControlSet\Services\WinSightFirewall';

// Whether CommandLine starts with the executable Path: all of it, or followed by its arguments.
function StartsTheCommand(CommandLine, Path: String): Boolean;
begin
  // One test at a time: the character after the path is read only once it is known to exist.
  Result := False;
  if Length(CommandLine) < Length(Path) then
    exit;
  if CompareText(Copy(CommandLine, 1, Length(Path)), Path) <> 0 then
    exit;
  if Length(CommandLine) = Length(Path) then
    Result := True
  else
    Result := CommandLine[Length(Path) + 1] = ' ';
end;

// Whether the WinSightFirewall service is registered to run Expected, this installation's executable.
// ImagePath receives the registration as found, empty when there is no service or no ImagePath.
function ServiceRunsThisInstallation(Expected: String; var ImagePath: String): Boolean;
var
  Quote: Integer;
begin
  Result := False;
  ImagePath := '';
  if not RegQueryStringValue(HKLM, FirewallServiceKey, 'ImagePath', ImagePath) then
    exit;
  ImagePath := Trim(ImagePath);
  if (Length(ImagePath) > 1) and (ImagePath[1] = '"') then
  begin
    // "<path>" run, as FirewallServiceInstaller.BuildBinaryPath writes it.
    Quote := Pos('"', Copy(ImagePath, 2, Length(ImagePath) - 1));
    Result := (Quote > 1) and (CompareText(Copy(ImagePath, 2, Quote - 1), Expected) = 0);
  end
  else
    // Re-registered by hand without quotes. Windows runs the leading path, adding ".exe" when it has
    // none, so this installation's executable is recognised as the start of the command, with or
    // without its extension. Searching for ".exe" instead stopped at the first one in the path - a
    // folder named "tools.exe" - and read this installation's service as someone else's, which let
    // the uninstall delete the program under it.
    Result := StartsTheCommand(ImagePath, Expected)
      or StartsTheCommand(ImagePath, Copy(Expected, 1, Length(Expected) - Length('.exe')));
end;

// WS-63. The firewall service is registered separately and deliberately, from an all-users
// installation (docs/ADMINISTRATION.md). Uninstalling that installation deleted the executable and
// left a LocalSystem service pointing at a file that no longer exists. When the service runs this
// installation's executable, its own verb removes it first - stop, remove its WFP objects, then the
// registration - while the file is still there. A service registered from any other location is
// not this installation's to remove and is left alone.
//
// RA-05. A failure stops the uninstall instead of carrying on: continuing deleted the program and
// left exactly the dangling LocalSystem service this exists to prevent, while the message told the
// operator to act "before deleting that file". Raised from usUninstall, the exception is fatal to
// Inno: nothing has been removed yet ([UninstallRun] and file deletion come after), the uninstaller
// exits with code 1, and the message is shown - or, with /SUPPRESSMSGBOXES, only logged, so an
// unattended uninstall fails instead of hanging. The installation stays whole and the service keeps
// its program; the message gives the commands that remove it, then the uninstall is run again.
procedure RemoveFirewallServiceOfThisInstallation();
var
  ImagePath, Expected: String;
  ResultCode: Integer;
begin
  if not IsAdminInstallMode then
    exit;
  Expected := ExpandConstant('{app}\winsight-firewall-service.exe');
  if not ServiceRunsThisInstallation(Expected, ImagePath) then
  begin
    if ImagePath <> '' then
      Log('WinSightFirewall runs ' + ImagePath + ', not this installation; left in place.');
    exit;
  end;
  if Exec(Expected, 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    Log('Removed the WinSight firewall service of this installation.')
  else
  begin
    Log('The firewall service of this installation was not removed (exit ' + IntToStr(ResultCode) + '); uninstall stopped.');
    RaiseException(FmtMessage(CustomMessage('FirewallServiceNotRemoved'), [Expected]));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  // usUninstall runs before [UninstallRun] and before any file is deleted.
  if CurUninstallStep = usUninstall then
    RemoveFirewallServiceOfThisInstallation();
end;

function GetDashboardLanguage(Param: String): String;
begin
  if ActiveLanguage = 'french' then
    Result := 'fr'
  else if ActiveLanguage = 'spanish' then
    Result := 'es'
  else
    Result := 'en';
end;
