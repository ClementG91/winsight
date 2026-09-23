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
english.FirewallServiceNotRemoved=The WinSight firewall service could not be removed. Remove it from an elevated console with:%n%n"%1" uninstall%n%nbefore deleting that file, or remove the service with: sc delete WinSightFirewall
french.FirewallServiceNotRemoved=Le service pare-feu WinSight n'a pas pu être retiré. Retirez-le depuis une console élevée avec :%n%n"%1" uninstall%n%navant de supprimer ce fichier, ou supprimez le service avec : sc delete WinSightFirewall
spanish.FirewallServiceNotRemoved=No se pudo quitar el servicio de firewall de WinSight. Quítelo desde una consola elevada con:%n%n"%1" uninstall%n%nantes de eliminar ese archivo, o elimine el servicio con: sc delete WinSightFirewall

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

// The executable the WinSightFirewall service is registered to run, from its ImagePath
// ("<path>" run, as FirewallServiceInstaller.BuildBinaryPath writes it); empty when there is none.
function FirewallServiceImage(): String;
var
  ImagePath: String;
  Quote: Integer;
begin
  Result := '';
  if not RegQueryStringValue(HKLM, FirewallServiceKey, 'ImagePath', ImagePath) then
    exit;
  ImagePath := Trim(ImagePath);
  if (Length(ImagePath) > 1) and (ImagePath[1] = '"') then
  begin
    Delete(ImagePath, 1, 1);
    Quote := Pos('"', ImagePath);
    if Quote > 1 then
      Result := Copy(ImagePath, 1, Quote - 1);
  end;
end;

// WS-63. The firewall service is registered separately and deliberately, from an all-users
// installation (docs/ADMINISTRATION.md). Uninstalling that installation deleted the executable and
// left a LocalSystem service pointing at a file that no longer exists. When the service runs this
// installation's executable, its own verb removes it first - stop, remove its WFP objects, then the
// registration - while the file is still there. A service registered from any other location is
// not this installation's to remove and is left alone. A failure is reported and does not block the
// uninstall: the operator gets the exact command instead of a half-removed product.
procedure RemoveFirewallServiceOfThisInstallation();
var
  Image, Expected, Message: String;
  ResultCode: Integer;
begin
  if not IsAdminInstallMode then
    exit;
  Image := FirewallServiceImage();
  if Image = '' then
    exit;
  Expected := ExpandConstant('{app}\winsight-firewall-service.exe');
  if CompareText(Image, Expected) <> 0 then
  begin
    Log('WinSightFirewall runs ' + Image + ', not this installation; left in place.');
    exit;
  end;
  if Exec(Expected, 'uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    Log('Removed the WinSight firewall service of this installation.')
  else
  begin
    Message := FmtMessage(CustomMessage('FirewallServiceNotRemoved'), [Expected]);
    Log(Message);
    if not UninstallSilent then
      MsgBox(Message, mbError, MB_OK);
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
