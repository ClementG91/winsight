# Qualification WinSight sur VM vierge

Ce protocole qualifie un commit, un run CI, deux artefacts et une architecture native exacts. Il
échoue fermé : valeur générique, fichier ambigu, hash manquant, script modifié, inventaire ETW
illisible ou preuve non exportée signifie **STOP / résultat rouge**.

> [!CAUTION]
> Exécuter les phases privilégiées uniquement dans une VM isolée et jetable. Ne jamais installer le
> service, modifier WFP ou arrêter une session ETW sur le poste de développement.

## 0. Ne pas confondre version, tag et candidat

Le rapport VM du 29 juillet 2026 a testé le commit de `main`
`a9fd4fbf783a3aabfca3682b9509be5d7330abcb`, run CI `30451063612`. Les fichiers indiquaient
0.10.5, mais ce commit est distinct du tag historique `v0.10.5` (`51c8417...`). Ce candidat a exposé
le crash ETW `0x800705AA`; aucun des deux ne constitue le candidat corrigé.

## 1. Lier l’identité et la conservation des preuves

Renseigner les valeurs du nouveau run CI réussi :

```powershell
$Repo = 'ClementG91/winsight'
$CandidateSha = '<SHA complet de 40 caractères>'
$RunId = '<id du run CI réussi>'
$ProductVersion = '<version produit>'
$ExpectedZipSha256 = '<SHA-256 du ZIP portable>'
$ExpectedInstallerSha256 = '<SHA-256 du setup>'
$RequireSigned = $false
$ExpectedPublisher = '<Subject exact commun attendu de SignPath>'

# Volume monté hors du snapshot de la VM ou partage réseau durable.
$EvidenceRoot = 'E:\WinSight-Evidence'
$EvidenceStorageOutsideSnapshot = $true
```

Contrôles obligatoires :

```powershell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($CandidateSha -notmatch '^[0-9a-fA-F]{40}$') { throw 'CandidateSha non lié.' }
if ($Repo -cne 'ClementG91/winsight') { throw 'Dépôt non lié.' }
if ([string]$RunId -notmatch '^[0-9]+$') { throw 'RunId non lié.' }
if ($ProductVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$') {
    throw 'ProductVersion non lié.'
}
if ($ExpectedZipSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Hash ZIP non lié.' }
if ($ExpectedInstallerSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Hash setup non lié.'
}
if (-not $EvidenceStorageOutsideSnapshot) { throw 'Les preuves ne survivront pas au restore.' }
$SystemVolumeRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$EvidenceFullPath = [IO.Path]::GetFullPath($EvidenceRoot)
if ([string]::Equals(
        [IO.Path]::GetPathRoot($EvidenceFullPath),
        $SystemVolumeRoot,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'EvidenceRoot doit être hors du volume restauré avec la VM.'
}
if ($RequireSigned -and $ExpectedPublisher -match '^<|>$') {
    throw 'ExpectedPublisher exact requis pour le candidat signé.'
}

New-Item -ItemType Directory -Force $EvidenceRoot | Out-Null
$evidenceProbe = Join-Path $EvidenceRoot 'write-test.tmp'
[IO.File]::WriteAllText($evidenceProbe, 'external-evidence')
Remove-Item -LiteralPath $evidenceProbe -Force
```

Tout transcript doit commencer par le SHA, le run, les deux hashes, l’architecture native, le nom du
snapshot et l’heure UTC. Avant chaque restauration de snapshot, fermer le transcript, générer son
manifest SHA-256 sur ce stockage externe et vérifier depuis l’hyperviseur qu’il est exporté.

## 2. Snapshot S0 et prérequis

Créer `S0-clean-before-winsight` avant toute installation. Le shell de qualification doit être le
Windows PowerShell natif lancé avec `-NoProfile`. Depuis le premier shell non élevé, installer les
prérequis puis relancer immédiatement le shell exact :

```powershell
winget install --id Git.Git --source winget --accept-package-agreements --accept-source-agreements
winget install --id GitHub.cli --source winget --accept-package-agreements --accept-source-agreements

$NativeSystemDirectory = [Environment]::SystemDirectory
$NativePowerShellExe = Join-Path $NativeSystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $NativePowerShellExe -PathType Leaf)) {
    throw 'Windows PowerShell natif absent.'
}
Start-Process -FilePath $NativePowerShellExe -ArgumentList @('-NoProfile', '-NoExit')
exit
```

Dans ce nouveau shell `-NoProfile`, établir tous les chemins critiques depuis les API OS et vérifier
les signatures avant usage. Aucune valeur `SystemRoot` ou résolution PATH n’entre dans la frontière :

```powershell
$NativeSystemDirectory = [Environment]::SystemDirectory
$ProgramFilesRoot = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
$NativePowerShellExe = Join-Path $NativeSystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
$ScExe = Join-Path $NativeSystemDirectory 'sc.exe'
$CurlExe = Join-Path $NativeSystemDirectory 'curl.exe'
$GitExe = Join-Path $ProgramFilesRoot 'Git\cmd\git.exe'
$GhExe = Join-Path $ProgramFilesRoot 'GitHub CLI\gh.exe'

foreach ($tool in @($NativePowerShellExe, $ScExe, $CurlExe, $GitExe, $GhExe)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Outil exact absent : $tool" }
    if ((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') {
        throw "Signature Authenticode outil invalide : $tool"
    }
}
& $GhExe auth login --hostname github.com --git-protocol https --web
if ($LASTEXITCODE -ne 0) { throw 'Authentification gh impossible.' }
```

Déterminer l’architecture matérielle avec CIM, pas avec l’architecture du processus :

```powershell
$cpuArchitectures = @(
    Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        ForEach-Object { [int]$_.Architecture } |
        Sort-Object -Unique
)
if ($cpuArchitectures.Count -ne 1) { throw 'Architecture native ambiguë.' }
$NativeArchitecture = switch ($cpuArchitectures[0]) {
    9 { 'x64' }
    12 { 'arm64' }
    default { throw "Architecture native non supportée : $($cpuArchitectures[0])." }
}
$ArtifactName = "winsight-win-$NativeArchitecture"
if ($ArtifactName -cne "winsight-win-$NativeArchitecture") {
    throw 'Artefact et architecture native divergent.'
}
"native=$NativeArchitecture process=$env:PROCESSOR_ARCHITECTURE artifact=$ArtifactName"
```

Pour un test x64 émulé sur Arm64, utiliser un dossier de preuves et un intitulé séparés. Ne jamais
modifier `$NativeArchitecture` pour faire passer l’artefact x64 comme preuve Arm64 native.

## 3. Télécharger sans exécuter, puis établir la racine protégée

Télécharger d’abord dans une zone non approuvée. Aucun binaire candidat n’est exécuté à ce stade :

```powershell
$SystemVolumeRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$LandingRoot = Join-Path $SystemVolumeRoot 'WinSight-Qualification-Landing'
New-Item -ItemType Directory -Force $LandingRoot | Out-Null

$run = & $GhExe api "repos/$Repo/actions/runs/$RunId" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Lecture du run CI impossible.' }
if ($run.head_sha -cne $CandidateSha -or $run.conclusion -cne 'success') {
    throw 'Le run CI ne correspond pas au candidat réussi.'
}
& $GhExe run download $RunId --repo $Repo -n $ArtifactName -D $LandingRoot
if ($LASTEXITCODE -ne 0) { throw 'Téléchargement artefact impossible.' }

$portableZips = @(Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-win-*.zip')
$installers = @(Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-setup.exe')
if ($portableZips.Count -ne 1) { throw "ZIP portable : cardinalité $($portableZips.Count)." }
if ($installers.Count -ne 1) { throw "Setup : cardinalité $($installers.Count)." }
if ((Get-FileHash $portableZips[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'Hash ZIP incorrect dans landing.' }
if ((Get-FileHash $installers[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Hash setup incorrect dans landing.' }
```

Ouvrir la console élevée depuis le shell exact, sans profil :

```powershell
Start-Process -FilePath $NativePowerShellExe -Verb RunAs `
    -ArgumentList @('-NoProfile', '-NoExit')
```

`Start-Process -Verb RunAs` ne transporte pas les variables PowerShell. Dans cette nouvelle console,
exécuter intégralement le bootstrap suivant en ressaisissant **les mêmes valeurs exactes** que dans la
section 1. Ne jamais remplacer ce bloc par des variables héritées, un profil ou une commande résolue
depuis `PATH` :

```powershell
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'ClementG91/winsight'
$CandidateSha = '<même SHA complet de 40 caractères>'
$RunId = '<même id du run CI réussi>'
$ProductVersion = '<même version produit>'
$ExpectedZipSha256 = '<même SHA-256 du ZIP portable>'
$ExpectedInstallerSha256 = '<même SHA-256 du setup>'
$RequireSigned = $false
$ExpectedPublisher = '<même Subject exact commun attendu de SignPath>'
$EvidenceRoot = 'E:\WinSight-Evidence'
$EvidenceStorageOutsideSnapshot = $true

if ($CandidateSha -notmatch '^[0-9a-fA-F]{40}$') { throw 'CandidateSha non lié.' }
if ($Repo -cne 'ClementG91/winsight') { throw 'Dépôt non lié.' }
if ([string]$RunId -notmatch '^[0-9]+$') { throw 'RunId non lié.' }
if ($ProductVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$') {
    throw 'ProductVersion non lié.'
}
if ($ExpectedZipSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Hash ZIP non lié.' }
if ($ExpectedInstallerSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Hash setup non lié.'
}
if (-not $EvidenceStorageOutsideSnapshot) { throw 'Les preuves ne survivront pas au restore.' }
if ($RequireSigned -and $ExpectedPublisher -match '^<|>$') {
    throw 'ExpectedPublisher exact requis pour le candidat signé.'
}

$NativeSystemDirectory = [Environment]::SystemDirectory
$SystemVolumeRoot = [IO.Path]::GetPathRoot($NativeSystemDirectory)
$ProgramFilesRoot = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
$NativePowerShellExe = Join-Path $NativeSystemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
$ScExe = Join-Path $NativeSystemDirectory 'sc.exe'
$CurlExe = Join-Path $NativeSystemDirectory 'curl.exe'
$GitExe = Join-Path $ProgramFilesRoot 'Git\cmd\git.exe'
$GhExe = Join-Path $ProgramFilesRoot 'GitHub CLI\gh.exe'

foreach ($tool in @($NativePowerShellExe, $ScExe, $CurlExe, $GitExe, $GhExe)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Outil exact absent : $tool" }
    if ((Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') {
        throw "Signature Authenticode outil invalide : $tool"
    }
}

$cpuArchitectures = @(
    Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        ForEach-Object { [int]$_.Architecture } |
        Sort-Object -Unique
)
if ($cpuArchitectures.Count -ne 1) { throw 'Architecture native ambiguë après élévation.' }
$NativeArchitecture = switch ($cpuArchitectures[0]) {
    9 { 'x64' }
    12 { 'arm64' }
    default { throw "Architecture native non supportée : $($cpuArchitectures[0])." }
}
$ArtifactName = "winsight-win-$NativeArchitecture"

$EvidenceFullPath = [IO.Path]::GetFullPath($EvidenceRoot)
if ([string]::Equals(
        [IO.Path]::GetPathRoot($EvidenceFullPath),
        $SystemVolumeRoot,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'EvidenceRoot doit être hors du volume restauré avec la VM.'
}
if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) {
    throw 'EvidenceRoot externe non remonté dans la console élevée.'
}
$evidenceProbe = Join-Path $EvidenceRoot 'elevated-write-test.tmp'
[IO.File]::WriteAllText($evidenceProbe, 'external-evidence')
Remove-Item -LiteralPath $evidenceProbe -Force

$LandingRoot = Join-Path $SystemVolumeRoot 'WinSight-Qualification-Landing'
$portableZips = @(
    Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-win-*.zip')
$installers = @(
    Get-ChildItem -LiteralPath $LandingRoot -Recurse -File -Filter 'winsight-*-setup.exe')
if ($portableZips.Count -ne 1) { throw "ZIP portable : cardinalité $($portableZips.Count)." }
if ($installers.Count -ne 1) { throw "Setup : cardinalité $($installers.Count)." }
if ((Get-FileHash $portableZips[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'Hash ZIP incorrect après élévation.' }
if ((Get-FileHash $installers[0].FullName -Algorithm SHA256).Hash -cne
    $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Hash setup incorrect après élévation.' }
```

Seulement après ce bootstrap, construire la racine protégée sous le véritable `Program Files`,
cloner les scripts du commit exact avec le Git absolu signé, puis recopier et re-hasher les
artefacts avant toute extraction :

```powershell
$ProtectedRoot = Join-Path $ProgramFilesRoot 'WinSight-Qualification'
$ProtectedArtifactRoot = Join-Path $ProtectedRoot 'artifacts'
$ProtectedPayloadRoot = Join-Path $ProtectedRoot 'payload'
$ProtectedSourceRoot = Join-Path $ProtectedRoot 'source'
if (Test-Path -LiteralPath $ProtectedRoot) {
    throw 'La racine protégée doit être absente sur le snapshot propre.'
}
New-Item -ItemType Directory -Path @($ProtectedArtifactRoot, $ProtectedPayloadRoot) | Out-Null

$ProtectedZip = Join-Path $ProtectedArtifactRoot $portableZips[0].Name
$ProtectedInstaller = Join-Path $ProtectedArtifactRoot $installers[0].Name
Copy-Item -LiteralPath $portableZips[0].FullName -Destination $ProtectedZip -Force
Copy-Item -LiteralPath $installers[0].FullName -Destination $ProtectedInstaller -Force
if ((Get-FileHash $ProtectedZip -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'ZIP protégé différent.' }
if ((Get-FileHash $ProtectedInstaller -Algorithm SHA256).Hash -cne
    $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Setup protégé différent.' }

& $GitExe clone "https://github.com/$Repo.git" $ProtectedSourceRoot
if ($LASTEXITCODE -ne 0) { throw 'Clone candidat impossible.' }
& $GitExe -C $ProtectedSourceRoot checkout --detach $CandidateSha
if ($LASTEXITCODE -ne 0) { throw 'Checkout candidat impossible.' }
$sourceHead = & $GitExe -C $ProtectedSourceRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'rev-parse candidat impossible.' }
if ($sourceHead -cne $CandidateSha) { throw 'Scripts non liés au candidat.' }

# Recheck immédiat du ZIP protégé avant extraction protégée.
if ((Get-FileHash $ProtectedZip -Algorithm SHA256).Hash -cne
    $ExpectedZipSha256.ToUpperInvariant()) { throw 'ZIP modifié avant extraction.' }
Expand-Archive -LiteralPath $ProtectedZip -DestinationPath $ProtectedPayloadRoot -Force
```

Le ZIP Actions peut être plat. Découvrir exactement un `winsight.exe`, puis les deux EXE sœurs :

```powershell
$cliCandidates = @(Get-ChildItem $ProtectedPayloadRoot -Recurse -File -Filter 'winsight.exe')
if ($cliCandidates.Count -ne 1) { throw "winsight.exe : cardinalité $($cliCandidates.Count)." }
$PackageRoot = $cliCandidates[0].Directory.FullName
$Cli = Join-Path $PackageRoot 'winsight.exe'
$Dashboard = Join-Path $PackageRoot 'winsight-dashboard.exe'
$Service = Join-Path $PackageRoot 'winsight-firewall-service.exe'
$CandidateExecutables = @($Cli, $Dashboard, $Service)
foreach ($path in $CandidateExecutables) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "EXE absent : $path" }
}
```

Avant la première exécution, utiliser le `Test-PeArchitecture.ps1` du clone exact protégé sur les
trois EXE. Un seul mismatch arrête le protocole :

```powershell
$PeScript = Join-Path $ProtectedSourceRoot 'scripts\Test-PeArchitecture.ps1'
$protectedStatus = @(& $GitExe -C $ProtectedSourceRoot status --porcelain)
if ($LASTEXITCODE -ne 0 -or $protectedStatus.Count -ne 0) {
    throw 'Le clone protégé a été modifié avant le contrôle PE.'
}
foreach ($path in $CandidateExecutables) {
    & $NativePowerShellExe `
        -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $PeScript -Path $path -Architecture $NativeArchitecture
    if ($LASTEXITCODE -ne 0) { throw "PE architecture incorrecte : $path" }
}
```

Établir les manifests protégés des trois EXE et de chaque script/module qui sera exécuté :

```powershell
$ValidationFiles = @(
    $PeScript,
    (Join-Path $ProtectedSourceRoot 'scripts\Test-Installer.ps1'),
    (Join-Path $ProtectedSourceRoot 'scripts\Test-McpServer.ps1'),
    (Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'),
    (Join-Path $PackageRoot 'Test-WfpValidation.ps1'),
    (Join-Path $PackageRoot 'Test-TrustBoundary.ps1'),
    (Join-Path $PackageRoot 'Test-IpcBoundary.ps1')
)
$CandidateHash = @{}
foreach ($path in $CandidateExecutables + $ValidationFiles) {
    $resolved = (Resolve-Path -LiteralPath $path).Path
    $CandidateHash[$resolved] = (Get-FileHash $resolved -Algorithm SHA256).Hash
}
$CandidateHash.GetEnumerator() | Sort-Object Name |
    ForEach-Object { "$($_.Value) *$($_.Name)" } |
    Set-Content (Join-Path $EvidenceRoot 'protected-candidate.sha256')

function Assert-CandidateFiles {
    foreach ($entry in $CandidateHash.GetEnumerator()) {
        if ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash -cne $entry.Value) {
            throw "Candidat/script protégé modifié : $($entry.Key)"
        }
    }
    if ((Get-FileHash $ProtectedZip -Algorithm SHA256).Hash -cne
        $ExpectedZipSha256.ToUpperInvariant()) { throw 'ZIP protégé modifié.' }
    if ((Get-FileHash $ProtectedInstaller -Algorithm SHA256).Hash -cne
        $ExpectedInstallerSha256.ToUpperInvariant()) { throw 'Setup protégé modifié.' }
}
```

Appeler `Assert-CandidateFiles` **immédiatement avant chaque** `Start-Process`, import de module,
commande WinSight, installation SCM, WFP ou installateur.

## 4. Authenticode et installateur

Avant SignPath, enregistrer `NotSigned` et conserver le blocage release. Avec `$RequireSigned=$true`,
le setup et les trois EXE portables doivent tous être `Valid`, timestampés et avoir exactement le
même Subject `$ExpectedPublisher` :

```powershell
function Assert-ExpectedSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -cne $ExpectedPublisher -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "Signature éditeur/timestamp invalide : $Path"
    }
}

Assert-CandidateFiles
$SignatureTargets = @($ProtectedInstaller) + $CandidateExecutables
if ($RequireSigned) {
    foreach ($path in $SignatureTargets) { Assert-ExpectedSignature $path }
}
else {
    $SignatureTargets | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_
        $signer = if ($null -eq $sig.SignerCertificate) { '<none>' }
            else { $sig.SignerCertificate.Subject }
        $timestamp = if ($null -eq $sig.TimeStamperCertificate) { '<none>' }
            else { $sig.TimeStamperCertificate.Subject }
        "$($_) status=$($sig.Status) signer=$signer timestamp=$timestamp"
    } | Set-Content (Join-Path $EvidenceRoot 'unsigned-signature-status.txt')
}
```

Valider ensuite le rapport read-only. `integrity` exit 1 signifie « résultat notable », pas crash :

```powershell
Assert-CandidateFiles
$integrityPath = Join-Path $EvidenceRoot 'integrity.json'
& $Cli integrity --json > $integrityPath
$integrityExit = $LASTEXITCODE
if ($integrityExit -notin @(0, 1)) { throw "integrity exit inattendu : $integrityExit" }
$integrity = @(Get-Content $integrityPath -Raw | ConvertFrom-Json)
if ($integrity.Count -ne 1 -or $integrity[0].tool -cne 'integrity' -or
    $null -eq $integrity[0].items -or $null -eq $integrity[0].notableCount) {
    throw 'Contrat JSON integrity invalide.'
}
```

Le script exact protégé vérifie aussi l’architecture native, le setup et les trois EXE **installés**.
En mode signé, il exige `Valid`, timestamp non nul et publisher exact commun :

```powershell
Assert-CandidateFiles
$installerArguments = @(
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $ProtectedSourceRoot 'scripts\Test-Installer.ps1'),
    '-InstallerPath', $ProtectedInstaller,
    '-Version', $ProductVersion,
    '-Architecture', $NativeArchitecture,
    '-ExpectedPublisher', $ExpectedPublisher
)
if ($RequireSigned) { $installerArguments += '-RequireSigned' }
& $NativePowerShellExe @installerArguments
if ($LASTEXITCODE -ne 0) { throw 'Cycle installateur invalide.' }
```

## 5. Continuité après restauration

Sceller les preuves des sections 1 à 4 sur `$EvidenceRoot`, puis restaurer
`S0-clean-before-winsight`. La restauration efface les prérequis, variables, téléchargements et la
racine protégée : ne pas continuer avec des chemins imaginés.

Après restore :

1. remonter `$EvidenceRoot` et vérifier son manifest depuis l’extérieur ;
2. réinitialiser explicitement toutes les variables de la section 1 ;
3. réinstaller Git/gh, se réauthentifier et recalculer `$NativeArchitecture` ;
4. répéter intégralement les sections 3 et 4 depuis le même run/hashes, y compris le bootstrap
   exécutable de toute nouvelle console élevée ;
5. comparer le nouveau `protected-candidate.sha256` au manifest exporté ;
6. créer seulement alors `S1-candidate-protected`.

Chaque section privilégiée suivante restaure `S1`, ouvre le Windows PowerShell natif avec
`-NoProfile`, ressaisit les valeurs exactes de la section 1 puis exécute uniquement le bootstrap de
reprise ci-dessous. Le bootstrap de création de la section 3 ne doit jamais être rejoué sur `S1` :
il exige à juste titre une racine absente et sert seulement à construire le snapshot.

### Bootstrap de reprise S1

Ce bloc ne clone, ne télécharge et n’extrait rien. Il reconstruit le contexte PowerShell perdu au
restore depuis l’état protégé de `S1`, puis compare chacun des dix fichiers exécutables au manifeste
SHA-256 scellé hors snapshot. Toute entrée supplémentaire, manquante, dupliquée, hors de
`ProtectedRoot`, non canonique ou modifiée invalide le snapshot.

```powershell
# S1-RESUME-BOOTSTRAP
function Initialize-WinSightS1QualificationContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CandidateSha,
        [Parameter(Mandatory)][string]$ExpectedZipSha256,
        [Parameter(Mandatory)][string]$ExpectedInstallerSha256,
        [Parameter(Mandatory)][string]$EvidenceRoot
    )

    if ($CandidateSha -notmatch '^[0-9a-fA-F]{40}$' -or
        $ExpectedZipSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
        $ExpectedInstallerSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Identité S1 non liée.'
    }

    $NativeSystemDirectory = [Environment]::SystemDirectory
    $SystemVolumeRoot = [IO.Path]::GetPathRoot($NativeSystemDirectory)
    $ProgramFilesRoot = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    $NativePowerShellExe = Join-Path $NativeSystemDirectory `
        'WindowsPowerShell\v1.0\powershell.exe'
    $ScExe = Join-Path $NativeSystemDirectory 'sc.exe'
    $CurlExe = Join-Path $NativeSystemDirectory 'curl.exe'
    $GitExe = Join-Path $ProgramFilesRoot 'Git\cmd\git.exe'
    foreach ($tool in @($NativePowerShellExe, $ScExe, $CurlExe, $GitExe)) {
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf) -or
            (Get-AuthenticodeSignature -LiteralPath $tool).Status -ne 'Valid') {
            throw "Outil S1 absent ou non signé : $tool"
        }
    }
    $evidenceFullPath = [IO.Path]::GetFullPath($EvidenceRoot)
    if (-not (Test-Path -LiteralPath $evidenceFullPath -PathType Container) -or
        [string]::Equals(
            [IO.Path]::GetPathRoot($evidenceFullPath),
            $SystemVolumeRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'EvidenceRoot S1 absent ou situé sur le volume restauré.'
    }

    $cpuArchitectures = @(
        Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
            ForEach-Object { [int]$_.Architecture } |
            Sort-Object -Unique
    )
    if ($cpuArchitectures.Count -ne 1) { throw 'Architecture S1 ambiguë.' }
    $NativeArchitecture = switch ($cpuArchitectures[0]) {
        9 { 'x64' }
        12 { 'arm64' }
        default { throw "Architecture S1 non supportée : $($cpuArchitectures[0])." }
    }
    $ArtifactName = "winsight-win-$NativeArchitecture"

    $ProtectedRoot = Join-Path $ProgramFilesRoot 'WinSight-Qualification'
    $ProtectedArtifactRoot = Join-Path $ProtectedRoot 'artifacts'
    $ProtectedPayloadRoot = Join-Path $ProtectedRoot 'payload'
    $ProtectedSourceRoot = Join-Path $ProtectedRoot 'source'
    foreach ($directory in @(
        $ProtectedRoot, $ProtectedArtifactRoot, $ProtectedPayloadRoot, $ProtectedSourceRoot)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            throw "Répertoire protégé S1 absent : $directory"
        }
    }

    $protectedZips = @(
        Get-ChildItem -LiteralPath $ProtectedArtifactRoot -File -Filter 'winsight-*-win-*.zip')
    $protectedInstallers = @(
        Get-ChildItem -LiteralPath $ProtectedArtifactRoot -File -Filter 'winsight-*-setup.exe')
    if ($protectedZips.Count -ne 1 -or $protectedInstallers.Count -ne 1) {
        throw 'Cardinalité ZIP/setup S1 invalide.'
    }
    $ProtectedZip = $protectedZips[0].FullName
    $ProtectedInstaller = $protectedInstallers[0].FullName
    if ((Get-FileHash -LiteralPath $ProtectedZip -Algorithm SHA256).Hash -cne
        $ExpectedZipSha256.ToUpperInvariant() -or
        (Get-FileHash -LiteralPath $ProtectedInstaller -Algorithm SHA256).Hash -cne
        $ExpectedInstallerSha256.ToUpperInvariant()) {
        throw 'Hash ZIP/setup S1 invalide.'
    }

    $cliCandidates = @(
        Get-ChildItem -LiteralPath $ProtectedPayloadRoot -Recurse -File -Filter 'winsight.exe')
    if ($cliCandidates.Count -ne 1) { throw 'Cardinalité winsight.exe S1 invalide.' }
    $PackageRoot = $cliCandidates[0].Directory.FullName
    $Cli = Join-Path $PackageRoot 'winsight.exe'
    $Dashboard = Join-Path $PackageRoot 'winsight-dashboard.exe'
    $Service = Join-Path $PackageRoot 'winsight-firewall-service.exe'
    $CandidateExecutables = @($Cli, $Dashboard, $Service)
    $PeScript = Join-Path $ProtectedSourceRoot 'scripts\Test-PeArchitecture.ps1'
    $ValidationFiles = @(
        $PeScript,
        (Join-Path $ProtectedSourceRoot 'scripts\Test-Installer.ps1'),
        (Join-Path $ProtectedSourceRoot 'scripts\Test-McpServer.ps1'),
        (Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'),
        (Join-Path $PackageRoot 'Test-WfpValidation.ps1'),
        (Join-Path $PackageRoot 'Test-TrustBoundary.ps1'),
        (Join-Path $PackageRoot 'Test-IpcBoundary.ps1')
    )
    $ExpectedCandidatePaths = @(
        $CandidateExecutables + $ValidationFiles |
            ForEach-Object { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path })
    if ($ExpectedCandidatePaths.Count -ne 10) {
        throw "Le set candidat S1 doit contenir 10 fichiers, pas $($ExpectedCandidatePaths.Count)."
    }

    $resolvedProtectedRoot = (Resolve-Path -LiteralPath $ProtectedRoot).Path.TrimEnd('\')
    $protectedPrefix = $resolvedProtectedRoot + '\'
    foreach ($path in $ExpectedCandidatePaths) {
        if (-not $path.StartsWith($protectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Chemin candidat hors ProtectedRoot : $path"
        }
    }

    $sourceHead = @(& $GitExe -C $ProtectedSourceRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $sourceHead.Count -ne 1 -or
        $sourceHead[0] -cne $CandidateSha) {
        throw 'HEAD source S1 différent du candidat.'
    }
    $sourceStatus = @(& $GitExe -C $ProtectedSourceRoot status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $sourceStatus.Count -ne 0) {
        throw 'Source protégée S1 modifiée.'
    }

    $manifestPath = Join-Path $EvidenceRoot 'protected-candidate.sha256'
    $manifestLines = @(
        Get-Content -LiteralPath $manifestPath -ErrorAction Stop |
            Where-Object { $_.Length -gt 0 })
    if ($manifestLines.Count -ne 10) {
        throw "Le manifest S1 doit contenir 10 entrées, pas $($manifestLines.Count)."
    }

    $CandidateHash = @{}
    foreach ($line in $manifestLines) {
        if ($line -cnotmatch '^(?<hash>[0-9A-F]{64}) \*(?<path>.+)$') {
            throw 'Entrée manifest S1 non canonique.'
        }
        $manifestPathValue = (Resolve-Path -LiteralPath $Matches.path -ErrorAction Stop).Path
        if ($manifestPathValue -cne $Matches.path -or
            -not $manifestPathValue.StartsWith(
                $protectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            $ExpectedCandidatePaths -notcontains $manifestPathValue -or
            $CandidateHash.ContainsKey($manifestPathValue)) {
            throw "Chemin manifest S1 inattendu ou dupliqué : $manifestPathValue"
        }
        $actualHash = (Get-FileHash -LiteralPath $manifestPathValue -Algorithm SHA256).Hash
        if ($actualHash -cne $Matches.hash) {
            throw "Hash manifest S1 différent : $manifestPathValue"
        }
        $CandidateHash[$manifestPathValue] = $Matches.hash
    }
    if ($CandidateHash.Count -ne 10 -or
        @($ExpectedCandidatePaths | Where-Object {
            -not $CandidateHash.ContainsKey($_)
        }).Count -ne 0) {
        throw 'Le manifest S1 ne couvre pas exactement le set candidat.'
    }

    [pscustomobject]@{
        NativeArchitecture = $NativeArchitecture
        ArtifactName = $ArtifactName
        NativePowerShellExe = $NativePowerShellExe
        ScExe = $ScExe
        CurlExe = $CurlExe
        GitExe = $GitExe
        ProtectedRoot = $ProtectedRoot
        ProtectedZip = $ProtectedZip
        ProtectedInstaller = $ProtectedInstaller
        ProtectedSourceRoot = $ProtectedSourceRoot
        PackageRoot = $PackageRoot
        Cli = $Cli
        Dashboard = $Dashboard
        Service = $Service
        CandidateExecutables = $CandidateExecutables
        ValidationFiles = $ValidationFiles
        CandidateHash = $CandidateHash
    }
}

$S1 = Initialize-WinSightS1QualificationContext `
    -CandidateSha $CandidateSha `
    -ExpectedZipSha256 $ExpectedZipSha256 `
    -ExpectedInstallerSha256 $ExpectedInstallerSha256 `
    -EvidenceRoot $EvidenceRoot
foreach ($property in $S1.PSObject.Properties) {
    Set-Variable -Name $property.Name -Value $property.Value -Scope Local
}

function Assert-CandidateFiles {
    foreach ($entry in $CandidateHash.GetEnumerator()) {
        if ((Get-FileHash -LiteralPath $entry.Key -Algorithm SHA256).Hash -cne $entry.Value) {
            throw "Candidat/script protégé modifié : $($entry.Key)"
        }
    }
    if ((Get-FileHash -LiteralPath $ProtectedZip -Algorithm SHA256).Hash -cne
        $ExpectedZipSha256.ToUpperInvariant() -or
        (Get-FileHash -LiteralPath $ProtectedInstaller -Algorithm SHA256).Hash -cne
        $ExpectedInstallerSha256.ToUpperInvariant()) {
        throw 'ZIP/setup protégé modifié après reprise S1.'
    }
}

Assert-CandidateFiles
$PeScript = Join-Path $ProtectedSourceRoot 'scripts\Test-PeArchitecture.ps1'
foreach ($path in $CandidateExecutables) {
    & $NativePowerShellExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $PeScript -Path $path -Architecture $NativeArchitecture
    if ($LASTEXITCODE -ne 0) { throw "Architecture PE S1 incorrecte : $path" }
}
$EtwModule = Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'
Import-Module $EtwModule -Force
```

Après chaque restore `S1`, conserver le transcript de ce bootstrap sous un nom de phase unique dans
`$EvidenceRoot`. Une restauration qui ne repasse pas ce bloc est `NOT_RUN`, jamais PASS.

## 6. Inventaire et récupération ETW native

Le module du clone exact fait échouer `logman` non nul. Il accepte les sorties tabulaires,
multi-colonnes ou localisées de l’outil, mais ne retourne que les tokens canoniques fermés legacy/v2 :

```powershell
Assert-CandidateFiles
$EtwModule = Join-Path $ProtectedSourceRoot 'scripts\WinSightEtwValidation.psm1'
Import-Module $EtwModule -Force
$EtwGateStart = Get-Date
Start-Transcript (Join-Path $EvidenceRoot 'etw-resilience.txt') -Force
$before = @(Get-WinSightEtwSessionNames)
$before | Set-Content (Join-Path $EvidenceRoot 'etw-before.txt')
if ($before.Count -ne 0) { throw 'Snapshot ETW non propre.' }
```

### Dashboard Attribution

Le dashboard n’a pas de mutex single-instance. La console élevée transmet son token aux processus :

```powershell
Assert-CandidateFiles
$dashboardOne = Start-Process -FilePath $Dashboard -PassThru
Assert-CandidateFiles
$dashboardTwo = Start-Process -FilePath $Dashboard -PassThru
Start-Sleep -Seconds 15

function Get-AttributionSession([Diagnostics.Process]$Process) {
    $Process.Refresh()
    if ($Process.HasExited) { throw "Dashboard $($Process.Id) arrêté." }
    Get-WinSightEtwSessionForProcess -Family Attribution -ProcessId $Process.Id
}
$sessionOne = Get-AttributionSession $dashboardOne
$sessionTwo = Get-AttributionSession $dashboardTwo
```

Fermer la fenêtre du premier avec **X** : le processus capturé et `$sessionOne` doivent rester.
Ensuite seulement, forcer **ce Process capturé** :

```powershell
$dashboardOne.Refresh()
if ($dashboardOne.HasExited) { throw 'X a quitté le dashboard au lieu de le masquer.' }
if ((Get-WinSightEtwSessionNames) -notcontains $sessionOne) { throw 'Session tray absente.' }
Stop-Process -InputObject $dashboardOne -Force
Start-Sleep -Seconds 2
if ((Get-WinSightEtwSessionNames) -notcontains $sessionOne) {
    throw "Le kill ne laisse pas l’orphelin attendu : résultat inconclusif."
}

Assert-CandidateFiles
$dashboardThree = Start-Process -FilePath $Dashboard -PassThru
Start-Sleep -Seconds 15
$sessionThree = Get-AttributionSession $dashboardThree
$dashboardTwo.Refresh()
if ($dashboardTwo.HasExited -or
    (Get-WinSightEtwSessionNames) -contains $sessionOne -or
    (Get-WinSightEtwSessionNames) -notcontains $sessionTwo) {
    throw 'Récupération orpheline ou préservation live échouée.'
}
```

Répéter deux cycles kill/relaunch avec les objets `Process` capturés. Le compte ne doit jamais
dépasser le nombre de dashboards vivants. Terminer les survivants par le menu tray **Exit**, attendre
leur `HasExited`, puis exiger aucune session Attribution.

### DNS

Lancer et conserver l’objet du processus CLI, puis utiliser exclusivement cet objet :

```powershell
Assert-CandidateFiles
$dnsOne = Start-Process -FilePath $Cli -ArgumentList @('dns', '--watch') -PassThru
Start-Sleep -Seconds 10
$dnsOne.Refresh()
if ($dnsOne.HasExited) { throw "Le watcher DNS initial a quitté avec $($dnsOne.ExitCode)." }
$dnsSession = Get-WinSightEtwSessionForProcess -Family DNS -ProcessId $dnsOne.Id
Stop-Process -InputObject $dnsOne -Force
if ((Get-WinSightEtwSessionNames) -notcontains $dnsSession) {
    throw 'Orphelin DNS attendu absent.'
}

Assert-CandidateFiles
$dnsTwo = Start-Process -FilePath $Cli -ArgumentList @('dns', '--watch') -PassThru
Start-Sleep -Seconds 10
$dnsTwo.Refresh()
if ($dnsTwo.HasExited) { throw "Le watcher DNS relancé a quitté avec $($dnsTwo.ExitCode)." }
$dnsTwoSession = Get-WinSightEtwSessionForProcess -Family DNS -ProcessId $dnsTwo.Id
if ((Get-WinSightEtwSessionNames) -contains $dnsSession) {
    throw 'Ancien orphelin supprimé mais nouveau watcher/session DNS absent ou ambigu.'
}
```

Envoyer Ctrl+C dans la console de `$dnsTwo`; ne pas le remplacer par un kill pour la preuve de
fermeture normale. Puis exiger une sortie bornée, exit 0 et absence de la session capturée :

```powershell
if (-not $dnsTwo.WaitForExit(30000)) { throw 'dnsTwo ne sort pas sous 30 secondes après Ctrl+C.' }
if ($dnsTwo.ExitCode -ne 0) { throw "dnsTwo exit inattendu : $($dnsTwo.ExitCode)." }
if ((Get-WinSightEtwSessionNames) -contains $dnsTwoSession) {
    throw 'La fermeture normale DNS laisse sa session ETW.'
}
```

### Outbound du service

Restaurer `S1`. Installer et démarrer explicitement en AuditOnly/WFP vide :

```powershell
Assert-CandidateFiles
& $Service install
if ($LASTEXITCODE -ne 0) { throw 'Install service échoué.' }
& $ScExe start WinSightFirewall
if ($LASTEXITCODE -ne 0) { throw 'Start service échoué.' }

$deadline = (Get-Date).AddSeconds(30)
do {
    $svc = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svc.State -eq 'Running' -and $svc.ProcessId -gt 0) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svc.State -ne 'Running') { throw 'Service non Running.' }

Assert-CandidateFiles
$mode = @(& $Service enforce-status); $modeExit = $LASTEXITCODE
Assert-CandidateFiles
$wfp = @(& $Service wfp-status); $wfpExit = $LASTEXITCODE
Assert-CandidateFiles
$ipc = @(& $Cli firewall-ipc-selftest); $ipcExit = $LASTEXITCODE
if ($modeExit -ne 0 -or ($mode -join "`n") -notmatch 'mode: AuditOnly\.' -or
    $wfpExit -ne 0 -or
    ($wfp -join "`n") -notmatch 'provider: absent, sublayer: absent, permit-filter: absent' -or
    $ipcExit -ne 0 -or ($ipc -join "`n") -notmatch 'serviceAvailable=true') {
    throw 'Précondition AuditOnly/WFP/IPC invalide.'
}
```

Rebinder le PID immédiatement avant le kill : CIM doit toujours porter le même PID, `Get-Process`
doit réussir et son chemin canonique doit être exactement `$Service`.

```powershell
$svcNow = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
if ($svcNow.State -ne 'Running' -or $svcNow.ProcessId -ne $svc.ProcessId) {
    throw 'PID SCM modifié avant rebind.'
}
$serviceProcess = Get-Process -Id ([int]$svcNow.ProcessId) -ErrorAction Stop
$canonicalOwnerPath = (Resolve-Path -LiteralPath $serviceProcess.Path).Path
$canonicalServicePath = (Resolve-Path -LiteralPath $Service).Path
if ($canonicalOwnerPath -cne $canonicalServicePath) { throw 'PID SCM ne pointe pas sur le candidat.' }
$oldOutbound = Get-WinSightEtwSessionForProcess `
    -Family Outbound -ProcessId $serviceProcess.Id

# Dernier rebind sans autre opération entre vérification et kill.
$svcKill = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
if ($svcKill.ProcessId -ne $serviceProcess.Id -or
    (Resolve-Path -LiteralPath (Get-Process -Id $serviceProcess.Id -ErrorAction Stop).Path).Path -cne
    $canonicalServicePath) { throw 'PID/path changé avant kill.' }
Stop-Process -InputObject $serviceProcess -Force
```

Attendre SCM Stopped, exiger l’orphelin, redémarrer, exiger un nouveau PID/session, l’ancien absent,
AuditOnly/WFP vide/IPC disponible et `curl.exe` System32 HTTP 200. Puis stop/uninstall :

```powershell
$deadline = (Get-Date).AddSeconds(30)
do {
    $svc = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svc.State -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svc.State -ne 'Stopped') { throw "SCM n’a pas observé le kill." }
if ((Get-WinSightEtwSessionNames) -notcontains $oldOutbound) {
    throw 'Orphelin Outbound attendu absent : run inconclusif.'
}

Assert-CandidateFiles
& $ScExe start WinSightFirewall
if ($LASTEXITCODE -ne 0) { throw 'Restart service échoué.' }
$deadline = (Get-Date).AddSeconds(30)
do {
    $svcNew = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svcNew.State -eq 'Running' -and
        $svcNew.ProcessId -gt 0 -and
        $svcNew.ProcessId -ne $serviceProcess.Id) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svcNew.State -ne 'Running' -or $svcNew.ProcessId -eq $serviceProcess.Id) {
    throw 'Service non redémarré sous un nouveau PID.'
}
Start-Sleep -Seconds 10
$newOutbound = Get-WinSightEtwSessionForProcess `
    -Family Outbound -ProcessId ([int]$svcNew.ProcessId)
if ((Get-WinSightEtwSessionNames) -contains $oldOutbound) {
    throw 'Récupération Outbound ou nouvelle session incorrecte.'
}

Assert-CandidateFiles
$mode = @(& $Service enforce-status); $modeExit = $LASTEXITCODE
Assert-CandidateFiles
$wfp = @(& $Service wfp-status); $wfpExit = $LASTEXITCODE
Assert-CandidateFiles
$ipc = @(& $Cli firewall-ipc-selftest); $ipcExit = $LASTEXITCODE
$http = & $CurlExe -s -o NUL -w '%{http_code}' `
    --max-time 20 https://example.com
$httpExit = $LASTEXITCODE
if ($modeExit -ne 0 -or ($mode -join "`n") -notmatch 'mode: AuditOnly\.' -or
    $wfpExit -ne 0 -or
    ($wfp -join "`n") -notmatch 'provider: absent, sublayer: absent, permit-filter: absent' -or
    $ipcExit -ne 0 -or ($ipc -join "`n") -notmatch 'serviceAvailable=true' -or
    $httpExit -ne 0 -or $http -ne '200') {
    throw 'AuditOnly/WFP/IPC/connectivité invalide après restart.'
}

& $ScExe stop WinSightFirewall | Out-Host
$deadline = (Get-Date).AddSeconds(30)
do {
    $svcNew = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($svcNew.State -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($svcNew.State -ne 'Stopped') { throw 'Service non arrêté après récupération.' }
Assert-CandidateFiles
& $Service uninstall
if ($LASTEXITCODE -ne 0) { throw 'Uninstall service échoué.' }
& $ScExe query WinSightFirewall 2>&1 | Out-Host
if ($LASTEXITCODE -ne 1060) { throw 'SCM absence 1060 non prouvée.' }
Start-Sleep -Seconds 3
$outboundAfter = @(Get-WinSightEtwSessionNames |
    Where-Object { $_ -cmatch '^WinSight-Outbound-(v2-)?' })
if ($outboundAfter.Count -ne 0) { throw 'Session Outbound persistante/inattendue.' }
```

Le bloc intermédiaire restart/réassertions doit être transcrit en entier ; toute omission est
`NOT_RUN`, pas PASS.

Le scénario legacy PID-only natif reste **NOT_RUN externe** dans ce kit : le fabriquer avec une
commande `logman` arbitraire ne prouverait pas le chemin TraceEvent legacy réel. Il exige une fixture
séparée, allowlistée et liée au candidat. Ne pas saturer le quota ETW pour le simuler.

Terminer le gate avec le helper du module. Sa lecture du journal Application est `-ErrorAction Stop`;
toute exception de lecture interrompt le run, elle ne peut jamais devenir « zéro crash » :

```powershell
Assert-WinSightEtwSessionsAbsent
$crashes = @(Get-WinSightRuntimeCrashEvents -StartTime $EtwGateStart)
if ($crashes.Count -ne 0) { throw 'Crash .NET Runtime WinSight pendant le gate ETW.' }
Stop-Transcript
```

## 7. Gates WFP, trust et IPC

Restaurer `S1` avant chaque famille et appeler `Assert-CandidateFiles` avant chaque EXE/script.

```powershell
$wfpScript = Join-Path $PackageRoot 'Test-WfpValidation.ps1'
Assert-CandidateFiles
& $wfpScript -ContractSelfTest                   # attendu 26/26, exit 0
if ($LASTEXITCODE -ne 0) { throw 'ContractSelfTest échoué.' }
Assert-CandidateFiles
& $wfpScript -ContractSelfTest -ContractNegativeControl # attendu 26/1, exit 1
if ($LASTEXITCODE -ne 1) { throw 'NegativeControl non rouge exact.' }
Assert-CandidateFiles
& $wfpScript -ServicePath $Service -SkipEnforcement     # attendu 16/16
if ($LASTEXITCODE -ne 0) { throw 'Pre-arm 16/16 échoué.' }
```

Créer `S2-before-WFP`, puis full WFP : attendu 25/25, curl cible 200→000, contrôle 200, rollback
AuditOnly, WFP vide, connectivité restaurée, SCM 1060. Ensuite trust : attendu 12/12 sans skip, avec
un vrai compte standard pour `-HostileAccount`.

```powershell
Assert-CandidateFiles
& $wfpScript -ServicePath $Service
if ($LASTEXITCODE -ne 0) { throw 'Full WFP 25/25 échoué; restaurer S2.' }
Assert-CandidateFiles
& (Join-Path $PackageRoot 'Test-TrustBoundary.ps1') -ServicePath $Service `
    -HostileAccount '<compte standard dédié>'
if ($LASTEXITCODE -ne 0) { throw 'Trust 12/12 échoué.' }
```

Le gate IPC final part d’un restore `S1` et fournit sa propre séquence complète :

```powershell
Assert-CandidateFiles
& $Service install
if ($LASTEXITCODE -ne 0) { throw 'IPC install échoué.' }
& $ScExe start WinSightFirewall
if ($LASTEXITCODE -ne 0) { throw 'IPC start échoué.' }
$deadline = (Get-Date).AddSeconds(30)
do {
    $ipcService = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($ipcService.State -eq 'Running' -and $ipcService.ProcessId -gt 0) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($ipcService.State -ne 'Running' -or $ipcService.ProcessId -le 0) {
    throw 'IPC service non Running.'
}
Assert-CandidateFiles
$mode = @(& $Service enforce-status)
if ($LASTEXITCODE -ne 0 -or ($mode -join "`n") -notmatch 'mode: AuditOnly\.') {
    throw 'IPC service non AuditOnly.'
}
Assert-CandidateFiles
$wfp = @(& $Service wfp-status)
if ($LASTEXITCODE -ne 0 -or
    ($wfp -join "`n") -notmatch 'provider: absent, sublayer: absent, permit-filter: absent') {
    throw 'IPC WFP non vide.'
}
& (Join-Path $PackageRoot 'Test-IpcBoundary.ps1')
if ($LASTEXITCODE -ne 0) { throw 'IPC 7/7 échoué.' }
# Elevated doit être CanMutate; restricted CanReadOnly/Unauthorized.
# ReadableMutateSkipped n’est pas un PASS AuditOnly.
& $ScExe stop WinSightFirewall | Out-Host
$deadline = (Get-Date).AddSeconds(30)
do {
    $ipcService = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if ($ipcService.State -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $deadline)
if ($ipcService.State -ne 'Stopped') { throw 'IPC service non Stopped.' }
Assert-CandidateFiles
& $Service uninstall
if ($LASTEXITCODE -ne 0) { throw 'IPC uninstall échoué.' }
& $ScExe query WinSightFirewall 2>&1 | Out-Host
if ($LASTEXITCODE -ne 1060) { throw 'IPC cleanup SCM 1060 non prouvé.' }
Assert-WinSightEtwSessionsAbsent
```

Exécuter séparément standard user, administrateur filtré, administrateur élevé et Network logon. Un
token ne prouve pas les autres.

## 8. Sceller, exporter, restaurer

Le dossier externe doit contenir pour chaque phase : SHA/run, hashes artefacts, architecture native
et process, snapshot, commandes/exits/comptes, manifests candidat/scripts, signatures/timestamp,
inventaires ETW/SCM/WFP avant/après, connectivité, tokens et actions humaines.

```powershell
$manifest = Join-Path $EvidenceRoot 'MANIFEST.sha256.txt'
Get-ChildItem $EvidenceRoot -Recurse -File |
    Where-Object { $_.FullName -cne $manifest } |
    Get-FileHash -Algorithm SHA256 |
    Sort-Object Path |
    ForEach-Object { "$($_.Hash) *$($_.Path)" } |
    Set-Content $manifest
```

Exporter/sceller hors VM **avant** de restaurer `S0`. Vérifier le manifest sur l’hôte, puis seulement
restaurer. Un nettoyage manuel après état incertain ne transforme jamais un run rouge en PASS.

x64, Arm64 natif et x64 émulé sur Arm64 sont trois preuves distinctes. Tant que CI/CodeQL/package
exacts, variantes natives/session, revue humaine EN/FR/ES et vraie chaîne SignPath Authenticode
timestampée ne sont pas enregistrés, `production_ready` reste faux.
