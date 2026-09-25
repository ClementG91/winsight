# WinSight Deep Audit

| | |
|---|---|
| Date | 2026-09-21, mis à jour les 23 et 24 septembre |
| Base | `main` @ `4a361a6` (v0.13.0) |
| Périmètre | dépôt complet : code, tests, docs, CI/CD, scripts de build/release, installeur |
| Auteurs de l'audit | Claude Code (sessions du 18-19, du 21, du 22-23 et du 24 septembre) et Codex (20-21 septembre, contre-audit indépendant le 24, §4.3), travaillant sur le même arbre et se relisant mutuellement |
| Environnement de validation | Windows 11 Pro 10.0.26200 x64, compte administrateur à jeton scindé (UAC), processus non élevé, SDK .NET 10.0.303 |
| État livré | branche d'audit, commits thématiques, non poussée |

**Validé sur ce poste** : build Release, suite complète, formatage, audit NuGet, mesures de
performance, et cycle complet de l'installeur x64 en portée utilisateur (installation, verbe
Explorer, MCP, smoke tests EN/FR/ES, désinstallation sans résidu) sur l'arbre final.

**Qualifié en VM le 22 septembre** (§17.1, candidat `5347a1b` construit localement, x64) : installeur
en portée utilisateur, scanners élevés, verbes de réponse, Guardian (Bloquer, Restaurer, Autoriser,
Révoquer), attribution du tableau de bord et récupération ETW (DNS, service), contrat et pré-armement
WFP, armement WFP complet et désarmement d'urgence (Hyper-V, 35 vérifications), frontière de confiance,
IPC locale, absence de résidu.

**Qualifié en VM le 23 septembre** (§17.2, candidats `bd4242f` puis `259056b`, Hyper-V, passes
autonomes) : toutes les portes du 22, plus l'installation « tous les utilisateurs » avec retrait du
service à la désinstallation (WS-63), la mise à niveau depuis la v0.13.0 publiée, les substituts
Cloud Files de OneDrive (WS-40), l'attribution des écritures dans le dossier Démarrage (WS-73, WS-60)
et l'IPC par ouverture de session réseau depuis une seconde VM (porte 36, 10/10). Les 31 portes x64
passent sur le candidat `259056b`.

**Réserve du 24 septembre** (contre-audit Codex, §4.3). Le harnais hôte de ces passes gardait ses
scripts, le candidat, les disques des VM et les preuves dans des dossiers que tout utilisateur
authentifié pouvait modifier (RA-01) : ce sont des preuves fonctionnelles de ce que ces octets ont
fait, pas une provenance attestée. Le harnais a été refait (`scripts/validation/hyperv`, vérifié par
`Verify-QualificationProvenance.ps1`) mais n'a pas encore tourné, et le code produit a changé depuis
`259056b` (RA-02 à RA-05, WS-74 à WS-83) : **la tête de la branche n'est pas qualifiée**. La passe complète `head-fe953fe` (§17.4, provenance vérifiée) a passé ses 32 portes sans échec (la porte 36 se passe à part, avec la VM de contrôle) ; la porte 17 est à repasser avec la mesure corrigée (WS-82).

**Ce qui n'a pas pu être validé ici, et ne doit pas être présumé** : ARM64 natif, signature
Authenticode, essai d'endurance (soak), machines multi-utilisateurs. Chaque section précise ce qui a
été mesuré et ce qui ne l'a pas été.

---

## 1. Executive Summary

- **État.** WinSight est une suite .NET 10 mature de 24 projets (~48 000 lignes de production,
  ~45 000 de tests), avec une CI exigeante (actions épinglées par SHA, trois images Windows dont
  ARM64 natif, seuil de couverture, attestations SLSA et SBOM, cycle d'installation testé).
- **Points forts.** Honnêteté de la couverture (« incomplet » plutôt que « rien trouvé »), un format
  de rapport unique partagé par CLI, tableau de bord et MCP, aucun appel réseau implicite, une
  frontière privilégiée solide (tube nommé authentifié + modèle de capacités + vérification de
  l'identité du serveur), un serveur MCP en lecture seule.
- **Problèmes trouvés.** L'audit a traité **77 défauts** : 72 corrigés et testés (dont neuf dans le
  kit de qualification VM), 4 rendus explicites dans la documentation (dont WS-60, mesuré en VM), et
  1 ouvert, WS-53 (runtime partagé), qui est un chantier de paquet. Les 11 de sévérité *High* sont
  tous corrigés :
  faux positif et faux négatif du scanner hijack, Guardian aveugle aux clés Run absentes ou
  recréées, fuites de lignes de commande vers le modèle via MCP, courses TOCTOU dans les actions de
  réponse (réutilisation de PID, suppression/restauration de persistance, liste de processus protégés
  par simple nom de fichier), actions destructrices réussies sans journal, accès fichiers suivant les
  points d'analyse (reparse points) vers d'autres emplacements, « Bloquer » devenu inutilisable
  sur Windows 11 faute de transactions registre (corrigé par un repli vérifié), et l'attribution d'une
  persistance à l'Explorateur ou à Defender qui l'avaient seulement ouverte (WS-73, trouvé en VM), et
  la règle d'abus d'interpréteur aveugle aux interpréteurs Windows authentiques depuis la v0.12.0
  (WS-74, trouvé en corrigeant RA-02). Le dernier corrigé, WS-75 (*Medium*), a été trouvé en
  déplaçant les tests sur le disque de données : le contrôle d'écriture du scanner hijack ignorait
  qu'un utilisateur peut s'accorder le droit de créer un fichier dans un dossier qu'il possède ;
  sa revue indépendante a relevé WS-76 (*Low*) : le niveau d'intégrité du dossier n'était pas lu.
- **Contre-audit.** Codex a relu la branche le 24 septembre : sept constats (RA-01 à RA-07), aucun
  n'étant une faille du produit démontrée ; tous repris et corrigés le jour même (§4.3). Restent à
  exécuter par l'opérateur le harnais refait et la requalification de la tête (RA-01, RA-02, RA-05).
- **Performance.** Scan de persistance 2,7× plus rapide (25,2 s → 9,3 s, A/B même machine) ;
  indexation WinSxS passée de ~46 000 handles de répertoire ouverts simultanément à quelques-uns
  (pic du processus 45 910 → 553) ; surveillance caméra/micro au repos ramenée de 1,7 % à 0,09 %
  d'un cœur.
- **Positionnement.** WinSight couvre l'objectif de KnockKnock, de What's Your Sign et de DHS, et
  partiellement BlockBlock, OverSight, RansomWhere?, ReiKey et KextViewr. Il ne peut pas égaler LuLu
  sans pilote : un programme en mode utilisateur ne peut pas suspendre une connexion WFP en attente
  d'une décision. Autoruns reste plus large en surfaces, Sysmon (désormais intégré à Windows 11)
  plus riche en télémétrie, System Informer meilleur en inspection de processus.
- **Différenciation réelle.** Un triage unifié, local et compréhensible pour un non-spécialiste, avec
  des verdicts gradués (exploitabilité réelle, ancre de confiance, abus d'interpréteur signé) et une
  interface MCP sûre — aucune alternative ne réunit tout cela.
- **Priorités.** (1) qualification ARM64 ; (2) réduire le paquet installé (431 Mo, WS-53) ;
  (3) mode pare-feu « demander après la première connexion » ; (4) signature Authenticode.

---

## 2. Architecture actuelle

```text
WinSight
├── composants
│   ├── WinSight.Core ............ signatures (WinVerifyTrust, catalogue, MSIX), hachage, accès fichiers
│   │                              natif sans suivi de reparse, écritures atomiques, VirusTotal, santé des capteurs
│   ├── WinSight.Reporting ........ contrat ToolReport + neutralisation du texte non fiable
│   ├── WinSight.Application ...... orchestration partagée CLI / tableau de bord / MCP (Adapters)
│   ├── 17 bibliothèques .......... Persistence, Ransomware, AvMonitor, NetMonitor, Attribution, Processes,
│   │                              Modules, Browser, Certificates, Hosts, InputHooks, Drivers,
│   │                              CodeIntegrity, Hijack, Presence, Response, Firewall
│   ├── WinSight.FirewallService .. service LocalSystem : WFP, magasin de politique, IPC authentifié
│   ├── WinSight.Cli .............. `winsight.exe`, 28 verbes documentés + 3 verbes de maintenance
│   ├── WinSight.Dashboard ........ WPF + zone de notification, EN/FR/ES, fenêtre de décision Guardian
│   └── WinSight.Mcp .............. serveur MCP stdio en lecture seule (6 outils, 3 ressources, 2 prompts)
├── responsabilités ............... scanners = observation pure ; Response = seules mutations (confirmées,
│                                   journalisées, réversibles) ; FirewallService = seule autorité privilégiée
├── sources de données Windows .... registre, Planificateur de tâches (COM), WMI, IP Helper, ETW, journaux
│                                   d'événements, WSC, WinTrust/CryptCATAdmin, API d'empaquetage, WFP, SCM
├── pipeline de collecte .......... scans à la demande + moniteurs (Guardian, ransomware, caméra/micro, ETW)
├── traitement .................... normalisation → vérification de signature par lot → triage → rapport
├── stockage ...................... %LOCALAPPDATA%\WinSight (journaux, règles, quarantaine, baseline,
│                                   leurres) ; %ProgramData%\WinSight (politique pare-feu, ACL protégée)
├── détection ..................... verdicts de fichier + triage de ligne de commande + exploitabilité +
│                                   heuristiques (rafale, entropie avec signatures de conteneurs, leurres)
├── UI ............................ tableau de bord WPF, balises, fenêtre de décision, CLI texte/JSON, MCP
├── installation/update ........... Inno Setup par utilisateur (défaut) ou tous utilisateurs ; service pare-feu
│                                   enregistré séparément ; pas de mise à jour automatique
└── mécanismes de sécurité ........ tube nommé ACL + usurpation + capacités ; confiance du chemin du service
                                    (identité NTFS 128 bits) ; accès fichiers NtCreateFile + OBJ_DONT_REPARSE ;
                                    journal d'actions en deux phases ; échappement du texte pour MCP
```

### 2.1 Flux : événement Windows → collecte → traitement → détection → stockage → affichage/alerte

| Chaîne | Événement / source | Collecte | Traitement et détection | Stockage | Affichage / alerte |
|---|---|---|---|---|---|
| Scan de persistance | registre, tâches, WMI, dossiers de démarrage, profils | 28 énumérateurs par défaut (`WinSight.Persistence`) | résolution de la commande → vérification de signature par lot (cache par contenu → WinVerifyTrust sur handle stable → catalogue → MSIX) → `IsAdverse` + abus d'interpréteur signé | aucun (instantané) | CLI, JSON versionné, tableau de bord, MCP |
| Guardian (temps réel) | `RegNotifyChangeKeyValue` (clé ou ancêtre existant le plus proche), `FileSystemWatcher` | `RegistryChangeWatcher`, `FileSystemPersistenceWatcher`, réarmement et reprise toutes les 30 s | nouvel scan ciblé des énumérateurs concernés → différence avec la baseline → règles Allow | baseline TSV (remplacement atomique natif + mutex), journal d'alertes, journal d'actions | fenêtre de décision Allow / Bloquer / Plus tard, balise groupée, info-bulle de santé |
| Rançongiciel | écritures dans 6 dossiers connus, leurres | `FileSystemWatcher` (horodatage à l'arrivée) | leurre touché, renommages / suppressions en rafale, écriture à haute entropie hors signature de conteneur | manifeste et graine des leurres | alerte, journal ; posture Controlled Folder Access en lecture |
| Caméra / micro | `CapabilityAccessManager\ConsentStore` (HKCU/HKLM) | interrogation 1 s + réveil par notification registre | transitions actif/inactif par magasin, association au processus | journal d'alertes | balise, `winsight av --watch` |
| Réseau / DNS | IP Helper, cache DNS (WMI), ETW DNS-Client (administrateur) | instantané, file ETW bornée (1 024) | propriétaire, signature, externe, identité stable (PID + heure de création) | aucun | rapports ; pertes ETW exposées |
| Pare-feu sortant | décisions de l'opérateur ; ETW réseau (service) | tube nommé authentifié → service | coordinateur : politique ↔ filtres WFP `ALE_AUTH_CONNECT` v4/v6 par identité d'application | `%ProgramData%\WinSight` (ACL, confiance vérifiée) | état effectif vérifié contre WFP à chaque lecture |
| Réponse | choix de l'opérateur | fenêtre de décision, verbes CLI `--confirm` | revalidation de l'identité (processus : un seul handle ; fichier : même handle ; registre : TxR ou repli vérifié) | quarantaine (DACL privée), journal d'actions en deux phases, règles | résultat explicite (réussi, refusé, partiellement appliqué) |
| MCP | requête d'un client IA | stdio, verrou de scan, délai coopératif | projection : champs sensibles retenus, budget de caractères, texte machine échappé et délimité | aucun | réponse JSON au client |

### 2.2 Frontières de confiance

- **Utilisateur ↔ LocalSystem** : uniquement le tube nommé (ACL : SYSTEM/Administrateurs complet,
  Interactif lecture/écriture, Réseau refusé), usurpation du client, capacité dérivée du jeton réel,
  vérification côté client que le serveur appartient à LocalSystem. Vérifié par lecture (voir §5).
- **Machine observée ↔ WinSight** : tout nom, chemin, valeur de registre ou sujet de certificat est
  contrôlé par l'adversaire ; texte neutralisé pour l'affichage et, pour MCP, échappé par catégorie
  Unicode et délimité.
- **WinSight ↔ système de fichiers** : les lectures automatiques passent par `NtCreateFile` avec
  `OBJ_DONT_REPARSE` et un handle stable ; les chemins UNC, de périphérique et non locaux sont refusés.
- **Même utilisateur** : hors périmètre défendable. Un logiciel malveillant exécuté sous le même
  compte peut arrêter le tableau de bord, réécrire les journaux et les règles et, en installation par
  utilisateur, remplacer les binaires (documenté dans `THREAT_MODEL.md`).

### 2.3 Sources Windows réellement utilisées (vérifiées dans le code)

| Capacité | API / source | Documentée | Privilège |
|---|---|---|---|
| Signatures | `WinVerifyTrust` (handle de fichier), `CryptCATAdmin*`, `IAppxFactory::CreateValidatedBlockMapReader` | oui | aucun |
| Accès fichiers | `NtCreateFile` + `OBJ_DONT_REPARSE`, `ReOpenFile`, `SetFileInformationByHandle` | oui (ntifs/winternl) | aucun |
| Persistance | registre (`Run*`, services, Winlogon, IFEO, LSA, COM…), Task Scheduler COM, WMI `root\subscription` | oui | partiel sans élévation |
| Temps réel persistance | `RegNotifyChangeKeyValue` (THREAD_AGNOSTIC), `ReadDirectoryChangesW` | oui | aucun |
| Réseau | `GetExtendedTcpTable` / `GetExtendedUdpTable` | oui | aucun |
| DNS | WMI `MSFT_DNSClientCache` ; ETW `Microsoft-Windows-DNS-Client` | WMI oui ; fournisseur ETW sans page de référence | ETW : administrateur |
| Attribution | ETW noyau (Process, Registry, FileIOInit) | oui (TraceEvent) | administrateur |
| Caméra / micro | registre `ConsentStore` | **non documenté** (l'alternative documentée est `MFCreateSensorActivityMonitor`) | aucun |
| Processus | WMI `Win32_Process` (ligne de commande, `CreationDate`) | oui | partiel |
| Modules | `Process.Modules` (PSAPI) | oui | partiel |
| Pilotes, filtres clavier/souris | registre SCM et classes de périphériques | oui | aucun |
| Intégrité du code | `NtQuerySystemInformation(SystemCodeIntegrityInformation)` | partiellement | aucun |
| Antivirus / CFA | WSC `IWSCProductList` ; WMI `MSFT_MpComputerStatus` / `MSFT_MpPreference` | oui | aucun |
| Présence | journal Système (Power-Troubleshooter) | oui | aucun |
| Hijack | `AccessCheck` avec le jeton non élevé ; analyse PE statique | oui | aucun |
| Pare-feu | WFP (`FwpmEngineOpen0`, session dynamique, filtres `ALE_AUTH_CONNECT`) | oui | LocalSystem |
| Réponse | `OpenProcess`/`GetProcessTimes`/`TerminateProcess`, Toolhelp + `OpenThread`, Restart Manager, KTM (TxR) | oui | utilisateur |

Non utilisés (vérifié) : pilote noyau, minifiltre, AMSI, ETW Threat-Intelligence, WMI temps réel
(`__InstanceCreationEvent`), journaux Sysmon, `FwpmNetEventSubscribe`.

---

## 3. Fonctionnalités actuelles

| Domaine | WinSight | Méthode | Temps réel | Historique | Alertes | Limites |
|---|---|---|---|---|---|---|
| Processus | ✅ | WMI + signatures | non | non | non (scan) | lignes de commande illisibles pour d'autres comptes sans élévation |
| DLL / modules | ✅ | PSAPI | non | non | non | lent (~57-87 s) ; processus protégés illisibles |
| Connexions | ✅ | IP Helper | `--watch` côté service (ETW, administrateur) | non | non | pas de domaine / SNI ; identité stable seulement si le processus vit encore |
| DNS | 🟡 | cache WMI ; ETW DNS-Client | `dns --watch` (administrateur) | non | non | pas d'attribution fiable par processus depuis le cache |
| Connexions sortantes (contrôle) | 🟡 | WFP par application | application immédiate | journal des applications en attente | non | aucune invite avant connexion ; identité = chemin |
| Autoruns | ✅ | 28 énumérateurs, 27 familles | Guardian | baseline + journal | fenêtre de décision | LSP, extensions shell, Office, GPO, BITS, `Command Processor\AutoRun`, `SetupExecute` absents ; profils déconnectés illisibles |
| Registre (sensible) | 🟡 | notifications sur clés d'autostart | oui | journal | oui | pas de journal de valeurs générique |
| Services | ✅ | registre SCM | Guardian | oui | oui | Bloquer : non (niveau service à venir) |
| Tâches planifiées | ✅ | COM + `System32\Tasks` | oui si le dossier est surveillable | oui | oui | dossier non surveillable pour un utilisateur standard (lacune signalée) |
| Pilotes | 🟡 | registre SCM + signatures | non | non | non | inscrits ≠ résidents |
| Création de fichiers | 🟡 | FSW (dossiers connus, démarrage) | oui | non | rançongiciel | pas de surveillance générique |
| Modifications sensibles | 🟡 | hosts, racines, CFA, intégrité | non | non | non | instantanés |
| Webcam | 🟡 | ConsentStore | ~1 s | oui (horodatages Windows) | oui | accès hors intermédiaire (DirectShow, pilote) invisible ; applis empaquetées non associées au processus |
| Microphone | 🟡 | ConsentStore | ~1 s | oui | oui | idem |
| Hooks clavier | 🟡 | filtres de classe clavier/souris | `input --watch` | non | CLI | `SetWindowsHookEx` non énumérable ; filtres par instance non lus |
| Persistance (réponse) | 🟡 | quarantaine + suppression | — | journal d'actions | — | HKCU Run/RunOnce et dossier Démarrage de l'utilisateur uniquement |
| Signature Authenticode | ✅ | WinVerifyTrust + catalogue + MSIX | — | cache | — | révocation depuis le cache local seulement (par conception) |
| Hash | ✅ | MD5/SHA-1/SHA-256 liés au même objet | — | — | — | — |
| Réputation | 🟡 | VirusTotal (clé utilisateur, quotas) | — | cache | — | désactivé pour MCP ; opt-in |
| Rançongiciel | 🟡 | leurres + rafale + entropie | oui | journal | oui | pas de blocage ni de suspension automatique ; attribution élevée seulement |
| Hijack / chemins | ✅ | AccessCheck + PE | non | non | non | chargements dynamiques (`LoadLibrary`) invisibles |
| Présence physique | 🟡 | journal Système | non | oui | non | cause du réveil souvent absente |
| MCP (IA) | ✅ | stdio, lecture seule | — | journal d'alertes | — | délai coopératif (pas d'isolation dure) |

Légende : ✅ couvert, 🟡 partiel, ❌ absent.

---

## 4. Problèmes trouvés

Statuts : **Corrigé** (code et tests), **Documenté** (limite rendue explicite, pas de changement de
code), **Ouvert** (recommandation, non traité), **Corrigé en partie** (la part corrigée figure en 4.1, le
reste en 4.2). « Preuve » renvoie au fichier concerné ; les
corrections sont couvertes par des tests nommés dans l'historique de la branche.

### 4.1 Corrigés pendant l'audit

| ID | Sév. | Composant | Description | Impact | Preuve | Correction | Statut |
|---|---|---|---|---|---|---|---|
| WS-01 | High | Hijack | En élévation, `C:\` était jugé inscriptible par un utilisateur standard (ACE héritage seul + droit « créer un dossier » lus comme « créer un fichier ») | chaque chemin de service non cité gradué *Exploitable* | `UnprivilegedWriteAccess.cs` ; `icacls C:\` | distinction fichier/dossier, ACE héritage seul ignorées, puis évaluation `AccessCheck` avec le jeton non élevé | Corrigé |
| WS-02 | High | Hijack | Entrée PATH absente évaluée avec le droit « créer un fichier » dans le parent | faux négatif classique (`C:\Python27` recréable par tous) | `HijackTriage.cs` | question « créer un dossier » à l'ancêtre existant le plus proche | Corrigé |
| WS-03 | High | Guardian | Clés d'autostart absentes au démarrage jamais surveillées ; clé supprimée puis recréée perdue ; couverture comptée à tort | persistance dans `Policies\Explorer\Run` ou Run recréée invisible jusqu'au redémarrage | `RegistryChangeWatcher.cs` | surveillance de l'ancêtre existant puis bascule sur la clé ; refus distingué de l'absence ; reprise toutes les 30 s | Corrigé |
| WS-04 | Medium | Réponse | Revalidation puis action par PID nu (réutilisation de PID) | suspension ou arrêt d'un processus sans rapport | `Win32ProcessController.cs` | action via le handle vérifié (heure de création) ; threads vérifiés par `GetProcessIdOfThread` | Corrigé |
| WS-05 | Medium | Réponse | « Suspendu » dès qu'un seul thread l'était ; threads en échec jamais réessayés | processus présenté comme gelé alors qu'il tourne | idem | succès seulement si tous les threads vivants ; retour arrière par les handles exacts, `PartiallyApplied` sinon | Corrigé |
| WS-06 | Medium | Signatures | Lot de vérification non dédupliqué (4 533 entrées → 438 fichiers) | scan de persistance 25,2 s | `NativeSignatureVerifier.cs`, `CachingSignatureVerifier.cs` | déduplication insensible à la casse : 9,3 s | Corrigé |
| WS-07 | Medium | Persistance | Ruches des autres utilisateurs lues sous deux vues registre | chaque entrée en double, l'une avec un emplacement `WOW6432Node` inexistant | `UserHiveEnumerator.cs` | vue 64 bits seule | Corrigé |
| WS-08 | High | MCP | Ligne de commande (arguments, secrets) exposée au modèle via `context` du hijack et le détail d'alerte, hors barrière *sensitive* | fuite vers le fournisseur d'IA | `Adapters.cs`, `PersistenceMonitorPresenter.cs` | ligne complète dans le champ retenu `command` ; exécutable seul dans le texte | Corrigé |
| WS-09 | Medium | MCP | Échappement par liste de 15 caractères BMP : caractères TAG U+E0000–E007F, U+2028/2029, U+2060… passaient | instructions invisibles lues par le modèle | `UntrustedText.cs` | échappement par catégorie Unicode sur tous les plans + sosies de délimiteurs | Corrigé |
| WS-10 | Medium | MCP | Le délai de 90 s n'annulait pas le scan, qui gardait le verrou | toutes les requêtes suivantes refusées jusqu'au redémarrage | `McpScanService.cs` | jeton lié annulé à l'échéance ; fournisseur bloqué signalé immédiatement ensuite | Corrigé |
| WS-11 | Medium | Rançongiciel | Rafales horodatées au traitement, pas à l'arrivée | détection manquée sous forte charge disque | `RansomwareFileWatcher.cs` | horodatage à l'arrivée ; ordre monotone préservé dans le détecteur | Corrigé |
| WS-12 | Low | Guardian | Baseline : nom temporaire fixe, pas de vidage disque, écritures concurrentes | baseline vide après coupure → nouvelles entrées absorbées sans alerte | `FilePersistenceBaselineStore.cs` | mutex nommé + remplacement atomique natif vidé sur disque | Corrigé |
| WS-13 | Medium | Installeur | Verbe Explorer « Vérifier la signature » jamais enregistré ; aucun nettoyage | fonction annoncée absente après installation normale | `installer/WinSight.iss` | tâche d'installation (ruche HKA), suppression à la désinstallation, test du cycle de vie | Corrigé |
| WS-14 | Low | CLI / docs | `alerts` et verbes de maintenance absents de l'aide ; README inexact sur les commandes modifiant la machine | découverte impossible, affirmation fausse | `CliHelp.cs`, `README.md` | aide et README corrigés (28 verbes) | Corrigé |
| WS-15 | Medium | Pare-feu | L'arrêt d'urgence refusait d'agir si le stockage de la politique n'était plus « de confiance » | filtres actifs sans voie de sortie documentée | `EnforcementCoordinator.cs` | nettoyage WFP indépendant de la confiance du stockage, stockage non touché, état `Degraded` | Corrigé |
| WS-16 | Medium | Pare-feu (docs) | Blocage par identité de chemin non divulgué comme contournable | faux sentiment de confinement | `THREAT_MODEL.md` | copie/lien/enfant/injection documentés | Documenté |
| WS-17 | High | Réponse | Suppression/restauration de persistance : capture, vérification et action séparées | suppression d'une valeur remplacée entre-temps | `RegistryAndFilePersistenceMutator.cs` | fichiers : même handle et `CreateNew` ; registre : TxR | Corrigé |
| WS-18 | High | Réponse | TxR indisponible sur Windows 11 (6801 sur HKCU et HKLM) : le correctif WS-17 faisait refuser tout blocage de valeur | « Bloquer » inutilisable pour le registre | test natif `RegOpenKeyTransacted` | repli vérifié : un handle de clé, relecture ; entrée réinscrite signalée ; garde de ruche | Corrigé |
| WS-19 | High | Réponse | Action destructrice réussie même si le journal échouait | action non auditée présentée comme normale | `ActionJournal.cs` | journal en deux phases (intention, puis résultat), `PartiallyApplied` explicite | Corrigé |
| WS-20 | High | Réponse | Processus protégés reconnus au nom de fichier (un `lsass.exe` renommé ailleurs l'était aussi, et inversement) | contournement de la protection ou refus erroné | `ProtectedProcesses.cs` | identité : chemin canonique sous System32/SysWOW64, processus WinSight courant | Corrigé |
| WS-21 | Medium | Signatures | Verdict et empreintes calculés sur des ouvertures distinctes du même chemin | rapport combinant deux objets différents | `FileSignatureReport.cs` | verdict, certificat et hachages liés au même handle | Corrigé |
| WS-22 | High | Accès fichiers | Lectures automatiques suivant un reparse point local vers un partage UNC | authentification SMB / lecture d'un autre fichier | `AutomaticFileAccess.cs` | `NtCreateFile` + `OBJ_DONT_REPARSE`, identité revérifiée ; mutations relatives au handle | Corrigé |
| WS-23 | Medium | Concurrence | Mutex nommés : délai expiré puis poursuite sans verrou (règles, manifeste des leurres) | écrasements concurrents | `RuleStore.cs`, `CanaryManager.cs` | bail uniquement après possession prouvée | Corrigé |
| WS-24 | Medium | Rançongiciel | Réécriture en place de formats conteneurs (docx, zip, pdf…) ignorée | chiffrement sans renommage invisible hors leurres | `RansomwareEntropySampler.cs` | signatures de conteneurs requises avant l'entropie | Corrigé |
| WS-25 | Medium | Capteurs | Aucune santé commune : pertes ETW, débordements FSW, réarmements invisibles | couverture présentée comme complète | `SensorHealth.cs` | état, compteurs de pertes et reprises exposés dans l'interface et la CLI (code 13) | Corrigé |
| WS-26 | Medium | Pare-feu | Journal des applications en attente : les 128 premières gagnaient | un attaquant pouvait masquer toutes les suivantes | `PendingOutboundLog.cs` | fenêtre LRU bornée, pertes comptées, journalisation plafonnée | Corrigé |
| WS-27 | Medium | DNS | Travail consommateur dans le rappel ETW, pas de santé de perte | pertes silencieuses | `DnsEtwWatcher.cs` | canal borné, ordre préservé, pertes natives + applicatives | Corrigé |
| WS-28 | Medium | Corrélation | Jointures entre instantanés par PID seul | ascendance et modules attribués au mauvais processus | `ProcessInsight.cs` | identité PID + heure de création | Corrigé |
| WS-29 | Medium | Hijack | Deux sondes (scanner et triage) : les échecs de la seconde n'entraient pas dans la couverture ; SID connus seulement | scan « complet, rien trouvé » alors qu'aucune question n'avait abouti | `HijackScanner.cs` | sonde partagée ; repli SID connus étiqueté sous SYSTEM / UAC désactivé | Corrigé |
| WS-30 | Low | MCP | Le scan hijack écrivait des fichiers malgré l'annotation « lecture seule » | trace laissée, contradiction avec le contrat | `WritabilityProbe.cs` | plus aucune écriture (AccessCheck) | Corrigé |
| WS-31 | Medium | Tableau de bord | Plusieurs instances interactives possibles | moniteurs, alertes et journaux en double | `App.xaml.cs` | instance unique par utilisateur et session ; la seconde réactive la première | Corrigé |
| WS-32 | Medium | Hijack (perf) | Indexation WinSxS récursive : ~46 000 handles de répertoire ouverts simultanément | pression noyau et filtres antivirus | `SideBySideStore.cs` | parcours en profondeur, un handle à la fois (pic 45 910 → 553) | Corrigé |
| WS-33 | Low | Réponse | Chemin transactionnel sans garde de ruche (ouvrait HKCU avec la sous-clé d'une cible HKLM) | action sur la mauvaise clé si une cible machine arrivait jusque-là | `RegistryAndFilePersistenceMutator.cs` | garde HKCU explicite | Corrigé |
| WS-40 | Medium | Accès fichiers | Crainte initiale : toute lecture refuse un fichier portant `ReparsePoint`, donc les fichiers OneDrive. Mesuré en VM avec une racine Cloud Files jetable (porte 17) : les substituts hydratés se lisent (l'attribut est masqué aux applications), mais lire un fichier « en ligne uniquement » demandait deux téléchargements au fournisseur et bloquait 120 s, même par une réouverture interdisant le rappel | sous OneDrive, un scan aurait téléchargé les fichiers de l'utilisateur, et chaque lecture pouvait bloquer une minute | `AutomaticFileAccess.cs` | réouverture relative au handle avec `FILE_OPEN_NO_RECALL` (`ReOpenFile` refuse ce drapeau), et refus de toute lecture d'un fichier marqué hors ligne, rappel à l'ouverture ou rappel à l'accès : métadonnées visibles, données jamais rapatriées ; porte 17 : aucun téléchargement, réponse immédiate ; résidu RA-02 (nom d'origine lu par chemin, hors de cette garde) corrigé le 24 septembre (§4.3) | Corrigé, qualifié en VM (porte 17) ; RA-02 à requalifier |
| WS-41 | Medium | Pilotes | `ImagePath` non résolu ou fichier introuvable → repli sur `System32\drivers\<nom>.sys` même quand `ImagePath` était défini ; `\??\GLOBALROOT` et noms de volume lus comme chemins relatifs | un pilote enregistré ailleurs vérifié comme le fichier Microsoft du même nom, donc « fourni par Windows » et masqué | `KernelDriverScanner.cs`, `InputFilterScanner.cs` | `DriverImagePath` partagé : défaut seulement sans `ImagePath` ; nom d'objet NT ou partage = `Unresolvable`, signalé avec la valeur enregistrée ; verdicts inchangés pour les 456 pilotes de ce poste | Corrigé |
| WS-42 | Medium | Signatures | L'ancre « racine installée par l'utilisateur » n'était prise en compte que par la persistance et le verbe signature | processus, module ou propriétaire de connexion signé via une racine importée sans privilège présenté comme sain ; un certificat « Microsoft Windows » forgé faisait passer un pilote de System32 pour fourni par Windows | `ProcessInfo.cs`, `LoadedModule.cs`, `Connection.cs`, `WindowsImage.cs` | signalé partout (champ `userInstalledTrust`, texte explicite) ; jamais « fourni par Windows » ; pilotes et filtres `Untrusted` (l'intégrité du code noyau ignore le magasin de l'utilisateur) | Corrigé |
| WS-43 | Medium | Filtres d'entrée | `kbdclass` / `mouclass` jugés attendus sur leur seul nom | `ImagePath` repointé vers un autre pilote : la ligne reste « pilote de classe Windows » et sort de la vue signalée | `InputFilterTriage.cs` | attendu = nom **et** image `<nom>.sys` signée par l'identité exacte Windows dans System32 (règle partagée `WindowsImage`) ; sinon `Impersonating` ; vérification impossible = `Unverified` | Corrigé |
| WS-44 | Medium | WMI | `ReturnImmediately = false` (processus, cache DNS, Controlled Folder Access), aucune option pour les règles pare-feu : le délai ne bornait pas la requête elle-même | fournisseur bloqué → scan et annulation figés (mesuré : `Get()` bloqué 27 s sous un délai d'1 s) | `ProcessLister.cs`, `DnsCacheReader.cs`, `ControlledFolderAccessReader.cs`, `FirewallRuleReader.cs` | mode semi-synchrone, délai par résultat ; options épinglées par des tests (dont un qui figeait le mode synchrone) | Corrigé |
| WS-45 | Medium | Persistance | Contexte 32 bits : une DLL inscrite sous `WOW6432Node` (AppInit_DLLs, assistants netsh, serveurs COM in-process, BHO) était résolue comme par un processus 64 bits | le jumeau 64 bits vérifié à la place du fichier que chargent les processus 32 bits, ou « introuvable » pour une DLL réelle | `CommandLine.cs`, `LoaderContext.cs` | contexte de chargement porté par l'entrée : `System32` → `SysWOW64` (hors exemptions du redirecteur), `Sysnative` → `System32`, `%ProgramFiles%` → `Program Files (x86)` ; mesuré ici : 22 entrées vérifient désormais le fichier 32 bits (19 assistants netsh, 2 `shell32`, `mscoree`), aucun verdict changé | Corrigé |
| WS-46 | Medium | Persistance | Variables d'environnement des autres comptes (clés Run des autres ruches, tâches planifiées exécutées sous un autre compte) résolues avec celles du compte qui scanne ; une valeur `REG_EXPAND_SZ` était même développée par .NET avec le profil du scanner | mauvais fichier vérifié ou faux « introuvable » | `UserHiveEnumerator.cs`, `ScheduledTaskPrincipal.cs`, `AccountEnvironment.cs` | valeurs lues brutes, résolues avec le profil du compte (ProfileList, puis dossiers redirigés et variables de sa ruche si elle est chargée) ; principal des actions de la tâche (SID, nom connu, compte local — jamais de requête à un annuaire) ; variable propre au compte qu'il ne définit pas laissée non développée plutôt que pointant vers le profil du scanner | Corrigé |
| WS-66 | Medium | Persistance | Chemins relatifs et noms nus cherchés d'abord dans le répertoire de travail de WinSight | verdict dépendant du dossier de lancement : le pilote 3ware lu « signature valide » depuis `C:\Windows`, « non signé » depuis un dossier contenant un leurre `System32\drivers\3ware.sys` ; un fichier signé déposé là pouvait répondre pour un enregistrement | `CommandLine.cs` | candidats pleinement qualifiés uniquement, sonde qui refuse le reste, entrées `%PATH%` relatives ignorées ; 1 entrée sur 4 540 change (un `StubPath` réduit à « U », désormais non résoluble) | Corrigé |
| WS-47 | Medium | Hosts | `Tcpip\Parameters\DataBasePath` ignoré : le fichier hosts réellement utilisé par Windows pouvait être déplacé hors de vue | toutes les redirections déplacées, fichier standard propre présenté | `HostsReader.cs` | emplacement lu dans le registre (`%SystemRoot%`/`%windir%` résolus depuis le répertoire Windows du système, jamais depuis l'environnement), déplacement signalé, fichier déplacé lu ; partage, chemin relatif ou autre variable : signalé, non lu | Corrigé |
| WS-48 | Medium | Extensions | `content_scripts` ignoré ; canaux Beta/Dev/Canary, Chromium et Opera GX absents ; extensions chargées depuis un dossier (mode développeur, `--load-extension`, entrée forgée de `Secure Preferences`) jamais lues | script injecté sur tous les sites jugé sans accès ; navigateurs non lus ; extension hors boutique invisible, alors que c'est le mode de persistance des chargeurs forcés | `ExtensionScanner.cs` | motifs `matches` comptés comme accès hôte ; 10 racines ajoutées ; `extensions.settings` lu dans `Secure Preferences` et `Preferences` (emplacements 4 et 8), manifeste lu dans le dossier, extension toujours signalée ; dossier disparu ou sur un partage nommé sans être ouvert ; mesuré ici : 24 → 26 extensions (deux dossiers de build de l'opérateur) | Corrigé |
| WS-49 | Medium | Tableau de bord | La raison d'un signalement (racine installée par l'utilisateur, code tiers dans un processus privilégié) disparaissait ; lignes processus/modules sans état de signature ; tout le cache DNS « résolu par le réseau » | [!] à côté de « Signature valide », ou d'un chemin nu | `DashboardFindingPresenter.cs` | champs `privilegedHost`/`userInstalledTrust`, raison localisée ajoutée, état de signature affiché ; DNS « dans le cache du résolveur » | Corrigé |
| WS-50 | Medium | Tableau de bord | Une exception imprévue dans un gestionnaire d'interface terminait l'application, donc toute la protection temps réel | Guardian, rançongiciel et caméra arrêtés sans avertissement | `CrashReporter.cs`, `DispatcherRecoveryPolicy.cs` | une fois démarré : exception absorbée, rapport écrit, avis dans la zone de notification ; jamais au démarrage, ni pour une exception qui compromet le processus (mémoire, pile, état corrompu, déploiement cassé), ni au-delà de 3 par minute | Corrigé |
| WS-51 | Medium | Hijack | Index WinSxS non terminé dans son budget de 8 s : le parcours de tout WinSxS prenait 9,75 s à chaud (124 584 répertoires), davantage à froid | imports « fantômes » dégradés en « non déterminé », scan hijack déclaré incomplet | `SideBySideStore.cs` | parcours limité à ce que le chargeur utilise : dossiers techniques (`Temp`, `InstallTemp`, `Backup`, `Manifests`, `Catalogs`, `FileMaps`) et deltas `f`/`r`/`n` exclus, `Fusion` et tout dossier futur parcourus (liste d'exclusion) ; 27 039 répertoires en 2,1 s, mêmes 5 828 noms sauf 5 fichiers en attente de suppression ; `winsight hijack` 8,3-8,7 s incomplet → 2,4-3,4 s complet, les deux imports autrefois non déterminés répondus comme par un parcours complet ; un homonyme n'importe où dans WinSxS valait encore résolution : lié au manifeste de l'image le 24 septembre (RA-04) | Corrigé |
| WS-52 | Medium | Perf | Surveillance caméra/micro au repos : ~1,7 % d'un cœur (relecture complète du ConsentStore chaque seconde malgré la notification registre) | batterie pour un moniteur permanent | `CameraMicMonitor.cs`, `RegistryKeyWatcher.cs` | interrogation à 30 s tant que la notification des deux ruches est confirmée armée, sinon 1 s ; mesuré 0,09 % et 27 Mo (contre 1,7 % et 47 Mo) | Corrigé |
| WS-54 | Low | Persistance | Chaque CLSID HKCU rapporté comme « ComHijack » (3 941 lignes, JSON de 5,3 Mo), copies de la classe machine comprises, sans distinguer le détournement d'un CLSID HKLM | bruit, rapport lourd, le vrai détournement noyé | `ComHijackEnumerator.cs` | copie identique à la classe machine ignorée ; classe utilisateur qui remplace le serveur de la machine signalée (T1546.015), sauf signée Microsoft ; mesuré ici : 4 541 → 698 entrées, JSON 5,3 → 0,9 Mo, même entrée signalée | Corrigé |
| WS-55 | Low | Certificats | Racines machine comptées deux fois ; `TrustedPublisher` et `Disallowed` non audités | liste doublée ; un éditeur approuvé ajouté sans élévation (vue utilisateur) invisible | `CertStoreAuditor.cs`, `TrustedCertificate.cs` | dédoublonnage par magasin ; rôle Root / TrustedPublisher / Disallowed : éditeur propre à l'utilisateur ou dont la clé privée est présente signalé, `Disallowed` jamais une alerte ; `CA` volontairement non lu (un intermédiaire n'accorde aucune confiance sans racine) ; mesuré ici : 67 racines, 2 éditeurs machine, les mêmes 6 racines signalées | Corrigé |
| WS-56 | Low | Intégrité | WDAC en audit présenté comme appliqué ; chemins d'exclusion ignorés ; bit d'audit HVCI lu à l'envers (activé + audit = « n'applique rien », audit seul = « désactivé ») ; signature « flight » non signalée | fausse assurance et fausse alarme | `CodeIntegrityTriage.cs` | lecture conforme à la documentation de `SYSTEM_CODEINTEGRITY_INFORMATION` ; test de localisation générant toutes les combinaisons d'options | Corrigé |
| WS-57 | Low | Filtres CLI | `--nonmicrosoft` masquait tout signataire dont le texte contenait « Microsoft » | un faux « CN=Microsoft » auto-signé ou sous racine utilisateur disparaissait du filtre | `ReportItemFilter.cs` | champ `microsoftSigned` établi depuis le verdict entier (identité exacte, chaîne de confiance machine) | Corrigé |
| WS-58 | Low | Présence | Durées au-delà de 24 h tronquées (30 h lues « 06:00 ») ; un `Data` dupliqué levait une exception qui interrompait le scan | affichage faux, scan interrompu | `PresenceScanner.cs` | jours conservés ; première occurrence retenue | Corrigé |
| WS-59 | Low | Hosts | Puits détectés par comparaison de chaînes | `127.1`, `0`, `::ffff:127.0.0.1` signalés comme redirections externes | `HostEntry.cs` | adresse analysée : bouclage, non spécifiée, 0.0.0.0/8 | Corrigé |
| WS-61 | Low | MCP | Rédaction des chemins sans frontière (`C:\Users\nom2` → `%USERPROFILE%2`) ; alertes bloquées derrière le verrou de scan ; étanchéité à la couche de réponse testée par références directes seulement (MCP → application → réponse) | fragment d'un autre nom de compte divulgué ; « un autre scan est en cours » ; régression possible non détectée | `McpModels.cs`, `McpScanService.cs`, `IlCallGraph.cs` | rédaction par chemin entier ; journal lu hors verrou ; graphe d'appels IL conservateur (machines à états, lambdas, dispatch virtuel, rappels du framework) depuis chaque méthode MCP : aucun mutateur **listé** atteignable, zéro jeton non résolu, témoin positif depuis la CLI ; vérifié en injectant un appel caché dans une lambda. Une garde ciblée, pas une preuve : étendue le 24 septembre à la frontière du framework et des P/Invoke (RA-06) | Corrigé |
| WS-62 | Low | Supply chain | Le workflow de release restaurait le cache `setup-dotnet` dans un build de tag | empoisonnement de cache théorique | `release.yml` | cache désactivé pour les releases, test de contrat | Corrigé |
| WS-63 | Low | Installeur | La désinstallation « tous les utilisateurs » laissait le service pare-feu enregistré depuis cette installation | service LocalSystem pointant vers un binaire supprimé, blocages conservés | `installer/WinSight.iss` | en mode administrateur, si `ImagePath` désigne l'exécutable de cette installation, son verbe `uninstall` (arrêt, objets WFP, enregistrement) avant toute suppression ; service d'un autre emplacement laissé en place ; en cas d'échec, la désinstallation s'arrête avant de supprimer quoi que ce soit (RA-05 : elle se poursuivait jusqu'au 24 septembre) ; porte VM 15 (`Test-InstallerServiceUninstall.ps1`, cas négatif et échec injecté) | Corrigé, qualifié en VM (porte 15, deux passes) ; cas d'échec RA-05 à qualifier |
| WS-67 | Low | Maintenabilité | `Adapters.cs` : 1 958 lignes pour tous les scans | revue et diff difficiles | `Application/Adapters*.cs` | 11 fichiers partiels par domaine (85 à 411 lignes), déplacement pur | Corrigé |
| WS-68 | Low | Tableau de bord | Les lignes hosts « fichier illisible » et « enregistrements mal formés » présentées comme « redirection externe » | message contraire aux faits | `DashboardFindingPresenter.cs` | présentation propre et localisée | Corrigé |
| WS-69 | Low | Maintenabilité | Fichiers au-delà de 800 lignes : `MainWindow.xaml.cs` (1 449), `WfpProvisioning.cs` (1 300), `Enumerators.cs` (1 257), `EnforcementCoordinator.cs` (808) | revue et diff difficiles | ces fichiers | déplacement pur vérifié ligne à ligne : un énumérateur par fichier, partiels par thème pour la fenêtre, WFP et les transitions ; plus aucun fichier de production au-delà de 800 lignes ; exclusions de couverture reportées sur les partiels | Corrigé |
| WS-70 | Medium | Guardian | La ligne de base persistée ne mémorisait pas quelles sources étaient lisibles : tout élément d'une source devenue lisible était annoncé comme nouveau (en VM, ~60 tâches planifiées et services Windows au premier tableau de bord élevé) | rafale de fausses alertes au moment où l'utilisateur suit le conseil d'élever ; fatigue d'alerte | `PersistenceCoverageMap.cs`, `PersistenceMonitorCore.cs`, `FilePersistenceBaselineStore.cs` | portées couvertes (source × portée) persistées avec la ligne de base, union conservée d'un scan à l'autre ; éléments d'une portée qui n'était pas couverte absorbés sans annonce ; format lisible par la v0.13 (lignes ignorées), ligne de base sans couverture : règle précédente ; 4 tests échouent sans le correctif ; l'absorption se faisait sans un mot : annoncée comme incertaine depuis le 24 septembre (RA-03) | Corrigé |
| WS-71 | Low | Validation | Kit VM, §6 : « no single-instance mutex » et deux tableaux de bord lancés côte à côte, alors que le tableau de bord est à instance unique depuis WS-31 ; la porte échouait sur le comportement voulu (« Dashboard … stopped ») | requalification bloquée à tort | `docs/validation/VM_QUALIFICATION_KIT.md` | la porte prouve la passation (second lancement : sortie 0, aucune session) et la préservation d'une session vivante face à `attribution --watch` ; test de contrat | Corrigé |
| WS-72 | Low | Validation | Kit VM, §6 : `sc start` explicite après l'arrêt brutal du service, en course avec l'action de récupération du SCM (redémarrage à 5 s) ; dès que le re-hachage intermédiaire dépassait 5 s, l'échec 1056 faisait passer un service rétabli pour un service qui ne redémarre pas | faux échec ; récupération SCM jamais qualifiée | `docs/validation/VM_QUALIFICATION_KIT.md` | attendre, et donc prouver, le redémarrage par le SCM sous un nouveau PID, puis vérifier que c'est le candidat ; test de contrat | Corrigé |
| WS-73 | High | Attribution | Chaque `FileIOCreate` était enregistré comme écriture, simple ouverture comprise. Mesuré en VM (porte 25) : juste après le dépôt d'un raccourci dans le dossier Démarrage, l'Explorateur (`sihost.exe`) et Defender (`MsMpEng.exe`) l'ouvrent, et l'index, qui retient l'écriture la plus récente, les aurait désignés comme auteurs | Guardian nomme l'Explorateur ou l'antivirus comme auteur d'une persistance malveillante : un faux nom à côté d'une alerte, qui invite à la tolérer | `WriteAttributionWatcher.cs` | création comptée seulement si sa disposition peut créer ou remplacer (tout sauf `OPEN_EXISTING`) ; une écriture après une ouverture reste vue par son événement d'écriture ; porte 25 : seul l'auteur réel est attribué | Corrigé, qualifié en VM (porte 25) |
| WS-74 | High | Persistance | Le nom compilé dans l'image était lu par `FileVersionInfo`, qui prend la ressource localisée du fichier de langue : `powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe` et `regsvr32.exe` se nommaient `*.MUI` (mesuré sur Windows 11 26200), un nom absent de la table des interpréteurs, et ce nom prime sur le chemin | `powershell -enc <charge>` dans une clé Run restait une entrée ordinaire signée Microsoft, jamais signalée ; livré dans la v0.12.0 et la v0.13.0 | `PersistenceScanner.cs`, `InterpreterAbuseTriage.cs` | ressource de version de l'image elle-même, lue par le handle acquis (`PeResources`, `VersionResource`) ; suffixe `.mui` retiré des entrées déjà enregistrées ; test de bout en bout sur le vrai `powershell.exe`, en échec sur l'ancien code | Corrigé |
| WS-75 | Medium | Hijack | Le contrôle d'écriture ne demandait à Windows que le droit de créer (`FILE_ADD_FILE`), jamais ceux qui permettent de se l'accorder : `WRITE_DAC`, que le propriétaire détient sans aucune entrée, et `WRITE_OWNER`, qui permet de le devenir. Trouvé en corrigeant un test qui ne passait qu'avec TEMP sous le profil (C:) : il changeait le propriétaire, ce qui exige `WRITE_OWNER` | un dossier qu'un utilisateur standard possède (créé par lui, puis verrouillé par un administrateur qui a gardé le propriétaire) : entrée du PATH, dossier de service ou chemin non cité, jugé non plantable par l'utilisateur même qui peut le rouvrir | `UnprivilegedWriteAccess.cs` | `AccessCheck` en `MAXIMUM_ALLOWED` (droits implicites du propriétaire compris) ; si seul `WRITE_OWNER` revient, question reposée sur le descripteur tel qu'il serait après la prise de possession ; modèle des groupes connus : `WRITE_DAC`, `WRITE_OWNER` et propriétaire comptés, entrée `OWNER RIGHTS` respectée ; sémantique mesurée sur Windows 11 26200 (un refus explicite n'ôte pas le `WRITE_DAC` du propriétaire, une entrée `OWNER RIGHTS` si) ; 8 tests en échec sur l'ancien code ; pas de porte VM dédiée (la porte 06 ne vérifie que le contrat du rapport) | Corrigé |
| WS-76 | Low | Hijack | Le descripteur de sécurité était lu sans le niveau d'intégrité obligatoire (étiquette) : un dossier étiqueté au-dessus de *Medium* refuse toute écriture au jeton d'un utilisateur standard, quelle que soit sa DACL, mais les deux méthodes jugeaient la DACL seule. Relevé par la revue indépendante de WS-75, qui en élargissait la portée (WRITE_DAC et WRITE_OWNER comptés) | un dossier étiqueté *High* ou *System* accordant la création aux utilisateurs présenté comme plantable : une fausse accusation, rare (peu de dossiers portent une telle étiquette) | `AutomaticFileAccess.cs`, `UnprivilegedWriteAccess.cs` | étiquette lue avec le descripteur (`LABEL_SECURITY_INFORMATION`, READ_CONTROL suffit) ; `AccessCheck` l'applique de lui-même (mesuré : les drapeaux NR ou NX seuls bloquent aussi l'écriture, par la politique « pas d'écriture montante » de tout jeton standard) ; le modèle des groupes connus refuse un dossier étiqueté au-dessus de *Medium* ; 6 tests en échec sur l'ancien code. La même revue a relevé deux points mineurs corrigés avec : une double libération possible du tampon de privilèges si sa réallocation échouait, et la lecture du propriétaire hors de la garde d'exceptions | Corrigé |
| WS-77 | Low | Validation | Le harnais Hyper-V ne démarrait pas sous Windows PowerShell 5.1 : ses scripts avancés (`[CmdletBinding()]`) calculaient des valeurs par défaut de paramètres à partir de `$PSScriptRoot`, que PowerShell 5.1 laisse vide pendant l'évaluation de ces valeurs quand le script est lancé avec `-File` (mesuré ; le même script lancé avec `&` ou par PowerShell 7 le voit). Le dépôt de l'exécuteur et du vérificateur en dépendait depuis la refonte RA-01, tous les emplacements depuis le retrait du lecteur codé en dur ; trouvé au premier lancement de la protection du stockage | la protection du stockage, l'exécuteur et le vérificateur de provenance échouaient avant leur première ligne (« GetPathRoot : le chemin d'accès n'a pas une forme conforme ») ; aucune preuve concernée, le harnais n'avait jamais tourné ; trois scripts de validation portaient le même défaut, sans effet dans la VM qui leur passe les chemins | `scripts/validation/hyperv/*.ps1`, `Test-IpcBoundary.ps1`, `Test-IpcNetworkObserver.ps1`, `Measure-Performance.ps1` | valeurs calculées dans le corps, avec la même expression, seulement si le paramètre est absent ; test de contrat sur les 33 scripts de `scripts/`, en échec sur l'ancien code pour les 11 concernés ; en-têtes des 11 scripts exécutés sous PowerShell 5.1 avec `-File` : chemins attendus | Corrigé |
| WS-78 | Low | Validation | La vérification du stockage des VM ne connaissait pas les entrées qu'Hyper-V pose lui-même : elle ne connaissait que l'identité propre à chaque VM (`S-1-5-83-1-*`) et refusait l'écriture accordée à la capacité du processus de travail (`vmWorkerProcess`, `S-1-15-3-1024-…`) sur le disque de données de la VM de contrôle, puis l'entrée CREATOR OWNER (GENERIC_ALL, héritage seul) du dossier de chaque VM ; elle s'arrêtait au premier refus, une passe de protection par entrée ; le scellement des empreintes lisait ensuite avec `Get-FileHash`, qui échoue sur la configuration d'un point de contrôle que le service de gestion Hyper-V garde ouverte même VM éteinte | protection du stockage impossible, donc aucune passe VM ; rien de modifié au-delà du propriétaire des disques et du verrou du dossier parent | `WinSightHyperV.psm1` | la capacité, et elle seule, acceptée dans le stockage des VM seulement (une capacité ne compte que pour un jeton AppContainer, au second de ses deux contrôles d'accès, et ne donne jamais l'écriture à un utilisateur local ; SID recalculé comme Windows le fait, SHA-256 du nom en majuscules, et vérifié par `DeriveCapabilitySidsFromName`) ; CREATOR OWNER accepté (il désigne, sur chaque nouvel élément, son créateur, qui devait déjà détenir un droit de création réservé aux comptes de confiance), CREATOR GROUP toujours refusé (le groupe principal du créateur est un groupe ordinaire) ; tous les refus listés en une fois ; empreintes lues avec tous les modes de partage, et un fichier que son détenteur ne laisse pas lire nommé dans le scellement sans empreinte plutôt que de faire échouer une protection déjà en place ; tests de contrat et huit autocontrôles PowerShell 5.1, en échec sur les modules précédents | Corrigé |
| WS-79 | Medium | Validation | Sur un Windows client, un processus élevé crée ses fichiers au nom du compte de l'opérateur (réglage par défaut « créateur de l'objet ») : les 400 fichiers écrits par le premier exécuteur appartiennent à ce compte. Le harnais refait fixait le propriétaire de ses dossiers protégés, pas celui des fichiers qu'il y copie ou y écrit | le propriétaire d'un fichier peut toujours en changer les droits : tout processus du compte de l'opérateur aurait pu modifier une copie protégée ou les preuves scellées, ce que la vérification de provenance, qui teste seulement le refus d'une écriture, n'aurait pas vu ; l'exécuteur, qui revérifie sa copie du harnais, aurait par ailleurs refusé de démarrer | `WinSightHyperV.psm1` et les six scripts élevés | chaque script élevé fait des Administrateurs le propriétaire par défaut de son jeton (`SetTokenInformation(TokenOwner)`, hérité par les processus qu'il lance) avant de créer quoi que ce soit, ce que Windows n'accorde qu'à un jeton élevé ; test de contrat sur les six scripts et autocontrôle PowerShell 5.1 (le propre SID accepté, Administrateurs refusé hors élévation, erreur 1307), en échec sur les scripts précédents | Corrigé |
| WS-80 | Low | Validation | Première passe complète : l'invité s'est éteint seul après 121 minutes, puis le retrait du disque de transport a échoué une seconde plus tard (« l'opération ne peut pas être effectuée tant que l'objet se trouve dans son état actuel ») ; le pilote s'est arrêté sans rapatrier les résultats, et la VM, redémarrée avec un disque qui disait toujours « qualify », a rejoué toutes les portes par-dessus. La passe suivante a été refusée : restaurer le point de contrôle crée un disque différentiel dont le propriétaire est l'identité de la VM | deux heures de passe perdues, résultats écrasés ; aucune preuve scellée | `WinSightHyperV.psm1`, `Invoke-HyperVQualification.ps1`, `Invoke-HyperVNetworkLogon.ps1`, `guest/run-guest-checks.ps1` | retrait du disque réessayé jusqu'à ce que la VM soit vraiment éteinte, VM trouvée relancée éteinte et consignée ; l'invité écrit « done » avant de s'éteindre et s'éteint aussitôt s'il redémarre ; identité de la VM acceptée comme propriétaire dans le stockage des VM seulement ; test de contrat et autocontrôle PowerShell 5.1, en échec sur le harnais précédent | Corrigé |
| WS-81 | Low | Validation | L'étape réseau (porte 36) démarre deux VM ensemble sans vérifier que l'hôte peut les contenir. À la première passe du harnais refait, la cible a démarré (4 Go), puis la VM de contrôle n'a pas obtenu ses 3 Go (Hyper-V `0x800705AA`, 2,3 Go libres sur 15,9 Go). Le pilote s'est arrêté là, sans rien remettre en place : la cible est restée allumée sur le commutateur privé, sa passe chargée, avec la configuration de la passe (carte réseau privée, mémoire) | une passe réseau perdue et une VM laissée allumée que l'opérateur a dû éteindre ; aucune preuve concernée | `Invoke-HyperVNetworkLogon.ps1`, `WinSightHyperV.psm1`, `WinSightQualRunner.ps1` | mémoire disponible vérifiée avant tout changement (cible + contrôle + 0,5 Go, `Assert-WinSightHostMemory`, message qui dit quoi faire) ; VM de contrôle à 2 Go pendant la passe (elle ne fait qu'ouvrir une session réseau) ; démarrages dans un `try` dont le `catch` éteint les deux VM, retire les disques, restaure les deux points de contrôle, le réseau de la cible et la mémoire de chacune, puis échoue avec la cause ; l'exécuteur transmet `memoryGB` (3 à 8) à l'étape réseau ; test de contrat et autocontrôle PowerShell 5.1, en échec sur le harnais précédent | Corrigé |
| WS-82 | Low | Validation | La porte 17 comptait toute demande de téléchargement reçue par le fournisseur Cloud Files de la sonde, sans savoir quel processus l'avait faite. Elle lançait en outre le scan de persistance à l'instant même où la valeur Run était écrite, pendant que ce qui réagit à une nouvelle valeur Run réagit encore. À la première passe du harnais refait, le scan a vu une demande. Tout indique qu'elle ne venait pas de WinSight : le verbe `sign` sur le même fichier n'en fait aucune, les lectures de fichier du scan, relues dans le code, passent par la garde « données locales » (`LocalPathLease.OpenRead`), et le scan a fini en 38 s, alors qu'une demande de sa part l'aurait bloqué au moins une minute (le fournisseur de la sonde ne répond jamais). La mesure ne permettait pas de le prouver | porte 17 en échec sans coupable établi : RA-02 non démontré en VM pour la tête | `scripts/Measure-CloudFilesAccess.ps1`, `guest/qualify.ps1`, `VM_QUALIFICATION_KIT.md` | le fournisseur se connecte avec `CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO` et enregistre, pour chaque demande, le processus (PID, image, ligne de commande) et le fichier ; une demande est imputée à WinSight si elle vient du processus mesuré ou d'une image `winsight*`, ou si la plateforme ne sait pas la nommer ; 30 s d'attente après l'écriture de la valeur Run, dont les demandes sont consignées à part et bornées de la même façon (Guardian compris) ; les demandes d'autres programmes figurent dans la preuve et la sortie, sans faire échouer la porte ; test de contrat, et autocontrôle qui compile les types de la sonde et décode un rappel écrit aux décalages x64 de `cfapi.h`, en échec sur la sonde précédente. Première passe avec l'attribution (`head-fe953fe`, §17.4) : les seules demandes, pendant l'attente comme pendant le scan, venaient de `sihost.exe` (l'hôte d'infrastructure de l'interpréteur de commandes de Windows, qui réagit à la nouvelle valeur Run), aucune de WinSight. Mais elles arrivaient une à une, à 60 s d'écart : la plateforme ne garde qu'une demande par fichier et fait attendre derrière elle tout autre lecteur, sans rappel à son nom (la primitive Win32 a attendu 90 s derrière une demande de sihost). Une lecture de WinSight pendant le scan, qu'une demande de sihost couvrait de bout en bout, n'aurait donc été comptée nulle part. Le fournisseur fait désormais échouer chaque demande sur-le-champ (`CfExecute`, `TRANSFER_DATA` en échec sur tout le fichier) : plus aucune demande n'attend, et chaque lecture arrive en demande à son nom ; autocontrôle de la disposition de `CF_OPERATION_INFO` (48 octets) et de `CF_OPERATION_PARAMETERS.TransferData` (40 octets) aux décalages x64 de `cfapi.h`, en échec sur la sonde précédente | Corrigé dans la mesure ; porte 17 à repasser en VM |
| WS-83 | Low | Validation | Sous Windows PowerShell 5.1, `Add-Content` et `Set-Content` échouent dès qu'un autre processus tient le fichier ouvert en lecture, même un lecteur qui partage l'écriture (mesuré). Or l'exécuteur et les pilotes écrivaient ainsi les fichiers qu'on lit pendant une campagne : journal, état, liste des requêtes traitées, journal des opérations hôte. Au redémarrage de l'exécuteur pour la troisième campagne, un `tail -F` sur le journal (la surveillance de l'agent) l'a arrêté entre deux requêtes, la qualification déjà marquée traitée et jamais lancée ; relancé, il s'est arrêté à sa première ligne | un opérateur qui suit le journal (`Get-Content -Wait`, un éditeur) arrête l'exécuteur, ou un pilote entre la fin de l'invité et la collecte ; aucune preuve concernée cette fois, aucune VM démarrée | `WinSightHyperV.psm1`, `WinSightQualRunner.ps1`, `Invoke-HyperVQualification.ps1`, `Invoke-HyperVNetworkLogon.ps1`, `New-WinSightControlVm.ps1` | ces quatre fichiers écrits par un flux ouvert avec partage lecture et écriture (`Write-SharedText`, `Add-SharedLine`), une violation de partage réessayée cinq secondes ; plus aucun `Add-Content` dans les scripts hôtes ; test de contrat, et autocontrôle PowerShell 5.1 qui garde le fichier ouvert en lecture (`Add-Content` y échoue, les deux fonctions y écrivent), en échec sur le harnais précédent | Corrigé |

### 4.2 Ouverts ou documentés

| ID | Sév. | Composant | Description | Impact | Preuve | Correction proposée | Statut |
|---|---|---|---|---|---|---|---|
| WS-53 | Medium | Package | Trois exécutables autonomes « single-file » : 431 Mo installés (installeur 116 Mo) | téléchargement, disque, mises à jour | `Build-Release.ps1` | runtime partagé dans un répertoire commun | Ouvert |
| WS-60 | Medium | Attribution | Une écriture par un handle ouvert avant la session ETW n'a pas de nom de fichier (seul `FileIOInit` est activé ; le noyau ne donne le rundown des noms qu'en fin de session). Mesuré en VM (porte 25) : l'auteur n'est pas attribué | auteur « inconnu » pour ces écritures : une réponse honnête, pas un faux nom (WS-73) | `WriteAttributionWatcher.cs` | résoudre ces écritures demanderait de relier chaque objet fichier à la table des handles des processus au démarrage de la session (privilège de débogage, pointeurs noyau) : disproportionné pour un fichier de démarrage gardé ouvert avant WinSight | Documenté |
| WS-64 | Info | Réponse | Fenêtre résiduelle de quelques microsecondes entre comparaison et changement pour une valeur de registre sans TxR | valeur concurrente supprimée sans quarantaine | `THREAT_MODEL.md` | aucune primitive Windows ne ferme cette fenêtre | Documenté |
| WS-65 | Info | Pare-feu | Aucune invite avant la première connexion | pas d'équivalent LuLu | `WFP_DESIGN.md` | décision « après coup » via les événements WFP (§11) | Documenté |

### 4.3 Contre-audit Codex du 24 septembre

Codex a relu la branche à `9fbe1b3`, sans modifier le code : sept constats, dont aucun n'est une faille
du produit démontrée, et le verdict « pas prêt pour une publication de production ». Chacun a été
repris depuis le code, prouvé par un test en échec sur l'ancien code quand c'était possible, puis
corrigé. La suite complète passe ensuite : 3 551 tests, 0 échec.

| ID | Gravité | Constat | Correction | Commit | Statut |
|---|---|---|---|---|---|
| RA-01 | Haute (harnais) | Scripts du harnais, candidat, disques des VM et preuves à la racine d'un volume de données, où les utilisateurs authentifiés ont « Modification » par héritage (ACL par défaut d'un volume NTFS non système) : les hachages prouvaient la cohérence, pas la provenance. La relecture ajoute que l'exécuteur élevé écrivait dans ce dossier et commençait par un `Remove-Item -Recurse` que Windows PowerShell 5.1 fait à travers une jonction, et que les pilotes supprimaient récursivement le dossier écrit par l'invité, qui exécute le candidat en administrateur. Rien n'a été exploité | harnais versé au dépôt (`scripts/validation/hyperv`) : requêtes lues sans jamais être écrites ni supprimées ; toute écriture élevée sous une racine créée avec une DACL réservée aux administrateurs ; copies d'une liste fermée sans point d'analyse, SHA-256 et blob git scellés et revérifiés avant chaque action ; stockage des VM verrouillé, sinon refus ; disque de transport formaté, résultats copiés sans suivre de lien ; `Verify-QualificationProvenance.ps1` non élevé. `Test-HarnessHelpers.ps1` 8/8 sous PowerShell 5.1, 6 contrats dont 3 échouent sur l'ancien exécuteur | `2cc522c` | Corrigé dans le code ; verrouillage du stockage, lancement et requalification par l'opérateur à faire |
| RA-02 | Moyenne | Le nom d'origine (`OriginalFilename`) lu par `FileVersionInfo.GetVersionInfo(chemin)` : seconde ouverture par nom, hors de la garde WS-40 ; un fichier échangé prêtait son nom, un fichier hors ligne était lu | lecteur de ressources PE borné sur le handle acquis ; nom lu seulement dans le fichier que la résolution a trouvé (volume et index), jamais si ses données ne sont pas locales ; trois tests en échec sur l'ancien code (`Cmd.Exe` hors ligne, `whoami.exe` échangé, `PowerShell.EXE.MUI`) ; a révélé WS-74 | `bb608ff` | Corrigé ; porte VM 17 par la persistance à refaire |
| RA-03 | Moyenne | WS-70 absorbait sans un mot ce qui devenait lisible : une entrée posée pendant l'intervalle illisible était indiscernable d'une ancienne | lot « incertain » (nombre, surfaces, entrées) remis par le moniteur, journalisé `Guardian/CoverageGain` sans bulle, montré *Unverified* par `winsight alerts` et le MCP, jamais comme une détection ; livré au moins une fois (tant qu'il ne l'est pas, ses entrées restent hors de la ligne de base sauvegardée, donc annoncées au lancement suivant) ; emplacement couvert toujours annoncé, ancienne ligne de base inchangée | `9f7af15` | Corrigé |
| RA-04 | Moyenne | WS-51 : un homonyme n'importe où dans WinSxS (autre architecture, fonctionnalité en attente, composant sans rapport) valait résolution de l'import | index par composant (architecture, nom, clé) ; manifeste de l'image lu (XML sans DTD ni résolveur, borné) ; résolu seulement par un assemblage lié ou du même éditeur non Windows, sinon non résolu ou inconnu ; test de bout en bout en échec sur l'ancienne recherche ; même sortie sur ce poste | `66d4f61` | Corrigé |
| RA-05 | Moyenne | Échec du verbe de retrait du service : message, puis désinstallation poursuivie, laissant le service pointer vers un fichier supprimé | exception à `usUninstall`, fatale pour Inno avant toute suppression (code 1 ; sans boîte avec `/SUPPRESSMSGBOXES`), vérifié dans les sources d'Inno ; messages EN/FR/ES ; porte VM avec échec injecté (DELETE refusé sur l'objet service) et contrôle WFP ; contrats en échec sur l'ancien script ; compilé par ISCC 6.7.3 | `861a9c9` | Corrigé ; porte VM à exécuter |
| RA-06 | Basse (assurance) | WS-61 présenté comme une preuve ; seuls les mutateurs listés étaient cherchés | frontière : aucune API d'écriture du framework, aucune primitive d'écriture de WinSight, seules 22 fonctions natives relues, hors trois propriétaires relus (netstat en lecture seule ; VirusTotal et son fichier de quota, présents dans l'IL mais coupés par `allowNetworkLookups: false`, épinglé à chaque appel MCP) ; un canari par détecteur ; inventaire des 6 outils et de leurs annotations | `76826b2` | Corrigé |
| RA-07 | Basse (docs) | `PRODUCTION_READINESS.md` « faisant autorité » au 14 septembre, contredit par le §17.2 | version publiée, candidat local qualifié (hachages exacts, réserve RA-01) et tête actuelle distingués | `f18ec16` | Corrigé |
| RA-08 | — | ARM64 natif, x64 sur ARM64, multi-utilisateur, Authenticode, débit ETW et endurance, WS-53 | chacun reste une porte à part, non qualifiée | — | Ouvert, inchangé |

Une revue de sécurité indépendante de ces correctifs, le même jour, a relevé quatre défauts, tous
corrigés avec un test en échec sur l'état précédent :

| Correctif revu | Défaut | Correction | Commit |
|---|---|---|---|
| RA-06 | la frontière ne voyait ni les tubes nommés ni les fichiers ouverts par chemin : `winsight_outbound_firewall` écrit bien une requête sur le tube du service pare-feu, jamais jugée | tubes (client, serveur, écriture), `FileStream`/`StreamWriter` construits depuis un chemin, `RandomAccess`, fichiers mappés, ZIP et XML ajoutés ; `FirewallServiceClient.SendAsync` devient un quatrième propriétaire relu (lecteur de posture seul, service qui refuse toute mutation à un appelant non élevé) ; trois canaris de plus | `1cc1cf6` |
| RA-04 | le manifeste vient de l'image scannée : un assemblage inventé sous la clé Visual C++ atteignait tout composant Visual C++ | un assemblage lié n'atteint que lui-même et, pour une bibliothèque Visual C++ (MFC, ATL, OpenMP), le CRT de la même version | `dc9f080` |
| RA-05 | l'`ImagePath` non guillemeté était coupé au premier « .exe » : un dossier `tools.exe` sur le chemin faisait passer le service de cette installation pour étranger, et la désinstallation continuait | exécutable reconnu comme début de la commande, avec ou sans extension ; cas VM ajouté | `df92198` |
| RA-01 | les vérifications s'arrêtaient au dossier protégé ; le dossier `Hyper-V` à la racine de ce volume, parent du stockage des VM, appartient au compte ordinaire et reste renommable par les utilisateurs authentifiés | chaîne des parents vérifiée jusqu'à la racine (propriétaire, suppression, DACL, suppression des enfants), droits génériques comptés ; parents verrouillés par `Protect-WinSightVmStorage.ps1`, stockage revérifié avant chaque passe | `066b3e1` |

---

## 5. Security Review

**Frontière privilégiée (vérifiée par lecture intégrale).** Le tube nommé refuse le SID Réseau,
n'accorde pas `CreateNewInstance` aux interactifs et est créé avec `FIRST_PIPE_INSTANCE` ; le client
vérifie que le propriétaire du tube est LocalSystem (un utilisateur standard ne peut pas forger ce
propriétaire sans `SeRestorePrivilege`) ; la capacité est dérivée du jeton usurpé et revérifiée par
commande ; le protocole est borné (trames de 64 Kio, membres inconnus refusés, pagination liée à un
condensat). Le chemin du service est vérifié composant par composant et lié à l'identité NTFS 128
bits. L'état « Actif » n'est jamais affirmé sans lecture exacte des objets WFP.

**Élévation de privilège par un utilisateur non privilégié.** Aucune voie trouvée vers le service.
Voies résiduelles connues et documentées : installation par utilisateur (binaires remplaçables par ce
même utilisateur), service non protégé contre un administrateur.

**Accès fichiers (corrigé).** Les lectures automatiques ne suivent plus aucun reparse point ; les
mutations (journaux, baseline, quarantaine, politique, leurres) passent par des opérations relatives à
un handle. Les substituts Cloud Files (OneDrive) ont été mesurés en VM : les fichiers hydratés se lisent, et aucune lecture ne rapatrie plus un fichier « en ligne uniquement » (WS-40).

**Surface de réponse (corrigée).** Identité de processus liée au handle, liste protégée par identité,
journal en deux phases, comparaison-et-mutation par objet (WS-17/18), refus explicite des cibles machine.

**MCP (corrigé).** Barrière *sensitive* réellement étanche aux lignes de commande, échappement complet,
délai qui annule, aucune écriture. Plafond assumé : l'échappement n'empêche pas un modèle de lire le
texte ; le serveur reste en lecture seule pour que le pire cas soit une mauvaise réponse.

**Un logiciel malveillant peut-il aveugler WinSight ?**

| Action | Possible ? | Observabilité |
|---|---|---|
| Tuer le tableau de bord (même utilisateur) | oui | aucune alerte (pas de chien de garde) |
| Supprimer ou réécrire journaux et règles (même utilisateur) | oui | une règle Allow non créée par l'opérateur reste listée ; pas de chaîne d'intégrité |
| Remplacer les binaires | oui en installation par utilisateur, non en tous utilisateurs | aucune auto-vérification |
| Saturer les capteurs | limité | pertes ETW, débordements FSW et évictions désormais comptés et affichés |
| Arrêter le service pare-feu | administrateur uniquement | l'état effectif le montre |
| Contourner un blocage pare-feu | oui (copie, lien, processus enfant) | documenté (WS-16) |
| Écrire la persistance dans une clé absente | détecté en temps réel depuis WS-03 | — |

**Supply chain.** Actions épinglées par SHA, `persist-credentials: false`, permissions minimales, tag
vérifié comme ancêtre de `main`, sommes de contrôle revérifiées dans un job séparé, attestations SLSA et
SBOM pour l'archive et l'installeur, compilateur Inno Setup vérifié par SHA-256 **et** Authenticode.
Aucune dépendance vulnérable connue (`dotnet list package --vulnerable --include-transitive`) ; seuls des
correctifs mineurs 10.0.12 sont disponibles. Points faibles : binaires non signés (voir §13) et cache de
build dans le workflow de release (WS-62). La CodeQL passe par la configuration par défaut de GitHub, non
versionnée dans le dépôt.

---

## 6. Performance Review

Mesures sur la machine de développement (8 cœurs logiques, SSD), outil `scripts/Measure-Performance.ps1`.
Ce sont des observations d'une machine à un commit, pas des budgets.

| Mesure | Valeur | Commentaire |
|---|---|---|
| `persistence` avant/après déduplication (A/B, cache disque chaud) | 25,2 s → 9,3 s | même sortie |
| `persistence` (arbre final) | 8,2-13,5 s, 120 Mo, 24 threads, ~770 handles | varie avec la charge |
| `all` (vue d'ensemble) | 22,9-26,1 s, 182 Mo | |
| `net` | 7,1 s, 92 Mo | |
| `hijack` | 8,3-8,7 s et incomplet → 2,4-3,4 s et complet (index WinSxS 9,75 → 2,1 s) ; pic de handles 45 910 → 553 | WS-32, WS-51 |
| `modules` | 57-87 s | PSAPI appel par module, un processus à la fois |
| `av --watch` au repos | 0,09 % d'un cœur, 27 Mo (1,7 % et 47 Mo avant WS-52) | notification registre vérifiée |
| `input --watch` au repos | 0,05 % d'un cœur, 25 Mo | |
| Sortie JSON `persistence` | 5,3 Mo (4 541 entrées dont 3 941 CLSID HKCU) → 0,9 Mo (698 entrées) | WS-54 |
| Installeur / archive / installé | 116 Mo / 170 Mo / 431 Mo | WS-53 |
| Suite de tests complète | ~5 min, 3 615 tests (2 976 au début de l'audit), 0 échec | Release, 23 projets |

Non mesuré : CPU et mémoire du tableau de bord au repos avec tous les moniteurs (il partagerait l'état
de l'installation réelle de ce poste), débit d'événements ETW soutenable, latence de détection bout à
bout, endurance sur sept jours.

---

## 7. Reliability Review

- **Capteurs honnêtes.** Chaque moniteur expose désormais un état (actif, dégradé, échoué), les pertes,
  les reprises et les échecs de livraison ; une couverture incomplète n'est plus présentée comme totale.
- **Clés et dossiers qui disparaissent.** Surveillance de l'ancêtre, bascule à la réapparition, reprise
  toutes les 30 s, réconciliation forcée après un débordement ou une reprise.
- **Écritures d'état.** Remplacement atomique natif vidé sur disque, mutex dont la possession est
  prouvée, journal d'actions en deux phases.
- **Délais.** MCP : délai coopératif, fournisseur bloqué signalé immédiatement ; l'isolation dure
  demanderait un processus enfant jetable. WMI : chaque résultat est désormais borné (mode
  semi-synchrone, WS-44).
- **Instance unique.** Plus de moniteurs en double (WS-31).
- **Arrêt brutal.** Une exception d'interface imprévue est absorbée une fois le tableau de bord démarré
  (rapport écrit, avis affiché), sauf si elle compromet le processus ou se répète (WS-50).
- **Cas limites testés** : processus disparu, PID réutilisé (simulé par une heure de création
  différente), fichier remplacé après capture, clé supprimée puis recréée, débordement FSW, journal en
  échec à chaque phase, stockage non fiable, fournisseur MCP bloqué, verrou nommé détenu par un autre.

---

## 8. Objective-See parity

Versions relevées sur objective-see.org et les dépôts officiels le 19 septembre 2026. La comparaison
porte sur l'objectif de sécurité, pas sur l'API (Endpoint Security et Network Extension n'ont pas
d'équivalent direct sous Windows).

| Capability | Objective-See | WinSight | Gap | Pertinence Windows | Priorité |
|---|---|---|---|---|---|
| Pare-feu sortant avec invite | LuLu 4.5.1 : alerte avant connexion, règles par processus ou destination, expiration, liste de blocage, mode passif | 🟡 règles par application WFP, audit puis application, journal des inconnus après coup | pas d'invite avant connexion (exige un pilote *callout* : `FwpsPendClassify0` est noyau), pas de règles par destination ni de listes | haute | P1 (décision après coup) |
| Surveillance de la persistance | BlockBlock 2.5.2 : alerte et blocage, règles, mode notarisation, protection contre le collage « ClickFix » | 🟡 Guardian : fenêtre Allow/Bloquer, règles | blocage limité au périmètre utilisateur ; pas d'équivalent « ClickFix » (Win+R / PowerShell collé) | haute | P1 |
| Inventaire de persistance | KnockKnock 4.1.0 : 20+ emplacements, VirusTotal, filtres, JSON, comparaison de scans | ✅ 27 familles, VirusTotal, filtres, JSON | pas de comparaison de deux scans en CLI | haute | P2 |
| Caméra / micro | OverSight 2.4.0 : alerte marche/arrêt avec processus, liste d'autorisation, arrêt, script | 🟡 ConsentStore + association au processus | source non documentée ; pas de règles ni d'action ; coût au repos | haute | P1 |
| Enregistreurs de frappe | ReiKey 1.4.2 (non maintenu) : *event taps* | 🟡 filtres de classe clavier/souris + surveillance | hooks `SetWindowsHookEx` non énumérables ; filtres par instance | moyenne | P2 |
| Explorateur de processus | TaskExplorer 3.0.0 : signatures, VirusTotal, bibliothèques, fichiers, réseau, assistant IA | 🟡 `processes`, `modules`, `process <pid>`, MCP | pas de vue interactive rafraîchie, modules lents | moyenne | P2 |
| Rançongiciel | RansomWhere? 2.2.0 : entropie des fichiers créés, **suspension** du processus, règles | 🟡 leurres, rafale, entropie, suspension manuelle | ni suspension automatique ni attribution sans élévation | haute | P1 |
| Accès physique | DoNotDisturb 2.1.0 : ouverture du capot, alertes, photo | 🟡 chronologie des réveils | après coup seulement | faible | P3 |
| Connexions | Netiquette 2.3.0 | ✅ | — | moyenne | — |
| Signature d'un fichier | What's Your Sign 3.2.2 : extension Finder, hachages, notarisation | ✅ verbe Explorer + `winsight sign` | menu moderne de Windows 11 ; origine (Mark-of-the-Web) absente | moyenne | P2 |
| Extensions noyau | KextViewr 2.0.0 | 🟡 pilotes inscrits | ensemble résident (élévation) | moyenne | P2 |
| Détournement de bibliothèques | Dylib Hijack Scanner 1.6.0 | ✅ plus large : chemins non cités, dossiers inscriptibles, PATH, imports fantômes, gradué par exploitabilité | chargements dynamiques | haute | — |
| Flux de processus | ProcessMonitor 1.5.0 | ❌ | pas de flux de créations de processus exposé | moyenne (Sysmon intégré à Windows couvre ce besoin) | P2 |
| Flux de fichiers | FileMonitor 1.3.0 | ❌ | — | faible | P3 |
| DNS | DNSMonitor 1.3.0 : proxy, blocage | 🟡 cache + ETW (administrateur) | pas de blocage | moyenne | P3 |
| Notifications, BTM | AuRevoir, DumpBTM | ⚪ | propre à macOS | — | — |

---

## 9. Windows competitors

| Outil | Ce qu'il fait mieux que WinSight | Ce que WinSight fait qu'il ne fait pas |
|---|---|---|
| Autoruns 14.3 | plus de catégories (Winsock, codecs, extensions shell, Office, pilotes d'affichage), analyse hors ligne, soumission VirusTotal | temps réel et décision (Guardian), triage de ligne de commande, ancre de confiance, JSON versionné, MCP, EN/FR/ES |
| Process Explorer 17.14 / System Informer | inspection profonde des processus, handles, threads, piles, graphes, interface live | triage orienté verdict, corrélation lignée + modules non signés + sockets en une vue |
| Process Monitor 4.11 | trace fichier/registre/processus complète, journalisation au démarrage | rien de comparable ; WinSight n'est pas un traceur |
| TCPView 4.19 | vue live, fermeture de connexions | signature du propriétaire, contrôle WFP |
| Sigcheck 2.92 | options riches, entropie, vidage des magasins de certificats | verbe Explorer, ancre de confiance, verdict MSIX lié au bloc |
| Sysmon 15.22 / Sysmon intégré (Windows 11, Server 2025) | télémétrie complète (événements 1-29 : création de processus, DNS, WMI, tampering…), piloté par règles, protégé | interprétation, alertes, décisions ; Sysmon enregistre sans analyser |
| Defender : CFA, ASR (19 règles dont persistance WMI), Tamper Protection, Smart App Control | **blocage** effectif par le noyau, réputation cloud | visibilité et explication ; WinSight lit la posture CFA sans la modifier |
| Pare-feu Windows | filtrage entrant/sortant par profil, règles riches | lisibilité par application ; mais pas d'invite sortante non plus |
| simplewall / TinyWall | liste blanche par défaut, notifications de paquets rejetés (WFP en mode utilisateur, via les événements WFP) | intégration à la suite, état vérifié contre WFP |
| Portmaster 2.2 | invite avant connexion (pilote WFP), DNS sécurisé, listes de filtrage | aucun pilote, audit par défaut |
| GlassWire | historique réseau graphique, alertes de nouvelles applications | code ouvert, local, aucune télémétrie |
| osquery 5.23 / Velociraptor 0.77 / Wazuh 4.14 | parc, requêtes SQL/VQL, forensique, SIEM | ergonomie pour un particulier, verdicts compréhensibles, zéro infrastructure |

**Synthèse par profil.** Particulier : WinSight est le plus accessible de cette liste (verdicts
expliqués, décision en un clic, trois langues). Power user : utile en complément de Sysinternals,
jamais en remplacement. Analyste : l'intérêt principal est l'export JSON et le MCP ; la télémétrie
de référence reste Sysmon/Velociraptor.

---

## 10. WinSight differentiation

1. **Un verdict plutôt qu'une liste.** Exploitabilité réelle du hijack (*latent*, *exploitable*,
   *occupé*), ancre de confiance (racine machine ou installée par l'utilisateur), interpréteur signé
   chargé d'une charge utile distante ou encodée. Autoruns montre, WinSight explique.
2. **Honnêteté de la couverture comme fonctionnalité.** « Ce que je n'ai pas pu voir » est affiché,
   compté, et désormais vrai pour chaque capteur.
3. **Décision au moment de l'arrivée**, réversible et journalisée, sans pilote.
4. **Interface MCP sûre**, une première pour ce type d'outil : un assistant peut trier la machine sans
   pouvoir rien y changer.
5. **Local, sans compte, sans télémétrie, en trois langues** : ce qui rend un « Objective-See pour
   Windows » crédible auprès du grand public.
6. **Pistes d'unicité** : corréler Guardian, pare-feu et rançongiciel autour d'une même identité de
   processus (« ce programme non signé, arrivé hier dans Run, parle à ce domaine et vient de toucher un
   leurre ») ; consommer Sysmon intégré quand il est présent pour obtenir l'ascendance et le DNS sans
   pilote.

---

## 11. Missing capabilities

### P0 — indispensable

- Requalifier en VM le candidat actuel : arrêt d'urgence, nouvelle couche d'accès fichiers, réponse,
  instance unique, installeur (portée utilisateur et tous utilisateurs), x64 puis ARM64.
- Leurres rançongiciel dans un dossier sauvegardé par OneDrive : plantation, vérification et nettoyage restent à mesurer (la lecture des fichiers l'est, WS-40).

### P1 — forte valeur

- **Pare-feu « décider après la première connexion »** : `FwpmNetEventSubscribe` fournit en mode
  utilisateur les connexions autorisées/refusées ; proposer « bloquer ce programme » dans une fenêtre
  de décision, plus des règles par destination. C'est l'équivalent LuLu atteignable sans pilote.
- **Caméra/micro** : `MFCreateSensorActivityMonitor` (documenté, Windows 10 1703+) comme source
  principale, notification plutôt qu'interrogation, règles d'autorisation et action « arrêter ».
- **Protection « ClickFix »** : détecter une commande collée dans Win+R (`RunMRU`) ou un PowerShell
  encodé lancé depuis l'Explorateur — la menace qui a motivé l'évolution récente de BlockBlock.
- **Surveillance des tâches planifiées et abonnements WMI pour un utilisateur standard** via les
  journaux `TaskScheduler/Operational` et `WMI-Activity/Operational` (lisibles par les interactifs).
- **Intégration Sysmon** (lecture de `Microsoft-Windows-Sysmon/Operational` quand il est activé).
- Attribution des arrivées
  Guardian sans élévation lorsqu'une source documentée le permet.

### P2 — amélioration intéressante

Vue de processus interactive, pilotes résidents (élévation), filtres d'entrée par instance, Firefox,
menu contextuel moderne de Windows 11, comparaison de deux scans en CLI, magasins de certificats
supplémentaires, chronologie corrélée (décision d'architecture requise, D6).

### P3 — nice-to-have

Présence en direct, blocage DNS, flux de fichiers générique.

### Rejected — complexité supérieure à la valeur

- Pilote noyau (minifiltre ou *callout* WFP) : signature EV, attestation, programme de sûreté ; à ne
  rouvrir que si la décision « après coup » s'avère insuffisante.
- ETW Threat-Intelligence : réservé aux processus protégés avec pilote ELAM.
- Énumération des hooks `SetWindowsHookEx` : aucune API documentée.
- Console cloud, télémétrie, moteur antivirus par signatures : contraires au modèle du projet.

---

## 12. Performance opportunities

| Opportunité | Impact | Complexité | Risque |
|---|---|---|---|
| Déduplication des lots de signatures (fait) | élevé (2,7×) | faible | faible |
| Parcours WinSxS en profondeur (fait) | élevé sur les handles | faible | faible |
| Caméra/micro pilotée par notification, secours à 30 s | élevé pour un portable | faible | moyen |
| Répertoire d'exécution partagé pour les trois exécutables | élevé (~431 → ~200 Mo) | moyenne | moyen (requalification) |
| Modules : instantané Toolhelp, parallélisme borné, déduplication | élevé (57-87 s) | moyenne | faible |
| Vue `process <pid>` sans vérification de toute la liste | moyen (11 s) | faible | faible |
| Rapport COM limité aux masquages (5,3 Mo → quelques Ko) | élevé sur la sortie et l'interface | faible | faible |
| Index WinSxS limité aux sources de chargement (fait, WS-51) | 9,75 → 2,1 s, index complet | faible | faible |
| WMI semi-synchrone | fiabilité | faible | faible |

---

## 13. Security hardening roadmap

1. **Maintenant** : exécuter le harnais refait (RA-01) et requalifier la tête de la branche ; puis
   ARM64. Les passes VM du 23 septembre ont validé WS-63, WS-40, WS-73, la mise à niveau et l'IPC par
   ouverture de session réseau (porte 36), sous la réserve RA-01. L'étanchéité MCP est gardée au
   niveau IL (WS-61, étendue par RA-06 : une garde ciblée, pas une preuve) et la release restaure ses
   paquets sans cache (WS-62).
2. **Ensuite** : recommander l'installation tous utilisateurs quand l'utilisateur fait partie du modèle
   de menace ; journal d'actions chaîné par hachage (preuve d'altération) ; chien de garde signalant
   l'arrêt du tableau de bord ; niveau de réponse machine dans le service avec son autorité propre.
3. **Signature Authenticode** : option réaliste la plus rapide, Azure Trusted Signing si une entité
   juridique éligible existe, sinon nouvelle candidature SignPath Foundation dès que les signaux
   d'adoption sont réunis, sinon certificat OV commercial. En attendant : sommes de contrôle,
   attestations et politique « non signé » visible, déjà en place. Une signature n'efface pas
   immédiatement SmartScreen (réputation à construire) mais apporte une identité d'éditeur.

---

## 14. UX / product improvements

- Une seule fenêtre de décision pour les trois moteurs (persistance, rançongiciel, caméra) avec les
  mêmes actions et le même historique.
- Afficher « pourquoi c'est signalé » partout (WS-49) et « ce qui n'a pas pu être vu » en langage
  simple dans l'info-bulle de santé.
- Prévenir l'opérateur quand un blocage est « partiellement appliqué » parce que l'entrée revient
  (fait) et proposer de retrouver le programme responsable.
- Réduire le bruit par défaut : masquer les CLSID HKCU ne masquant rien, grouper les entrées signées
  Microsoft.
- Pare-feu : présenter le blocage comme « bloque ce programme à cet emplacement » (WS-16).

---

## 15. Documentation issues

Corrigées : nombre de verbes et aide CLI ; commandes qui modifient la machine ; écritures du scan
hijack (il n'écrit plus rien) ; arrêt d'urgence et voie de secours ; contournement du blocage par
chemin ; garanties TOCTOU par type d'objet ; lacunes de persistance non listées (AutoRun de
`cmd.exe`, `SetupExecute`, `InitialProgram`, App Paths, BITS, shims) ; résolution pour d'autres
profils et en contexte 32 bits ; fichier hosts déplacé ; limites des preuves caméra/micro ;
`regsvr32` cité deux fois ; affirmations sur l'architecture (aucun pilote WinSight, ETW réellement
utilisés, négociation MCP) — ces dernières corrigées par Codex.

Restantes : `PRODUCTION_READINESS.md` distingue désormais la version publiée, le candidat qualifié et
la tête (RA-07) et sera à mettre à jour après la requalification ; les nombres
« 27 surfaces » et « 57 s » pour les modules sont des mesures anciennes à revalider avec l'outil de
mesure.

---

## 16. Tests missing

- Environnement OneDrive (Known Folder Move) pour la couche d'accès fichiers et les leurres : la
  lecture des substituts Cloud Files est qualifiée (porte VM 17, WS-40), les leurres restent à couvrir.
- Parcours « Bloquer » avec un programme qui réinscrit sa valeur.
- Débit ETW soutenu et pertes sous charge ; endurance de sept jours du tableau de bord.
- Installation tous utilisateurs, mise à niveau depuis la v0.13 publiée, désinstallation avec service :
  outillés (portes VM 15 et 16), à exécuter.
- Qualification ARM64 native des chemins privilégiés.

---

## 17. Changes applied during audit

Tous les changements sont couverts par des tests ajoutés ou adaptés ; sur l'arbre final, la suite
complète (3 615 tests, 0 échec), le build Release (0 avertissement, avertissements traités comme
erreurs), `dotnet format --verify-no-changes` et `git diff --check` passent. Les nouveaux tests des
correctifs principaux ont été vérifiés en échec sur l'ancien code avant d'être validés sur le nouveau. La liste exhaustive des fichiers est dans l'historique de la branche ;
ci-dessous, par thème, avec la justification.

| Thème | Fichiers principaux | Justification |
|---|---|---|
| Accès fichiers natif sans reparse | `Core/AutomaticFileAccess.cs`, `Core/AutomaticFileMutation.cs`, `Core/AtomicFile.cs`, migration de tous les lecteurs et écrivains automatiques | WS-22, WS-12, WS-21 |
| Signatures | `Core/NativeSignatureVerifier.cs`, `CachingSignatureVerifier.cs`, `CatalogSignatureVerifier.cs`, `PackageContentSignatureVerifier.cs`, `FileSignatureReport.cs`, `AuthenticodeCertificateReader.cs` | WS-06, WS-21 |
| Santé des capteurs | `Core/SensorHealth.cs`, `NetMonitor/EtwSensorHealthTracker.cs`, `DnsEventDelivery.cs`, watchers Persistence/Attribution/NetMonitor, `PersistenceMonitor.cs` | WS-25, WS-27 |
| Guardian | `Persistence/RegistryChangeWatcher.cs`, `FileSystemPersistenceWatcher.cs`, `FilePersistenceBaselineStore.cs`, `UserHiveEnumerator.cs` | WS-03, WS-07, WS-12 |
| Réponse | `Response/*` (contrôleur, inspecteur, processus protégés, journal, quarantaine, règles), `Application/PersistenceResponder.cs`, `RegistryAndFilePersistenceMutator.cs` | WS-04, WS-05, WS-17 à WS-20, WS-23, WS-33 |
| Hijack | `Hijack/UnprivilegedWriteAccess.cs`, `WritabilityProbe.cs`, `HijackTriage.cs`, `HijackScanner.cs`, `UnquotedPath.cs`, `SideBySideStore.cs` | WS-01, WS-02, WS-29, WS-30, WS-32, WS-75, WS-76 |
| MCP | `Mcp/McpScanService.cs`, `UntrustedText.cs`, `Application/Adapters.cs`, `PersistenceMonitorPresenter.cs` | WS-08 à WS-10 |
| Rançongiciel | `Ransomware/RansomwareFileWatcher.cs`, `RansomwareBurstDetector.cs`, `RansomwareEntropySampler.cs`, `CanaryManager.cs`, `CanaryFile.cs` | WS-11, WS-23, WS-24 |
| Pare-feu | `FirewallService/EnforcementCoordinator.cs`, `OutboundObserverService.cs`, `Firewall/PendingOutboundLog.cs`, `FirewallRequestDispatcher.cs`, `FirewallPolicyStore.cs` | WS-15, WS-26 |
| Corrélation | `Processes/ProcessLister.cs`, `ProcessInfo.cs`, `Modules/*`, `NetMonitor/ConnectionMonitor.cs`, `Application/ProcessInsight.cs`, `CaptureDeviceProcessLocator.cs` | WS-28 |
| Pilotes et filtres d'entrée | `Core/DriverImagePath.cs`, `Core/WindowsImage.cs`, `Drivers/*`, `InputHooks/*` | WS-41, WS-43 |
| Ancre de confiance utilisateur | `Processes/ProcessInfo.cs`, `Modules/LoadedModule.cs`, `NetMonitor/Connection.cs`, `Application/ProcessInsight*.cs`, `Adapters.cs` | WS-42 |
| WMI | `Processes/ProcessLister.cs`, `NetMonitor/DnsCacheReader.cs`, `Firewall/FirewallRuleReader.cs`, `Ransomware/ControlledFolderAccessReader.cs` | WS-44 |
| Résolution des commandes de persistance | `Persistence/CommandLine.cs` | WS-66 |
| Intégrité du code | `CodeIntegrity/CodeIntegrityTriage.cs`, `CodeIntegrityState.cs` | WS-56 |
| Filtres et champs de rapport | `Reporting/ReportItemFilter.cs`, champs `microsoftSigned`, `userInstalledTrust`, `privilegedHost` | WS-57, WS-49 |
| Hosts | `Hosts/HostsReader.cs`, `HostEntry.cs`, `Dashboard/DashboardFindingPresenter.cs` | WS-47, WS-59, WS-68 |
| Présence | `Presence/PresenceScanner.cs`, `Application/Adapters.Presence.cs` | WS-58 |
| Stabilité du tableau de bord | `Dashboard/DispatcherRecoveryPolicy.cs`, `CrashReporter.cs` | WS-50 |
| Caméra/micro au repos | `AvMonitor/CameraMicMonitor.cs`, `ConsentStoreChangeSignal.cs`, `Core/RegistryKeyWatcher.cs` | WS-52 |
| Certificats, extensions | `Certificates/CertStoreAuditor.cs`, `CertificateTrustRole.cs`, `TrustedCertificate.cs`, `Browser/ExtensionScanner.cs`, `ExtensionLocation.cs` | WS-55, WS-48 |
| MCP (suite) | `Mcp/McpModels.cs`, `McpScanService.cs`, `tests/WinSight.Mcp.Tests/IlCallGraph.cs` | WS-61 |
| Guardian (couverture de la ligne de base) | `Persistence/PersistenceCoverageMap.cs`, `PersistenceMonitorCore.cs`, `FilePersistenceBaselineStore.cs` | WS-70 |
| COM et contexte de chargement | `Persistence/ComHijackEnumerator.cs`, `CommandLine.cs`, `LoaderContext.cs`, `AccountEnvironment.cs`, `ScheduledTaskPrincipal.cs`, `UserHiveEnumerator.cs` | WS-54, WS-45, WS-46 |
| Release | `.github/workflows/release.yml` | WS-62 |
| Maintenabilité | `Application/Adapters*.cs` (11 fichiers), `Persistence/*Enumerator.cs`, `Dashboard/MainWindow.*.cs`, `FirewallService/WfpProvisioning.*.cs`, `EnforcementCoordinator.*.cs` | WS-67, WS-69 |
| Tableau de bord | `Dashboard/DashboardSingleInstance.cs`, `App.xaml.cs`, `AlertWindow.xaml.cs`, `MainWindow.xaml.cs`, ressources EN/FR/ES | WS-31, WS-18 |
| CLI | `Application/CliHelp.cs`, `CliContract.cs`, `Cli/Program.cs` | WS-14, code de sortie de couverture incomplète |
| Installeur | `installer/WinSight.iss`, `scripts/Test-Installer.ps1`, `Test-InstallerServiceUninstall.ps1`, `Test-InstallerUpgrade.ps1` | WS-13, WS-63 |
| Mesure | `scripts/Measure-Performance.ps1` | outil de mesure reproductible (D3) |
| Documentation | `README.md`, `docs/THREAT_MODEL.md`, `WFP_DESIGN.md`, `RECOVERY.md`, `DETECTIONS.md`, `ARCHITECTURE.md`, `MCP.md`, `INSTALLATION.md`, `OBJECTIVE_SEE_PARITY.md`, `ROADMAP.md`, `RANSOMWARE_DESIGN.md`, `GUARDIAN_DESIGN.md`, `ATTRIBUTION_DESIGN.md`, ce fichier | §15 |
| Kit de qualification VM | `docs/validation/VM_QUALIFICATION_KIT.md`, `VmQualificationKitContractTests.cs`, `scripts/Measure-CloudFilesAccess.ps1`, `ScriptParameterDefaultContractTests.cs` | WS-71, WS-72, WS-77 à WS-83, WS-40 (mesure) |
| Lecture automatique et attribution | `Core/AutomaticFileAccess.cs`, `AutomaticFileMutation.cs`, `Attribution/WriteAttributionWatcher.cs` | WS-40, WS-73 |
| Contre-audit : nom d'origine par le handle | `Core/PeResources.cs`, `VersionResource.cs`, `Persistence/PersistenceScanner.cs`, `CommandLine.cs`, `InterpreterAbuseTriage.cs` | RA-02, WS-74 |
| Contre-audit : Guardian incertain | `Persistence/PersistenceCoverageGain.cs`, `PersistenceMonitorCore.cs`, `PersistenceMonitor*.cs`, `Application/GuardianHost.cs`, `Adapters.Alerts.cs`, `Dashboard/MainWindow.Monitors.cs` | RA-03 |
| Contre-audit : WinSxS lié au manifeste | `Hijack/SideBySideStore.cs`, `SideBySideComponent.cs`, `SideBySideManifest.cs`, `PeImports.cs`, `HijackScanner.cs` | RA-04 |
| Contre-audit : désinstallation | `installer/WinSight.iss`, `scripts/Test-InstallerServiceUninstall.ps1`, `InstallerUninstallContractTests.cs` | RA-05 |
| Contre-audit : frontière MCP | `tests/WinSight.Mcp.Tests/McpSideEffectBoundaryTests.cs`, `IlCallGraph.cs`, `docs/MCP.md` | RA-06 |
| Contre-audit : harnais de qualification | `scripts/validation/hyperv/*`, `QualificationHarnessContractTests.cs` | RA-01 |
| Contre-audit : état de publication | `docs/PRODUCTION_READINESS.md` | RA-07 |

### 17.1 Qualification VM du 22 septembre 2026

Candidat : `5347a1b`, construit localement (`Build-Release.ps1 -DisableSignature`, x64 non signé) —
une **répétition**, pas une preuve attestée par la CI. VM `WinSight-Qualification-Fresh` (Windows 11
26200), pilotée entièrement depuis l'hôte : restauration de snapshot, tâche d'ouverture de session
qui lance le harnais élevé, résultats sur le dossier partagé, scellement SHA-256 hors de la VM, puis
restauration de `S0-clean-before-winsight`. Aucune authentification dans l'invité. Preuves sur
l'hôte, hors dépôt : `WinSight-Host-Evidence\v0.13.0-audit-5347a1b\run1…run6` (chacune avec
`SHA256SUMS.txt`).

| Porte | Résultat | Note |
|---|---|---|
| 01 identité et racine protégée, 02 Authenticode/PE, 03 contrat CLI, 04 cycle de l'installeur (portée utilisateur), 05 MCP en lecture seule | PASS | passe 3 |
| 06 scanners en lecture seule (17), 07 preuve MSIX, 08 verbes de réponse, 09 détenteurs, 10 verbe de signature | PASS | passe 3 ; `persistence` élevé : 6 min 23 s pour les 17 scanners |
| 11-13 Guardian : Bloquer/Restaurer, Autoriser/silence/Révoquer, nettoyage | PASS | passe 3 ; la 12 a attendu 51 min que l'écran de l'invité se rallume (harnais, voir ci-dessous) |
| 14 langues EN/FR/ES, 20 état ETW initial, 22 DNS (orphelin, reprise, Ctrl+C) | PASS | passe 3 |
| 23 service sortant (orphelin, redémarrage par le SCM, AuditOnly, IPC, HTTP 200), 24 état ETW final, 99 résidus | PASS | passe 4, kit corrigé (WS-72) |
| 30-32 WFP : autotest du contrat, témoin négatif, pré-armement | PASS | passe 3 |
| 34 frontière de confiance (propriétaire étranger), 35 IPC locale (7 vérifications) | PASS | passe 3 |
| 21 attribution du tableau de bord | PASS | passe 7, kit corrigé (WS-71) : second lancement rendu à la première instance (sortie 0, aucune session), fenêtre masquée par X, orphelin repris à la relance, session vivante de `attribution --watch` préservée sur deux cycles, Ctrl+C sans résidu, sortie par le vrai menu de l'icône de notification |
| 33 WFP complet (armement puis désarmement d'urgence) | PASS | sous Hyper-V (`hv-run3-gate33`, 23 septembre), 35 vérifications : blocage de `curl.exe` effectif et témoin PowerShell intact, état WFP exact, arrêt du service qui efface l'état dynamique, redémarrage qui le recrée, désarmement d'urgence vers AuditOnly sans état WFP, désinstallation sans service résiduel. Les deux décisions d'opérateur ont été prises par `operator-automation.ps1` (sélecteur de fichier réel, confirmations réelles), tracé dans les preuves |
| 36 IPC par ouverture de session réseau | NOT_RUN | exige une seconde machine et un compte à mot de passe |

Aucun défaut du produit n'a fait échouer une porte. La campagne a produit un constat produit
(WS-70, corrigé depuis : fausses arrivées Guardian au premier lancement élevé, relevées dans le journal d'alertes de
l'invité) et deux corrections du kit (WS-71, WS-72). Les autres échecs venaient du harnais ou de
l'environnement :

- **Environnement.** VirtualBox n'obtient pas VT-x sur cet hôte (Hyper-V et HVCI actifs) et tourne
  en mode NEM : la VM est lente, son horloge dérive, elle perd des frappes, et elle a gelé trois fois
  (passes 5, 6 et 11 ; celle de la passe 6 pendant la porte 01, avant tout composant WinSight). Le snapshot
  d'origine datait d'une semaine : chaque restauration relançait la mise à jour cumulative de
  septembre, qui saturait l'invité (`persistence` à 34 min au lieu de 15 s sur l'hôte). Un nouveau
  snapshot `S0-autorun-2026-09-22` (mises à jour installées puis suspendues 35 jours, file ngen
  vidée, 6 Go de RAM) a ramené la porte 06 à 6 min 23 s.
- **Harnais** (hors dépôt, `qualify.ps1` sur le dossier partagé, versions archivées avec les
  preuves) : porte 21 alignée sur l'instance unique, nettoyage en `finally`, porte 23 alignée sur la
  récupération SCM, `@()` autour d'une liste d'un élément, et écran de l'invité maintenu allumé
  (`SetThreadExecutionState`) — l'écran éteint bloquait les appels UI Automation vers le tableau de
  bord (hypothèse la plus probable : la porte 12 a repris à la seconde où l'écran s'est rallumé).
  Nouveau `operator-automation.ps1` : quand ce fichier accompagne le candidat, le harnais lui confie
  les décisions d'opérateur (portes 33 et sortie par l'icône de notification de la porte 21) ; il
  n'agit que par les vraies commandes du produit et le consigne dans `operator-automation.txt`, donc
  une campagne automatisée ne peut pas être prise pour une campagne conduite par un humain.
- **Hyper-V.** La porte 33 a été conduite sous Hyper-V (`hyperv/` à côté des preuves : guide,
  VM de génération 2 créée depuis le disque exporté de VirtualBox, pilote avec un disque de données
  `WINSIGHTQ` en guise de dossier partagé, sans compte ni mot de passe invité). Aucun gel : c'est
  désormais l'environnement recommandé ; les étapes administrateur restent celles de l'opérateur.

### 17.2 Qualification VM du 23 septembre 2026

Passes entièrement autonomes sous Hyper-V : un exécuteur élevé, lancé une fois par l'opérateur
(invite UAC), n'accepte qu'une liste fermée d'actions et les exécute depuis une copie des scripts
placée dans un dossier réservé aux administrateurs, avec leurs hachages revérifiés avant chaque
action. Chaque passe restaure le point de contrôle propre, charge le candidat sur le disque de
données, laisse l'invité exécuter le harnais puis s'éteindre, scelle les preuves (SHA-256) et
restaure la VM. Candidats construits localement (`Build-Release.ps1 -DisableSignature
-Architectures x64`), non signés : une **répétition**, pas une preuve attestée par la CI. Preuves
sur l'hôte, hors dépôt, sous `WinSight-Host-Evidence\v0.13.0-audit-bd4242f\` ; `candidate.json` de chaque passe
porte le commit réellement qualifié.

**Réserve (RA-01).** Cette copie des scripts était prise, au démarrage, dans un dossier que tout
utilisateur authentifié pouvait modifier, comme le candidat, les disques des VM et les preuves ; et
l'exécuteur élevé écrivait lui-même dans ce dossier. Ces passes prouvent ce que les octets hachés ont
fait, pas qu'aucun script n'a été changé avant ni aucun résultat après. Le harnais refait
(`scripts/validation/hyperv`) n'a pas encore tourné, et `259056b` n'est plus la tête de la branche.

Le harnais reprend les portes du §17.1 et en ajoute quatre :

| Porte | Ce qu'elle prouve | Critère |
|---|---|---|
| 15 installeur tous utilisateurs et service | WS-63 : la désinstallation retire le service de cette installation, et seulement celui-là | `PASS own-service` et `PASS foreign-service`, `sc query` 1060, aucun fichier restant |
| 16 mise à niveau | remplacement en place de la v0.13.0 publiée (`c3bf248`) | une entrée de désinstallation, aucun fichier obsolète, désinstallation propre |
| 17 Cloud Files | WS-40 : racine de synchronisation jetable (API Cloud Files, sans OneDrive ni compte), substituts hydratés, déshydratés et dossier substitut | substituts hydratés lisibles, aucune demande de téléchargement, réponse en moins de 30 s |
| 25 écriture dans Démarrage | WS-73 et WS-60 : l'auteur d'une écriture fraîche et d'une écriture par un handle ouvert avant la session ETW | l'auteur réel attribué, aucun processus qui n'a fait qu'ouvrir le fichier ; l'écriture pré-ouverte est mesurée |

| Passe | Candidat | Résultat | Ce qu'elle a appris |
|---|---|---|---|
| `hv-run1-all` | `bd4242f` | 28 PASS, 2 FAIL, 36 NOT_RUN | 15 PASS (WS-63) ; 16 : mise à niveau réussie, script de test fautif ; 17 : un fichier « en ligne uniquement » était rapatrié (2 demandes, 120 s) ; 25 : critère trop faible, la relecture révèle WS-73 |
| `hv-run2-all-2c3085a` | `2c3085a` | 29 PASS, 1 FAIL, 36 NOT_RUN | 16 PASS ; 25 : seul l'auteur réel est attribué (WS-73 corrigé), l'écriture pré-ouverte ne l'est pas (WS-60) ; 17 : la réouverture avec `FILE_OPEN_NO_RECALL` ne suffit pas |
| `hv-run3c-gate17-259056b` | `259056b` | 2 PASS | 17 : lecture refusée en 138 ms sans téléchargement ; les primitives montrent que le filtre Cloud Files ignore `FILE_OPEN_NO_RECALL` en lecture (NT comme Win32 : 2 demandes, 90 s) et qu'un processus ordinaire voit l'attribut « rappel à l'accès » (`0x00401620`) |
| `hv-run4-all-259056b` | `259056b` (final) | **30 PASS, 0 FAIL**, 36 NOT_RUN | la qualification complète du candidat final |
| `hv-network1` | `259056b` (final) | **36 PASS (10/10)**, 99 PASS | ouverture de session réseau depuis la VM de contrôle : 7/7 (jeton `S-1-5-2` sans `S-1-5-4`, tube authentifié inaccessible, aucune mutation), observateur 3/3 (même instance du service avant et après) |

La porte 36 (IPC par ouverture de session réseau) est passée à part, avec deux VM : la cible et
`WinSight-Control-HV`, sur un disque différentiel du même disque de base, reliées par un commutateur
Hyper-V privé que ni l'hôte ni Internet ne voient ; WinRM HTTPS avec `Basic` sur TLS seulement,
comme au §7 du kit, et un rendez-vous HTTP sur ce commutateur pour le certificat public et le
résultat. L'opérateur a créé le compte jetable, et tapé son mot de passe, dans la boîte
d'identification Windows de chaque VM. Deux écarts de harnais, consignés dans
`host-operations.txt` : le pilote hôte s'est fermé en cours de passe (preuves collectées ensuite
avec `-Resume`, VM restaurées), et le script de contrôle lisait la réponse du rendez-vous comme du
texte alors que Windows PowerShell la rend en octets. L'opérateur l'a corrigé dans la VM (décodage
des octets) avant de le relancer ; les scripts sont corrigés pour les passes suivantes. Ni l'un ni
l'autre ne touche le produit ni ce que la porte vérifie.

### 17.3 Historique réécrit avant publication

Avant sa première publication, la branche a été réécrite le 24 septembre pour retirer de ses
80 commits un nom de compte local et des chemins propres au poste de qualification (lecteur de
données, dossiers de preuves, partage VirtualBox), dans les fichiers comme dans les messages. Le
code n'a pas changé : l'arbre du dernier commit est identique avant et après, et chaque commit
garde son auteur, ses dates et son message à ces chaînes près, signé par la même clé. Les SHA
cités dans ce rapport sont ceux d'origine, auxquels les preuves VM sont liées (`candidate.json` de
chaque passe) ; leur équivalent dans l'historique publié :

| Cité | Publié | Cité | Publié |
|---|---|---|---|
| `5347a1b` | `aec330d` | `861a9c9` | `4ae37ec` |
| `bd4242f` | `2ed85a6` | `76826b2` | `a72a130` |
| `2c3085a` | `cf9cfbb` | `f18ec16` | `73eaab8` |
| `259056b` | `13066b1` | `2cc522c` | `8e912cc` |
| `631c4dc` | `f8bbc58` | `1cc1cf6` | `f5b7fbc` |
| `9fbe1b3` | `04e0386` | `dc9f080` | `13717ed` |
| `bb608ff` | `8e4a108` | `df92198` | `781895e` |
| `9f7af15` | `cc4a6c1` | `066b3e1` | `ce2edbb` |
| `66d4f61` | `02b17de` |  |  |


### 17.4 Qualification VM du 25 septembre 2026 (harnais refait)

Premières passes du harnais refait (`scripts/validation/hyperv`, RA-01) : exécuteur élevé lancé par
l'opérateur depuis une extraction du commit sur le volume de données, copies protégées du harnais et
du candidat, stockage des VM et preuves réservés aux administrateurs, provenance vérifiée par
`Verify-QualificationProvenance.ps1` sous un compte ordinaire. Candidats construits localement, non
signés : des répétitions, pas des preuves attestées par la CI.

| Passe | Candidat | Résultat | Ce qu'elle a appris |
|---|---|---|---|
| `head-72c48a7` | `72c48a7` | perdue | l'invité s'est éteint après 121 minutes, le retrait du disque a échoué, la VM a rejoué les portes (WS-80) ; rien de scellé |
| `head-771a67b` | `771a67b` | **30 PASS, 1 FAIL**, 36 NOT_RUN (passe à part) ; provenance : 11/11 PASS | première passe attestée de bout en bout ; 17 : le scan de persistance a vu une demande de téléchargement que la sonde ne savait pas attribuer (WS-82) |
| `net-771a67b` | `771a67b` | non démarrée | la VM de contrôle n'a pas obtenu sa mémoire après le démarrage de la cible (WS-81) |
| `head-bf9aad9` | `bf9aad9` | non démarrée | candidat chargé, puis l'exécuteur s'est arrêté sur une écriture de son journal qu'un lecteur tenait ouvert (WS-83) |
| `head-fe953fe` | `fe953fe` | **32 portes, 0 FAIL**, 36 NOT_RUN (passe à part) ; provenance : 11/11 PASS | qualification complète ; 17 : demandes de téléchargement de `sihost.exe` seulement, aucune de WinSight, mais une lecture attendant derrière une demande de sihost n'aurait pas été vue (WS-82, second temps) |

Restent la porte 36 (`net-fe953fe`) et la porte 17 avec la sonde qui fait échouer chaque demande
sur-le-champ. La tête n'est donc toujours pas qualifiée.

---

## 18. Recommended roadmap

### Maintenant — bugs, sécurité, fiabilité

- Relire et fusionner la branche d'audit par thème. Qualification x64 : `259056b` a passé 31 portes
  sur 31 (§17.2), sous la réserve RA-01 ; la tête est à requalifier avec le harnais refait : 32 portes sur 32 passées à `fe953fe`
  (§17.4), restent la porte 17 avec la mesure corrigée et la porte 36 ; ARM64.
- `PRODUCTION_READINESS.md` : distinction faite (RA-07) ; déclarer le candidat seulement après cette
  requalification.

### Ensuite — fonctionnalités différenciantes

- Pare-feu « décider après la première connexion » et règles par destination.
- Caméra/micro via `MFCreateSensorActivityMonitor`, règles et actions.
- Protection ClickFix ; tâches et WMI surveillées pour un utilisateur standard ; lecture de Sysmon.
- Corrélation par identité de processus entre Guardian, pare-feu et rançongiciel.
- Package à runtime partagé (WS-53).

### Plus tard — changements importants

- Chronologie corrélée et recherche (décision d'architecture et migration de stockage, D6).
- Niveau de réponse machine dans le service.
- Signature Authenticode et distribution (winget, Microsoft Store).
- Réévaluation d'un pilote uniquement si les mesures montrent qu'une décision avant connexion ou un
  blocage d'écriture est indispensable.

---

## WinSight vs State of the Art

| Domaine | WinSight aujourd'hui | Meilleur outil de référence | Gap | WinSight après optimisations |
|---|---|---|---|---|
| Inventaire de persistance | ●●●○ 27 familles, verdicts gradués, masquage COM, contexte 32 bits et par compte | Autoruns (●●●●) | catégories manquantes (Winsock, shell, Office, GPO) | ●●●● avec ces catégories |
| Persistance en temps réel | ●●●○ clés et dossiers, décision, réversible | BlockBlock (macOS) / Sysmon 12-14 (Windows, sans décision) | blocage machine, attribution sans élévation | ●●●● avec le niveau machine du service |
| Processus | ●●○○ scans | System Informer / Process Explorer (●●●●) | vue live, handles, threads | ●●●○ avec une vue interactive |
| Réseau / pare-feu | ●●○○ règles WFP, état prouvé | Portmaster (●●●●, pilote) / simplewall (●●●○) | invite, destinations, historique | ●●●○ avec décision après coup et règles par destination |
| DNS | ●●○○ | Sysmon 22 / DNSMonitor | attribution continue, blocage | ●●●○ via Sysmon intégré |
| Caméra / micro | ●●○○ | OverSight (●●●○) / indicateurs Windows | source documentée, règles, coût | ●●●○ avec l'API de capteurs Media Foundation |
| Rançongiciel | ●●○○ détection | Defender CFA (●●●●, blocage) / RansomWhere? | suspension, attribution | ●●●○ détection + suspension confirmée ; le blocage reste à CFA |
| Signatures / hachages | ●●●● lié à l'objet, MSIX, ancre | Sigcheck (●●●●) | origine (Mark-of-the-Web) | ●●●● |
| Hijack / chemins | ●●●● gradué par exploitabilité, index WinSxS complet | PrivescCheck, scripts (●●●○) | chargements dynamiques | ●●●● |
| Télémétrie / corrélation | ●○○○ | Sysmon + Velociraptor / Wazuh (●●●●) | journal d'événements corrélé | ●●○○ en consommant Sysmon |
| Ergonomie grand public | ●●●● trois langues, verdicts expliqués | GlassWire (●●●○) | — | ●●●● |
| Intégration IA | ●●●● MCP en lecture seule | TaskExplorer 3 (assistant intégré) | — | ●●●● |

## Top 10 améliorations avec le meilleur ROI

| # | Fonctionnalité | Pourquoi | Valeur utilisateur | Difficulté (1-5) | Risque (1-5) | Coût performance | Fichiers / composants |
|---|---|---|---|---|---|---|---|
| 1 | Requalifier la tête avec le harnais refait, puis publier | `259056b` a passé 31/31, mais sous la réserve RA-01 et avant RA-02 à RA-05 | une version publiable dont la provenance tient | 2 | 1 | nul | `scripts/validation/hyperv`, `docs/PRODUCTION_READINESS.md`, release |
| 2 | Qualification ARM64 native | seconde architecture publiée, jamais qualifiée | publication ARM64 | 3 | 2 | nul | runner ARM64, kit de qualification |
| 3 | Pare-feu « décider après la première connexion » | l'attente n°1 d'un utilisateur de LuLu | contrôle réseau compréhensible | 3 | 3 | faible (événements WFP) | `FirewallService/OutboundObserverService.cs`, `Dashboard` |
| 4 | Leurres rançongiciel dans les dossiers OneDrive | la plantation et le nettoyage des leurres sous une racine Cloud Files ne sont pas mesurés | détection rançongiciel fiable sur un PC grand public | 2 | 2 | nul | `Ransomware/CanaryManager.cs`, `scripts/Measure-CloudFilesAccess.ps1` |
| 5 | Caméra/micro par capteurs Media Foundation | source documentée au lieu du ConsentStore non documenté (le coût au repos est déjà réglé, WS-52) | confiance dans l'alerte | 3 | 2 | nul | `AvMonitor/*`, `Application/AvWatchHost.cs` |
| 6 | Catégories Autoruns manquantes (Winsock, extensions du shell, Office, GPO) | angles morts de l'inventaire | parité avec Autoruns | 3 | 1 | faible | `Persistence` |
| 7 | Protection « ClickFix » | vecteur d'infection majeur en 2025-2026 | prévention concrète | 3 | 2 | faible | `Persistence`, `Application`, `Dashboard` |
| 8 | Runtime partagé | 431 Mo installés | téléchargement et mises à jour | 3 | 3 | nul | `scripts/Build-Release.ps1`, `installer` |
| 9 | Règles pare-feu par destination | le blocage par application seule est tout ou rien | contrôle réseau fin | 3 | 3 | faible | `Firewall`, `FirewallService`, `Dashboard` |
| 10 | Lecture de Sysmon intégré | ascendance, DNS et réseau sans pilote quand il est activé | corrélation | 3 | 2 | faible | nouveau lecteur dans `NetMonitor`/`Application` |

WS-40, WS-41 à WS-44, WS-48, WS-50 à WS-52, WS-54 et WS-55, qui figuraient dans des versions précédentes de ce
classement, ont été corrigés pendant l'audit (§4.1).
