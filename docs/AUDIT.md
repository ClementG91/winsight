# WinSight Deep Audit

| | |
|---|---|
| Date | 2026-09-21 |
| Base | `main` @ `4a361a6` (v0.13.0) |
| Périmètre | dépôt complet : code, tests, docs, CI/CD, scripts de build/release, installeur |
| Auteurs de l'audit | Claude Code (sessions du 18-19 et du 21 septembre) et Codex (20-21 septembre), travaillant sur le même arbre et se relisant mutuellement |
| Environnement de validation | Windows 11 Pro 10.0.26200 x64, compte administrateur à jeton scindé (UAC), processus non élevé, SDK .NET 10.0.303 |
| État livré | branche d'audit, commits thématiques, non poussée |

**Validé sur ce poste** : build Release, suite complète, formatage, audit NuGet, mesures de
performance, et cycle complet de l'installeur x64 en portée utilisateur (installation, verbe
Explorer, MCP, smoke tests EN/FR/ES, désinstallation sans résidu) sur l'arbre final.

**Ce qui n'a pas pu être validé ici, et ne doit pas être présumé** : qualification privilégiée en VM
(WFP/SCM, frontière IPC, installation « tous les utilisateurs », mise à niveau), ARM64 natif,
signature Authenticode, essai d'endurance (soak), dossiers redirigés par OneDrive (Known Folder
Move), machines multi-utilisateurs. Chaque section précise ce qui a été mesuré et ce qui ne l'a pas été.

---

## 1. Executive Summary

- **État.** WinSight est une suite .NET 10 mature de 24 projets (~45 000 lignes de production,
  ~45 000 de tests), avec une CI exigeante (actions épinglées par SHA, trois images Windows dont
  ARM64 natif, seuil de couverture, attestations SLSA et SBOM, cycle d'installation testé).
- **Points forts.** Honnêteté de la couverture (« incomplet » plutôt que « rien trouvé »), un format
  de rapport unique partagé par CLI, tableau de bord et MCP, aucun appel réseau implicite, une
  frontière privilégiée solide (tube nommé authentifié + modèle de capacités + vérification de
  l'identité du serveur), un serveur MCP en lecture seule.
- **Problèmes trouvés.** L'audit a traité **33 défauts** (32 corrigés dans le code et testés, 1 rendu
  explicite dans la documentation), dont 9 de sévérité *High* :
  faux positif et faux négatif du scanner hijack, Guardian aveugle aux clés Run absentes ou
  recréées, fuites de lignes de commande vers le modèle via MCP, courses TOCTOU dans les actions de
  réponse (réutilisation de PID, suppression/restauration de persistance, liste de processus protégés
  par simple nom de fichier), actions destructrices réussies sans journal, accès fichiers suivant les
  points d'analyse (reparse points) vers d'autres emplacements, et « Bloquer » devenu inutilisable
  sur Windows 11 faute de transactions registre (corrigé par un repli vérifié).
- **Performance.** Scan de persistance 2,7× plus rapide (25,2 s → 9,3 s, A/B même machine) ;
  indexation WinSxS passée de ~46 000 handles simultanés à ~6.
- **Positionnement.** WinSight couvre l'objectif de KnockKnock, de What's Your Sign et de DHS, et
  partiellement BlockBlock, OverSight, RansomWhere?, ReiKey et KextViewr. Il ne peut pas égaler LuLu
  sans pilote : un programme en mode utilisateur ne peut pas suspendre une connexion WFP en attente
  d'une décision. Autoruns reste plus large en surfaces, Sysmon (désormais intégré à Windows 11)
  plus riche en télémétrie, System Informer meilleur en inspection de processus.
- **Différenciation réelle.** Un triage unifié, local et compréhensible pour un non-spécialiste, avec
  des verdicts gradués (exploitabilité réelle, ancre de confiance, abus d'interpréteur signé) et une
  interface MCP sûre — aucune alternative ne réunit tout cela.
- **Priorités.** (1) requalifier en VM les changements privilégiés et la nouvelle couche d'accès
  fichiers ; (2) vérifier le comportement sur dossiers OneDrive ; (3) fermer les quatre constats
  *Medium* ouverts côté scanners ; (4) mode pare-feu « demander après la première connexion » ;
  (5) coût CPU au repos de la surveillance caméra/micro.

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
| Hijack / chemins | ✅ | AccessCheck + PE | non | non | non | chargements dynamiques (`LoadLibrary`) invisibles ; index WinSxS partiel |
| Présence physique | 🟡 | journal Système | non | oui | non | cause du réveil souvent absente |
| MCP (IA) | ✅ | stdio, lecture seule | — | journal d'alertes | — | délai coopératif (pas d'isolation dure) |

Légende : ✅ couvert, 🟡 partiel, ❌ absent.

---

## 4. Problèmes trouvés

Statuts : **Corrigé** (code et tests), **Documenté** (limite rendue explicite, pas de changement de
code), **Ouvert** (recommandation, non traité). « Preuve » renvoie au fichier concerné ; les
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

### 4.2 Ouverts ou documentés

| ID | Sév. | Composant | Description | Impact | Preuve | Correction proposée | Statut |
|---|---|---|---|---|---|---|---|
| WS-40 | Medium | Accès fichiers | Toute lecture refuse un fichier portant `ReparsePoint`. Les fichiers compressés WOF passent (vérifié) ; les fichiers cloud OneDrive **n'ont pas pu être testés** | si les fichiers cloud exposent l'attribut : entropie aveugle et leurres ni vérifiables ni nettoyables dans les dossiers sauvegardés par OneDrive | `AutomaticFileAccess.cs` | tester sur une machine avec Known Folder Move ; si confirmé, accepter les balises non « name surrogate » | À vérifier |
| WS-41 | Medium | Pilotes | Chemin d'image non résolu → repli sur `System32\drivers\<nom>.sys`, qui écrase aussi le chemin attendu | un binaire Microsoft à cet endroit masque un pilote réel ailleurs | `KernelDriverScanner.cs` | repli uniquement si `ImagePath` est absent ; chemin non résolu = non vérifié | Ouvert |
| WS-42 | Medium | Signatures | L'ancre « racine installée par l'utilisateur » n'est prise en compte que par la persistance | un module ou un pilote signé sous une racine importée par l'utilisateur apparaît sain | `LoadedModule.cs`, `ProcessInfo.cs`, `Connection.cs`, `KernelDriverTriage.cs` | appliquer `RestsOnUserInstalledTrust` partout | Ouvert |
| WS-43 | Medium | Filtres d'entrée | `kbdclass` / `mouclass` jugés sains sur leur seul nom | un ImagePath repointé passe inaperçu | `InputFilterTriage.cs` | exiger nom **et** binaire Windows signé | Ouvert |
| WS-44 | Medium | WMI | `ReturnImmediately = false` : le délai ne borne que l'itération, pas la requête | fournisseur bloqué → scan et annulation figés | `ProcessLister.cs`, `DnsCacheReader.cs`, `ControlledFolderAccessReader.cs` | mode semi-synchrone | Ouvert |
| WS-45 | Medium | Persistance | Contexte 32 bits : un nom nu inscrit sous `WOW6432Node` n'est pas cherché dans `SysWOW64` | verdict « introuvable » pour une DLL réelle | `CommandLine.cs` | propager la vue registre jusqu'à la résolution | Documenté |
| WS-46 | Medium | Persistance | Variables d'environnement des autres profils résolues avec celles du compte qui scanne | mauvais fichier vérifié ou faux « introuvable » | `CommandLine.cs` | résolution avec le profil propriétaire | Documenté |
| WS-47 | Medium | Hosts | `Tcpip\Parameters\DataBasePath` ignoré | fichier hosts déplacé invisible | `HostsReader.cs` | lire et signaler une valeur non standard | Documenté |
| WS-48 | Medium | Extensions | `content_scripts` ignoré ; extensions non empaquetées, Opera GX, canaux Beta/Dev/Canary absents | accès « tous les sites » sous-évalué ; navigateurs manqués | `ExtensionScanner.cs` | compléter les racines et le calcul de risque | Ouvert |
| WS-49 | Medium | Tableau de bord | La raison d'un signalement (ancre utilisateur, code tiers dans LSASS) disparaît du texte ; DNS affiché « réseau » pour tout le cache | ligne « Signature valide » marquée [!] | `DashboardFindingPresenter.cs` | champs dédiés | Ouvert |
| WS-50 | Medium | Tableau de bord | Une exception inattendue dans un gestionnaire d'interface met fin à l'application, donc à la protection temps réel | Guardian, rançongiciel et caméra arrêtés sans avertissement | `CrashReporter.cs` | contenir les exceptions non catastrophiques dans les gestionnaires | Ouvert (plausible) |
| WS-51 | Medium | Hijack | Index WinSxS non terminé dans le budget de 8 s (3 164 noms sur 5 833 ici) | imports « fantômes » dégradés en « non déterminé » | `SideBySideStore.cs` | index persistant invalidé par la maintenance Windows | Ouvert |
| WS-52 | Medium | Perf | Surveillance caméra/micro au repos : ~1,7 % d'un cœur | batterie pour un moniteur permanent | mesure `Measure-Performance.ps1` | notification comme source principale, interrogation de secours à 30 s | Ouvert |
| WS-53 | Medium | Package | Trois exécutables autonomes « single-file » : 431 Mo installés (installeur 116 Mo) | téléchargement, disque, mises à jour | `Build-Release.ps1` | runtime partagé dans un répertoire commun | Ouvert |
| WS-54 | Low | Persistance | Chaque CLSID HKCU rapporté comme « ComHijack » (3 941 lignes, JSON de 5,3 Mo) sans distinguer le masquage d'un CLSID HKLM | bruit, rapport lourd | `Enumerators.cs` | signaler en priorité les CLSID qui en masquent un de la machine | Ouvert |
| WS-55 | Low | Certificats | `Root` seulement, racines machine comptées deux fois ; `TrustedPublisher`, `CA`, `Disallowed` absents | couverture partielle | `CertStoreAuditor.cs` | ajouter ces magasins | Ouvert |
| WS-56 | Low | Intégrité | WDAC en audit présenté comme appliqué | fausse assurance | `CodeIntegrityTriage.cs` | tenir compte de `UMCI_AUDITMODE` | Ouvert |
| WS-57 | Low | Filtres CLI | `--nonmicrosoft` : sous-chaîne du sujet, sans l'état de signature | un faux « CN=Microsoft » auto-signé disparaît du filtre | `ReportItemFilter.cs` | nom commun exact + ancre machine | Ouvert |
| WS-58 | Low | Présence | Durées au-delà de 24 h tronquées ; un `Data` dupliqué lève une exception | affichage erroné, scan interrompu | `PresenceScanner.cs` | format et tolérance | Ouvert |
| WS-59 | Low | Hosts | Détection des redirections locales par comparaison de chaînes | `127.1` ou `0` signalés comme externes | `HostEntry.cs` | analyser l'adresse | Ouvert |
| WS-60 | Medium | Attribution | Fichiers ouverts avant la session ETW sans nom résoluble (`DiskFileIO` non activé) | auteur inconnu pour ces écritures | `WriteAttributionWatcher.cs` | mesurer, puis activer ou documenter | Ouvert (plausible) |
| WS-61 | Low | MCP | L'étanchéité à la couche de réponse n'est testée que par références directes ; alertes derrière le verrou de scan ; rédaction des chemins sans frontière de séparateur | régression possible non détectée ; refus en parallèle | `ResponseIsNotReachableFromMcpTests.cs`, `McpModels.cs` | test IL ; verrou séparé ; rédaction par frontière | Ouvert |
| WS-62 | Low | Supply chain | Le workflow de release restaure le cache `setup-dotnet` dans un build de tag | empoisonnement de cache théorique | `release.yml` | désactiver le cache pour les releases | Ouvert |
| WS-63 | Low | Installeur | La désinstallation ne retire pas le service pare-feu (choix documenté) | service orphelin pointant vers un binaire supprimé | `ADMINISTRATION.md` | proposer la désinstallation du service en mode tous utilisateurs | Documenté |
| WS-64 | Info | Réponse | Fenêtre résiduelle de quelques microsecondes entre comparaison et changement pour une valeur de registre sans TxR | valeur concurrente supprimée sans quarantaine | `THREAT_MODEL.md` | aucune primitive Windows ne ferme cette fenêtre | Documenté |
| WS-65 | Info | Pare-feu | Aucune invite avant la première connexion | pas d'équivalent LuLu | `WFP_DESIGN.md` | décision « après coup » via les événements WFP (§11) | Documenté |

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
un handle. Le point à vérifier est WS-40 (fichiers cloud).

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
| `hijack` | ~10-12 s dont ~8 s d'index WinSxS ; pic de handles 45 910 → 553 | WS-32, WS-51 |
| `modules` | 57-87 s | PSAPI appel par module, un processus à la fois |
| `av --watch` au repos | 1,7 % d'un cœur, 47 Mo | WS-52 |
| `input --watch` au repos | 0,05 % d'un cœur, 25 Mo | |
| Sortie JSON `persistence` | 5,3 Mo (4 541 entrées dont 3 941 CLSID HKCU) | WS-54 |
| Installeur / archive / installé | 116 Mo / 170 Mo / 431 Mo | WS-53 |
| Suite de tests complète | ~5 min, 3 179 tests (2 976 au début de l'audit), 0 échec | Release, 23 projets |

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
  demanderait un processus enfant jetable. WMI : délai non borné pour la requête elle-même (WS-44).
- **Instance unique.** Plus de moniteurs en double (WS-31).
- **Arrêt brutal.** Une exception d'interface non prévue arrête encore toute la protection (WS-50).
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
- Vérifier le comportement sur dossiers redirigés par OneDrive (WS-40) avant publication.
- Fermer WS-41, WS-42, WS-43 et WS-44 (confiance erronée ou gel de scan).

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
- Détection du masquage COM (WS-54), index WinSxS persistant (WS-51), attribution des arrivées
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
| Index WinSxS persistant | moyen | moyenne | faible |
| WMI semi-synchrone | fiabilité | faible | faible |

---

## 13. Security hardening roadmap

1. **Maintenant** : requalification VM ; WS-40 à WS-44 ; test d'étanchéité MCP au niveau IL (WS-61) ;
   release sans cache (WS-62).
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

Restantes : `PRODUCTION_READINESS.md` doit être mis à jour après la requalification ; les nombres
« 27 surfaces » et « 57 s » pour les modules sont des mesures anciennes à revalider avec l'outil de
mesure.

---

## 16. Tests missing

- Environnement OneDrive (Known Folder Move) pour la couche d'accès fichiers et les leurres.
- Deux vrais processus de tableau de bord (instance unique) et parcours « Bloquer » avec un
  programme qui réinscrit sa valeur.
- Débit ETW soutenu et pertes sous charge ; endurance de sept jours du tableau de bord.
- Installation tous utilisateurs, mise à niveau depuis v0.12/v0.13, désinstallation avec service.
- Qualification ARM64 native des chemins privilégiés.
- Tests négatifs pour WS-41 à WS-44 lors de leur correction.

---

## 17. Changes applied during audit

Tous les changements sont couverts par des tests ajoutés ou adaptés ; sur l'arbre final, la suite
complète (3 179 tests, 0 échec), le build Release (0 avertissement, avertissements traités comme
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
| Hijack | `Hijack/UnprivilegedWriteAccess.cs`, `WritabilityProbe.cs`, `HijackTriage.cs`, `HijackScanner.cs`, `UnquotedPath.cs`, `SideBySideStore.cs` | WS-01, WS-02, WS-29, WS-30, WS-32 |
| MCP | `Mcp/McpScanService.cs`, `UntrustedText.cs`, `Application/Adapters.cs`, `PersistenceMonitorPresenter.cs` | WS-08 à WS-10 |
| Rançongiciel | `Ransomware/RansomwareFileWatcher.cs`, `RansomwareBurstDetector.cs`, `RansomwareEntropySampler.cs`, `CanaryManager.cs`, `CanaryFile.cs` | WS-11, WS-23, WS-24 |
| Pare-feu | `FirewallService/EnforcementCoordinator.cs`, `OutboundObserverService.cs`, `Firewall/PendingOutboundLog.cs`, `FirewallRequestDispatcher.cs`, `FirewallPolicyStore.cs` | WS-15, WS-26 |
| Corrélation | `Processes/ProcessLister.cs`, `ProcessInfo.cs`, `Modules/*`, `NetMonitor/ConnectionMonitor.cs`, `Application/ProcessInsight.cs`, `CaptureDeviceProcessLocator.cs` | WS-28 |
| Tableau de bord | `Dashboard/DashboardSingleInstance.cs`, `App.xaml.cs`, `AlertWindow.xaml.cs`, `MainWindow.xaml.cs`, ressources EN/FR/ES | WS-31, WS-18 |
| CLI | `Application/CliHelp.cs`, `CliContract.cs`, `Cli/Program.cs` | WS-14, code de sortie de couverture incomplète |
| Installeur | `installer/WinSight.iss`, `scripts/Test-Installer.ps1` | WS-13 |
| Mesure | `scripts/Measure-Performance.ps1` | outil de mesure reproductible (D3) |
| Documentation | `README.md`, `docs/THREAT_MODEL.md`, `WFP_DESIGN.md`, `RECOVERY.md`, `DETECTIONS.md`, `ARCHITECTURE.md`, `MCP.md`, `INSTALLATION.md`, `OBJECTIVE_SEE_PARITY.md`, `ROADMAP.md`, `RANSOMWARE_DESIGN.md`, `GUARDIAN_DESIGN.md`, `ATTRIBUTION_DESIGN.md`, ce fichier | §15 |

---

## 18. Recommended roadmap

### Maintenant — bugs, sécurité, fiabilité

- Relire et fusionner la branche d'audit par thème ; requalifier en VM (x64, puis ARM64).
- WS-40 (OneDrive), WS-41 à WS-44, WS-50, WS-62.
- Mettre à jour `PRODUCTION_READINESS.md` avec le nouveau candidat qualifié.

### Ensuite — fonctionnalités différenciantes

- Pare-feu « décider après la première connexion » et règles par destination.
- Caméra/micro via `MFCreateSensorActivityMonitor`, règles et actions.
- Protection ClickFix ; tâches et WMI surveillées pour un utilisateur standard ; lecture de Sysmon.
- Corrélation par identité de processus entre Guardian, pare-feu et rançongiciel.
- Package à runtime partagé ; masquage COM ; index WinSxS persistant.

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
| Inventaire de persistance | ●●●○ 27 familles, verdicts gradués | Autoruns (●●●●) | catégories manquantes (Winsock, shell, Office, GPO) | ●●●● avec ces catégories et le masquage COM |
| Persistance en temps réel | ●●●○ clés et dossiers, décision, réversible | BlockBlock (macOS) / Sysmon 12-14 (Windows, sans décision) | blocage machine, attribution sans élévation | ●●●● avec le niveau machine du service |
| Processus | ●●○○ scans | System Informer / Process Explorer (●●●●) | vue live, handles, threads | ●●●○ avec une vue interactive |
| Réseau / pare-feu | ●●○○ règles WFP, état prouvé | Portmaster (●●●●, pilote) / simplewall (●●●○) | invite, destinations, historique | ●●●○ avec décision après coup et règles par destination |
| DNS | ●●○○ | Sysmon 22 / DNSMonitor | attribution continue, blocage | ●●●○ via Sysmon intégré |
| Caméra / micro | ●●○○ | OverSight (●●●○) / indicateurs Windows | source documentée, règles, coût | ●●●○ avec l'API de capteurs Media Foundation |
| Rançongiciel | ●●○○ détection | Defender CFA (●●●●, blocage) / RansomWhere? | suspension, attribution | ●●●○ détection + suspension confirmée ; le blocage reste à CFA |
| Signatures / hachages | ●●●● lié à l'objet, MSIX, ancre | Sigcheck (●●●●) | origine (Mark-of-the-Web) | ●●●● |
| Hijack / chemins | ●●●● gradué par exploitabilité | PrivescCheck, scripts (●●●○) | chargements dynamiques | ●●●● avec index WinSxS persistant |
| Télémétrie / corrélation | ●○○○ | Sysmon + Velociraptor / Wazuh (●●●●) | journal d'événements corrélé | ●●○○ en consommant Sysmon |
| Ergonomie grand public | ●●●● trois langues, verdicts expliqués | GlassWire (●●●○) | — | ●●●● |
| Intégration IA | ●●●● MCP en lecture seule | TaskExplorer 3 (assistant intégré) | — | ●●●● |

## Top 10 améliorations avec le meilleur ROI

| # | Fonctionnalité | Pourquoi | Valeur utilisateur | Difficulté (1-5) | Risque (1-5) | Coût performance | Fichiers / composants |
|---|---|---|---|---|---|---|---|
| 1 | Requalification VM du candidat | changements privilégiés et couche fichiers non qualifiés | condition de toute publication | 2 | 1 | nul | `docs/validation`, scripts de qualification |
| 2 | Vérification et correctif OneDrive (WS-40) | cas par défaut de nombreux PC grand public | détection rançongiciel fiable | 2 | 2 | nul | `Core/AutomaticFileAccess.cs`, `Ransomware/*` |
| 3 | Pare-feu « décider après la première connexion » | l'attente n°1 d'un utilisateur de LuLu | contrôle réseau compréhensible | 3 | 3 | faible (événements WFP) | `FirewallService/OutboundObserverService.cs`, `Dashboard` |
| 4 | Ancre de confiance partout + pilotes (WS-41, WS-42, WS-43) | fausses assurances sur modules, pilotes et filtres | verdicts justes | 2 | 1 | nul | `Modules`, `Processes`, `NetMonitor`, `Drivers`, `InputHooks` |
| 5 | Caméra/micro par capteurs Media Foundation, pilotée par événements | source documentée, coût au repos divisé | confiance dans l'alerte, batterie | 3 | 2 | négatif (gain) | `AvMonitor/*`, `Application/AvWatchHost.cs` |
| 6 | Masquage COM et réduction du bruit | 3 941 lignes non pertinentes | rapport lisible | 2 | 1 | gain | `Persistence/Enumerators.cs` |
| 7 | Protection « ClickFix » | vecteur d'infection majeur en 2025-2026 | prévention concrète | 3 | 2 | faible | `Persistence`, `Application`, `Dashboard` |
| 8 | Runtime partagé | 431 Mo installés | téléchargement et mises à jour | 3 | 3 | nul | `scripts/Build-Release.ps1`, `installer` |
| 9 | WMI semi-synchrone + confinement des exceptions d'interface (WS-44, WS-50) | gels et arrêt de la protection | stabilité | 2 | 1 | nul | `Processes`, `NetMonitor`, `Ransomware`, `Dashboard` |
| 10 | Lecture de Sysmon intégré | ascendance, DNS et réseau sans pilote quand il est activé | corrélation | 3 | 2 | faible | nouveau lecteur dans `NetMonitor`/`Application` |
