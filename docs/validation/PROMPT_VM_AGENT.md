# Prompt d'agent — qualification VM du candidat `7c9ec93`

Ce fichier existe pour être copié tel quel dans un agent autonome disposant d'une VM Windows
isolée et jetable. Il lie un candidat précis ; le régénérer pour tout autre commit.

---

Tu qualifies un candidat WinSight sur une VM Windows vierge, isolée et jetable. Tu travailles
seul, sans me demander confirmation, et tu t'arrêtes rouge à la première ambiguïté.

## Le candidat, lié

```
Repo            ClementG91/winsight
CandidateSha    7c9ec935ed21d04483c553031c8d7dd70188d320
ArtifactKind    ci
RunId           33179811048          (ci.yml, conclusion=success, head_sha=7c9ec935…)
ProductVersion  0.11.6
```

`ArtifactKind = ci` n'est pas un détail : tu qualifies **un commit avant publication**, pas les
fichiers d'une release. Le packaging n'est pas reproductible octet pour octet entre `ci.yml` et
`release.yml`, donc ton rapport ne dira rien des binaires que téléchargent les utilisateurs. Énonce
`ArtifactKind` dans le rapport ; un rapport qui l'omet laisse le lecteur supposer la portée la plus
large, qui est justement celle que tu n'as pas.

## Règles absolues

1. **Uniquement dans une VM isolée et jetable.** N'installe jamais le service, ne modifie jamais WFP
   et n'arrête jamais une session ETW sur un poste de développement. Le protocole le dit en toutes
   lettres et c'est la seule règle qui n'a pas d'exception.
2. **Fail closed.** Valeur générique, fichier ambigu, hash manquant, script modifié, inventaire ETW
   illisible ou preuve non exportée ⇒ **STOP, résultat rouge**. Tu ne « contournes » rien, tu ne
   « réessayes en ignorant », tu ne relâches aucun seuil pour faire passer une étape.
3. **Les preuves survivent au restore.** `$EvidenceRoot` est un volume monté hors du snapshot ou un
   partage réseau durable. Si tu ne peux pas le garantir, arrête avant de commencer.
4. **Tu ne modifies aucun script de test pour le faire passer.** Si un script échoue, c'est le
   résultat. Rapporte-le.
5. **Aucun binaire candidat n'est exécuté avant que sa racine protégée soit établie et vérifiée.**

## Ce que tu exécutes

Suis `docs/validation/VM_QUALIFICATION_KIT.md` **intégralement et dans l'ordre**, sections 0 à 8. Ce
document est l'autorité ; ce prompt ne le remplace pas et ne l'abrège pas. Les attendus chiffrés
(26/26 et le contrôle négatif 26/1, pré-arm 17/17, full WFP 35/35, trust 13/13 sans skip, IPC local
7/7, Network Logon 7/7, ETW 19/19) sont dans le kit — n'en invente aucun et n'en assouplis aucun.

Pour lier les empreintes : télécharge l'artefact **sur l'hôte**, calcule `$ExpectedZipSha256` et
`$ExpectedInstallerSha256` là, puis transfère dans la VM et laisse la section 3 les revérifier. Ça
donne un vrai contrôle indépendant de la copie côté invité. Note dans le rapport d'où viennent les
empreintes.

## Les trois changements à surveiller particulièrement

Ce candidat contient une campagne de correctifs issue d'un audit. Trois d'entre eux touchent la
surface privilégiée que seule cette VM peut exercer, et **aucun n'a été vérifié sur matériel**. Ils
ne remplacent pas le protocole : tu les vérifies *en plus*, et tu les rapportes séparément.

### 1. Poids du sublayer WFP : 0 → `0x8000`

`WfpProvisioning.SublayerWeight`. Le sublayer était au minimum absolu, sous tout ce qui souhaitait le
surclasser, sur la seule fonction du produit qui bloque réellement du trafic. `VerifyExact` vérifie
désormais ce poids comme faisant partie de la forme exacte.

À prouver, une fois l'enforcement armé :

```powershell
netsh wfp show state file=$EvidenceRoot\wfp-state-armed.xml
```

Puis, dans le XML : le sublayer WinSight (`d7a9b1e1-5c3a-4b8e-9f21-6c0a7e2d1f34`) existe, son poids
est `0x8000`, et son ordre relatif aux autres sublayers présents est enregistré. Rapporte le poids et
la position **observés**, pas ceux attendus. Vérifie aussi qu'aucune régression n'apparaît sur
`wfp-status` : la sortie est basée sur présence/absence et ne doit pas avoir changé.

### 2. Repli de dérivation de l'app-id

`WfpApplicationId.TryDerive`. Quand `FwpmGetAppIdFromFileName0` refuse — typiquement parce que le
binaire bloqué n'existe plus — l'identifiant est reconstruit depuis le mapping de volume au lieu de
faire échouer la transition. La forme des octets est testée unitairement ; le comportement face à BFE
ne l'est pas.

Scénario à exécuter après le full WFP, avec preuve à chaque étape :

1. Bloquer une application de test, confirmer le blocage (curl cible `000`, contrôle `200`).
2. **Supprimer ou renommer le binaire bloqué**, puis provoquer une réconciliation (redémarrage du
   service).
3. Attendu : le service démarre, `enforce-status` reste `Enforcement`, WFP conserve ses filtres, et
   **aucun** rollback vers `AuditOnly` ne se produit. Avant ce correctif, cette séquence supprimait
   tous les filtres et remettait le service en démarrage à la demande.
4. Restaurer le binaire à son chemin d'origine et vérifier que le blocage s'applique de nouveau
   (curl `000`) **sans nouvelle transition** — c'est la partie qui prouve que l'identifiant dérivé
   correspond bien à celui que BFE calcule pour l'image réelle. Si le blocage ne revient pas, c'est
   un échec et il faut le dire : cela signifierait que le repli produit un identifiant qui ne
   correspond à rien.
5. Vérifier aussi un chemin sans volume résoluble (partage UNC) : le bloc doit être signalé comme non
   applicable, sans faire échouer la politique entière.

### 3. Code de sortie non nul à la perte d'endpoint

`FirewallServiceExitSignal`. Le processus sortait 0 en perdant son endpoint, ce que le SCM lit comme
un arrêt volontaire — donc `SERVICE_FAILURE_ACTIONS` (reprises à 5 s et 30 s) ne s'appliquait jamais.

À prouver :

1. Vérifier d'abord le profil SCM attendu par le kit (SID de service, trois privilèges requis,
   actions de reprise) via `QueryServiceConfig2W`.
2. Occuper le nom du pipe **avant** le démarrage du service (squat `FIRST_PIPE_INSTANCE`), démarrer
   le service, et observer : le processus sort non nul, le SCM enregistre l'échec, et une action de
   reprise se déclenche.
3. Relever `sc query` et le journal d'événements. Attendu : reprise après 5 s puis 30 s, et non un
   service arrêté proprement que rien ne relance.

## Ce que tu produis

Un enregistrement dans `docs/validation/`, nommé `AAAA-MM-JJ-<portée>-7c9ec93.md`, suivant exactement
le format des enregistrements existants (voir `2026-08-23-x64-qualification-8486155.md`) :

- **Evidence identity** : candidat, version, run CI, plateforme et build exact, machine de contrôle,
  version de PowerShell, snapshots restaurés en fin de campagne.
- **Artifact binding** : SHA-256 du ZIP et du setup, et d'où tu les tiens.
- Un tableau par famille de gates avec les résultats **littéraux** (`n/m`, codes de sortie, sorties
  curl), pas des résumés.
- Une section pour chacun des trois points ci-dessus.
- Une section « ce qui n'a pas été exercé » — la portée que ce rapport ne couvre pas.

Le rapport qualifie **ce candidat exact** et ne le promeut pas au-delà des gates réellement exécutés.
Si une famille est rouge, le rapport est rouge : ne présente pas une campagne partielle comme une
réussite.

## Conditions d'arrêt

Arrête et rapporte immédiatement si :

- le run CI ne correspond pas au candidat, ou n'a pas réussi ;
- un hash ne correspond pas ;
- `Assert-CandidateFiles` échoue à un quelconque moment ;
- un script de test refuse de démarrer sans élévation alors que tu la crois acquise ;
- tu ne peux pas créer ou restaurer un snapshot hôte quand le kit l'exige ;
- l'application de test que tu bloques n'est pas la tienne (n'utilise jamais un binaire système).
