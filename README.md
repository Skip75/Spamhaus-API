# Spamhaus Submission Script

Ce dépôt contient un script PowerShell interactif (`spamhaus_submission_v4.ps1`) dédié à la **soumission de contenu RAW d'e-mails** (en sélection multiple), de **domaines** et d'**adresses IP** malveillants vers l'API Spamhaus Submission Portal, ainsi qu'à la consultation du **compteur** et de la **liste** des soumissions récentes.

## Table des matières

- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Limitations de l'API Spamhaus](#limitations-de-lapi-spamhaus)
- [Vérifications implémentées dans le script](#vérifications-implémentées-dans-le-script)
- [Gestion avancée des erreurs](#gestion-avancée-des-erreurs)
- [Structure du script](#structure-du-script)
- [Usage](#usage)

## Fonctionnalités

1. **Soumission d'un ou plusieurs e-mails RAW (sélection multiple)**
   - Sélection du **type de menace** (`type=email`, ex. spam, phishing/impersonation...) via menu numérique, **une seule fois pour tout le lot** (fallback sur `source-of-spam` si l'API des types est indisponible)
   - Saisie de la **raison** (`reason`), également commune à tout le lot (défaut : `phishing/impersonation email`)
   - Ouverture d'une boîte de dialogue Windows (`OpenFileDialog`) en **mode multi-sélection** (Ctrl+clic / Shift+clic) pour choisir tous les fichiers `.eml` à soumettre dans cette catégorie
   - Lecture de chaque fichier en UTF-8 avec repli automatique en ISO-8859-1 (Latin-1) si le décodage UTF-8 échoue (emails mal encodés)
   - Validation individuelle par fichier : taille non nulle, taille ≤ 150 000 octets ; un fichier invalide est ignoré sans bloquer les autres
   - Envoi séquentiel de chaque fichier via `/submissions/add/email`, avec un délai de pacage de 2 secondes entre deux envois pour limiter le risque de HTTP 429
   - Récapitulatif final sous forme de tableau (fichier / statut OK-ECHEC-IGNORE / détail) à l'issue du lot
   - Pour soumettre un second lot avec une catégorie et/ou une raison différentes, il suffit de relancer l'option 1 du menu : chaque exécution est indépendante

2. **Soumission d'un domaine malveillant**
   - Saisie manuelle du nom de domaine, avec nettoyage automatique (suppression du protocole `http(s)://`, du préfixe `www.` et de tout chemin après le domaine)
   - Validation du format par expression régulière (domaine et non URL)
   - Sélection du type de menace **`type=domain`** via menu numérique (fallback sur `source-of-spam`)
   - Envoi via `/submissions/add/domain`, avec retry automatique géré par le cœur réseau commun

3. **Soumission d'une adresse IP malveillante**
   - Saisie manuelle de l'adresse IPv4, validée et normalisée via `[Net.IPAddress]::TryParse`
   - Sélection du type de menace **`type=ip`** via menu numérique (fallback sur `source-of-spam`)
   - Envoi via `/submissions/add/ip`, avec retry automatique géré par le cœur réseau commun

4. **Consultation du compteur de soumissions**
   - Nombre total de soumissions et nombre de correspondances trouvées (`matched`) sur les 30 derniers jours, avec calcul du taux de correspondance

5. **Affichage de la liste des soumissions**
   - Pagination configurable avec les paramètres `items` (1 à 10 000) et `page`
   - Détails affichés par ligne : date, type de soumission, objet (adresse IP/masque, domaine, ou sujet/raison pour un email), type de menace, statut de présence dans les datasets, date de dernière vérification

## Prérequis

- Windows PowerShell 5.1 ou PowerShell 7+ (aucun module tiers requis ; utilise uniquement les cmdlets natives et l'assembly `System.Windows.Forms` pour la boîte de dialogue de fichiers)
- Clé API valide à insérer dans la variable `$API_TOKEN` du script
  - Récupérable depuis votre profil Spamhaus : [https://auth.spamhaus.org/account/](https://auth.spamhaus.org/account/)
- Sur Windows PowerShell 5.1, le script force lui-même TLS 1.2 au démarrage (non nécessaire sur PowerShell 7+, qui le gère nativement)

## Limitations de l'API Spamhaus

- **Contenu RAW email** : taille maximale de **150 000 octets** de contenu brut
- **Pas d'endpoint de soumission groupée** : l'API n'accepte qu'un seul `source.object` par requête ; la « sélection multiple » du script reste une boucle d'appels individuels côté client, pas une soumission groupée côté serveur
- **Champ Reason** : maximum **255 caractères** (tronqué automatiquement par le script si dépassé)
- **Counter & List** : données restreintes aux **30 derniers jours**
- **Pagination Liste** : `items` maximal à 10 000 par page
- **Limitation de débit (HTTP 429)** : non chiffrée publiquement pour l'endpoint de soumission ; le script applique un délai de pacage de 2 s entre chaque envoi d'un lot d'emails et gère le 429 s'il survient malgré tout (voir ci-dessous)

## Vérifications implémentées dans le script

1. **Récupération des types de menaces (`Select-ThreatType`)**
   - Appel à `lookup/threats-types`, filtrage sur la catégorie (`email`, `domain` ou `ip`)
   - En cas d'échec de l'appel, fallback silencieux sur un code par défaut (`source-of-spam`)
   - Affichage numéroté avec présélection du code par défaut si présent dans la liste
2. **Soumission e-mail RAW (`Submit-Email` + `Get-EmailRawContent`)**
   - Lecture binaire (`[IO.File]::ReadAllBytes`) puis décodage UTF-8 avec repli ISO-8859-1
   - Validation : fichier existant, non vide, ≤ 150 000 octets — un fichier hors norme est ignoré et reporté dans le récapitulatif, sans interrompre le traitement des autres fichiers du lot
   - Catégorie et raison figées une fois pour tout le lot, appliquées à chaque envoi
3. **Soumission domaine**
   - Nettoyage (retrait protocole/`www.`/chemin) puis validation par regex
   - Signalement si la valeur a été normalisée par rapport à la saisie initiale
4. **Soumission IP**
   - Validation stricte IPv4 via `[Net.IPAddress]::TryParse` (rejette IPv6 et formats invalides)
   - Signalement si la valeur a été normalisée par rapport à la saisie initiale
5. **Gestion des retours d'API (`Invoke-SpamhausApi`)**
   - Codes gérés explicitement : 208 (soumission déjà signalée, traité comme non bloquant), 400 (requête invalide, message serveur affiché), 401 (token invalide/expiré), 429 (limite de débit)
   - Toute autre erreur HTTP ou réseau déclenche un retry générique avec délai croissant (3 s × numéro de tentative)

## Gestion avancée des erreurs

Le script centralise toute la logique réseau et d'erreur dans `Invoke-SpamhausApi`, utilisée par toutes les fonctions de soumission et de consultation :

- **Erreur 400** : récupération et affichage du message d'erreur exact fourni par Spamhaus dans le corps JSON de la réponse
- **Erreur 401** : message explicite « token invalide ou expiré », le message serveur est repris s'il est disponible
- **Erreur 208** : traitée comme un cas normal (soumission déjà connue), retournée sans lever d'exception
- **Erreur 429 (rate limit)** : lecture de l'en-tête `Retry-After` s'il est présent pour respecter le délai imposé par le serveur ; sinon, backoff exponentiel plafonné à 60 s (2 s, 4 s, 8 s...), jusqu'à 5 tentatives
- **Autres erreurs HTTP/réseau (timeout, DNS, 5xx...)** : retry générique jusqu'à 3 tentatives avec délai croissant (3 s, 6 s, 9 s)
- **Lecture du corps de réponse** : extraction du message JSON même en cas d'erreur HTTP, compatible PowerShell 5.1 (`StreamReader`) et PowerShell 7+ (`$_.ErrorDetails.Message`)
- **Soumission par lot d'emails** : un fichier en échec (lecture ou API) n'interrompt pas le traitement des fichiers suivants ; chaque résultat est consigné individuellement dans le récapitulatif final

## Structure du script

- `Get-ApiToken` : récupère le token depuis la variable d'environnement `SPAMHAUS_API_TOKEN` ou via saisie masquée (fonction disponible, le script utilise actuellement `$API_TOKEN` en dur à remplacer par votre clé)
- `Invoke-SpamhausApi` : cœur réseau générique (GET/POST, retry, gestion 400/401/208/429/erreurs génériques)
- `Select-ThreatType` : sélection interactive du type de menace filtré par catégorie
- `Read-Reason` : saisie de la raison avec valeur par défaut et troncature à 255 caractères
- `Get-EmailRawContent` : lecture et validation sécurisées d'un fichier `.eml` (taille, encodage)
- `Submit-Email` : sélection de catégorie + raison pour le lot, sélection multiple de fichiers, boucle d'envoi avec pacage et récapitulatif
- `Submit-Domain` : soumet un domaine malveillant au format JSON
- `Submit-IP` : soumet une adresse IP malveillante au format JSON
- `Get-SubmissionsCounter` : affiche le compteur des soumissions sur 30 jours
- `Get-SubmissionsList` : affiche une liste paginée des soumissions
- `Show-Menu` + boucle principale interactive

## Usage

1. Cloner ce dépôt
2. Ouvrir `spamhaus_submission_v4.ps1` et définir la variable `$API_TOKEN` avec votre clé API personnelle (ou définir la variable d'environnement `SPAMHAUS_API_TOKEN`)
3. Lancer le script avec :
   `powershell.exe -ExecutionPolicy Bypass -File .\spamhaus_submission_v4.ps1`
4. Choisir l'option du menu :
   - **1** : Soumettre un ou plusieurs e-mails RAW (sélection multiple, catégorie et raison communes au lot)
   - **2** : Soumettre un domaine malveillant
   - **3** : Soumettre une adresse IP malveillante
   - **4** : Consulter le compteur des soumissions
   - **5** : Afficher la liste paginée des soumissions
   - **6** : Quitter le script

---

Ce script se concentre exclusivement sur la **soumission d'e-mails (par lot), domaines et adresses IP malveillants** et la consultation rapide des résultats.
Il utilise uniquement les cmdlets PowerShell natives et l'assembly `System.Windows.Forms`, sans dépendances tierces.
