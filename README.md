# Spamhaus Submission Script

Ce dépôt contient un script PowerShell interactif dédié à la **soumission de contenu RAW d'e-mails**, de **domaines** et d'**adresses IP** malveillants vers l'API Spamhaus Submission Portal, ainsi qu'à la consultation du **compteur** et de la **liste** des soumissions récentes.

## Table des matières

- [Fonctionnalités](#fonctionnalités)  
- [Prérequis](#prérequis)  
- [Limitations réseau et contournements](#limitations-réseau-et-contournements)  
- [Limitations de l'API Spamhaus](#limitations-de-lapi-spamhaus)  
- [Vérifications implémentées dans le script](#vérifications-implémentées-dans-le-script)  
- [Gestion avancée des erreurs](#gestion-avancée-des-erreurs)  
- [Structure du script](#structure-du-script)  
- [Usage](#usage)  

## Fonctionnalités

1. **Soumission d'un e-mail RAW**  
   - Lecture d'un fichier `.eml` complet en UTF-8  
   - Nettoyage pour n'envoyer que la chaîne brute (texte complet du mail)  
   - Sélection du type de menace **`type=email`** via menu numérique (fallback sur `spam`)  
   - Retry automatique (3 tentatives) en cas d'échec réseau ou timeout API  
   - Pas de retry sur erreur 400 (erreur de données invalides)

2. **Soumission d'un domaine malveillant**  
   - Saisie manuelle du nom de domaine  
   - Sélection du type de menace **`type=domain`** via menu numérique (fallback sur `phish`)  
   - Validation format (domaine et non URL) et champ non vide
   - Envoi direct (1 tentative) via `/submissions/add/domain`  
   - Gestion détaillée des codes d'erreur HTTP et messages du serveur

3. **Soumission d'une adresse IP malveillante**  
   - Saisie manuelle de l'adresse IPv4  
   - Validation du format IPv4  
   - Sélection du type de menace **`type=ip`** via menu numérique (fallback dynamique sur `spam`)  
   - Envoi direct (1 tentative) via `/submissions/add/ip`  
   - Gestion détaillée des codes d'erreur HTTP et messages du serveur

4. **Consultation du compteur de soumissions**  
   - Nombre total de soumissions et nombre de correspondances trouvées (sur les 30 derniers jours)  

5. **Affichage de la liste des soumissions**  
   - Pagination configurable avec les paramètres `items` et `page`  
   - Détails affichés : ID, type de menace, raison, date, statut dans les datasets  

## Prérequis

- PowerShell (Windows 10+ recommandé)  
- Aucune dépendance externe requise  
- Clé API valide (à insérer dans la variable `$API_TOKEN` du script)  
  - Récupérable depuis votre profil Spamhaus : https://auth.spamhaus.org/account/

## Limitations réseau et contournements

- **Politique d'exécution PowerShell** : exécuter en bypass  
`powershell.exe -ExecutionPolicy Bypass -File .\spamhaus_submission.ps1`

- **Test TCP initial** : connectivité obligatoire à `submit.spamhaus.org:443` avec timeout à 5 secondes  
- **Connexion forcée** : désactivation de `KeepAlive` (HttpWebRequest.KeepAlive = $false)  
- **Retry intelligent** : 3 tentatives avec délais croissants (5 s, 10 s, 15 s) uniquement pour les erreurs réseau et serveur (emails uniquement)  

## Limitations de l'API Spamhaus

- **Contenu RAW email** : taille maximale de **150 Ko** au format JSON UTF-8  
- **Soumission de domaine/IP** : taille de payload négligeable (pas de limite pratique)  
- **Champ Reason** : maximum **255** caractères  
- **Counter & List** : données restreintes aux **30 derniers jours**  
- **Pagination Liste** : `items` maximal à 10 000 par page  

## Vérifications implémentées dans le script

1. **Connectivité réseau**  
 - Test initial TCP sur `submit.spamhaus.org:443` (timeout 5 s)  
2. **Récupération des types de menaces**  
 - Filtrage sur le type (`email`, `domain` ou `ip`) selon l'action  
 - Tentatives retry 3× (timeout 5 s)  
 - Déduplication des codes recevables  
 - Fallback dynamique sur type par défaut selon la liste retournée
3. **Soumission e-mail RAW**  
 - Lecture via `Get-Content -Raw -Encoding UTF8`  
 - Validation taille ≤ 150 000 octets  
 - Retry 3× avec délai progressif sur erreurs réseau/serveur uniquement
 - Pas de retry sur erreur 400 (données invalides)
4. **Soumission domaine**  
 - Validation champ non vide  
 - Construction du payload  
 - Timeout fixe de 10 s, pas de retry  
5. **Soumission IP**  
 - Validation format IPv4 via regex  
 - Construction du payload  
 - Timeout fixe de 10 s, pas de retry
6. **Gestion des retours d'API**  
 - Codes gérés : 200 (succès), 208 (doublon), 400 (erreur de données)
 - Messages d'erreur détaillés récupérés depuis la réponse JSON du serveur
 - Gestion des erreurs réseau et timeout
7. **Si fichier e-mail non trouvé à cause d'un caractère spécial**  
 - Liste et sélection interactive parmi tous les fichiers `*.eml` du dossier  

## Gestion avancée des erreurs

Le script implémente une **gestion détaillée des erreurs** pour toutes les soumissions :

- **Erreur 400** : récupération et affichage du message d'erreur exact fourni par Spamhaus (ex: "invalid domain name provided", "invalid IP address provided")
- **Erreurs 401/403** : problème d'authentification ou de permissions
- **Erreurs 5xx** : problème serveur Spamhaus (retry pour emails uniquement)
- **Erreurs réseau** : timeout, DNS, connexion refusée (retry pour emails uniquement)
- **Lecture du corps de réponse** : extraction du message JSON même en cas d'erreur HTTP

Cette approche permet un **diagnostic précis** des problèmes de soumission.

## Structure du script

- `Test-Port` : vérifie la connectivité TCP initiale  
- `Get-ThreatTypes` : récupère et déduplique la liste des types de menaces disponibles  
- `Submit-Email` : soumet un e-mail RAW au format JSON avec retry intelligent
- `Submit-Domain` : soumet un domaine malveillant au format JSON  
- `Submit-IP` : soumet une adresse IP malveillante au format JSON
- `Get-SubmissionsCounter` : affiche le compteur des soumissions sur 30 jours  
- `Get-SubmissionsList` : affiche une liste paginée des soumissions  
- `Show-Menu` + boucle principale interactive  

## Usage

1. Cloner ce dépôt  
2. Ouvrir le script et définir la variable `$API_TOKEN` avec votre clé API personnelle  
3. Lancer le script avec :  
`powershell.exe -ExecutionPolicy Bypass -File .\spamhaus_submission.ps1`
4. Choisir l'option du menu :  
- **1** : Soumettre un e-mail RAW  
- **2** : Soumettre un domaine malveillant  
- **3** : Soumettre une adresse IP malveillante  
- **4** : Consulter le compteur des soumissions  
- **5** : Afficher la liste paginée des soumissions  
- **6** : Quitter le script  

---

Ce script se concentre exclusivement sur la **soumission d'e-mails, domaines et adresses IP malveillants** et la consultation rapide des résultats.  
Il utilise uniquement les cmdlets PowerShell natives, sans dépendances tierces.
