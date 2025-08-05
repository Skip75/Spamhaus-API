# Spamhaus RAW Email Submission Script

Ce dépôt contient un script PowerShell interactif dédié à la **soumission de contenu RAW d’e-mails** malveillants vers l’API Spamhaus Submission Portal, ainsi qu'à la consultation du **compteur** et de la **liste** des soumissions récentes.

## Table des matières

- [Fonctionnalités](#fonctionnalités)  
- [Prérequis](#prérequis)  
- [Limitations réseau et contournements](#limitations-réseau-et-contournements)  
- [Limitations de l’API Spamhaus](#limitations-de-lapi-spamhaus)  
- [Vérifications implémentées dans le script](#vérifications-implémentées-dans-le-script)  
- [Structure du script](#structure-du-script)  
- [Usage](#usage)  

## Fonctionnalités

1. **Soumission d’un e-mail RAW**  
   - Lecture d’un fichier `.eml` complet en UTF-8  
   - Nettoyage pour n’envoyer que la chaîne brute (texte complet du mail)  
   - Sélection du type de menace via menu numérique (fallback sur `source-of-spam`)  
   - Retry automatique (3 tentatives) en cas d’échec réseau ou timeout API (fréquents)  

2. **Consultation du compteur de soumissions**  
   - Nombre total de soumissions et nombre de correspondances trouvées (sur les 30 derniers jours)  

3. **Affichage de la liste des soumissions**  
   - Pagination configurable avec les paramètres `items` et `page`  
   - Détails affichés : ID, type de menace, raison, date, statut dans les datasets  

## Prérequis

- PowerShell (Windows 10+ recommandé)  
- Aucune dépendance externe requise  
- Clé API valide (à insérer dans la variable `$API_TOKEN` du script)  
  - Récupérable depuis votre profil Spamhaus : https://auth.spamhaus.org/account/

## Limitations réseau et contournements

- **Politique d’exécution PowerShell** : exécuter en bypass  
`powershell.exe -ExecutionPolicy Bypass -File .\spamhaus_submission.ps1`

- **Test TCP initial** : connectivité obligatoire à `submit.spamhaus.org:443` avec timeout à 5 secondes  
- **Connexion forcée** : désactivation de `KeepAlive` (HttpWebRequest.KeepAlive = $false)  
- **Retry** : 3 tentatives avec délais croissants (5 s, 10 s, 15 s) sur appels API  

## Limitations de l’API Spamhaus

- **Contenu RAW email** : taille maximale de **150 Ko** au format JSON UTF-8  
- **Champ Reason** : maximum **255** caractères  
- **Counter & List** : données restreintes aux **30 derniers jours** uniquement  
- **Pagination Liste** : `items` maximal à 10 000 par page  

## Vérifications implémentées dans le script

1. **Connectivité réseau**  
 - Test initial TCP sur `submit.spamhaus.org:443` (timeout 5 s)  
2. **Récupération des types de menaces**  
 - Tentatives retry 3× (timeout 5 s)  
 - Déduplication des codes recevables  
3. **Lecture et nettoyage du RAW email**  
 - Lecture via `Get-Content -Raw -Encoding UTF8`  
 - Cast en `[string]` pour éviter métadonnées PowerShell  
4. **Validation de la taille du payload JSON**  
 - Calcul en octets UTF-8 (doit être ≤ 150 000 octets)  
5. **Soumission robuste**  
 - POST HTTP via `Invoke-WebRequest` sur `/submissions/add/email` (timeout 10 s)  
 - Retry 3× avec délai progressif  
 - Gestion explicite des codes d’erreur HTTP 400, 401, 208, et des exceptions réseaux  

## Structure du script

- `Test-Port` : vérifie la connectivité TCP initiale  
- `Get-ThreatTypes` : récupère et déduplique la liste des types de menaces disponibles  
- `Submit-Email` : soumet un e-mail RAW au format JSON  
- `Get-SubmissionsCounter` : affiche le compteur des soumissions sur 30 jours  
- `Get-SubmissionsList` : affiche une liste paginée des soumissions  
- `Show-Menu` + boucle principale interactive  

## Usage

1. Cloner ce dépôt  
2. Ouvrir le script et définir la variable `$API_TOKEN` avec votre clé API personnelle  
3. Lancer le script avec :  
`powershell.exe -ExecutionPolicy Bypass -File .\spamhaus_submission.ps1`
4. Choisir l’option du menu :  
- **1** : Soumettre un e-mail RAW  
- **2** : Consulter le compteur des soumissions  
- **3** : Afficher la liste paginée des soumissions  
- **4** : Quitter le script  

---

Ce script se concentre exclusivement sur la **soumission RAW d’e-mails** malveillants et la consultation rapide des résultats. Il utilise uniquement les cmdlets PowerShell natives sans dépendances tierces.
