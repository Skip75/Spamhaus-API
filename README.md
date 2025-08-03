# Spamhaus RAW Email Submission Script

Ce dépôt contient un script PowerShell interactif dédié à la **soumission de contenu RAW d’e-mail** malveillant vers l’API Spamhaus Submission Portal, ainsi que la consultation du **compteur** et de la **liste** des soumissions récentes.

## Table des matières

- [Fonctionnalités](#fonctionnalités)  
- [Prérequis](#prérequis)  
- [Limitations réseau et contournements](#limitations-réseau-et-contournements)  
- [Limitations de l’API Spamhaus](#limitations-de-lapi-spamhaus)  
- [Checks implémentés dans le script](#checks-implémentés-dans-le-script)  
- [Structure du script](#structure-du-script)  
- [Usage](#usage)  

## Fonctionnalités

1. **Soumission d’un e-mail RAW**  
   - Lecture d’un fichier `.eml` complet  
   - Nettoyage pour n’envoyer que la chaîne brute  
   - Sélection du type de menace via menu numérique (fallback `source-of-spam`)  
   - Retry (3 ×) en cas d’échec réseau ou timeout  

2. **Consultation du compteur de soumissions**  
   - Nombre total et correspondances trouvées (30 derniers jours)  

3. **Affichage de la liste des soumissions**  
   - Paginée, configurable `items` et `page`  
   - Détail : ID, type de menace, raison, date, statut  

## Prérequis

- PowerShell
- Aucune dépendance externe  
- Clé API valide (à injecter dans `$API_TOKEN`) à récupérer dans notre profil https://auth.spamhaus.org/account/

## Limitations réseau et contournements

- **Politique d’exécution** : lancer en bypass  
powershell.exe -ExecutionPolicy Bypass -File .\spamhaus_submission.ps1

- **Test TCP initial** : connectivité `submit.spamhaus.org:443` (timeout 5 s)  
- **Connexion forcée** : `HttpWebRequest.KeepAlive = $false`  
- **Retry** : 3 tentatives avec délais croissants (5 s, 10 s, 15 s)  

## Limitations de l’API Spamhaus

- **Contenu RAW email** : max **150 Kb**  
- **Reason** : max **255** caractères  
- **Counter & List** : uniquement les **30 derniers jours**  
- **Pagination list** : `items` ≤ 10 000  

## Checks implémentés

1. **Connectivité réseau**  
 - Test initial TCP (timeout 5 s)  
2. **Récupération des types de menaces**  
 - Retry 3× (timeout 5 s)  
 - Déduplication des codes  
3. **Lecture et nettoyage du RAW email**  
 - `Get-Content -Raw -Encoding UTF8`  
 - Cast en `[string]` pour éviter métadonnées PS  
4. **Validation taille payload JSON**  
 - Calcul UTF-8 (≤ 150 000 octets)  
5. **Soumission robuste**  
 - `HttpWebRequest` POST `/submissions/add/email` (timeout 10 s)  
 - Retry 3×, délai progressif  
 - Gestion des codes HTTP 400, 401, 208, WebException  

## Structure du script

- **Test-Port** : vérifie TCP initial  
- **Get-ThreatTypes** : récupère et déduplique les codes  
- **Submit-Email** : soumission RAW email  
- **Get-SubmissionsCounter** : compteur 30 jours  
- **Get-SubmissionsList** : liste paginée  
- **Show-Menu** + boucle principale  

## Usage

1. Cloner le dépôt  
2. Définir `$API_TOKEN` dans le script  
3. Exécuter :  powershell.exe -ExecutionPolicy Bypass -File .\spamhaus_submission.ps1
4. Sélectionner l’option **1** pour soumettre un email, **2** pour le compteur, **3** pour la liste.  

---

Ce script se concentre exclusivement sur la **soumission RAW d’e-mails** et la consultation des résultats.  
