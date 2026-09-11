# ============================================================================
# spamhaus_submission.ps1 - Client CLI pour l'API Spamhaus Submission Portal
# Compatible Windows PowerShell 5.1 et PowerShell 7+ (aucun module tiers requis)
# Documentation officielle : https://submit.spamhaus.org/api/
# ============================================================================

#Requires -Version 5.1

# --- TLS : force TLS1.2 minimum sur Windows PowerShell 5.1 (PS7+ le gere seul) ---
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$API_BASE_URL = "https://submit.spamhaus.org/portal/api/v1"

# --- Recuperation du token : variable d'environnement en priorite, sinon saisie masquee ---
function Get-ApiToken {
    if ($env:SPAMHAUS_API_TOKEN) { return $env:SPAMHAUS_API_TOKEN }
    $secure = Read-Host "Entrez votre token API Spamhaus (cree sur https://auth.spamhaus.org/account)" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
$API_TOKEN = "TOKEN_API"
if ([string]::IsNullOrWhiteSpace($API_TOKEN)) {
    Write-Host "Aucun token fourni. Arret du script." -ForegroundColor Red
    exit 1
}
$Headers = @{ "Authorization" = "Bearer $API_TOKEN" }

# ============================================================================
# Coeur reseau : une seule fonction generique gere GET/POST, retries, erreurs
# Gestion explicite du 429 (rate limit) : respecte l'en-tete Retry-After si
# present, sinon backoff exponentiel. C'est indispensable des qu'on envoie
# plusieurs requetes a la suite (soumission par lot).
# ============================================================================
function Invoke-SpamhausApi {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('GET','POST')][string]$Method = 'GET',
        [string]$Body,
        [int]$TimeoutSec = 15,
        [int]$MaxRetries = 5
    )
    $uri = "$API_BASE_URL/$Path"
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{
                Uri            = $uri
                Method         = $Method
                Headers        = $Headers
                TimeoutSec     = $TimeoutSec
                ErrorAction    = 'Stop'
            }
            if ($Method -eq 'POST') {
                $params.ContentType = 'application/json; charset=utf-8'
                $params.Body        = $Body
            }
            # -UseBasicParsing n'existe plus (et n'est plus necessaire) en PS6+
            if ($PSVersionTable.PSVersion.Major -lt 6) { $params.UseBasicParsing = $true }

            return Invoke-RestMethod @params
        }
        catch {
            $resp = $_.Exception.Response
            $status = $null
            $bodyMsg = $null
            $retryAfter = $null
            if ($resp) {
                $status = [int]$resp.StatusCode
                # PS7+ : le corps est deja accessible via $_.ErrorDetails.Message
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    $bodyMsg = $_.ErrorDetails.Message
                }
                elseif ($resp.GetResponseStream) {
                    try {
                        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                        $bodyMsg = $sr.ReadToEnd(); $sr.Close()
                    } catch {}
                }
                try {
                    if ($resp.Headers -and $resp.Headers['Retry-After']) {
                        [int]::TryParse($resp.Headers['Retry-After'], [ref]$retryAfter) | Out-Null
                    }
                } catch {}
            }
            $parsed = $null
            if ($bodyMsg) { try { $parsed = $bodyMsg | ConvertFrom-Json } catch {} }

            switch ($status) {
                400 { $msg400 = if ($parsed -and $parsed.message) { $parsed.message } elseif ($bodyMsg) { $bodyMsg } else { $_.Exception.Message }
                throw "Erreur 400 (requete invalide) : $msg400" }
                401 { $msg401 = if ($parsed -and $parsed.message) { $parsed.message } else { 'user is not authorized' }
        throw "Erreur 401 : token invalide ou expire ($msg401)." }
                208 { return $parsed } # soumission deja signalee : pas une erreur bloquante
                429 {
                    if ($attempt -ge $MaxRetries) {
                        throw "Echec apres $MaxRetries tentatives (HTTP 429 - limite de debit atteinte)."
                    }
                    $delay = if ($retryAfter) { $retryAfter } else { [Math]::Min(60, [Math]::Pow(2, $attempt) * 2) }
                    Write-Host "  Limite de debit atteinte (HTTP 429). Pause de ${delay}s avant nouvel essai ($attempt/$MaxRetries)..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $delay
                }
                default {
                    if ($attempt -ge $MaxRetries) {
                        throw "Echec apres $MaxRetries tentatives (HTTP $status) : $($_.Exception.Message)"
                    }
                    $delay = 3 * $attempt
                    Write-Host "  Tentative $attempt/$MaxRetries echouee (HTTP $status). Nouvel essai dans ${delay}s..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $delay
                }
            }
        }
    }
}

# ============================================================================
# Selection interactive d'un threat_type filtre par categorie ("ip","domain","email")
# ============================================================================
function Select-ThreatType {
    param(
        [Parameter(Mandatory)][ValidateSet('ip','domain','email')][string]$Category,
        [string]$DefaultCode = 'source-of-spam'
    )
    $types = $null
    try {
        $raw = Invoke-SpamhausApi -Path 'lookup/threats-types' -Method GET
        $types = $raw | Where-Object { $_.type -eq $Category -or $_.type -eq '*' }
    } catch {
        Write-Host "Impossible de recuperer les types de menaces ($($_.Exception.Message)). Fallback : $DefaultCode" -ForegroundColor Yellow
    }
    if (-not $types -or $types.Count -eq 0) { return $DefaultCode }

    Write-Host "`nTypes de menaces disponibles ($Category) :" -ForegroundColor Yellow
    for ($i = 0; $i -lt $types.Count; $i++) { Write-Host " $($i+1). $($types[$i].code) - $($types[$i].desc)" }

    $defaultIndex = [Array]::FindIndex($types, [Predicate[object]]{ param($t) $t.code -eq $DefaultCode })
    if ($defaultIndex -lt 0) { $defaultIndex = 0 }

    $sel = Read-Host "Numero (1-$($types.Count)) [defaut $($defaultIndex+1). $($types[$defaultIndex].code)]"
    if ([string]::IsNullOrWhiteSpace($sel)) { return $types[$defaultIndex].code }
    [int]$idx = 0
    while (-not ([int]::TryParse($sel.Trim(), [ref]$idx) -and $idx -ge 1 -and $idx -le $types.Count)) {
        $sel = Read-Host "Saisie invalide. Numero (1-$($types.Count))"
    }
    return $types[$idx - 1].code
}

function Read-Reason {
    param([string]$Default)
    $r = Read-Host "Raison (max 255 caracteres) [defaut: $Default]"
    if ([string]::IsNullOrWhiteSpace($r)) { $r = $Default }
    return $r.Substring(0, [Math]::Min(255, $r.Length))
}

# ============================================================================
# Lecture securisee d'un fichier .eml : controle taille + encodage
# Renvoie $null (et affiche le motif) si le fichier doit etre ignore.
# ============================================================================
function Get-EmailRawContent {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "  [IGNORE] Fichier introuvable : $Path" -ForegroundColor Red
        return $null
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) {
        Write-Host "  [IGNORE] Fichier vide : $Path" -ForegroundColor Red
        return $null
    }
    if ($bytes.Length -gt 150000) {
        Write-Host "  [IGNORE] $($bytes.Length) octets > limite API (150000) : $Path" -ForegroundColor Red
        return $null
    }
    try { return [Text.Encoding]::UTF8.GetString($bytes) }
    catch { return [Text.Encoding]::GetEncoding('ISO-8859-1').GetString($bytes) }
}

# ============================================================================
# 1. Soumission d'email(s) malveillant(s) - SELECTION MULTIPLE
#
# Principe : on choisit d'abord la categorie de menace (threat_type, ex: spam
# vs phishing) UNE SEULE FOIS pour le lot, puis on ouvre la fenetre Windows de
# selection de fichiers en mode multi-selection (Ctrl/Shift-clic) pour choisir
# tous les .eml a soumettre dans cette categorie, avec la meme reason pour
# tout le lot. Chaque email reste envoye par un appel API distinct (l'API
# Spamhaus n'expose pas d'endpoint "bulk" qui accepterait plusieurs
# source.object en une requete - cf. documentation officielle
# https://submit.spamhaus.org/api/), mais la boucle gere le rythme d'envoi,
# les erreurs 429 (rate limit) et produit un recapitulatif final. Pour un
# second lot avec une categorie et/ou une reason differente (ex: 2 phishing
# restants sur 5), on rappelle simplement le menu option 1 : chaque appel de
# Submit-Email est independant.
#
# Format attendu par l'API : source.object = CONTENU BRUT (raw) de l'email
# (voir doc officielle : "source.object source RAW email content").
# ConvertTo-Json echappe nativement guillemets, retours ligne et caracteres
# de controle -> aucun encodage Base64 n'est requis ni documente par Spamhaus.
# ============================================================================
function Submit-Email {
    Clear-Host
    Write-Host "=== Soumission d'un ou plusieurs emails malveillants ===" -ForegroundColor Cyan

    # 1) Categorie de menace choisie UNE FOIS pour tout le lot (spam, phishing, ...)
    $threatType = Select-ThreatType -Category 'email' -DefaultCode 'source-of-spam'
    $reason = Read-Reason -Default 'phishing/impersonation email'

    # 2) Selection multiple des fichiers via la fenetre Windows standard
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Fichiers email (*.eml)|*.eml|Tous les fichiers (*.*)|*.*"
    $dialog.Title = "Selectionnez un ou plusieurs emails a soumettre (Ctrl+clic / Shift+clic pour multi-selection) - categorie : $threatType"
    $dialog.Multiselect = $true
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK -or $dialog.FileNames.Count -eq 0) {
        Write-Host "Aucun fichier selectionne." -ForegroundColor Yellow; Pause; return
    }
    $files = $dialog.FileNames
    Write-Host "`n$($files.Count) fichier(s) selectionne(s) pour la categorie '$threatType'." -ForegroundColor Magenta

    # 3) Delai de pacage entre 2 envois pour eviter le HTTP 429 (rate limit non
    #    publie officiellement par Spamhaus pour cet endpoint : valeur prudente,
    #    ajustable si vous obtenez des 429 malgre tout).
    $DelayBetweenCallsSec = 2

    $results = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($path in $files) {
        $index++
        $fileName = Split-Path -Leaf $path
        Write-Progress -Activity "Soumission des emails ($threatType)" -Status "$fileName ($index/$($files.Count))" -PercentComplete (($index-1)/$files.Count*100)
        Write-Host "`n[$index/$($files.Count)] $fileName" -ForegroundColor Yellow

        $rawContent = Get-EmailRawContent -Path $path
        if ($null -eq $rawContent) {
            $results.Add([PSCustomObject]@{ Fichier = $fileName; Statut = 'IGNORE'; Detail = 'Fichier invalide, vide ou trop volumineux' })
            continue
        }

        $payload = @{ threat_type = $threatType; reason = $reason; source = @{ object = $rawContent } } | ConvertTo-Json -Depth 5 -Compress
        try {
            $data = Invoke-SpamhausApi -Path 'submissions/add/email' -Method POST -Body $payload
            $subId = if ($data -and $data.id) { $data.id } else { '-' }
            Write-Host "  OK - ID de soumission : $subId" -ForegroundColor Green
            $results.Add([PSCustomObject]@{ Fichier = $fileName; Statut = 'OK'; Detail = "ID: $subId" })
        }
        catch {
            Write-Host "  ECHEC - $($_.Exception.Message)" -ForegroundColor Red
            $results.Add([PSCustomObject]@{ Fichier = $fileName; Statut = 'ECHEC'; Detail = $_.Exception.Message })
        }

        if ($index -lt $files.Count) { Start-Sleep -Seconds $DelayBetweenCallsSec }
    }
    Write-Progress -Activity "Soumission des emails ($threatType)" -Completed

    Write-Host "`n=== Recapitulatif ($threatType) ===" -ForegroundColor Cyan
    $results | Format-Table -AutoSize | Out-Host
    $ok = ($results | Where-Object Statut -eq 'OK').Count
    $ko = ($results | Where-Object Statut -eq 'ECHEC').Count
    $skip = ($results | Where-Object Statut -eq 'IGNORE').Count
    Write-Host "Total : $($results.Count) | OK : $ok | Echecs : $ko | Ignores : $skip" -ForegroundColor Cyan
    Pause
}

# ============================================================================
# 2. Soumission de domaine malveillant
# ============================================================================
function Submit-Domain {
    Clear-Host
    Write-Host "=== Soumission d'un domaine malveillant ===" -ForegroundColor Cyan

    $domainRaw = Read-Host "Nom de domaine (ex: baddomain.com)"
    $domain = ($domainRaw -replace '^https?://', '' -replace '/.*$', '' -replace '^www\.', '').Trim().ToLowerInvariant()
    if ($domain -notmatch '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$') {
        Write-Host "Format de domaine invalide (pas de chemin, pas de protocole)." -ForegroundColor Red; Pause; return
    }
    if ($domain -ne $domainRaw.Trim()) {
        Write-Host "Domaine nettoye/normalise : $domain" -ForegroundColor Cyan
    }
    Write-Host "Domaine soumis : $domain" -ForegroundColor Magenta

    $threatType = Select-ThreatType -Category 'domain' -DefaultCode 'source-of-spam'
    $reason = Read-Reason -Default "$threatType domain detected"
    $payload = @{ threat_type = $threatType; reason = $reason; source = @{ object = $domain } } | ConvertTo-Json -Compress

    Write-Host "`nEnvoi en cours..." -ForegroundColor Yellow
    try {
        $data = Invoke-SpamhausApi -Path 'submissions/add/domain' -Method POST -Body $payload
        Write-Host "OK - ID de soumission : $($data.id)" -ForegroundColor Green
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
    Pause
}

# ============================================================================
# 3. Soumission d'IP malveillante (IPv4)
# ============================================================================
function Submit-IP {
    Clear-Host
    Write-Host "=== Soumission d'une IP malveillante ===" -ForegroundColor Cyan

    $ipRaw = Read-Host "Adresse IPv4 a signaler"
    $ip = $ipRaw.Trim()
    $parsedIp = $null
    if (-not ([Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) -or $parsedIp.AddressFamily -ne 'InterNetwork') {
        Write-Host "Adresse IPv4 invalide." -ForegroundColor Red; Pause; return
    }
    $ip = $parsedIp.ToString()
    if ($ip -ne $ipRaw.Trim()) {
        Write-Host "IP nettoyee/normalisee : $ip" -ForegroundColor Cyan
    }
    Write-Host "IP soumise : $ip" -ForegroundColor Magenta

    $threatType = Select-ThreatType -Category 'ip' -DefaultCode 'source-of-spam'
    $reason = Read-Reason -Default 'sending spoofed emails'
    $payload = @{ threat_type = $threatType; reason = $reason; source = @{ object = $ip } } | ConvertTo-Json -Compress

    Write-Host "`nEnvoi en cours..." -ForegroundColor Yellow
    try {
        $data = Invoke-SpamhausApi -Path 'submissions/add/ip' -Method POST -Body $payload
        Write-Host "OK - ID de soumission : $($data.id)" -ForegroundColor Green
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
    Pause
}

# ============================================================================
# 4. Compteur de submissions (fenetre fixe de 30 jours imposee par l'API)
# ============================================================================
function Get-SubmissionsCounter {
    Clear-Host
    Write-Host "=== Compteur de submissions (30 derniers jours) ===" -ForegroundColor Cyan
    try {
        $data = Invoke-SpamhausApi -Path 'submissions/count' -Method GET
        Write-Host "Total envoyees : $($data.total)" -ForegroundColor Green
        Write-Host "Trouvees dans un dataset (matched) : $($data.matched)" -ForegroundColor Green
        if ($data.total -gt 0) {
            Write-Host "Taux de correspondance : $([Math]::Round(($data.matched/$data.total)*100,2)) %" -ForegroundColor Cyan
        }
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
    Pause
}

# ============================================================================
# 5. Liste des submissions avec statut (limitee aux 30 derniers jours par l'API)
# ============================================================================
function Get-SubmissionsList {
    Clear-Host
    Write-Host "=== Liste des submissions ===" -ForegroundColor Cyan

    [int]$items = 0
    if (-not [int]::TryParse((Read-Host "Elements par page (1-10000) [def=100]"), [ref]$items) -or $items -lt 1 -or $items -gt 10000) { $items = 100 }
    [int]$page = 0
    if (-not [int]::TryParse((Read-Host "Page [def=1]"), [ref]$page) -or $page -lt 1) { $page = 1 }

    try {
        $list = Invoke-SpamhausApi -Path "submissions/list?items=$items&page=$page" -Method GET
        if (-not $list -or $list.Count -eq 0) {
            Write-Host "Aucune submission trouvee." -ForegroundColor Yellow
        } else {
            $rows = foreach ($s in $list) {
                $obj = switch ($s.submission_type) {
                    'ip'     { $mask = if ($s.attributes.mask) { "/$($s.attributes.mask)" } else { '' }; "$($s.attributes.address)$mask" }
                    'domain' { $s.attributes.domain }
                    'email'  { if ($s.attributes.subject) { "Subject: $($s.attributes.subject)" } else { "Reason: $($s.reason)" } }
                    default  { $s.source.object }
                }
                $listed = if ($null -eq $s.listed) { 'Pending' } elseif ($s.listed.Count -eq 0) { 'No' } else { "Yes ($($s.listed -join ', '))" }
                [PSCustomObject]@{
                    Date       = ([DateTime]$s.submission_ts).ToString('yyyy-MM-dd HH:mm')
                    Type       = $s.submission_type
                    Objet      = if ($obj.Length -gt 50) { $obj.Substring(0,47) + '...' } else { $obj }
                    ThreatType = $s.threat_type
                    Statut     = $listed
                    DernierCheck = if ($s.last_check) { ([DateTime]$s.last_check).ToString('yyyy-MM-dd HH:mm') } else { '-' }
                }
            }
            $rows | Format-Table -AutoSize | Out-Host
            Write-Host "Total affiche : $($list.Count)" -ForegroundColor Green
        }
    } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
    Pause
}

# ============================================================================
# Menu principal
# ============================================================================
function Show-Menu {
    Clear-Host
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "  Spamhaus Submission Portal API" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "1. Soumettre un ou plusieurs email(s) malveillant(s)" -ForegroundColor Green
    Write-Host "2. Soumettre un domaine malveillant" -ForegroundColor Green
    Write-Host "3. Soumettre une IP malveillante"    -ForegroundColor Green
    Write-Host "4. Compteur de submissions (30j)"    -ForegroundColor Green
    Write-Host "5. Liste des submissions"            -ForegroundColor Green
    Write-Host "6. Quitter"                          -ForegroundColor Red
}

do {
    Show-Menu
    $choice = Read-Host "`nVotre choix (1-6)"
    switch ($choice) {
        '1' { Submit-Email }
        '2' { Submit-Domain }
        '3' { Submit-IP }
        '4' { Get-SubmissionsCounter }
        '5' { Get-SubmissionsList }
        '6' { Write-Host "Sortie du script." -ForegroundColor Green }
        default { Write-Host "Choix invalide." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
} while ($choice -ne '6')
