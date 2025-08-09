# spamhaus_submission.ps1
# Script PowerShell pour Spamhaus Submission Portal API
# Auteur: Skip75
# Documentation API : https://submit.spamhaus.org/api/

# Forcer TLS1.2 et désactiver Keep-Alive avant toute fonction
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::SetTcpKeepAlive($false, 0, 0)

# ─── Vérification unique de connectivité réseau avec timeout ────────────────
function Test-Port {
    param(
        [string]$Server,
        [int]   $Port,
        [int]   $TimeoutMs = 5000
    )
    $tcp   = New-Object System.Net.Sockets.TcpClient
    $async = $tcp.BeginConnect($Server, $Port, $null, $null)
    if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
        try { $tcp.EndConnect($async); $true }
        catch { $false }
        finally { $tcp.Close() }
    } else {
        $tcp.Close()
        $false
    }
}

Write-Host "Vérification de la connexion à submit.spamhaus.org:443 (timeout 5s) ..." -ForegroundColor Cyan
if (-not (Test-Port -Server 'submit.spamhaus.org' -Port 443 -TimeoutMs 5000)) {
    Write-Host "Erreur : impossible de joindre submit.spamhaus.org:443 en moins de 5s." -ForegroundColor Red
    Write-Host "Vérifiez votre réseau ou votre firewall." -ForegroundColor Yellow
    exit
}
Write-Host "Connexion établie en moins de 5s." -ForegroundColor Green
Start-Sleep -Seconds 1

# Configuration de l'API
$API_BASE_URL = "https://submit.spamhaus.org/portal/api/v1"
$API_TOKEN    = "API-KEY"

# Headers pour les requêtes API
$headers = @{
    "Authorization" = "Bearer $API_TOKEN"
    "Content-Type"  = "application/json"
}

function Show-Menu {
    Clear-Host
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host "  Spamhaus Submission Portal API" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Sélectionnez une option:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Soumettre un email malveillant" -ForegroundColor Green
    Write-Host "2. Obtenir le compteur de submissions (soumis dans les 30 derniers jours)" -ForegroundColor Green
    Write-Host "3. Obtenir la liste des submissions"   -ForegroundColor Green
    Write-Host "4. Quitter"                             -ForegroundColor Red
    Write-Host ""
    Write-Host -NoNewline "Votre choix (1-4): "          -ForegroundColor White
}

# Récupération robuste des types de menaces
function Get-ThreatTypes {
    $maxRetries = 3
    $attempt    = 0
    $url        = "$API_BASE_URL/lookup/threats-types"

    while ($attempt -lt $maxRetries) {
        $attempt++
        Write-Host "`nTentative $attempt/$maxRetries : récupération types de menaces (timeout 5s) ..." -ForegroundColor Yellow
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method           = "GET"
            $req.Timeout          = 5000
            $req.ReadWriteTimeout = 5000
            $req.KeepAlive        = $false
            $req.Headers.Add("Authorization", "Bearer $API_TOKEN")
            $req.ContentType      = "application/json"

            $resp   = $req.GetResponse()
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $json   = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()

            return $json | ConvertFrom-Json
        }
        catch [System.Net.WebException] {
            Write-Host "× Échec récupération menaces : $($_.Exception.Message)" -ForegroundColor Red
            if ($attempt -lt $maxRetries) { Start-Sleep -Seconds (2 * $attempt) }
        }
    }
    throw "Impossible de récupérer les types de menaces après $maxRetries tentatives."
}

function Submit-Email {
    Clear-Host
    Write-Host "Soumission d'email malveillant" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan

    # Récupération des types de menaces
    try {
        $rawTypes = Get-ThreatTypes
    } catch {
        Write-Host "Attention : impossible de récupérer les types, fallback vers 'source-of-spam'." -ForegroundColor Yellow
        $rawTypes = @(@{ code = "source-of-spam"; desc = "Source of spam" })
    }

    # Déduplication et menu...
    $threats = $rawTypes | Group-Object code | ForEach-Object { $_.Group[0] }

    Write-Host "`nTypes de menaces disponibles :" -ForegroundColor Yellow
    for ($i = 0; $i -lt $threats.Count; $i++) {
        Write-Host " $($i + 1). $($threats[$i].code) ($($threats[$i].desc))"
    }

    $sel = Read-Host "`nEntrez un numéro (1-$($threats.Count)) [défaut source-of-spam]"
    if ([string]::IsNullOrWhiteSpace($sel)) {
        $threatType = "source-of-spam"
    } else {
        $sel = $sel.Trim()
        [int]$intSel = 0
        while (-not ([int]::TryParse($sel, [ref]$intSel) -and $intSel -ge 1 -and $intSel -le $threats.Count)) {
            $sel = Read-Host "Saisie invalide. Entrez un numéro (1-$($threats.Count))"
            $sel = $sel.Trim()
        }
        $threatType = $threats[$intSel - 1].code
    }

    $emailPathRaw = Read-Host "`nChemin complet du fichier .eml"
    $emailPathRaw = $emailPathRaw.Trim('"')

    if (-not (Test-Path $emailPathRaw)) {
        Write-Host "`nFichier introuvable : $emailPathRaw" -ForegroundColor Red
        Write-Host "Voici tous les fichiers .eml présents dans le dossier :" -ForegroundColor Yellow
    
        $directory = Split-Path $emailPathRaw
        $emlFiles = Get-ChildItem -Path $directory -Filter "*.eml"
    
        if ($emlFiles.Count -eq 0) {
            Write-Host "Aucun fichier .eml trouvé dans le dossier." -ForegroundColor DarkYellow
            Pause
            return  # Retour au menu principal
        }

        # Afficher la liste numérotée
        for ($i = 0; $i -lt $emlFiles.Count; $i++) {
            Write-Host ("{0}. {1}" -f ($i+1), $emlFiles[$i].Name)
        }

        # Demande à l'utilisateur de choisir un fichier
        $choice = Read-Host "Entrez le numéro du fichier à utiliser, ou appuyez sur Entrée pour annuler"
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $emlFiles.Count) {
            $emailPathRaw = $emlFiles[[int]$choice - 1].FullName
            Write-Host "`nFichier sélectionné : $emailPathRaw" -ForegroundColor Green
        } else {
            Write-Host "Aucun fichier choisi, retour au menu." -ForegroundColor DarkYellow
            Pause
            return
        }
    }


    $emailContent = [string](Get-Content -Path $emailPathRaw -Raw -Encoding UTF8)
    if ([string]::IsNullOrWhiteSpace($emailContent)) {
        Write-Host "Erreur: email vide." -ForegroundColor Red
        Read-Host "Appuyez sur Entrée..."
        return
    }
    
    $reason = Read-Host "Raison (max 255 chars)"
    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "Email malveillant detecte" }

    $payload = @{
        threat_type = $threatType
        reason      = $reason
        source      = @{ object = $emailContent }
    } | ConvertTo-Json -Depth 3

    $sizeBytes = [System.Text.Encoding]::UTF8.GetByteCount($payload)
    if ($sizeBytes -gt 150000) {
        Write-Host "Erreur : payload >150Kb." -ForegroundColor Red
        Read-Host "Appuyez sur Entrée..."
        return
    }

    $maxRetries = 3; $attempt = 0; $success = $false
    while (-not $success -and $attempt -lt $maxRetries) {
        $attempt++
        Write-Host "`nTentative $attempt/$maxRetries : Soumission email (timeout 10s)..." -ForegroundColor Yellow
        try {
            $response = Invoke-WebRequest `
                -Uri "$API_BASE_URL/submissions/add/email" `
                -Method POST `
                -Headers $headers `
                -Body $payload `
                -TimeoutSec 10 `
                -UseBasicParsing

            $data = $response.Content | ConvertFrom-Json
            Write-Host "← Soumission réussie ! ID: $($data.id)" -ForegroundColor Green
            $success = $true
        }
        catch [System.Net.WebException] {
            Write-Host "× Erreur : $($_.Exception.Message)" -ForegroundColor Red
            if ($attempt -lt $maxRetries) {
                $delay = 5 * $attempt
                Write-Host "→ Nouvelle tentative dans $delay s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }
    }
    if (-not $success) {
        Write-Host "`nÉchec après $maxRetries tentatives." -ForegroundColor Red
    }
    Read-Host "`nAppuyez sur Entrée..."
}

function Get-SubmissionsCounter {
    Clear-Host
    Write-Host "Compteur des submissions (30 derniers jours)" -ForegroundColor Cyan
    $maxRetries = 3; $attempt = 0; $success = $false
    while (-not $success -and $attempt -lt $maxRetries) {
        $attempt++
        Write-Host "`nTentative $attempt/$maxRetries : récupération compteur (timeout 10s)..." -ForegroundColor Yellow
        try {
            $response = Invoke-WebRequest `
                -Uri "$API_BASE_URL/submissions/count" `
                -Method GET `
                -Headers $headers `
                -TimeoutSec 10 `
                -UseBasicParsing

            $data = $response.Content | ConvertFrom-Json
            Write-Host "← Réponse : Total $($data.total), Matched $($data.matched)" -ForegroundColor Green
            if ($data.total -gt 0) {
                $pct = [math]::Round(($data.matched/$data.total)*100,2)
                Write-Host "Correspondance: $pct%" -ForegroundColor Cyan
            }
            $success = $true
        }
        catch [System.Net.WebException] {
            Write-Host "× Erreur : $($_.Exception.Message)" -ForegroundColor Red
            if ($attempt -lt $maxRetries) {
                $delay = 5 * $attempt
                Write-Host "→ Nouvelle tentative dans $delay s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }
    }
    if (-not $success) {
        Write-Host "`nÉchec après $maxRetries tentatives." -ForegroundColor Red
    }
    Read-Host "`nAppuyez sur Entrée..."
}

function Get-SubmissionsList {
    Clear-Host
    Write-Host "Liste des submissions" -ForegroundColor Cyan
    $items = Read-Host "`nÉléments par page (1-10000, def=100)"
    if (-not ($items -as [int] -and $items -ge 1)) { $items = 100 }
    $page = Read-Host "Page (def=1)"
    if (-not ($page -as [int] -and $page -ge 1)) { $page = 1 }

    $maxRetries = 3; $attempt = 0; $success = $false
    while (-not $success -and $attempt -lt $maxRetries) {
        $attempt++
        Write-Host "`nTentative $attempt/$maxRetries : récupération liste (timeout 10s)..." -ForegroundColor Yellow
        try {
            $response = Invoke-WebRequest `
                -Uri "$API_BASE_URL/submissions/list?items=$items&page=$page" `
                -Method GET `
                -Headers $headers `
                -TimeoutSec 10 `
                -UseBasicParsing

            $list = $response.Content | ConvertFrom-Json
            if ($list.Count -eq 0) {
                Write-Host "Aucune submission trouvée." -ForegroundColor Yellow
            } else {
                Write-Host "`nSubmissions: $($list.Count)" -ForegroundColor Green
                foreach ($s in $list) {
                    Write-Host "ID: $($s.id) - Type: $($s.threat_type) - Date: $($s.submission_ts)"
                }
            }
            $success = $true
        }
        catch [System.Net.WebException] {
            Write-Host "× Erreur : $($_.Exception.Message)" -ForegroundColor Red
            if ($attempt -lt $maxRetries) {
                $delay = 5 * $attempt
                Write-Host "→ Nouvelle tentative dans $delay s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }
    }
    if (-not $success) {
        Write-Host "`nÉchec après $maxRetries tentatives." -ForegroundColor Red
    }
    Read-Host "`nAppuyez sur Entrée..."
}


# Boucle principale
do {
    Show-Menu
    $choice = Read-Host
    switch ($choice) {
        '1' { Submit-Email }
        '2' { Get-SubmissionsCounter }
        '3' { Get-SubmissionsList }
        '4' {
            Write-Host "`nSortie du Script" -ForegroundColor Green
            break
        }
        default {
            Write-Host "`nChoix invalide. Sélectionnez 1–4." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne '4')
