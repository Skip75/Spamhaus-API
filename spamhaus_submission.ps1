# spamhaus_submission.ps1
# Script PowerShell pour Spamhaus Submission Portal API
# Auteur: Skip75
# Documentation API : https://submit.spamhaus.org/api/

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
$API_TOKEN    = "API KEY TO EDIT"

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

    # Déduplication des codes (conserver le premier desc rencontré pour chaque code)
    $threats = $rawTypes |
        Group-Object -Property code |
        ForEach-Object { $_.Group[0] }

    # Optionnel : forcer 'source-of-spam' en début de liste si non présent
    if (-not ($threats.code -contains "source-of-spam")) {
        $threats = ,@{ code = "source-of-spam"; desc = "Source of spam" } + $threats
    }

    # Affichage du menu
    Write-Host "`nTypes de menaces disponibles :" -ForegroundColor Yellow
    for ($i = 0; $i -lt $threats.Count; $i++) {
        Write-Host " $($i+1). $($threats[$i].code) ($($threats[$i].desc))"
    }

    # Lecture de la sélection avec fallback sur source-of-spam
    $sel = Read-Host "`nEntrez un numéro (1-$($threats.Count)) [défaut source-of-spam]"
    if ([string]::IsNullOrWhiteSpace($sel)) {
        $threatType = "source-of-spam"
    } else {
        while (-not ($sel -as [int] -and $sel -ge 1 -and $sel -le $threats.Count)) {
            $sel = Read-Host "Saisie invalide. Entrez un numéro (1-$($threats.Count))"
        }
        $threatType = $threats[$sel - 1].code
    }

    # Chemin du fichier email
    $emailPathRaw = Read-Host "`nVeuillez entrer le chemin complet vers le fichier email"
    if (-not (Test-Path $emailPathRaw)) {
        Write-Host "Erreur: Le fichier spécifié n'existe pas." -ForegroundColor Red
        Read-Host "Appuyez sur Entrée pour continuer..."
        return
    }

    # Lecture et nettoyage du contenu brut
    $contentRaw = Get-Content -Path $emailPathRaw -Raw -Encoding UTF8
    $emailContent = [string]$contentRaw
    if ([string]::IsNullOrWhiteSpace($emailContent)) {
        Write-Host "Erreur: Le fichier email est vide." -ForegroundColor Red
        Read-Host "Appuyez sur Entrée pour continuer..."
        return
    }

    # Raison
    $reason = Read-Host "Entrez la raison de la soumission (max 255 caractères)"
    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = "Email malveillant detecte" }

    $maxRetries = 3
    $attempt    = 0
    $success    = $false

    while (-not $success -and $attempt -lt $maxRetries) {
        $attempt++
        Write-Host "`nTentative $attempt/$maxRetries : Soumission email via API (timeout 10s)..." -ForegroundColor Yellow

        try {
            # Préparer payload
            $payloadObj = [PSCustomObject]@{
                threat_type = $threatType
                reason      = $reason
                source      = @{ object = $emailContent }
            }
            $payloadJson = $payloadObj | ConvertTo-Json -Depth 3
            # Calcul de la taille en octets du JSON car limité par spamhaus
            $sizeBytes = [System.Text.Encoding]::UTF8.GetByteCount($payloadJson)
            Write-Host "`n[CHECK] Taille du payload : $sizeBytes octets" -ForegroundColor DarkGray

            if ($sizeBytes -gt 150000) {
                Write-Host "Erreur : le contenu brut de l'email dépasse 150 Kb et ne peut pas être soumis." -ForegroundColor Red
                Read-Host "`nAppuyez sur Entrée pour continuer..."
                return
            }

            # DEBUG : afficher le JSON envoyé
            #Write-Host "`n[DEBUG] Payload JSON :" -ForegroundColor DarkGray
            #Write-Host $payloadJson -ForegroundColor DarkGray

            # Création et envoi de la requête
            $url = "$API_BASE_URL/submissions/add/email"
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method            = "POST"
            $req.Timeout           = 10000
            $req.ReadWriteTimeout  = 10000
            $req.KeepAlive         = $false
            $req.AllowAutoRedirect = $false
            $req.Headers.Add("Authorization", "Bearer $API_TOKEN")
            $req.ContentType       = "application/json"
            $bytes                 = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
            $req.ContentLength     = $bytes.Length

            $streamReq = $req.GetRequestStream()
            $streamReq.Write($bytes, 0, $bytes.Length)
            $streamReq.Close()

            # Lecture de la réponse
            $resp   = $req.GetResponse()
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $json   = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()

            Write-Host "← Réponse reçue" -ForegroundColor Green
            $data = $json | ConvertFrom-Json

            Write-Host "`nSoumission réussie!"                       -ForegroundColor Green
            Write-Host "ID de soumission : $($data.id)"              -ForegroundColor White
            Write-Host "Type de menace   : $($data.threat_type)"      -ForegroundColor White
            Write-Host "Raison           : $($data.reason)"           -ForegroundColor White

            $success = $true
        }
        catch [System.Net.WebException] {
            Write-Host "× Échec (timeout ou réseau) : $($_.Exception.Message)" -ForegroundColor Red
            if ($attempt -lt $maxRetries) {
                $delay = 5 * $attempt
                Write-Host "→ Nouvelle tentative dans $delay secondes..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }
    }

    if (-not $success) {
        Write-Host "`nErreur critique : impossible de soumettre après $maxRetries tentatives." -ForegroundColor Red
    }

    Read-Host "`nAppuyez sur Entrée pour continuer..."
}

function Get-SubmissionsCounter {
    Clear-Host
    Write-Host "Compteur des submissions (soumis dans les 30 derniers jours)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $maxRetries = 3
    $attempt    = 0
    $success    = $false

    while (-not $success -and $attempt -lt $maxRetries) {
        $attempt++
        Write-Host "`nTentative $attempt/$maxRetries : Envoi requête API submissions/count (timeout 10s) ..." -ForegroundColor Yellow

        try {
            # Création de la requête HttpWebRequest
            $url = "$API_BASE_URL/submissions/count"
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method            = "GET"
            $req.Timeout           = 10000
            $req.ReadWriteTimeout  = 10000
            $req.KeepAlive         = $false
            $req.AllowAutoRedirect = $false
            $req.Headers.Add("Authorization", "Bearer $API_TOKEN")
            $req.ContentType       = "application/json"

            # Lecture de la réponse
            $resp   = $req.GetResponse()
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $json   = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()

            Write-Host "← Réponse reçue" -ForegroundColor Green
            $data = $json | ConvertFrom-Json

            Write-Host "`nTotal des submissions : $($data.total)"  -ForegroundColor White
            Write-Host "Trouvées dans datasets : $($data.matched)"  -ForegroundColor White
            if ($data.total -gt 0) {
                $pct = [math]::Round(($data.matched / $data.total) * 100, 2)
                Write-Host "Pourcentage de correspondances: $pct%"   -ForegroundColor Cyan
            }

            $success = $true
        }
        catch [System.Net.WebException] {
            Write-Host "× Échec (timeout ou réseau) : $($_.Exception.Message)" -ForegroundColor Red
            if ($attempt -lt $maxRetries) {
                $delay = 5 * $attempt
                Write-Host "→ Nouvelle tentative dans $delay secondes..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }
    }

    if (-not $success) {
        Write-Host "`nErreur critique : impossible de récupérer le compteur après $maxRetries tentatives." -ForegroundColor Red
    }

    Read-Host "`nAppuyez sur Entrée pour continuer..."
}

function Get-SubmissionsList {
    Clear-Host
    Write-Host "Liste des submissions" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan

    $items = Read-Host "`nNombre d'éléments par page (défaut 100, max 10000)"
    if (-not ($items -as [int] -and $items -ge 1)) { $items = 100 }
    $page  = Read-Host "Numéro de page (défaut 1)"
    if (-not ($page -as [int] -and $page -ge 1))  { $page = 1 }

    $maxRetries = 3
    $attempt    = 0
    $success    = $false

    while (-not $success -and $attempt -lt $maxRetries) {
        $attempt++
        Write-Host "`nTentative $attempt/$maxRetries : Envoi requête API submissions/list (timeout 10s) ..." -ForegroundColor Yellow

        try {
            # Création de la requête HttpWebRequest
            $url = "$API_BASE_URL/submissions/list?items=$items&page=$page"
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method            = "GET"
            $req.Timeout           = 10000
            $req.ReadWriteTimeout  = 10000
            $req.KeepAlive         = $false
            $req.AllowAutoRedirect = $false
            $req.Headers.Add("Authorization", "Bearer $API_TOKEN")
            $req.ContentType       = "application/json"

            # Lecture de la réponse
            $resp   = $req.GetResponse()
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $json   = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()

            Write-Host "← Réponse reçue" -ForegroundColor Green
            $list = $json | ConvertFrom-Json

            if ($list.Count -eq 0) {
                Write-Host "`nAucune submission trouvée." -ForegroundColor Yellow
            } else {
                Write-Host "`nSubmissions récupérées: $($list.Count)" -ForegroundColor Green
                Write-Host ("=" * 80) -ForegroundColor Gray

                foreach ($s in $list) {
                    Write-Host "`nID            : $($s.id)"                    -ForegroundColor White
                    Write-Host "Type          : $($s.submission_type)"       -ForegroundColor Cyan
                    Write-Host "Type menace   : $($s.threat_type)"           -ForegroundColor Yellow
                    Write-Host "Raison        : $($s.reason)"                -ForegroundColor White
                    Write-Host "Date soumis   : $($s.submission_ts)"        -ForegroundColor Gray
                    if ($s.listed) {
                        Write-Host "Datasets trouvés : $($s.listed -join ', ')" -ForegroundColor Green
                        Write-Host "Dernière vérif   : $($s.last_check)"      -ForegroundColor Gray
                    } else {
                        Write-Host "Statut        : En attente / non trouvé"   -ForegroundColor Yellow
                    }
                    if ($s.attributes) {
                        Write-Host "Attributs :" -ForegroundColor Cyan
                        $s.attributes.PSObject.Properties | ForEach-Object {
                            Write-Host "  $_.Name : $_.Value" -ForegroundColor White
                        }
                    }
                    Write-Host ("-" * 80) -ForegroundColor Gray
                }
            }

            $success = $true
        }
        catch [System.Net.WebException] {
            Write-Host "× Échec (timeout ou réseau) : $($_.Exception.Message)" -ForegroundColor Red
            if ($attempt -lt $maxRetries) {
                $delay = 5 * $attempt
                Write-Host "→ Nouvelle tentative dans $delay secondes..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
        }
    }

    if (-not $success) {
        Write-Host "`nErreur critique : impossible de récupérer la liste après $maxRetries tentatives." -ForegroundColor Red
    }

    Read-Host "`nAppuyez sur Entrée pour continuer..."
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
            Write-Host "`nAu revoir!" -ForegroundColor Green
            break
        }
        default {
            Write-Host "`nChoix invalide. Sélectionnez 1–4." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne '4')
