#Requires -Version 5.1
<#
.SYNOPSIS
    CSCA sertifikalarindaki CRL Distribution Points URL'lerinden
    CRL dosyalarini indirip ulke bazli klasorlere kaydeder.

.DESCRIPTION
    src\VerifyBlind.Enclave\Certificates\CSCA\{UlkeKodu}\*.crt dosyalarini tarar,
    her sertifikanin CRL Distribution Points uzantisindaki URL'leri toplar,
    ayni URL'yi tekrar indirmemek icin deduplikasyon yapar ve
    CRL dosyalarini Certificates\CRL\{UlkeKodu}\ altina kaydeder.

    extract_csca.ps1 ile birlikte veya bagimsiz olarak calistirilabilir.
    CRL'ler sertifikalardan daha sik degistigi icin (haftalik/aylik)
    bu scriptin periyodik olarak calistirilmasi onerilir.

.PARAMETER CscaDir
    CSCA sertifikalarinin bulundugu ust dizin.
    Belirtilmezse projenin Certificates\CSCA dizini kullanilir.

.PARAMETER OutputBase
    CRL dosyalarinin kaydedilecegi ust dizin.
    Belirtilmezse projenin Certificates\CRL dizini kullanilir.

.PARAMETER TimeoutSec
    Her CRL indirme istegi icin zaman asimi (saniye). Varsayilan: 30

.EXAMPLE
    .\download-crl.ps1
    .\download-crl.ps1 -CscaDir "C:\certs\CSCA" -OutputBase "C:\certs\CRL"
#>
param(
    [string]$CscaDir    = "",
    [string]$OutputBase = "",
    [int]$TimeoutSec    = 30
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Yollar
# ---------------------------------------------------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# openssl cozumleme: once script'in yanindaki tasinabilir kopya (Windows gelistirme
# makinesi), yoksa PATH'teki sistem openssl'i (GitHub Actions ubuntu runner).
$opensslCandidates = @(
    (Join-Path $scriptDir "openssl.exe"),                 # yaninda tasinabilir kopya varsa
    ((Get-Command openssl -ErrorAction SilentlyContinue).Source),  # PATH (CI runner)
    "C:\Program Files\Git\usr\bin\openssl.exe"            # Git for Windows ile gelir; PATH'te DEGILDIR
)
$openssl = $opensslCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $openssl) {
    Write-Error "openssl bulunamadi. Denenen yerler: $($opensslCandidates -ne $null -join ', ')"
    exit 1
}
Write-Host "openssl     : $openssl"

# Script enclave repo'sunun scripts/ dizininde yasar; sertifikalar bir ust seviyede.
# Join-Path kullaniliyor -> ayirici hem Windows'ta hem Linux'ta dogru olur.
$repoRoot = Split-Path -Parent $scriptDir
if (-not $CscaDir)    { $CscaDir    = Join-Path (Join-Path $repoRoot "Certificates") "CSCA" }
if (-not $OutputBase) { $OutputBase = Join-Path (Join-Path $repoRoot "Certificates") "CRL"  }

if (-not (Test-Path $CscaDir)) {
    Write-Error "CSCA dizini bulunamadi: $CscaDir"
    exit 1
}

Write-Host "CSCA dizini : $CscaDir"
Write-Host "CRL dizini  : $OutputBase"
Write-Host "Timeout     : ${TimeoutSec}s"
Write-Host ""

# ---------------------------------------------------------------------------
# Adim 1: Tum sertifikalardan CRL URL'lerini topla (ulke bazli, deduplike)
# ---------------------------------------------------------------------------
Write-Host "Sertifikalardan CRL Distribution Points okunuyor..."

# { URL -> UlkeKodu[] } eslestirmesi — ayni URL birden fazla ulkede olabilir
$urlToCountries = @{}
# { UlkeKodu -> URL[] } eslestirmesi
$countryToUrls  = @{}

$countryDirs = Get-ChildItem $CscaDir -Directory | Sort-Object Name
$totalCerts  = 0
$certsWithCrl = 0

$prevErrorPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"

foreach ($dir in $countryDirs) {
    $country = $dir.Name
    $crts    = Get-ChildItem $dir.FullName -Filter "*.crt" -File -ErrorAction SilentlyContinue

    foreach ($crt in $crts) {
        $totalCerts++

        # CRL Distribution Points cikart
        $textOut = & $openssl x509 -in $crt.FullName -inform DER -text -noout 2>&1
        if ($LASTEXITCODE -ne 0) { continue }

        # URI satirlarini bul (CRL Distribution Points blogu icinde)
        $inCrlBlock = $false
        $urls = @()

        foreach ($line in $textOut) {
            $trimmed = "$line".Trim()

            if ($trimmed -match "CRL Distribution Points") {
                $inCrlBlock = $true
                continue
            }

            if ($inCrlBlock) {
                if ($trimmed -match "^URI:(.+)$") {
                    $url = $Matches[1].Trim()
                    # ldap:// ve bos/eksik URL'leri atla — sadece http(s) indirilebilir
                    if ($url -match "^https?://.{5,}") {
                        $urls += $url
                    }
                }
                # Baska bir X509v3 uzantisina gecince blogu kapat
                elseif ($trimmed -match "^X509v3 " -or $trimmed -match "^Signature Algorithm") {
                    $inCrlBlock = $false
                }
            }
        }

        if ($urls.Count -gt 0) {
            $certsWithCrl++
            foreach ($url in $urls) {
                if (-not $urlToCountries.ContainsKey($url)) {
                    $urlToCountries[$url] = @()
                }
                if ($urlToCountries[$url] -notcontains $country) {
                    $urlToCountries[$url] += $country
                }

                if (-not $countryToUrls.ContainsKey($country)) {
                    $countryToUrls[$country] = @()
                }
                if ($countryToUrls[$country] -notcontains $url) {
                    $countryToUrls[$country] += $url
                }
            }
        }
    }
}

$uniqueUrls = $urlToCountries.Keys.Count
Write-Host ""
Write-Host "Tarama tamamlandi:"
Write-Host "  Toplam sertifika      : $totalCerts"
Write-Host "  CRL URL'si olan       : $certsWithCrl"
Write-Host "  Benzersiz CRL URL'si  : $uniqueUrls"
Write-Host "  CRL olan ulke sayisi  : $($countryToUrls.Count)"
Write-Host ""

$ErrorActionPreference = $prevErrorPref

if ($uniqueUrls -eq 0) {
    Write-Host "Indirilecek CRL bulunamadi."
    exit 0
}

# ---------------------------------------------------------------------------
# Adim 2: CRL dosyalarini indir
# ---------------------------------------------------------------------------
Write-Host "CRL dosyalari indiriliyor..."
Write-Host ""

if (-not (Test-Path $OutputBase)) {
    New-Item -ItemType Directory -Path $OutputBase -Force | Out-Null
}

$downloaded  = 0
$failed      = 0
$skipped     = 0
$failedUrls  = @()
$current     = 0

# TLS 1.2 desteğini aktif et
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

foreach ($entry in $urlToCountries.GetEnumerator() | Sort-Object { $_.Value[0] }) {
    $url       = $entry.Key
    $countries = $entry.Value
    $current++

    # Dosya adi: URL'nin son kismini kullan, yoksa hash
    $urlUri = $null
    try { $urlUri = [System.Uri]::new($url) } catch {}

    if ($urlUri -and $urlUri.Segments.Count -gt 0) {
        $fileName = $urlUri.Segments[-1].TrimEnd('/')
        # Uzanti yoksa ekle
        if ($fileName -notmatch '\.crl$') {
            $fileName = "$fileName.crl"
        }
    }
    else {
        # URL parse edilemezse SHA256 hash kullan
        $hash = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($url))
        $fileName = ([BitConverter]::ToString($hashBytes) -replace "-","").Substring(0,16) + ".crl"
    }

    # Her ilgili ulke icin klasor olustur ve dosya yolunu belirle
    $targetPaths = @()
    foreach ($c in $countries) {
        $countryDir = Join-Path $OutputBase $c
        if (-not (Test-Path $countryDir)) {
            New-Item -ItemType Directory -Path $countryDir -Force | Out-Null
        }
        $targetPaths += Join-Path $countryDir $fileName
    }

    # Progress
    Write-Progress -Activity "CRL indiriliyor" `
        -Status "[$current/$uniqueUrls] $($countries -join ',') - $fileName" `
        -PercentComplete ([math]::Min(99, $current * 100 / $uniqueUrls))

    # Indir
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "VerifyBlind-CRL-Updater/1.0")
        $tempFile = Join-Path ([IO.Path]::GetTempPath()) "crl_download_$($current).tmp"

        # Async indirme ile timeout simule et
        $task = $wc.DownloadFileTaskAsync($url, $tempFile)
        $completed = $task.Wait($TimeoutSec * 1000)

        if (-not $completed) {
            $wc.CancelAsync()
            throw "Zaman asimi (${TimeoutSec}s)"
        }

        if ($task.IsFaulted) {
            throw $task.Exception.InnerException
        }

        # Dosya boyutu kontrol (CRL en az birkac yuz byte olmali)
        $fileSize = (Get-Item $tempFile).Length
        if ($fileSize -lt 100) {
            throw "Dosya cok kucuk ($fileSize byte), gecersiz CRL olabilir"
        }

        # Her ulke klasorune kopyala
        foreach ($tp in $targetPaths) {
            Copy-Item $tempFile $tp -Force
        }
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

        $sizeKb = [math]::Round($fileSize / 1024, 1)
        Write-Host ("  OK  {0}/{1} ({2} KB) <- {3}" -f ($countries -join ','), $fileName, $sizeKb, $url)
        $downloaded++
    }
    catch {
        $errMsg = $_.Exception.Message
        # Ic exception varsa onu goster
        if ($_.Exception.InnerException) {
            $errMsg = $_.Exception.InnerException.Message
        }
        Write-Host ("  HATA {0}/{1} <- {2}" -f ($countries -join ','), $fileName, $url)
        Write-Host ("       {0}" -f $errMsg)
        $failedUrls += [PSCustomObject]@{ URL=$url; Countries=($countries -join ','); Error=$errMsg }
        $failed++
        Remove-Item (Join-Path ([IO.Path]::GetTempPath()) "crl_download_$($current).tmp") -Force -ErrorAction SilentlyContinue
    }
}

Write-Progress -Activity "CRL indiriliyor" -Completed

# ---------------------------------------------------------------------------
# Ozet
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 60)
Write-Host "TAMAMLANDI"
Write-Host "  Indirilen CRL    : $downloaded"
Write-Host "  Basarisiz        : $failed"
Write-Host "  Toplam URL       : $uniqueUrls"
Write-Host ""

if ($failed -gt 0) {
    Write-Host "BASARISIZ URL LISTESI:"
    foreach ($f in $failedUrls) {
        Write-Host ("  [{0}] {1}" -f $f.Countries, $f.URL)
        Write-Host ("    -> {0}" -f $f.Error)
    }
    Write-Host ""
}

# Ulke bazinda ozet
Write-Host "Ulke bazinda CRL dosyalari:"
$crlDirs = Get-ChildItem $OutputBase -Directory -ErrorAction SilentlyContinue | Sort-Object Name
foreach ($d in $crlDirs) {
    $crlCount = (Get-ChildItem $d.FullName -Filter "*.crl" -File -ErrorAction SilentlyContinue).Count
    if ($crlCount -gt 0) {
        Write-Host ("  {0,-5} : {1} dosya" -f $d.Name, $crlCount)
    }
}
Write-Host ("=" * 60)
