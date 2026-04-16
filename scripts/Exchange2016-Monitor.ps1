#Requires -Version 5.1
<#
.SYNOPSIS
    Exchange Server 2016 - Dienste, Zertifikate und Mailfluss Monitoring

.DESCRIPTION
    Dieses Skript ueberwacht kritische Exchange Server 2016 Komponenten:
      - Windows-Dienste (Exchange-Dienste und Abhaengigkeiten)
      - Exchange-Zertifikate (Ablaufdatum und Dienst-Zuweisung)
      - Mailfluss (Transportwarteschlangen, Connectoren, Test-Mailflow)

    Konzipiert fuer den Einsatz als geplante Aufgabe in NinjaOne RMM.

    NinjaOne-Integration:
      - Exit 0  -> Alles in Ordnung, kein Alert ausloesen
      - Exit 1  -> Fehler/Warnungen erkannt, Alert ausloesen
      - Stdout  -> Strukturierte Statusmeldungen; Zeilen mit "[FEHLER]" oder
                   "[WARNUNG]" als Sentinel-String fuer Alert-Bedingungen verwenden.

.PARAMETER WarnungTageBisAblauf
    Ab wie vielen verbleibenden Tagen ein Zertifikat als Warnung gilt. Standard: 30

.PARAMETER KritischTageBisAblauf
    Ab wie vielen verbleibenden Tagen ein Zertifikat als kritisch gilt. Standard: 7

.PARAMETER MaxWarteschlange
    Maximale Anzahl Nachrichten in einer einzelnen Transportwarteschlange
    bevor ein Fehler gemeldet wird. Standard: 100

.PARAMETER NinjaCustomFeld
    Optionaler Name eines NinjaOne Custom Fields fuer das Gesamtergebnis.
    Erfordert Ninja-Property-Set. Leer lassen um zu deaktivieren.

.EXAMPLE
    .\Exchange2016-Monitor.ps1

.EXAMPLE
    .\Exchange2016-Monitor.ps1 -WarnungTageBisAblauf 45 -MaxWarteschlange 50

.NOTES
    Benoetigt Exchange Management Shell (EMS) oder Exchange-Snapin.
    Muss auf dem Exchange-Server selbst ausgefuehrt werden.
    Empfohlene Ausfuehrung als SYSTEM oder Konto mit Exchange View-Only Admin.

    WICHTIG fuer NinjaOne: Skript als PowerShell (64-bit) ausfuehren lassen,
    damit der Exchange-Snapin korrekt geladen werden kann.
#>

[CmdletBinding()]
param(
    [int]$WarnungTageBisAblauf  = 30,
    [int]$KritischTageBisAblauf = 7,
    [int]$MaxWarteschlange      = 100,
    [string]$NinjaCustomFeld    = ""
)

Set-StrictMode -Version Latest

# ── Globaler Zustand ──────────────────────────────────────────────────────────
# Bewusst script-scope Variablen statt Funktions-Rueckgabewerten:
# In PowerShell wird bei "$var = FunktionX()" der GESAMTE Write-Output-Stream
# der Funktion in $var gespeichert - nichts erscheint auf dem Bildschirm.
$script:gesamtFehler   = $false
$script:emsVerfuegbar  = $false

#region ── Ausgabe-Hilfsfunktionen ────────────────────────────────────────────

function Write-Status   { param([string]$M) Write-Output "[INFO]    $M" }
function Write-OK       { param([string]$M) Write-Output "[OK]      $M" }
function Write-Warnung  { param([string]$M) Write-Output "[WARNUNG] $M" }

function Write-Fehler {
    param([string]$M)
    Write-Output "[FEHLER]  $M"
    $script:gesamtFehler = $true
}

function Write-Abschnitt {
    param([string]$Titel)
    Write-Output ""
    Write-Output ("=" * 60)
    Write-Output "  $Titel"
    Write-Output ("=" * 60)
}

#endregion

#region ── Exchange Management Shell laden ────────────────────────────────────

function Initialize-ExchangeShell {
    # Pruefe ob Exchange-Cmdlets bereits verfuegbar sind
    if (Get-Command Get-ExchangeCertificate -ErrorAction SilentlyContinue) {
        $script:emsVerfuegbar = $true
        return
    }

    # Versuche Exchange-Snapin zu laden
    $snapin = "Microsoft.Exchange.Management.PowerShell.SnapIn"
    if (-not (Get-PSSnapin -Name $snapin -ErrorAction SilentlyContinue)) {
        try {
            Add-PSSnapin $snapin -ErrorAction Stop
            $script:emsVerfuegbar = $true
            return
        }
        catch {
            # Snapin nicht registriert - weiter versuchen
        }
    }
    else {
        # Snapin bereits geladen
        $script:emsVerfuegbar = $true
        return
    }

    # Versuche lokales RemoteExchange.ps1
    $emsPfade = @(
        "$env:ExchangeInstallPath\bin\RemoteExchange.ps1",
        "C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1"
    )

    foreach ($pfad in $emsPfade) {
        if (Test-Path $pfad -ErrorAction SilentlyContinue) {
            try {
                # Output von dot-source und Connect-ExchangeServer unterdruecken
                . $pfad
                $null = Connect-ExchangeServer -auto -ClientApplication:ManagementShell 2>$null

                if (Get-Command Get-ExchangeCertificate -ErrorAction SilentlyContinue) {
                    $script:emsVerfuegbar = $true
                    return
                }
            }
            catch {
                # Weiter versuchen
            }
        }
    }

    Write-Fehler "Exchange Management Shell konnte nicht geladen werden. Exchange-Cmdlets nicht verfuegbar."
    Write-Output "          Hinweis: Skript muss auf dem Exchange-Server als 64-bit PowerShell ausgefuehrt werden."
}

#endregion

#region ── Dienste-Pruefung ───────────────────────────────────────────────────

function Test-ExchangeDienste {
    Write-Abschnitt "EXCHANGE DIENSTE"

    # Kritische Dienste - Fehler wenn gestoppt
    $kritisch = @(
        @{ Name = "MSExchangeADTopology";         Anz = "AD Topology"                  }
        @{ Name = "MSExchangeDelivery";           Anz = "Mailbox Transport Delivery"   }
        @{ Name = "MSExchangeFrontEndTransport";  Anz = "Frontend Transport"           }
        @{ Name = "MSExchangeHM";                 Anz = "Health Manager"               }
        @{ Name = "MSExchangeIS";                 Anz = "Information Store"            }
        @{ Name = "MSExchangeMailboxAssistants";  Anz = "Mailbox Assistants"           }
        @{ Name = "MSExchangeRPC";                Anz = "RPC Client Access"            }
        @{ Name = "MSExchangeServiceHost";        Anz = "Service Host"                 }
        @{ Name = "MSExchangeSubmission";         Anz = "Mailbox Transport Submission" }
        @{ Name = "MSExchangeThrottling";         Anz = "Throttling"                   }
        @{ Name = "MSExchangeTransport";          Anz = "Transport"                    }
        @{ Name = "MSExchangeMailboxReplication"; Anz = "Mailbox Replication"          }
        @{ Name = "MSExchangeDiagnostics";        Anz = "Diagnostics"                  }
        @{ Name = "W3SVC";                        Anz = "IIS (W3SVC)"                  }
        @{ Name = "WinRM";                        Anz = "Windows Remote Management"    }
    )

    # Optionale Dienste - Warnung wenn vorhanden aber gestoppt
    $optional = @(
        @{ Name = "MSExchangeRepl";               Anz = "Replication (DAG)"            }
        @{ Name = "MSExchangeTransportLogSearch"; Anz = "Transport Log Search"         }
        @{ Name = "MSExchangeIMAP4";              Anz = "IMAP4"                        }
        @{ Name = "MSExchangePOP3";               Anz = "POP3"                         }
        @{ Name = "MSExchangeUM";                 Anz = "Unified Messaging"            }
        @{ Name = "MSExchangeUMCR";               Anz = "UM Call Router"               }
        @{ Name = "MSExchangeEdgeSync";           Anz = "EdgeSync"                     }
    )

    foreach ($d in $kritisch) {
        try {
            $svc = Get-Service -Name $d.Name -ErrorAction Stop
            if ($svc.Status -ne "Running") {
                Write-Fehler "Dienst gestoppt: $($d.Anz) [$($d.Name)] | Status: $($svc.Status)"
            }
            else {
                Write-OK "Dienst laeuft:   $($d.Anz) [$($d.Name)]"
            }
        }
        catch {
            Write-Fehler "Dienst nicht gefunden: $($d.Anz) [$($d.Name)]"
        }
    }

    foreach ($d in $optional) {
        try {
            $svc = Get-Service -Name $d.Name -ErrorAction Stop
            if ($svc.Status -ne "Running") {
                Write-Warnung "Optionaler Dienst gestoppt: $($d.Anz) [$($d.Name)] | Status: $($svc.Status)"
            }
            else {
                Write-OK "Optionaler Dienst laeuft: $($d.Anz) [$($d.Name)]"
            }
        }
        catch {
            # Dienst nicht installiert - ignorieren
        }
    }
}

#endregion

#region ── Zertifikat-Pruefung ────────────────────────────────────────────────

function Test-ExchangeZertifikate {
    Write-Abschnitt "EXCHANGE ZERTIFIKATE"

    $jetzt = Get-Date

    try {
        $zertifikate = Get-ExchangeCertificate -ErrorAction Stop

        if (-not $zertifikate) {
            Write-Warnung "Keine Exchange-Zertifikate gefunden."
            return
        }

        foreach ($z in $zertifikate) {
            $ablauf      = $z.NotAfter
            $tage        = ($ablauf - $jetzt).Days
            $betreff     = $z.Subject
            $thumb       = $z.Thumbprint.Substring(0, 8) + "..."
            $dienste     = if ($z.Services) { [string]$z.Services } else { "(keine)" }
            $status      = $z.Status

            # Abgelaufen
            if ($tage -lt 0) {
                Write-Fehler "Zertifikat ABGELAUFEN: '$betreff' | Thumb: $thumb | Seit: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
                continue
            }

            # Ungueltig (nicht abgelaufen aber Status-Problem)
            if ($status -ne "Valid") {
                Write-Fehler "Zertifikat ungueltig (Status: $status): '$betreff' | Thumb: $thumb | Ablauf: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
            }

            # Ablauf-Schwellwerte
            if ($tage -le $KritischTageBisAblauf) {
                Write-Fehler "Zertifikat laeuft KRITISCH bald ab ($tage Tage): '$betreff' | Thumb: $thumb | Ablauf: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
            }
            elseif ($tage -le $WarnungTageBisAblauf) {
                Write-Warnung "Zertifikat laeuft bald ab ($tage Tage): '$betreff' | Thumb: $thumb | Ablauf: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
            }
            else {
                Write-OK "Zertifikat gueltig ($tage Tage): '$betreff' | Thumb: $thumb | Ablauf: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
            }
        }
    }
    catch {
        Write-Fehler "Zertifikatspruefung fehlgeschlagen: $($_.Exception.Message)"
    }
}

#endregion

#region ── Mailfluss-Pruefung ─────────────────────────────────────────────────

function Test-Mailfluss {
    Write-Abschnitt "MAILFLUSS & TRANSPORTWARTESCHLANGEN"

    # ── Transportwarteschlangen ───────────────────────────────────────────────
    try {
        $queues = Get-Queue -ErrorAction Stop

        foreach ($q in $queues) {
            $name    = [string]$q.Identity
            $anzahl  = $q.MessageCount
            $qStatus = [string]$q.Status
            $hop     = if ($q.NextHopDomain) { [string]$q.NextHopDomain } else { "(intern)" }

            # Poison-Queue
            if ($name -match "Poison" -or $q.DeliveryType -eq "Undefined") {
                if ($anzahl -gt 0) {
                    Write-Fehler "Poison-Warteschlange nicht leer: '$name' | Nachrichten: $anzahl"
                }
                continue
            }

            # Suspended
            if ($qStatus -eq "Suspended") {
                Write-Fehler "Warteschlange angehalten: '$name' | Nachrichten: $anzahl | Hop: $hop"
                continue
            }

            # Retry
            if ($qStatus -eq "Retry") {
                Write-Warnung "Warteschlange im Retry-Modus: '$name' | Nachrichten: $anzahl | Hop: $hop"
            }

            # Ueberlauf
            if ($anzahl -gt $MaxWarteschlange) {
                Write-Fehler "Warteschlange ueberlaeuft: '$name' | Nachrichten: $anzahl (Limit: $MaxWarteschlange) | Status: $qStatus | Hop: $hop"
            }
            elseif ($anzahl -gt 0) {
                Write-Status "Warteschlange aktiv: '$name' | Nachrichten: $anzahl | Status: $qStatus | Hop: $hop"
            }
            else {
                Write-OK "Warteschlange leer: '$name' | Status: $qStatus"
            }
        }
    }
    catch {
        Write-Fehler "Warteschlangen-Abfrage fehlgeschlagen: $($_.Exception.Message)"
    }

    # ── Feststeckende Nachrichten (>4h) ───────────────────────────────────────
    try {
        $altSeit = (Get-Date).AddHours(-4)
        $alteMsgs = @(Get-Message -ResultSize Unlimited -ErrorAction Stop |
            Where-Object { $_.DateReceived -lt $altSeit -and $_.Status -ne "Complete" })

        if ($alteMsgs.Count -gt 0) {
            Write-Fehler "Feststeckende Nachrichten (>4h in Queue): $($alteMsgs.Count) Nachricht(en)"
            foreach ($m in ($alteMsgs | Select-Object -First 5)) {
                Write-Output "          Von: $($m.FromAddress) | Eingang: $($m.DateReceived.ToString('dd.MM.yyyy HH:mm')) | Status: $($m.Status)"
            }
            if ($alteMsgs.Count -gt 5) {
                Write-Output "          ... und $($alteMsgs.Count - 5) weitere."
            }
        }
        else {
            Write-OK "Keine feststeckenden Nachrichten (>4h) gefunden."
        }
    }
    catch {
        Write-Warnung "Nachrichtendetail-Abfrage fehlgeschlagen: $($_.Exception.Message)"
    }

    # ── Test-Mailflow (lokal) ─────────────────────────────────────────────────
    try {
        $tm        = Test-Mailflow -ErrorAction Stop
        $tmResult  = [string]$tm.TestMailflowResult
        # Sprachunabhaengiger Vergleich: Exchange gibt je nach Systemsprache
        # "Success" (EN) oder "Erfolgreich" (DE) zurueck.
        if ($tmResult -notmatch "(?i)^(success|erfolgreich)$") {
            Write-Fehler "Test-Mailflow fehlgeschlagen: $tmResult | Latenz: $($tm.MessageLatencyTime)"
        }
        else {
            Write-OK "Test-Mailflow erfolgreich | Latenz: $($tm.MessageLatencyTime)"
        }
    }
    catch {
        Write-Warnung "Test-Mailflow konnte nicht ausgefuehrt werden: $($_.Exception.Message)"
    }

    # ── Empfangsconnectoren ───────────────────────────────────────────────────
    try {
        $recv  = @(Get-ReceiveConnector -ErrorAction Stop)
        $inakt = @($recv | Where-Object { $_.Enabled -eq $false })

        if ($inakt.Count -gt 0) {
            foreach ($c in $inakt) {
                Write-Warnung "Empfangsconnector deaktiviert: '$($c.Name)' auf Server '$($c.Server)'"
            }
        }
        else {
            Write-OK "Alle Empfangsconnectoren aktiv ($($recv.Count) gesamt)."
        }
    }
    catch {
        Write-Warnung "Empfangsconnectoren konnten nicht abgerufen werden: $($_.Exception.Message)"
    }

    # ── Sendeconnectoren ──────────────────────────────────────────────────────
    try {
        $send      = @(Get-SendConnector -ErrorAction Stop)
        $inaktSend = @($send | Where-Object { $_.Enabled -eq $false })

        if ($send.Count -eq 0) {
            Write-Fehler "Kein Sendeconnector konfiguriert - externer Mailversand nicht moeglich."
        }
        else {
            if ($inaktSend.Count -gt 0) {
                foreach ($c in $inaktSend) {
                    Write-Warnung "Sendeconnector deaktiviert: '$($c.Name)'"
                }
            }
            else {
                Write-OK "Alle Sendeconnectoren aktiv ($($send.Count) gesamt)."
            }
        }
    }
    catch {
        Write-Warnung "Sendeconnectoren konnten nicht abgerufen werden: $($_.Exception.Message)"
    }
}

#endregion

#region ── Hauptprogramm ──────────────────────────────────────────────────────

$startzeit = Get-Date
Write-Output "Exchange Server 2016 Monitoring - $($env:COMPUTERNAME)"
Write-Output "Ausfuehrungszeitpunkt : $($startzeit.ToString('dd.MM.yyyy HH:mm:ss'))"
Write-Output "Zertifikat-Warnung ab : $WarnungTageBisAblauf Tage | Kritisch ab: $KritischTageBisAblauf Tage"
Write-Output "Queue-Limit           : $MaxWarteschlange Nachrichten"

# Exchange Management Shell laden
Initialize-ExchangeShell

# Pruefungen ausfuehren
# WICHTIG: Funktionen werden NICHT einer Variable zugewiesen, da in PowerShell
# alle Write-Output-Ausgaben einer Funktion in der Variablen landen wuerden
# statt auf dem Bildschirm zu erscheinen.
Test-ExchangeDienste

if ($script:emsVerfuegbar) {
    Test-ExchangeZertifikate
    Test-Mailfluss
}
else {
    Write-Abschnitt "EXCHANGE ZERTIFIKATE"
    Write-Warnung "Uebersprungen - Exchange Management Shell nicht verfuegbar."
    Write-Abschnitt "MAILFLUSS & TRANSPORTWARTESCHLANGEN"
    Write-Warnung "Uebersprungen - Exchange Management Shell nicht verfuegbar."
}

# Zusammenfassung
$laufzeit = [math]::Round(((Get-Date) - $startzeit).TotalSeconds, 1)
Write-Abschnitt "ZUSAMMENFASSUNG"

if ($script:gesamtFehler) {
    Write-Output "[FEHLER]  Monitoring abgeschlossen - FEHLER/WARNUNGEN erkannt. Laufzeit: ${laufzeit}s"
}
else {
    Write-Output "[OK]      Monitoring abgeschlossen - Alle Komponenten in Ordnung. Laufzeit: ${laufzeit}s"
}

# Optional: NinjaOne Custom Field setzen
if ($NinjaCustomFeld -ne "") {
    try {
        $wert = if ($script:gesamtFehler) { "FEHLER - $(Get-Date -Format 'dd.MM.yyyy HH:mm')" } `
                else                       { "OK - $(Get-Date -Format 'dd.MM.yyyy HH:mm')" }
        Ninja-Property-Set $NinjaCustomFeld $wert
    }
    catch {
        Write-Warnung "NinjaOne Custom Field '$NinjaCustomFeld' konnte nicht gesetzt werden: $($_.Exception.Message)"
    }
}

# NinjaOne Exit-Code: 0 = OK, 1 = Fehler/Warnung
if ($script:gesamtFehler) { exit 1 } else { exit 0 }

#endregion
