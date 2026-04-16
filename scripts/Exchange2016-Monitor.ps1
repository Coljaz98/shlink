#Requires -Version 5.1
<#
.SYNOPSIS
    Exchange Server 2016 - Dienste, Zertifikate und Mailfluss Monitoring

.DESCRIPTION
    Dieses Skript ueberwacht kritische Exchange Server 2016 Komponenten:
      - Windows-Dienste (Exchange-Dienste und Abhaengigkeiten)
      - Exchange-Zertifikate (Ablaufdatum und Dienst-Zuweisung)
      - Mailfluss (Transportwarteschlangen und Teststatus)

    Konzipiert fuer den Einsatz als geplante Aufgabe in NinjaOne RMM.

    NinjaOne-Integration:
      - Exit 0  -> Alles in Ordnung, kein Alert ausloesen
      - Exit 1  -> Fehler/Warnungen erkannt, Alert ausloesen
      - Stdout  -> Strukturierte Statusmeldungen; Zeilen mit "[FEHLER]"
                   oder "[WARNUNG]" als Sentinel-String fuer Alert-Bedingungen
                   in NinjaOne verwenden.

.PARAMETER WarnungTageBisAblauf
    Ab wie vielen verbleibenden Tagen ein Zertifikat als Warnung gilt. Standard: 30

.PARAMETER KritischTageBisAblauf
    Ab wie vielen verbleibenden Tagen ein Zertifikat als kritisch gilt. Standard: 7

.PARAMETER MaxWarteschlange
    Maximale Anzahl Nachrichten in einer einzelnen Transportwarteschlange bevor
    ein Fehler gemeldet wird. Standard: 100

.PARAMETER NinjaCustomFeld
    Optionaler Name eines NinjaOne-Custom-Fields, in das das Ergebnis
    geschrieben wird (erfordert Ninja-Property-Set). Leer lassen um zu deaktivieren.

.EXAMPLE
    # Standardausfuehrung
    .\Exchange2016-Monitor.ps1

.EXAMPLE
    # Zertifikat-Warnung ab 45 Tagen, Queue-Limit 50
    .\Exchange2016-Monitor.ps1 -WarnungTageBisAblauf 45 -MaxWarteschlange 50

.NOTES
    Benoetigt Exchange Management Shell (EMS) oder Exchange-Snapin.
    Muss auf dem Exchange-Server selbst oder mit Remote-EMS ausgefuehrt werden.
    Empfohlene Ausfuehrung als SYSTEM oder Konto mit Exchange View-Only Admin.
#>

[CmdletBinding()]
param(
    [int]$WarnungTageBisAblauf  = 30,
    [int]$KritischTageBisAblauf = 7,
    [int]$MaxWarteschlange      = 100,
    [string]$NinjaCustomFeld    = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── Hilfsfunktionen ──────────────────────────────────────────────────────

function Write-Status {
    param([string]$Nachricht)
    Write-Output $Nachricht
}

function Write-Warnung {
    param([string]$Nachricht)
    Write-Output "[WARNUNG] $Nachricht"
}

function Write-Fehler {
    param([string]$Nachricht)
    Write-Output "[FEHLER] $Nachricht"
}

function Write-OK {
    param([string]$Nachricht)
    Write-Output "[OK] $Nachricht"
}

function Write-Abschnitt {
    param([string]$Titel)
    Write-Output ""
    Write-Output ("=" * 60)
    Write-Output "  $Titel"
    Write-Output ("=" * 60)
}

#endregion

#region ── Exchange Management Shell laden ─────────────────────────────────────

function Initialize-ExchangeShell {
    # Pruefen ob Exchange-Cmdlets bereits verfuegbar sind
    if (Get-Command Get-ExchangeCertificate -ErrorAction SilentlyContinue) {
        return $true
    }

    # Versuche Exchange-Snapin zu laden
    $snapin = "Microsoft.Exchange.Management.PowerShell.SnapIn"
    if ((Get-PSSnapin -Name $snapin -ErrorAction SilentlyContinue) -eq $null) {
        try {
            Add-PSSnapin $snapin -ErrorAction Stop
            return $true
        }
        catch {
            # Snapin nicht gefunden, versuche Remote-EMS
        }
    }

    # Versuche lokale EMS-Profilskripte
    $emsPfade = @(
        "$env:ExchangeInstallPath\bin\RemoteExchange.ps1",
        "C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1"
    )
    foreach ($pfad in $emsPfade) {
        if (Test-Path $pfad) {
            try {
                . $pfad
                Connect-ExchangeServer -auto -ClientApplication:ManagementShell
                return $true
            }
            catch {
                # Weiter versuchen
            }
        }
    }

    return $false
}

#endregion

#region ── Dienste-Pruefung ────────────────────────────────────────────────────

function Test-ExchangeDienste {
    Write-Abschnitt "EXCHANGE DIENSTE"

    # Kritische Dienste die laufen MUESSEN
    $kritischeDienste = @(
        @{ Name = "MSExchangeADTopology";         Anzeige = "AD Topology"                   }
        @{ Name = "MSExchangeDelivery";           Anzeige = "Mailbox Transport Delivery"    }
        @{ Name = "MSExchangeFrontEndTransport";  Anzeige = "Frontend Transport"            }
        @{ Name = "MSExchangeHM";                 Anzeige = "Health Manager"                }
        @{ Name = "MSExchangeIS";                 Anzeige = "Information Store"             }
        @{ Name = "MSExchangeMailboxAssistants";  Anzeige = "Mailbox Assistants"            }
        @{ Name = "MSExchangeRepl";               Anzeige = "Replication"                   }
        @{ Name = "MSExchangeRPC";                Anzeige = "RPC Client Access"             }
        @{ Name = "MSExchangeServiceHost";        Anzeige = "Service Host"                  }
        @{ Name = "MSExchangeSubmission";         Anzeige = "Mailbox Transport Submission"  }
        @{ Name = "MSExchangeThrottling";         Anzeige = "Throttling"                    }
        @{ Name = "MSExchangeTransport";          Anzeige = "Transport"                     }
        @{ Name = "MSExchangeTransportLogSearch"; Anzeige = "Transport Log Search"          }
        @{ Name = "MSExchangeMailboxReplication"; Anzeige = "Mailbox Replication"           }
        @{ Name = "MSExchangeDiagnostics";        Anzeige = "Diagnostics"                   }
        @{ Name = "W3SVC";                        Anzeige = "IIS (W3SVC)"                   }
        @{ Name = "WinRM";                        Anzeige = "Windows Remote Management"     }
    )

    # Optionale Dienste (nur warnen wenn vorhanden aber gestoppt)
    $optionaleDienste = @(
        @{ Name = "MSExchangeIMAP4";   Anzeige = "IMAP4"         }
        @{ Name = "MSExchangePOP3";    Anzeige = "POP3"          }
        @{ Name = "MSExchangeUM";      Anzeige = "Unified Messaging" }
        @{ Name = "MSExchangeUMCR";    Anzeige = "UM Call Router" }
        @{ Name = "MSExchangeEdgeSync"; Anzeige = "EdgeSync"     }
    )

    $fehlerGefunden = $false

    foreach ($dienst in $kritischeDienste) {
        try {
            $svc = Get-Service -Name $dienst.Name -ErrorAction Stop
            if ($svc.Status -ne "Running") {
                Write-Fehler "Dienst gestoppt: $($dienst.Anzeige) [$($dienst.Name)] - Status: $($svc.Status)"
                $fehlerGefunden = $true
            }
            else {
                Write-OK "Dienst laeuft: $($dienst.Anzeige) [$($dienst.Name)]"
            }
        }
        catch {
            Write-Fehler "Dienst nicht gefunden: $($dienst.Anzeige) [$($dienst.Name)]"
            $fehlerGefunden = $true
        }
    }

    foreach ($dienst in $optionaleDienste) {
        try {
            $svc = Get-Service -Name $dienst.Name -ErrorAction Stop
            if ($svc.Status -ne "Running") {
                Write-Warnung "Optionaler Dienst gestoppt: $($dienst.Anzeige) [$($dienst.Name)] - Status: $($svc.Status)"
            }
            else {
                Write-OK "Optionaler Dienst laeuft: $($dienst.Anzeige) [$($dienst.Name)]"
            }
        }
        catch {
            # Dienst nicht installiert - ignorieren
        }
    }

    return $fehlerGefunden
}

#endregion

#region ── Zertifikat-Pruefung ─────────────────────────────────────────────────

function Test-ExchangeZertifikate {
    Write-Abschnitt "EXCHANGE ZERTIFIKATE"

    $fehlerGefunden = $false
    $jetzt = Get-Date

    try {
        $zertifikate = Get-ExchangeCertificate -ErrorAction Stop

        if ($zertifikate.Count -eq 0) {
            Write-Warnung "Keine Exchange-Zertifikate gefunden."
            return $true
        }

        foreach ($zert in $zertifikate) {
            $ablauf       = $zert.NotAfter
            $verbleibend  = ($ablauf - $jetzt).Days
            $betreff      = $zert.Subject
            $thumbprint   = $zert.Thumbprint.Substring(0, 8) + "..."
            $dienste      = if ($zert.Services) { $zert.Services -join ", " } else { "(keine)" }
            $status       = $zert.Status

            # Abgelaufen
            if ($verbleibend -lt 0) {
                Write-Fehler "Zertifikat ABGELAUFEN: '$betreff' | Thumb: $thumbprint | Abgelaufen: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
                $fehlerGefunden = $true
                continue
            }

            # Zertifikatsstatus ungueltig
            if ($status -ne "Valid") {
                Write-Fehler "Zertifikat ungueltig: '$betreff' | Thumb: $thumbprint | Status: $status | Dienste: $dienste"
                $fehlerGefunden = $true
            }

            # Kritisch: laeuft bald ab
            if ($verbleibend -le $KritischTageBisAblauf) {
                Write-Fehler "Zertifikat laeuft KRITISCH bald ab ($verbleibend Tage): '$betreff' | Thumb: $thumbprint | Ablauf: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
                $fehlerGefunden = $true
            }
            # Warnung: laeuft in Kuerze ab
            elseif ($verbleibend -le $WarnungTageBisAblauf) {
                Write-Warnung "Zertifikat laeuft bald ab ($verbleibend Tage): '$betreff' | Thumb: $thumbprint | Ablauf: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
            }
            else {
                Write-OK "Zertifikat gueltig ($verbleibend Tage): '$betreff' | Thumb: $thumbprint | Ablauf: $($ablauf.ToString('dd.MM.yyyy')) | Dienste: $dienste"
            }

            # Pruefen ob Zertifikat Diensten zugewiesen (SMTP, IIS mindestens erwartet)
            if ($zert.Services -and ($zert.Services -match "SMTP|IIS")) {
                $fehlendeDienste = @()
                if ($zert.Services -notmatch "SMTP") { $fehlendeDienste += "SMTP" }
                if ($zert.Services -notmatch "IIS")  { $fehlendeDienste += "IIS"  }
                # Nur melden wenn dieses Zert als Haupt-Zert erscheint (SAN/Wildcard)
            }
        }
    }
    catch {
        Write-Fehler "Zertifikatspruefung fehlgeschlagen: $($_.Exception.Message)"
        $fehlerGefunden = $true
    }

    return $fehlerGefunden
}

#endregion

#region ── Mailfluss-Pruefung ──────────────────────────────────────────────────

function Test-Mailfluss {
    Write-Abschnitt "MAILFLUSS & TRANSPORTWARTESCHLANGEN"

    $fehlerGefunden = $false

    # ── 1. Transportwarteschlangen pruefen ──────────────────────────────────────
    try {
        $warteschlangen = Get-Queue -ErrorAction Stop

        foreach ($q in $warteschlangen) {
            $name      = $q.Identity
            $anzahl    = $q.MessageCount
            $qStatus   = $q.Status
            $nexthop   = if ($q.NextHopDomain) { $q.NextHopDomain } else { "(intern)" }

            # Poison-Queue: alle Nachrichten darin sind kritisch
            if ($q.DeliveryType -eq "Undefined" -or $name -match "Poison") {
                if ($anzahl -gt 0) {
                    Write-Fehler "Poison-Warteschlange nicht leer: '$name' | Nachrichten: $anzahl"
                    $fehlerGefunden = $true
                    continue
                }
            }

            # Retry-Status
            if ($qStatus -eq "Retry") {
                Write-Warnung "Warteschlange im Retry-Modus: '$name' | Nachrichten: $anzahl | Naechster Hop: $nexthop"
            }

            # Suspended
            if ($qStatus -eq "Suspended") {
                Write-Fehler "Warteschlange angehalten (Suspended): '$name' | Nachrichten: $anzahl | Naechster Hop: $nexthop"
                $fehlerGefunden = $true
                continue
            }

            # Zu viele Nachrichten
            if ($anzahl -gt $MaxWarteschlange) {
                Write-Fehler "Warteschlange ueberlaeuft: '$name' | Nachrichten: $anzahl (Limit: $MaxWarteschlange) | Status: $qStatus | Naechster Hop: $nexthop"
                $fehlerGefunden = $true
            }
            elseif ($anzahl -gt 0) {
                Write-Status "[INFO] Warteschlange aktiv: '$name' | Nachrichten: $anzahl | Status: $qStatus | Naechster Hop: $nexthop"
            }
            else {
                Write-OK "Warteschlange leer: '$name' | Status: $qStatus"
            }
        }
    }
    catch {
        Write-Fehler "Warteschlangen-Abfrage fehlgeschlagen: $($_.Exception.Message)"
        $fehlerGefunden = $true
    }

    # ── 2. Nachrichten in Warteschlangen mit altem Eingang pruefen ──────────────
    try {
        $altSchwellwert = (Get-Date).AddHours(-4)
        $alteNachrichten = Get-Message -ResultSize Unlimited -ErrorAction Stop |
            Where-Object { $_.DateReceived -lt $altSchwellwert -and $_.Status -ne "Complete" }

        if ($alteNachrichten.Count -gt 0) {
            Write-Fehler "Feststeckende Nachrichten (>4h in Queue): $($alteNachrichten.Count) Nachrichten"
            foreach ($msg in ($alteNachrichten | Select-Object -First 5)) {
                Write-Fehler "  -> Von: $($msg.FromAddress) | An: $($msg.Recipients -join ', ') | Eingang: $($msg.DateReceived.ToString('dd.MM.yyyy HH:mm')) | Status: $($msg.Status)"
            }
            if ($alteNachrichten.Count -gt 5) {
                Write-Status "     ... und $($alteNachrichten.Count - 5) weitere."
            }
            $fehlerGefunden = $true
        }
        else {
            Write-OK "Keine feststeckenden Nachrichten (>4h) gefunden."
        }
    }
    catch {
        Write-Warnung "Nachrichtendetails konnten nicht abgerufen werden: $($_.Exception.Message)"
    }

    # ── 3. Test-Mailflow (lokal) ────────────────────────────────────────────────
    try {
        $testErgebnis = Test-Mailflow -ErrorAction Stop
        if ($testErgebnis.TestMailflowResult -ne "Success") {
            Write-Fehler "Test-Mailflow fehlgeschlagen: $($testErgebnis.TestMailflowResult) | Latenz: $($testErgebnis.MessageLatencyTime)"
            $fehlerGefunden = $true
        }
        else {
            Write-OK "Test-Mailflow erfolgreich | Latenz: $($testErgebnis.MessageLatencyTime)"
        }
    }
    catch {
        Write-Warnung "Test-Mailflow konnte nicht ausgefuehrt werden: $($_.Exception.Message)"
    }

    # ── 4. SMTP-Empfangs-Connectoren pruefen ────────────────────────────────────
    try {
        $empfangsConnectors = Get-ReceiveConnector -ErrorAction Stop
        $deaktiviert = $empfangsConnectors | Where-Object { $_.Enabled -eq $false }
        if ($deaktiviert.Count -gt 0) {
            foreach ($conn in $deaktiviert) {
                Write-Warnung "Empfangsconnector deaktiviert: '$($conn.Name)' auf '$($conn.Server)'"
            }
        }
        else {
            Write-OK "Alle Empfangsconnectoren aktiv ($($empfangsConnectors.Count) gesamt)."
        }
    }
    catch {
        Write-Warnung "Empfangsconnectoren konnten nicht abgerufen werden: $($_.Exception.Message)"
    }

    # ── 5. SMTP-Sendecconnectoren pruefen ───────────────────────────────────────
    try {
        $sendeConnectors = Get-SendConnector -ErrorAction Stop
        $deaktiviertSend = $sendeConnectors | Where-Object { $_.Enabled -eq $false }
        if ($deaktiviertSend.Count -gt 0) {
            foreach ($conn in $deaktiviertSend) {
                Write-Warnung "Sendeconnector deaktiviert: '$($conn.Name)'"
            }
        }
        else {
            Write-OK "Alle Sendeconnectoren aktiv ($($sendeConnectors.Count) gesamt)."
        }

        # Pruefen ob mindestens ein Sendeconnector fuer externe Mail existiert
        if ($sendeConnectors.Count -eq 0) {
            Write-Fehler "Kein Sendeconnector konfiguriert - externer Mailversand nicht moeglich."
            $fehlerGefunden = $true
        }
    }
    catch {
        Write-Warnung "Sendeconnectoren konnten nicht abgerufen werden: $($_.Exception.Message)"
    }

    return $fehlerGefunden
}

#endregion

#region ── Hauptprogramm ───────────────────────────────────────────────────────

$gesamtFehler = $false
$startzeit    = Get-Date

Write-Output "Exchange Server 2016 Monitoring - $($env:COMPUTERNAME)"
Write-Output "Ausfuehrungszeitpunkt: $($startzeit.ToString('dd.MM.yyyy HH:mm:ss'))"
Write-Output "Zertifikat-Warnung ab: $WarnungTageBisAblauf Tage | Kritisch ab: $KritischTageBisAblauf Tage | Queue-Limit: $MaxWarteschlange"

# Exchange Management Shell initialisieren
$emsVerfuegbar = Initialize-ExchangeShell
if (-not $emsVerfuegbar) {
    Write-Fehler "Exchange Management Shell konnte nicht geladen werden. Exchange-Cmdlets nicht verfuegbar."
    Write-Output ""
    Write-Output "Hinweis: Stellen Sie sicher, dass das Skript auf dem Exchange-Server oder mit"
    Write-Output "         Remote-EMS-Zugriff ausgefuehrt wird."
}

# 1. Dienste pruefen (immer, unabhaengig von EMS)
$dienstFehler = Test-ExchangeDienste
if ($dienstFehler) { $gesamtFehler = $true }

# 2. Zertifikate pruefen (erfordert EMS)
if ($emsVerfuegbar) {
    $zertFehler = Test-ExchangeZertifikate
    if ($zertFehler) { $gesamtFehler = $true }
}
else {
    Write-Abschnitt "EXCHANGE ZERTIFIKATE"
    Write-Warnung "Zertifikatspruefung uebersprungen - Exchange Management Shell nicht verfuegbar."
}

# 3. Mailfluss pruefen (erfordert EMS)
if ($emsVerfuegbar) {
    $mailflusssFehler = Test-Mailfluss
    if ($mailflusssFehler) { $gesamtFehler = $true }
}
else {
    Write-Abschnitt "MAILFLUSS & TRANSPORTWARTESCHLANGEN"
    Write-Warnung "Mailfluss-Pruefung uebersprungen - Exchange Management Shell nicht verfuegbar."
}

# Zusammenfassung
Write-Abschnitt "ZUSAMMENFASSUNG"
$laufzeit = ((Get-Date) - $startzeit).TotalSeconds
if ($gesamtFehler) {
    Write-Output "[FEHLER] Monitoring abgeschlossen - FEHLER/WARNUNGEN erkannt. Laufzeit: $([math]::Round($laufzeit,1))s"
}
else {
    Write-Output "[OK] Monitoring abgeschlossen - Alle geprueften Komponenten in Ordnung. Laufzeit: $([math]::Round($laufzeit,1))s"
}

# Optional: Ergebnis in NinjaOne Custom Field schreiben
if ($NinjaCustomFeld -ne "") {
    try {
        $feldWert = if ($gesamtFehler) { "FEHLER - $(Get-Date -Format 'dd.MM.yyyy HH:mm')" } `
                    else               { "OK - $(Get-Date -Format 'dd.MM.yyyy HH:mm')" }
        Ninja-Property-Set $NinjaCustomFeld $feldWert
    }
    catch {
        Write-Warnung "NinjaOne Custom Field '$NinjaCustomFeld' konnte nicht gesetzt werden: $($_.Exception.Message)"
    }
}

# Exit-Code fuer NinjaOne: 0 = OK, 1 = Fehler/Warnung
if ($gesamtFehler) {
    exit 1
}
else {
    exit 0
}

#endregion
