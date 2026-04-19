# Agrargemeinschaft – Hilfe für Administratoren

## Berechtigungen nach Rolle

| Rolle | Buchhaltung | Viehtrieb | Ausschüttung | Alm | Leistungen | Fakturierung | Admin |
|-------|-------------|-----------|--------------|-----|------------|--------------|-------|
| Obmann | RW | RW | RW | RW | RW | RW | R |
| Kassier | RW | R | RW | R | RW | RW | — |
| Schriftführer | R | RW | R | RW | RW | R | — |
| Kassaprüfer | R | R | R | R | R | — | — |
| Weidebeauftragter | — | R | — | RW | R | — | — |

R = Lesen, RW = Lesen + Schreiben, — = kein Zugriff. Hauptadmin hat immer vollen Zugriff.

## Obmann
Der Obmann hat den umfassendsten Zugriff und ist für die Gesamtleitung verantwortlich.
- Übersicht über Bankkonten und offene Rechnungen im Dashboard
- Alle Module lesen und schreiben
- Leistungsanträge genehmigen oder ablehnen
- Nachrichten an alle Mitglieder versenden
- Admin-Bereich einsehen (nur lesen)

## Kassier
Der Kassier verwaltet die Finanzen der Gemeinschaft.
- Buchhaltung vollständig verwalten (Buchungen, Kontenplan, Bank-Import)
- Jahresabschluss und Jahreseröffnung durchführen
- Ausschüttung berechnen und buchen
- Rechnungen und Gutschriften erstellen (Fakturierung)
- Leistungsanträge genehmigen (erstellt automatisch Buchungen)
- Datensicherung (Backup/Restore)

**Bank-Import:** Kontoauszüge als CSV importieren unter Buchhaltung → Bank-Import.
Zuordnungsschlüssel hinterlegen damit Buchungstexte automatisch dem richtigen Konto zugeordnet werden.

## Schriftführer
- Nachrichten an alle Mitglieder verfassen und versenden (auch per E-Mail)
- Viehtrieb verwalten (Triebrechte, Auftrieb)
- Alm-Daten verwalten
- Leistungsanträge genehmigen
- Mitgliederliste einsehen

## Kassaprüfer
Nur Leserechte — können nichts ändern.
- Buchhaltung einsehen (Journal, Saldenliste, Kontenplan)
- Viehtrieb, Ausschüttung, Alm, Leistungsanträge einsehen
- Keine Buchungen erstellen, ändern oder löschen

## Weidebeauftragter
- Alm vollständig verwalten (Tiere erfassen, bearbeiten, Abtrieb)
- Schnellerfassung für mobile Nutzung auf der Alm
- Viehtrieb einsehen
- Leistungsanträge einsehen

## Buchhaltung
- **Journal** — alle Buchungen chronologisch, mit Stornofunktion
- **Kontenplan** — Konten anlegen und verwalten, Kostenstellen-Flag setzen
- **Saldenliste** — Konten mit Soll/Haben-Summen je Geschäftsjahr
- **Bank-Import** — CSV-Kontoauszug importieren, Schlüssel für Automatik
- **Jahresabschluss** — Geschäftsjahr abschließen und Eröffnungsbuchungen erstellen
- **Sammelbuchung** — mehrere Buchungen in einem Schritt

Buchungen können storniert, aber nicht gelöscht werden. Stornobuchungen bleiben im Journal sichtbar.

### Neue Buchung erstellen
1. Buchhaltung → "Neue Buchung"
2. Datum, Buchungstext eingeben
3. Sollkonto und Habenkonto wählen
4. Betrag eingeben
5. Speichern

### Splitbuchung
Eine Splitbuchung teilt einen Betrag auf mehrere Konten auf:
1. Buchhaltung → "Neue Buchung"
2. Hauptbetrag und Gegenkonto eingeben
3. "Split hinzufügen" klicken
4. Teilbeträge und Konten eingeben (Summe muss dem Hauptbetrag entsprechen)
5. Speichern

### Bank-Import
1. Buchhaltung → "Bank-Import"
2. CSV-Datei der Bank hochladen
3. Vorschau prüfen — erkannte Zuordnungen werden angezeigt
4. Unbekannte Buchungen manuell zuordnen oder Schlüssel anlegen
5. Importieren

### Jahresabschluss
1. Buchhaltung → "Jahresabschluss"
2. Aktuelles Geschäftsjahr wählen
3. Saldenliste prüfen
4. "Abschluss durchführen" — erstellt automatisch Eröffnungsbuchungen für das neue Jahr

## Viehtrieb
- **Triebrechte** — Anzahl der Triebrechte je Betrieb festlegen
- **Auftrieb** — tatsächlich aufgetriebene Tiere erfassen
- **Ausschüttungsvorschau** — Berechnung auf Basis der Triebrechte
- Bei Überschreitung der Triebrechte: automatische Lastschrift auf das Betriebskonto

## Ausschüttung
Die Ausschüttung verteilt den Überschuss anteilig auf die Mitglieder.
1. Ausschüttungsbetrag eingeben
2. Vorschau prüfen (Berechnung nach Triebrechten)
3. Buchungen erstellen — automatisch auf die Verrechnungskonten der Betriebe

## Fakturierung
- Rechnungen und Gutschriften erstellen und als PDF exportieren
- Kunden verwalten
- Vorlagen für wiederkehrende Rechnungen
- Status: Offen → Bezahlt → Storniert
- Forderungskonto für automatische Buchungen

## Geschäftsjahr wechseln
In der Navigationsleiste oben: Pfeiltasten links/rechts neben der GJ-Anzeige klicken.
Oder auf die GJ-Zahl klicken und direkt ein Jahr eingeben.

## Backup & Restore
Unter Admin → Backup kann eine vollständige Datensicherung erstellt werden.
Restore: Admin → Restore → Backup-Datei hochladen.
