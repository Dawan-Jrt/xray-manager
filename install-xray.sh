#!/bin/bash
#==========================================================
#  Xray Manager (pribadi)
#  VLESS + VMess + Trojan | WebSocket + TLS | nginx di port 443
#  Untuk Ubuntu 22.04 / 24.04. Jalankan sebagai root di VPS BERSIH.
#  Tanpa pengecekan lisensi, tanpa panggilan ke server pihak lain
#  selain: apt, installer resmi Xray (XTLS), dan Let's Encrypt.
#==========================================================
set -e

[ "$(id -u)" -eq 0 ] || { echo "Jalankan sebagai root."; exit 1; }
. /etc/os-release
[ "$ID" = "ubuntu" ] || { echo "Script ini untuk Ubuntu."; exit 1; }

# Jangan timpa autoscript lain (mis. Sensi VIP AIO)
if [ "$FORCE" != "1" ]; then
  if [ -d /etc/xray ] || [ -f /etc/systemd/system/xray.service ] || [ -f /etc/nginx/conf.d/xray.conf ]; then
    echo "Terdeteksi instalasi Xray/autoscript lain di VPS ini."
    echo "Script ini sebaiknya dipakai di VPS baru (instal ulang OS)."
    echo "Kalau tetap mau lanjut dan menimpa: FORCE=1 bash install-xray.sh"
    exit 1
  fi
fi

echo "=== Xray Manager: instalasi ==="
read -rp "Domain (sudah diarahkan ke IP VPS ini): " DOMAIN
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { echo "Domain tidak valid."; exit 1; }
read -rp "Email untuk Let's Encrypt (boleh kosong): " EMAIL

SERVER_IP=$(curl -4 -s --max-time 10 ifconfig.me || true)
DOM_IP=$(getent ahostsv4 "$DOMAIN" | awk '{print $1; exit}' || true)
if [ -z "$DOM_IP" ] || [ "$SERVER_IP" != "$DOM_IP" ]; then
  echo "PERINGATAN: IP domain ($DOM_IP) tidak sama dengan IP VPS ($SERVER_IP)."
  echo "Sertifikat TLS akan gagal kalau domain belum mengarah ke VPS ini."
  read -rp "Tetap lanjut? (y/N): " YN
  [ "$YN" = "y" ] || exit 1
fi

export DEBIAN_FRONTEND=noninteractive
echo "[1/6] Memasang paket..."
apt-get update -y
apt-get install -y nginx certbot jq curl openssl cron

echo "[2/6] Memasang Xray (installer resmi XTLS)..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo "[3/6] Meminta sertifikat TLS..."
systemctl stop nginx || true
if [ -n "$EMAIL" ]; then MAIL_OPT="--email $EMAIL"; else MAIL_OPT="--register-unsafely-without-email"; fi
certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos $MAIL_OPT \
  --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"

echo "[4/6] Menyiapkan folder dan nginx..."
mkdir -p /etc/xray-manager /var/log/xray
echo "$DOMAIN" > /etc/xray-manager/domain
touch /etc/xray-manager/accounts.db
chown -R nobody:nogroup /var/log/xray

cat > /etc/nginx/conf.d/xray-manager.conf <<'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name __DOMAIN__;
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name __DOMAIN__;

    ssl_certificate     /etc/letsencrypt/live/__DOMAIN__/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/__DOMAIN__/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / { return 404; }

    location /vless {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 86400s;
    }
    location /vmess {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 86400s;
    }
    location /trojan-ws {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 86400s;
    }
}
NGINX
sed -i "s/__DOMAIN__/$DOMAIN/g" /etc/nginx/conf.d/xray-manager.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

echo "[5/6] Memasang menu (perintah: xmenu)..."
cat > /usr/local/bin/xmenu <<'XMENU'
#!/bin/bash
DB=/etc/xray-manager/accounts.db
LOCK=/etc/xray-manager/locked.db   # akun yang dikunci sementara: nama|waktu_buka(epoch)
LOCK_MIN=15      # lama akun dikunci kalau melebihi limit IP (menit)
WINDOW_MIN=2     # jendela waktu penghitungan IP unik (menit)
ACCESS_LOG=/var/log/xray/access.log
CFG=/usr/local/etc/xray/config.json
DOMAIN=$(cat /etc/xray-manager/domain 2>/dev/null)
XRAY=/usr/local/bin/xray
touch "$DB" "$LOCK"

# Bangun ulang config Xray dari daftar akun (sumber kebenaran = accounts.db)
rebuild() {
  local tmp
  tmp=$(mktemp)
  jq -n --rawfile db "$DB" --rawfile lk "$LOCK" '
    def ok($L): (.n | IN($L[]) | not);
    ($db | split("\n") | map(select(length > 0) | split("|") | {p: .[0], n: .[1], s: .[2]})) as $a
    | ($lk | split("\n") | map(select(length > 0) | split("|") | .[0])) as $L
    | {
        log: {access: "/var/log/xray/access.log", error: "/var/log/xray/error.log", loglevel: "warning"},
        inbounds: [
          {tag: "vless-ws", listen: "127.0.0.1", port: 10001, protocol: "vless",
           settings: {decryption: "none", clients: [$a[] | select(.p == "vless" and ok($L)) | {id: .s, email: .n}]},
           streamSettings: {network: "ws", wsSettings: {path: "/vless"}}},
          {tag: "vmess-ws", listen: "127.0.0.1", port: 10002, protocol: "vmess",
           settings: {clients: [$a[] | select(.p == "vmess" and ok($L)) | {id: .s, alterId: 0, email: .n}]},
           streamSettings: {network: "ws", wsSettings: {path: "/vmess"}}},
          {tag: "trojan-ws", listen: "127.0.0.1", port: 10003, protocol: "trojan",
           settings: {clients: [$a[] | select(.p == "trojan" and ok($L)) | {password: .s, email: .n}]},
           streamSettings: {network: "ws", wsSettings: {path: "/trojan-ws"}}}
        ],
        outbounds: [
          {protocol: "freedom", tag: "direct"},
          {protocol: "blackhole", tag: "block"}
        ],
        routing: {rules: [
          {type: "field", outboundTag: "block",
           ip: ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]}
        ]}
      }' > "$tmp" || { echo "Gagal membuat config."; rm -f "$tmp"; return 1; }
  if ! "$XRAY" run -test -config "$tmp" >/dev/null 2>&1; then
    echo "Config tidak valid, perubahan dibatalkan."
    rm -f "$tmp"
    return 1
  fi
  install -m 640 -o root -g nogroup "$tmp" "$CFG"
  rm -f "$tmp"
  systemctl restart xray || { echo "Xray gagal start. Cek: journalctl -u xray -n 20 --no-pager"; return 1; }
}

make_link() { # proto nama rahasia
  case "$1" in
    vless)
      echo "vless://$3@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&type=ws&host=$DOMAIN&path=%2Fvless#$2" ;;
    vmess)
      local j
      j=$(jq -nc --arg n "$2" --arg d "$DOMAIN" --arg id "$3" \
        '{v:"2",ps:$n,add:$d,port:"443",id:$id,aid:"0",net:"ws",type:"none",host:$d,path:"/vmess",tls:"tls",sni:$d}')
      echo "vmess://$(echo -n "$j" | base64 -w0)" ;;
    trojan)
      echo "trojan://$3@$DOMAIN:443?security=tls&sni=$DOMAIN&type=ws&host=$DOMAIN&path=%2Ftrojan-ws#$2" ;;
  esac
}

add_account() {
  local proto=$1 name days id exp lim
  read -rp "Nama akun (huruf/angka/_/-, 3-20 karakter): " name
  [[ "$name" =~ ^[A-Za-z0-9_-]{3,20}$ ]] || { echo "Nama tidak valid."; return; }
  grep -q "^[^|]*|$name|" "$DB" && { echo "Nama sudah dipakai."; return; }
  read -rp "Masa aktif (hari): " days
  [[ "$days" =~ ^[0-9]+$ ]] && [ "$days" -ge 1 ] || { echo "Jumlah hari tidak valid."; return; }

  if [ "$proto" = "trojan" ]; then
    read -rp "Password custom (8-64 karakter huruf/angka/_/-, kosong = acak): " id
    if [ -z "$id" ]; then
      id=$(openssl rand -hex 12)
    elif ! [[ "$id" =~ ^[A-Za-z0-9_-]{8,64}$ ]]; then
      echo "Password tidak valid."; return
    fi
  else
    read -rp "UUID custom (kosong = acak): " id
    if [ -z "$id" ]; then
      id=$(cat /proc/sys/kernel/random/uuid)
    elif ! [[ "$id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
      echo "Format UUID tidak valid. Contoh: 123e4567-e89b-12d3-a456-426614174000"; return
    fi
    id=${id,,}
  fi
  if cut -d'|' -f3 "$DB" | grep -qxF "$id"; then
    echo "UUID/password itu sudah dipakai akun lain."; return
  fi

  read -rp "Limit IP (maks perangkat/IP bersamaan, 0 = tanpa batas) [0]: " lim
  lim=${lim:-0}
  [[ "$lim" =~ ^[0-9]{1,3}$ ]] || { echo "Limit IP tidak valid."; return; }

  exp=$(date -d "+$days days" +%F)
  cp "$DB" "$DB.bak"
  echo "$proto|$name|$id|$exp|$lim" >> "$DB"
  if rebuild; then
    echo
    echo "Akun dibuat. Protokol: $proto | Berlaku sampai: $exp | Limit IP: $lim"
    echo "Domain: $DOMAIN | Port: 443 (TLS) | Network: ws"
    echo
    make_link "$proto" "$name" "$id"
  else
    cp "$DB.bak" "$DB"
  fi
}

list_accounts() {
  if [ ! -s "$DB" ]; then echo "Belum ada akun."; return; fi
  printf "%-8s %-20s %-11s %-6s %s\n" PROTOKOL NAMA EXPIRED LIMIT STATUS
  awk -F'|' -v lk="$LOCK" '
    BEGIN { while ((getline l < lk) > 0) { split(l, a, "|"); L[a[1]] = 1 } }
    { printf "%-8s %-20s %-11s %-6s %s\n", $1, $2, $4, (($5 == "" || $5 == 0) ? "-" : $5), ($2 in L ? "TERKUNCI" : "") }
  ' "$DB" | sort
}

show_link() {
  local name line
  list_accounts
  read -rp "Nama akun: " name
  line=$(grep "^[^|]*|$name|" "$DB") || { echo "Akun tidak ditemukan."; return; }
  IFS='|' read -r p n s e l <<< "$line"
  echo "Berlaku sampai: $e | Limit IP: ${l:-0}"
  make_link "$p" "$n" "$s"
}

delete_account() {
  local name
  list_accounts
  read -rp "Nama akun yang dihapus: " name
  grep -q "^[^|]*|$name|" "$DB" || { echo "Akun tidak ditemukan."; return; }
  cp "$DB" "$DB.bak"
  grep -v "^[^|]*|$name|" "$DB.bak" > "$DB" || true
  awk -F'|' -v n="$name" '$1 != n' "$LOCK" > "$LOCK.tmp" && mv "$LOCK.tmp" "$LOCK"
  if rebuild; then echo "Akun $name dihapus."; else cp "$DB.bak" "$DB"; fi
}

extend_account() {
  local name days line old today base new
  list_accounts
  read -rp "Nama akun: " name
  line=$(grep "^[^|]*|$name|" "$DB") || { echo "Akun tidak ditemukan."; return; }
  read -rp "Tambah berapa hari: " days
  [[ "$days" =~ ^[0-9]+$ ]] && [ "$days" -ge 1 ] || { echo "Jumlah hari tidak valid."; return; }
  old=$(echo "$line" | cut -d'|' -f4)
  today=$(date +%F)
  base=$old
  [[ "$old" < "$today" ]] && base=$today
  new=$(date -d "$base +$days days" +%F)
  sed -i "s/^\([^|]*|$name|[^|]*|\)[^|]*/\1$new/" "$DB"
  echo "Expired baru untuk $name: $new"
}

clean_expired() {
  local today
  today=$(date +%F)
  if awk -F'|' -v t="$today" '$4 < t {f=1} END {exit !f}' "$DB"; then
    cp "$DB" "$DB.bak"
    awk -F'|' -v t="$today" '$4 >= t' "$DB.bak" > "$DB"
    rebuild || cp "$DB.bak" "$DB"
    echo "Akun expired sudah dihapus."
  else
    echo "Tidak ada akun expired."
  fi
}

set_limit() {
  local name lim
  list_accounts
  read -rp "Nama akun: " name
  grep -q "^[^|]*|$name|" "$DB" || { echo "Akun tidak ditemukan."; return; }
  read -rp "Limit IP baru (0 = tanpa batas): " lim
  [[ "$lim" =~ ^[0-9]{1,3}$ ]] || { echo "Angka tidak valid."; return; }
  awk -F'|' -v OFS='|' -v n="$name" -v l="$lim" '$2 == n { $5 = l } { print }' "$DB" > "$DB.tmp" \
    && mv "$DB.tmp" "$DB"
  echo "Limit IP untuk $name sekarang: $lim"
}

unlock_account() {
  local name
  if [ ! -s "$LOCK" ]; then echo "Tidak ada akun yang terkunci."; return; fi
  echo "Akun terkunci:"
  cut -d'|' -f1 "$LOCK"
  read -rp "Nama akun yang dibuka (atau 'all'): " name
  cp "$LOCK" "$LOCK.bak"
  if [ "$name" = "all" ]; then : > "$LOCK"; else awk -F'|' -v n="$name" '$1 != n' "$LOCK.bak" > "$LOCK"; fi
  if rebuild; then echo "Kunci dibuka."; else cp "$LOCK.bak" "$LOCK"; fi
}

# Dipanggil cron tiap menit: hitung IP unik per akun, kunci sementara kalau melebihi limit
check_limits() {
  local now since changed=0 counts p name id exp lim cnt
  [ -f "$ACCESS_LOG" ] || return 0
  now=$(date +%s)

  # buka kunci yang waktunya sudah lewat
  if [ -s "$LOCK" ]; then
    cp "$LOCK" "$LOCK.bak"
    awk -F'|' -v n="$now" '$2 > n' "$LOCK.bak" > "$LOCK"
    [ "$(wc -l < "$LOCK")" != "$(wc -l < "$LOCK.bak")" ] && changed=1
  fi

  since=$(date -d "-$WINDOW_MIN minutes" "+%Y/%m/%d %H:%M:%S")
  counts=$(tail -n 30000 "$ACCESS_LOG" | awk -v s="$since" '
    ($1 " " $2) >= s {
      for (i = 3; i <= NF; i++) if ($i == "accepted") break
      if (i > NF) next
      ip = $(i - 1); sub(/^(tcp|udp):/, "", ip); sub(/:[0-9]+$/, "", ip)
      if (!(($NF SUBSEP ip) in seen)) { seen[$NF, ip] = 1; c[$NF]++ }
    }
    END { for (n in c) print n, c[n] }')

  while IFS='|' read -r p name id exp lim; do
    [[ "$lim" =~ ^[0-9]+$ ]] && [ "$lim" -gt 0 ] || continue
    grep -q "^$name|" "$LOCK" && continue
    cnt=$(echo "$counts" | awk -v n="$name" '$1 == n { print $2 }')
    if [ "${cnt:-0}" -gt "$lim" ]; then
      echo "$name|$((now + LOCK_MIN * 60))" >> "$LOCK"
      echo "$(date '+%F %T') $name dikunci $LOCK_MIN menit: $cnt IP (limit $lim)" >> /var/log/xray-manager.log
      changed=1
    fi
  done < "$DB"

  [ "$changed" = 1 ] && rebuild
  return 0
}

status_all() {
  echo "xray : $(systemctl is-active xray)"
  echo "nginx: $(systemctl is-active nginx)"
  echo -n "Sertifikat TLS: "
  openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -enddate 2>/dev/null || echo "tidak terbaca"
}

test_path() {
  local p
  for p in vless vmess trojan-ws; do
    echo -n "/$p -> "
    curl -sk -i --http1.1 --max-time 4 \
      -H "Connection: Upgrade" -H "Upgrade: websocket" \
      -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
      "https://$DOMAIN/$p" | head -n 1
  done
  echo "(HTTP/1.1 101 = jalur server beres)"
}

case "$1" in
  --rebuild) rebuild; exit $? ;;
  --clean) clean_expired >/dev/null 2>&1; exit 0 ;;
  --check)
    exec 9>/var/lock/xmenu.lock
    flock -n 9 || exit 0
    check_limits >/dev/null 2>&1
    exit 0 ;;
esac

while true; do
  clear
  echo "=========== XRAY MANAGER ==========="
  echo "Domain: $DOMAIN"
  echo "1) Buat akun VLESS"
  echo "2) Buat akun VMess"
  echo "3) Buat akun Trojan"
  echo "4) Daftar akun"
  echo "5) Lihat link akun"
  echo "6) Hapus akun"
  echo "7) Perpanjang akun"
  echo "8) Hapus akun expired sekarang"
  echo "9) Status layanan dan sertifikat"
  echo "10) Tes jalur server"
  echo "11) Restart layanan"
  echo "12) Ubah limit IP akun"
  echo "13) Buka kunci akun (kena limit IP)"
  echo "0) Keluar"
  echo "===================================="
  read -rp "Pilih: " c
  echo
  case "$c" in
    1) add_account vless ;;
    2) add_account vmess ;;
    3) add_account trojan ;;
    4) list_accounts ;;
    5) show_link ;;
    6) delete_account ;;
    7) extend_account ;;
    8) clean_expired ;;
    9) status_all ;;
    10) test_path ;;
    11) systemctl restart xray nginx && echo "Layanan di-restart." ;;
    12) set_limit ;;
    13) unlock_account ;;
    0) exit 0 ;;
    *) echo "Pilihan tidak dikenal." ;;
  esac
  echo
  read -rp "Tekan Enter untuk kembali ke menu..." _
done
XMENU
chmod +x /usr/local/bin/xmenu

echo "[6/6] Mengaktifkan BBR, cron hapus akun expired, dan Xray..."
cat > /etc/sysctl.d/99-bbr.conf <<'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYSCTL
sysctl --system >/dev/null 2>&1 || true

cat > /etc/cron.d/xray-manager <<'CRON'
5 0 * * * root /usr/local/bin/xmenu --clean >/dev/null 2>&1
* * * * * root /usr/local/bin/xmenu --check >/dev/null 2>&1
CRON
cat > /etc/logrotate.d/xray-manager <<'LOGROT'
/var/log/xray/*.log {
    daily
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}
LOGROT
systemctl enable xray
/usr/local/bin/xmenu --rebuild

echo
echo "==============================================="
echo " Selesai. Ketik: xmenu"
echo " Pastikan port 80 dan 443 (TCP) terbuka di firewall/security group VPS."
echo "==============================================="
