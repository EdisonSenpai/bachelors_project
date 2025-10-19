#!/bin/bash

# IP-ul de blocat primit ca argument
TARGET_IP=$1

# Verificam ca IP-ul este valid
if [[ -z "$TARGET_IP" ]]; then
    echo "Usage: $0 <ip_address>"
    exit 1
fi

echo "[+] Blochez IP-ul $TARGET_IP folosind iptables..."
sudo iptables -A INPUT -s "$TARGET_IP" -j DROP

echo "[*] IP-ul $TARGET_IP a fost blocat. Se va debloca automat dupa 20 secunde..."

# Asteapta 20 de secunde
sleep 20

echo "[*] Deblochez IP-ul $TARGET_IP..."
sudo iptables -D INPUT -s "$TARGET_IP" -j DROP

echo "[+] IP-ul $TARGET_IP a fost deblocat."
