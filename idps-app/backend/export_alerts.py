import sqlite3
import csv

DB_PATH = 'db/alert_history.db'
EXPORT_PATH = 'db/alerts_for_labeling.csv'

# Etichete automate pentru semnaturi cunoscute
signature_labels = {
    "ICMP Ping detectat - TEST": "malicious",
    "Ping detected": "malicious",
    "ET P2P BitTorrent Announce": "normal",
    "GPL P2P BitTorrent announce request": "normal",
    "ET P2P Vuze BT UDP Connection (5)": "normal",
    "ET POLICY Windows Update P2P Activity": "normal",
    "ET POLICY Spotify P2P Client": "normal",
    "ET INFO Microsoft Connection Test": "information",
    "ET INFO Discord Chat Service Domain in DNS Lookup (discord .com)": "information",
    "ET INFO Observed Discord Domain in DNS Lookup (discord .com)": "information",
    "ET INFO Observed Discord Domain in DNS Lookup (discordapp .com)": "information",
    "ET DNS Query for .cc TLD": "normal",
    "ET INFO Observed Discord Domain (discord .com in TLS SNI)": "information",
    "ET INFO Observed Discord Service Domain (gateway .discord .gg) in TLS SNI": "information",
    "ET INFO Discord Chat Service Domain in DNS Lookup (gateway .discord .gg)": "information",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request On Non-Standard High Port)": "information",      
    "ET INFO Observed Discord Service Domain (discord .com) in TLS SNI": "information",
    "ET USER_AGENTS Steam HTTP Client User-Agent": "normal",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Response)": "information",
    "ET INFO Observed DNS Query to .biz TLD": "information",
    "ET P2P BitTorrent DHT ping request": "normal",
    "GPL P2P BitTorrent transfer": "normal",
    "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)": "information",
    "ET DNS Query for .to TLD": "normal",
    "ET P2P BitTorrent peer sync": "normal",
    "ET P2P Bittorrent P2P Client User-Agent (uTorrent)": "normal",
    "ET P2P BitTorrent DHT nodes reply": "normal",
    "ET P2P BTWebClient UA uTorrent in use" : "normal",
    "ET P2P BitTorrent DHT announce_peers request" : "normal",
    "ET INFO Observed Cloudflare workers.dev Domain in TLS SNI": "information",
    "ET INFO Referrer-Policy set to unsafe-url": "information",
    # adauga altele pe masura ce etichetezi manual si le inveti
}

def export_alerts():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = """
    SELECT timestamp, src_ip, dest_ip, proto, signature 
    FROM alerts 
    ORDER BY timestamp DESC 
    LIMIT 150000;
    """
    cursor.execute(query)
    rows = cursor.fetchall()

    with open(EXPORT_PATH, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['timestamp', 'src_ip', 'dest_ip', 'proto', 'signature', 'label'])

        for row in rows:
            signature = row[4]
            label = signature_labels.get(signature, '')  # eticheta daca exista, altfel gol
            writer.writerow(list(row) + [label])

    conn.close()
    print(f'[+] Exportat {len(rows)} alerte in {EXPORT_PATH}')

if __name__ == '__main__':
    export_alerts()
