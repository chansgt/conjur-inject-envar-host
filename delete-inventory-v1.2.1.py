import requests
import urllib3
import csv
from datetime import datetime
from tqdm import tqdm  # Progress bar

# ========== CONFIG ==========
tower_url = "https://100.0.1.43"
atoken = "ffULT4ib9nzz6UmJha6TZ6FalNUauJ"
pattern = "Audit Hardening Prod Conjur"
read_only = False  # True = hanya lihat dan log, False = hapus semua

# ========== SETUP ==========
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    "Authorization": f"Bearer {atoken}",
    "Content-Type": "application/json"
}

now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = f"{now}-delete-inventory.log"
csv_file = f"{now}-inventory-list.csv"

def log_to_file(msg):
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(msg + '\n')

# ========== FIND INVENTORIES ==========
print(f"🔍 Searching for inventories with pattern: '{pattern}'")
log_to_file(f"START - Inventory Deletion Job ({'READ-ONLY' if read_only else 'DELETE'})")
log_to_file(f"Pattern: {pattern}")

inventories = []
url = f"{tower_url}/api/v2/inventories/?page_size=100"

while url:
    # Jika URL adalah relative (tidak mulai dengan http), tambahkan prefix tower_url
    if not url.startswith("http"):
        url = f"{tower_url}{url}"
    
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        print(f"❌ Failed to get inventories: {response.status_code} - {response.text}")
        log_to_file(f"[ERROR] Failed to get inventories: {response.status_code} - {response.text}")
        exit(1)

    data = response.json()
    inventories.extend(data.get("results", []))
    url = data.get("next")

matched_inventories = [inv for inv in inventories if pattern.lower() in inv["name"].lower()]

# ========== WRITE INVENTORY CSV ==========
with open(csv_file, 'w', newline='', encoding='utf-8') as f:
    fieldnames = ['inventory_id', 'inventory_name', 'host_deleted', 'status']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()

    # ========== PROCESS EACH INVENTORY ==========
    deleted_hosts = 0
    deleted_inventories = 0

    for inv in tqdm(matched_inventories, desc="🧹 Processing inventories", unit="inventory", ncols=100):
        inv_id = inv['id']
        inv_name = inv['name']
        host_deleted_count = 0
        status = "READ-ONLY"

        log_to_file(f"\nProcessing Inventory: {inv_name} (ID: {inv_id})")
        print(f"\n🔨 Inventory: {inv_name} (ID: {inv_id})")

        # Step 1: Get Hosts
        host_url = f"{tower_url}/api/v2/inventories/{inv_id}/hosts/"
        host_res = requests.get(host_url, headers=headers, verify=False)
        hosts = host_res.json().get("results", [])

        for host in tqdm(hosts, desc=f"   🧽 Hosts in {inv_name}", unit="host", ncols=90, leave=True):
            host_id = host["id"]
            ip = host["name"]

            if read_only:
                log_to_file(f"  [READ] Host: {ip} (ID: {host_id})")
                print(f"  [READ] Host: {ip} (ID: {host_id})")
            else:
                del_host_url = f"{tower_url}/api/v2/hosts/{host_id}/"
                del_host_res = requests.delete(del_host_url, headers=headers, verify=False)
                if del_host_res.status_code in (200, 202, 204):
                    host_deleted_count += 1
                    deleted_hosts += 1
                    log_to_file(f"  [✓] Deleted host {ip} (Status {del_host_res.status_code})")
                    print(f"  [✓] Deleted host {ip} (Status {del_host_res.status_code})")
                else:
                    err = del_host_res.text.strip() or "No error message"
                    log_to_file(f"  [x] Failed to delete host {ip}: {del_host_res.status_code} - {err}")
                    print(f"  [x] Failed to delete host {ip}: {del_host_res.status_code} - {err}")

        # Step 2: Delete Inventory
        if read_only:
            log_to_file(f"  [READ] Inventory remains: {inv_name}")
            print(f"  [READ] Inventory remains: {inv_name}")
        else:
            del_inv_url = f"{tower_url}/api/v2/inventories/{inv_id}/"
            del_inv_res = requests.delete(del_inv_url, headers=headers, verify=False)
            if del_inv_res.status_code in (200, 202, 204):
                status = f"{del_inv_res.status_code} - Deleted (Accepted)"
                log_to_file(f"  [✓] Deleted inventory: {inv_name} (Status {del_inv_res.status_code})")
                print(f"  [✓] Deleted inventory: {inv_name} (Status {del_inv_res.status_code})")
                deleted_inventories += 1
            else:
                err = del_inv_res.text.strip() or "No error message"
                status = f"{del_inv_res.status_code} - {err}"
                log_to_file(f"  [x] Failed to delete inventory: {inv_name} — {status}")
                print(f"  [x] Failed to delete inventory: {inv_name} — {status}")

        writer.writerow({
            'inventory_id': inv_id,
            'inventory_name': inv_name,
            'host_deleted': host_deleted_count,
            'status': status
        })

print(f"📄 Found {len(matched_inventories)} inventories matching pattern. Written to: {csv_file}")
log_to_file(f"Found {len(matched_inventories)} inventories")
log_to_file(f"Inventory list saved to {csv_file}")

# ========== SUMMARY ==========
print("\n🎉 Deletion Summary:")
print(f"✓ Inventories matched : {len(matched_inventories)}")
print(f"✓ Hosts deleted       : {deleted_hosts}")
print(f"✓ Inventories deleted : {deleted_inventories}")

log_to_file(f"\nSUMMARY:")
log_to_file(f"Matched Inventories: {len(matched_inventories)}")
log_to_file(f"Deleted Hosts: {deleted_hosts}")
log_to_file(f"Deleted Inventories: {deleted_inventories}")
log_to_file(f"END - Inventory Deletion Job ({'READ-ONLY' if read_only else 'DELETE'})")
