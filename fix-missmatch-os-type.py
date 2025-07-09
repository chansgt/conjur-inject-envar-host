import requests
import csv
import logging
import time
from urllib.parse import quote
from datetime import datetime
import urllib3
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CONFIG
tower_url = "https://100.0.1.43"
atoken = "ffULT4ib9nzz6UmJha6TZ6FalNUauJ"
ORG_ID = 1
verify_ssl = False

# Setup Logging
now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
logfile = f"{now}-fix-inventory-hosts.log"
logging.basicConfig(filename=logfile, level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s")
log = logging.getLogger()

# User input
csv_file = input("Enter CSV filename: ").strip()
mode = input("Mode (dryrun/delete/update): ").strip().lower()

if mode not in ["dryrun", "delete", "update"]:
    print("❌ Invalid mode. Choose dryrun, delete, or update.")
    exit(1)

def log_step(level, msg):
    getattr(log, level.lower())(msg)

def get_inventory_id(name):
    url = f"{tower_url}/api/v2/inventories/?name={quote(name)}"
    headers = {"Authorization": f"Bearer {atoken}"}
    r = requests.get(url, headers=headers, verify=verify_ssl)
    if r.status_code == 200 and r.json()["results"]:
        return r.json()["results"][0]["id"]
    return None

def find_host(ip):
    url = f"{tower_url}/api/v2/hosts/?name={ip}"
    headers = {"Authorization": f"Bearer {atoken}"}
    r = requests.get(url, headers=headers, verify=verify_ssl)
    if r.status_code == 200 and r.json()["results"]:
        return r.json()["results"][0]
    return None

def delete_host(host_id):
    url = f"{tower_url}/api/v2/hosts/{host_id}/"
    headers = {"Authorization": f"Bearer {atoken}"}
    r = requests.delete(url, headers=headers, verify=verify_ssl)
    return r.status_code == 204

def create_inventory_if_missing(name, system):
    inv_id = get_inventory_id(name)
    if inv_id:
        return inv_id
    payload = {
        "name": name,
        "description": "Auto-created by fix script",
        "organization": ORG_ID
    }
    if system == "win":
        payload["variables"] = '{"ansible_connection": "winrm", "ansible_port": 5985, "ansible_winrm_transport": "ntlm", "ansible_winrm_server_cert_validation": "ignore"}'
    url = f"{tower_url}/api/v2/inventories/"
    headers = {"Authorization": f"Bearer {atoken}", "Content-Type": "application/json"}
    r = requests.post(url, headers=headers, json=payload, verify=verify_ssl)
    if r.status_code == 201:
        return r.json()["id"]
    return None

def move_host(ip, os_type):
    result = {
        "ip": ip,
        "os_type": os_type,
        "old_inventory": "",
        "new_inventory": "",
        "action": mode,
        "status": "",
        "error": ""
    }

    host = find_host(ip)
    if not host:
        result["status"] = "not found"
        result["action"] = "skip"
        return result

    inv_id = host["inventory"]
    result["old_inventory"] = inv_id
    segment = ".".join(ip.split(".")[:3])

    if "windows" in os_type.lower() or "microsoft" in os_type.lower():
        expected_inv_name = f"Audit Hardening Prod Conjur Windows-{segment}"
        expected_system = "win"
    else:
        expected_inv_name = f"Audit Hardening Prod Conjur-{segment}"
        expected_system = "nix"

    expected_inv_id = get_inventory_id(expected_inv_name)

    if not expected_inv_id:
        if mode == "dryrun":
            result["new_inventory"] = expected_inv_name
            result["status"] = "would create inventory"
            return result
        
        if mode == "update":
            expected_inv_id = create_inventory_if_missing(expected_inv_name, expected_system)
            
            if not expected_inv_id:
                result["error"] = "Failed to create inventory"
                result["status"] = "error"
                return result

    result["new_inventory"] = expected_inv_id

    if inv_id == expected_inv_id:
        result["status"] = "ok"
        result["action"] = "skip"
        return result

    if mode in ["delete", "update"]:
        if not delete_host(host["id"]):
            result["error"] = "Delete failed"
            result["status"] = "error"
            return result
        log_step("info", f"Deleted {ip} from wrong inventory {inv_id}")

    if mode == "update":
        # Recreate host in correct inventory
        payload = {
            "name": ip,
            "description": "Recreated by fix script",
            "enabled": True,
            "variables": "{}"
        }
        url = f"{tower_url}/api/v2/inventories/{expected_inv_id}/hosts/"
        headers = {"Authorization": f"Bearer {atoken}", "Content-Type": "application/json"}
        r = requests.post(url, headers=headers, json=payload, verify=verify_ssl)
        if r.status_code == 201:
            result["status"] = "moved"
            return result
        else:
            result["error"] = f"Recreate failed: {r.status_code} - {r.text}"
            result["status"] = "error"
            return result

    result["status"] = "deleted" if mode == "delete" else "dryrun"
    return result

# Main loop with progress
results = []
with open(csv_file, newline='') as f:
    reader = list(csv.DictReader(f))
    with tqdm(total=len(reader), desc="🔍 Checking Hosts", unit="host") as bar:
        for row in reader:
            ip = row["ip address"].strip()
            os_type = row["os type"].strip()
            res = move_host(ip, os_type)
            results.append(res)
            bar.update(1)


# Write results
output_csv = f"{now}-fixed-hosts.csv"
with open(output_csv, "w", newline="") as f:
    fieldnames = ["ip", "os_type", "old_inventory", "new_inventory", "action", "status", "error"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)

print(f"\n📄 Output written to {output_csv}")
print(f"📝 Logs written to {logfile}")
