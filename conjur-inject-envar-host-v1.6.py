import csv
import json
import requests
import urllib3
from tqdm import tqdm
import logging
import time
import os
from datetime import datetime
from urllib.parse import quote
from collections import defaultdict

# ========== CONFIG ==========
ORG_ID = 1
account = "VI"
atoken = "ffULT4ib9nzz6UmJha6TZ6FalNUauJ"
username = "host%2fprod%2fserver%2fjenkins%2f100.0.1.43-jenkins"
password = "10c8bsm1nzekh72q7jezmwyxvay20trkxyy0vhzxwyz32e126nybv"
conjur_url = "https://dap-master.cyberarkdemo.com"
tower_url = "https://100.0.1.43"
# ============================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

csv_file = input("Enter CSV filename (e.g. list-name.csv): ").strip()

now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_format = '%(asctime)s - %(levelname)s: %(message)s'
logging.basicConfig(filename=f'{now}-conjur-inject.log', level=logging.INFO, format=log_format)

def log_step(level, activity, code=None, msg=None):
    message = f"{activity}"
    if code:
        message += f" | {code} - {msg}"
    getattr(logging, level.lower())(message)

log_step("info", "=============== start job ===============")

def group_hosts(csv_filename):
    grouped = {}
    stats = {}
    with open(csv_filename, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row['ip address'].strip()
            os_type = row['os type'].strip().lower()
            account_name = row['account name'].strip()
            segment = '.'.join(ip.split('.')[:3])

            if 'windows' in os_type or 'microsoft' in os_type:
                system = 'win'
                inv_name = f"Audit Hardening Prod Conjur Windows-{segment}"
            else:
                system = 'nix'
                inv_name = f"Audit Hardening Prod Conjur-{segment}"

            key = (inv_name, system)

            grouped.setdefault(key, []).append({
                'ip': ip,
                'account_name': account_name,
                'os_type': os_type
            })
            stats.setdefault(segment, {'win': 0, 'nix': 0})
            stats[segment][system] += 1
    return grouped, stats

def create_or_get_inventory(name, system):
    url = f"{tower_url}/api/v2/inventories/"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {atoken}"}
    r = requests.get(f"{url}?name={quote(name)}", headers=headers, verify=False)
    if r.status_code == 200 and r.json()["results"]:
        inv_id = r.json()["results"][0]["id"]
        log_step("info", f"Inventory exists: {name}", 200, f"ID {inv_id}")
        return inv_id
    payload = {
        "name": name,
        "description": "Inventory created from script",
        "organization": ORG_ID
    }
    if system == "win":
        payload["variables"] = json.dumps({
            "ansible_connection": "winrm",
            "ansible_port": 5985,
            "ansible_winrm_transport": "ntlm",
            "ansible_winrm_server_cert_validation": "ignore"
        })
    r = requests.post(url, headers=headers, json=payload, verify=False)
    if r.status_code == 201:
        inv_id = r.json()["id"]
        log_step("info", f"Created inventory: {name}", 201)
        return inv_id
    else:
        log_step("ERROR", f"Failed to create inventory: {name}", r.status_code, r.text)
        return None

auth_token = None
token_time = None

def authenticate():
    global auth_token, token_time
    url = f"{conjur_url}/api/authn/{account}/{username}/authenticate"
    headers = {'Accept-Encoding': 'base64', 'Content-Type': 'text/plain'}
    r = requests.post(url, headers=headers, data=password, verify=False)
    if r.status_code == 200:
        auth_token = r.text
        token_time = time.time()
        log_step("info", "Authenticated to Conjur")
        return True
    else:
        log_step("ERROR", "Conjur authentication failed", r.status_code, r.text)
        return False

def token_expired():
    return (time.time() - token_time) > 420 if token_time else True

host_groups, os_stats = group_hosts(csv_file)

print("\n📊 OS Count per Segment:")
log_step("info", "=== OS Count per Segment ===")
for seg, count in os_stats.items():
    msg = f"{seg}: Windows={count['win']}, Unix={count['nix']}"
    print(f"  {msg}")
    log_step("info", msg)

if not authenticate():
    print("[ERROR] Authentication failed.")
    exit(1)

success, updated, failed = [], [], []

total = sum(len(v) for v in host_groups.values())

with tqdm(total=total, desc="🚀 Processing Hosts", unit="host") as bar:
    for (inv_name, system), hosts in host_groups.items():
        inv_id = create_or_get_inventory(inv_name, system)
        if not inv_id:
            for h in hosts:
                h.update({"segment": '.'.join(h['ip'].split('.')[:3]), "inventory name": inv_name, "ERROR": "Inventory creation failed"})
                failed.append(h)
                bar.update(1)
            continue

        for h in hosts:
            ip = h["ip"]
            acct = h["account_name"]
            seg = '.'.join(ip.split('.')[:3])
            log_step("info", f"Start processing {ip}")

            if token_expired() and not authenticate():
                h.update({"segment": seg, "inventory name": inv_name, "ERROR": "Token expired"})
                failed.append(h)
                bar.update(1)
                continue

            search = quote(acct, safe='')
            var_url = f"{conjur_url}/api/resources/{account}?kind=variable&search={search}"
            headers_var = {'Authorization': f'Token token="{auth_token}"'}
            r = requests.get(var_url, headers=headers_var, verify=False)

            if r.status_code != 200:
                h.update({"segment": seg, "inventory name": inv_name, "ERROR": f"Fetch variable failed: {r.status_code} - {r.text}"})
                log_step("ERROR", f"{ip} failed to process with ERROR code {r.status_code} - {r.text}")
                failed.append(h)
                bar.update(1)
                continue

            data = r.json()
            uvar = pvar = ""
            for d in data:
                vid = d.get("id", "")
                if vid.endswith("/username"):
                    uvar = vid.split(account + ":variable:")[-1]
                elif vid.endswith("/password"):
                    pvar = vid.split(account + ":variable:")[-1]
            if not uvar or not pvar:
                h.update({"segment": seg, "inventory name": inv_name, "ERROR": "Username/password not found in Conjur"})
                log_step("ERROR", f"{ip} failed to process reason: Username/password not found in Conjur")
                failed.append(h)
                bar.update(1)
                continue
            
            log_step("INFO", f"{ip} success found variable path in Conjur")

            var_payload = {
                "ansible_host": ip,
                "ansible_user": "{{ lookup('cyberark.conjur.conjur_variable','" + uvar + "',validate_certs=False) }}",
                "ansible_password": "{{ lookup('cyberark.conjur.conjur_variable','" + pvar + "',validate_certs=False) }}",
                "ansible_become_pass": "{{ lookup('cyberark.conjur.conjur_variable','" + pvar + "',validate_certs=False) }}"
            }

            host_payload = {
                "name": ip,
                "description": "Auto created by script",
                "enabled": True,
                "variables": json.dumps(var_payload)
            }
            
            headers = {"Authorization": f"Bearer {atoken}", "Content-Type": "application/json"}

            check_url = f"{tower_url}/api/v2/inventories/{inv_id}/hosts/?name={ip}"
            r_check = requests.get(check_url, headers=headers, verify=False)

            if r_check.status_code == 200 and r_check.json()["results"]:
                host_id = r_check.json()["results"][0]["id"]
                update_url = f"{tower_url}/api/v2/hosts/{host_id}/"
                r_update = requests.patch(update_url, headers=headers, json=host_payload, verify=False)
                if r_update.status_code == 200:
                    h.update({
                        "segment": seg,
                        "inventory name": inv_name,
                        "ERROR": "no ERROR"
                    })
                    updated.append(h)
                    log_step("info", f"Updated host: {ip}")
                else:
                    h.update({"segment": seg, "inventory name": inv_name, "ERROR": f"Update failed: {r_update.status_code} - {r_update.text}"})
                    log_step("ERROR", f"{ip} failed to process with ERROR code {r.status_code} - {r.text}")
                    failed.append(h)
            else:
                create_url = f"{tower_url}/api/v2/inventories/{inv_id}/hosts/"
                r_create = requests.post(create_url, headers=headers, json=host_payload, verify=False)
                if r_create.status_code == 201:
                    h.update({
                        "segment": seg,
                        "inventory name": inv_name,
                        "ERROR": "no ERROR"
                    })
                    success.append(h)
                    log_step("info", f"Created host: {ip}")
                else:
                    h.update({"segment": seg, "inventory name": inv_name, "ERROR": f"Update failed: {r_update.status_code} - {r_update.text}"})
                    log_step("ERROR", f"{ip} failed to process with ERROR code {r.status_code} - {r.text}")
                    failed.append(h)
            bar.update(1)

# ========== Write CSVs ==========
def write_segmented_csv(data, filename_prefix):
    if not data:
        return
    grouped = defaultdict(list)
    for row in data:
        segment = row.get("segment", "unknown")
        grouped[segment].append(row)

    filename = f"{now}-{filename_prefix}-hosts.csv"
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'account_name', 'os_type', 'segment', 'inventory name', 'ERROR']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for segment in sorted(grouped.keys()):
            for row in grouped[segment]:
                writer.writerow(row)
            writer.writerow({})  # Blank line per segment

    log_step("info", f"{filename_prefix.capitalize()} hosts written to {filename}")
    print(f"📄 {filename_prefix.capitalize()} hosts written to {filename}")

write_segmented_csv(success, "success")
write_segmented_csv(updated, "updated")
write_segmented_csv(failed, "failed")

# ========== Summary ==========
summary = f"\n✅ Success: {len(success)} | ✏️ Updated: {len(updated)} | ❌ Failed: {len(failed)}"
print(summary)
log_step("info", summary)
log_step("info", "=============== end job ===============")
