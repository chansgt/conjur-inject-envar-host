
import csv
import json
import requests
import urllib3
from tqdm import tqdm
import logging
import time
import os
import re
from datetime import datetime
from urllib.parse import quote
from collections import defaultdict

# ========== CONFIG ==========
ORG_ID = 1
account = "VI"
atoken = "ffULT4ib9nzz6UmJha6TZ6FalNUauJ"
username = "host%2fprod%2fserver%2fjenkins%2f100.0.1.43-jenkins"
password = "8j5xvt3jj1ch42h4hcrv1wgaq502tvypf62w2dhhn17b97f21y2eqfp"
conjur_url = "https://dap-master.cyberarkdemo.com"
tower_url = "https://100.0.1.43"
# ============================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

csv_file = input("Enter CSV filename (e.g. list-name.csv): ").strip()

now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
logging.basicConfig(
    filename=f'{now}-conjur-inject.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

logging.info("\n=============== %s ===============", now)
logging.info("=============== start job ===============")

def group_hosts_by_segment_and_os(csv_filename):
    grouped = {}
    os_count_by_segment = {}

    with open(csv_filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ip = row['ip address'].strip()
            os_type = row['os type'].strip().lower()

            ip_segments = ip.split('.')
            if len(ip_segments) < 3:
                continue

            segment = '.'.join(ip_segments[:3])

            if 'windows' in os_type or 'microsoft' in os_type:
                system = 'win'
                inv_name = f"Audit Hardening Prod Conjur Windows-{segment}"
            else:
                system = 'nix'
                inv_name = f"Audit Hardening Prod Conjur-{segment}"

            key = (inv_name, system)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append({
                'ip': ip,
                'account_name': row['account name'].strip()
            })

            if segment not in os_count_by_segment:
                os_count_by_segment[segment] = {'win': 0, 'nix': 0}
            os_count_by_segment[segment][system] += 1

    return grouped, os_count_by_segment

def create_inventory(name, system):
    url = f"{tower_url}/api/v2/inventories/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {atoken}"
    }

    logging.info("------------------ Processing Create Inventory ------------------")
    search_url = f"{url}?name={quote(name)}"
    r = requests.get(search_url, headers=headers, verify=False)
    if r.status_code == 200:
        results = r.json().get("results", [])
        if results:
            logging.info(f"Inventory '{name}' already exists with ID: {results[0]['id']}")
            logging.info("------------------ End of Create Inventory ------------------")
            return results[0]["id"]

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
        logging.info(f"Created inventory '{name}' with ID: {inv_id}")
        logging.info("------------------ End of Create Inventory ------------------")
        return inv_id
    else:
        logging.error(f"Failed to create inventory: {r.status_code} {r.text}")
        logging.info("------------------ End of Create Inventory ------------------")
        return None

auth_token = None
token_acquired_time = None

def authenticate():
    global auth_token, token_acquired_time
    url_login = f"{conjur_url}/api/authn/{account}/{username}/authenticate"
    headers_login = {'Accept-Encoding': 'base64', 'Content-Type': 'text/plain'}

    r = requests.post(url_login, headers=headers_login, data=password, verify=False)
    if r.status_code == 200:
        auth_token = r.text
        token_acquired_time = time.time()
        logging.info("Conjur authentication successful")
        return auth_token
    else:
        logging.error(f"Conjur authentication failed: {r.status_code} {r.text}")
        return None

def token_expired():
    return (time.time() - token_acquired_time) > 420 if token_acquired_time else True

# ========== Main Logic ==========

host_groups, os_stats = group_hosts_by_segment_and_os(csv_file)

# Log OS count per segment
print("\n📊 OS Count per Segment:")
logging.info("------------------ Report OS Count per Segment ------------------")
for segment, count in os_stats.items():
    print(f"  {segment}: Windows = {count['win']}, Unix = {count['nix']}")
    logging.info(f"  {segment}: Windows = {count['win']}, Unix = {count['nix']}")
logging.info("------------------ End of Report ------------------")

if not authenticate():
    print("[ERROR] Cannot authenticate to Conjur.")
    exit(1)

total_hosts = sum(len(hosts) for hosts in host_groups.values())
success_count = 0
fail_count = 0
failed_hosts = defaultdict(list)

with tqdm(total=total_hosts, desc="🚀 Creating Hosts", unit="host") as pbar:
    for (inventory_name, system_type), hosts in host_groups.items():
        inventory_id = create_inventory(inventory_name, system_type)

        if not inventory_id:
            for host in hosts:
                ip = host['ip']
                search = host['account_name']
                segment = '.'.join(ip.split('.')[:3])
                failed_hosts[segment].append({
                    "ip address": ip,
                    "account name": search,
                    "segment": segment,
                    "os type": system_type,
                    "inventory id": None,
                    "inventory name": inventory_name,
                    "error": "Inventory creation failed"
                })
            fail_count += len(hosts)
            pbar.update(len(hosts))
            continue

        for host in hosts:
            ip = host['ip']
            search = host['account_name']
            segment = '.'.join(ip.split('.')[:3])
            search_encoded = quote(search, safe='')

            logging.info(f"======>> start inject for ip: {ip}")

            if token_expired():
                if not authenticate():
                    failed_hosts[segment].append({
                        "ip address": ip,
                        "account name": search,
                        "segment": segment,
                        "os type": system_type,
                        "inventory id": inventory_id,
                        "inventory name": inventory_name,
                        "error": "Token authentication failed"
                    })
                    fail_count += 1
                    pbar.update(1)
                    continue

            url_var = f"{conjur_url}/api/resources/{account}?kind=variable&search={search_encoded}"
            headers_var = {'Authorization': f'Token token="{auth_token}"'}
            response_var = requests.get(url_var, headers=headers_var, verify=False)

            if response_var.status_code != 200:
                failed_hosts[segment].append({
                    "ip address": ip,
                    "account name": search,
                    "segment": segment,
                    "os type": system_type,
                    "inventory id": inventory_id,
                    "inventory name": inventory_name,
                    "error": f"Fetch variable failed: {response_var.status_code} {response_var.text}"
                })
                fail_count += 1
                pbar.update(1)
                continue

            data = response_var.json()
            uvar = pvar = ""
            for item in data:
                var_id = item.get("id", "")
                if var_id.endswith("/username"):
                    uvar = var_id.split(account + ":variable:")[-1]
                if var_id.endswith("/password"):
                    pvar = var_id.split(account + ":variable:")[-1]

            if not (uvar and pvar):
                failed_hosts[segment].append({
                    "ip address": ip,
                    "account name": search,
                    "segment": segment,
                    "os type": system_type,
                    "inventory id": inventory_id,
                    "inventory name": inventory_name,
                    "error": "Missing username or password variable"
                })
                fail_count += 1
                pbar.update(1)
                continue

            variables_dict = {
                "ansible_host": ip,
                "ansible_user": f"{{{{ lookup('cyberark.conjur.conjur_variable','{uvar}',validate_certs=False) }}}}",
                "ansible_password": f"{{{{ lookup('cyberark.conjur.conjur_variable','{pvar}',validate_certs=False) }}}}"
            }

            payload_tower = json.dumps({
                "name": ip,
                "description": "Conjur Credential - Auto Created Script",
                "enabled": True,
                "variables": json.dumps(variables_dict)
            })

            headers_tower = {
                'Content-Type': 'application/json',
                'Authorization': f"Bearer {atoken}"
            }

            url_atower = f"{tower_url}/api/v2/inventories/{inventory_id}/hosts/"
            response_tower = requests.post(url_atower, headers=headers_tower, data=payload_tower, verify=False)
            if response_tower.status_code == 201:
                logging.info(f"Host {ip} created.")
                success_count += 1
            else:
                failed_hosts[segment].append({
                    "ip address": ip,
                    "account name": search,
                    "segment": segment,
                    "os type": system_type,
                    "inventory id": inventory_id,
                    "inventory name": inventory_name,
                    "error": f"Host creation failed: {response_tower.status_code} {response_tower.text}"
                })
                fail_count += 1
            pbar.update(1)

# ========== Write failed hosts ==========
if failed_hosts:
    failed_filename = f"{now}-failed-hosts.csv"
    with open(failed_filename, 'w', newline='') as csvfile:
        fieldnames = ['ip address', 'account name', 'segment', 'os type', 'inventory id', 'inventory name', 'error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for segment in sorted(failed_hosts.keys()):
            for row in failed_hosts[segment]:
                writer.writerow(row)
            writer.writerow({})  # Blank line per segment
    logging.info(f"⚠️ Failed hosts written to {failed_filename}")
    print(f"\n⚠️ Failed hosts written to {failed_filename}")

# ========== Summary ==========
summary_msg = f"\n✅ Success: {success_count} | ❌ Failed: {fail_count}"
print(summary_msg)
logging.info(summary_msg)
logging.info("=============== end job ===============")
