This project helps integrate Conjur with Ansible Tower/Ansible Engine without the hassle of manually creating inventories, hosts, and defining variables for each host.

📋 Requirements
Install the Conjur plugin on Ansible Engine + Conjur authentication.

Python >= 3.10

Library tqdm >= 4.67.1

Library requests >= 2.32.3

Library urllib3 >= 2.2.3

📄 Files in this project
a. conjur-inject-envar-host-v1.6.py
Function:
Automatically creates inventories and hosts, and assigns lookup variables to each host (both Windows and Unix) in Ansible Tower.

b. delete-inventoryu-v1.2.1.py
Function:
Deletes all inventories and hosts in Ansible Tower.
It has a dry run feature to list all inventories that will be deleted, without actually deleting them.

c. fix-missmatch-os-type.py
Function:
Fixes hosts that are placed in the wrong inventory (e.g., Unix hosts placed under Windows inventory or vice versa).

🚀 How to run
python <python_file>

Replace <python_file> with one of the three scripts above.
For example:

python conjur-inject-envar-host-v1.6.py
