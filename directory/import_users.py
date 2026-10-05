"""Import Greenfield employees from data/employees.csv into Samba AD.

For each employee this script:
  1. creates the user in their department OU (e.g. OU=Finance)
  2. adds them to their department group (GRP-Dept-...), GRP-Org-All-Staff
     and any extra_groups (e.g. GRP-Role-IT-Admins)
  3. sets their manager (second pass, once every user exists)

Run from WSL (the domain controller must be reachable on 192.168.56.10):
    python directory/import_users.py

Safe to re-run: existing users are not re-created, only their groups/manager are checked.
Run directory/create_ous_groups.sh on the domain controller first.
"""

import csv
import getpass
import ssl
from pathlib import Path

from ldap3 import MODIFY_ADD, MODIFY_REPLACE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

DC_ADDRESS = "192.168.56.10"
DOMAIN = "greenfield.lab"
BASE_DN = "DC=greenfield,DC=lab"
GROUPS_OU = f"OU=Groups,{BASE_DN}"
CSV_PATH = Path(__file__).parent.parent / "data" / "employees.csv"

# Users must pick their own password the first time they log in.
FORCE_PASSWORD_CHANGE = True

# userAccountControl flag for a normal, enabled user account.
NORMAL_ACCOUNT = 512


def connect():
    """Log in to AD as Administrator over LDAPS (encrypted LDAP, port 636).

    AD only lets you set passwords over an encrypted connection.
    CERT_NONE accepts Samba's self-signed certificate: fine for this lab only.
    """
    admin_password = getpass.getpass("Domain Administrator password: ")
    tls = Tls(validate=ssl.CERT_NONE)
    server = Server(DC_ADDRESS, port=636, use_ssl=True, tls=tls)
    return Connection(server, user=f"administrator@{DOMAIN}", password=admin_password, auto_bind=True)


def find_user_dn(conn, username):
    """Return the user's DN (full path in AD), or None if they don't exist."""
    conn.search(BASE_DN, f"(sAMAccountName={escape_filter_chars(username)})", attributes=["distinguishedName"])
    if conn.entries:
        return conn.entries[0].entry_dn
    return None


def create_user(conn, employee, initial_password):
    """Create one user in their department OU and return their DN."""
    full_name = f"{employee['first_name']} {employee['last_name']}"
    user_dn = f"CN={full_name},OU={employee['department']},{BASE_DN}"

    attributes = {
        "sAMAccountName": employee["username"],           # login name: bonnie.jones
        "userPrincipalName": f"{employee['username']}@{DOMAIN}",
        "givenName": employee["first_name"],
        "sn": employee["last_name"],                       # sn = surname
        "displayName": full_name,
        "mail": employee["email"],
        "employeeID": employee["employee_id"],
        "department": employee["department"],
        "title": employee["job_title"],
        "company": "Greenfield Logistics",
        # AD expects the password in quotes, encoded as UTF-16.
        "unicodePwd": f'"{initial_password}"'.encode("utf-16-le"),
        "userAccountControl": NORMAL_ACCOUNT,
    }
    object_classes = ["top", "person", "organizationalPerson", "user"]

    if not conn.add(user_dn, object_classes, attributes):
        raise RuntimeError(f"Could not create {employee['username']}: {conn.result['message']}")

    if FORCE_PASSWORD_CHANGE:
        # pwdLastSet = 0 means "password must be changed at next login".
        conn.modify(user_dn, {"pwdLastSet": [(MODIFY_REPLACE, ["0"])]})

    return user_dn


def groups_for(employee):
    """Department group + all-staff group + anything listed in extra_groups."""
    groups = [f"GRP-Dept-{employee['department']}", "GRP-Org-All-Staff"]
    if employee["extra_groups"]:
        groups += employee["extra_groups"].split(";")
    return groups


def add_to_group(conn, user_dn, group_name):
    group_dn = f"CN={group_name},{GROUPS_OU}"
    conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
    # A user who is already a member is fine (happens when re-running the script).
    if conn.result["description"] not in ("success", "entryAlreadyExists", "attributeOrValueExists"):
        raise RuntimeError(f"Could not add {user_dn} to {group_name}: {conn.result['message']}")


def main():
    with CSV_PATH.open(newline="") as f:
        employees = list(csv.DictReader(f))

    conn = connect()
    initial_password = getpass.getpass("Initial password for all new users (min. 12 chars): ")

    # Pass 1: create users and add them to groups.
    dn_by_employee_id = {}
    for employee in employees:
        user_dn = find_user_dn(conn, employee["username"])
        if user_dn:
            print(f"exists   {employee['username']}")
        else:
            user_dn = create_user(conn, employee, initial_password)
            print(f"created  {employee['username']}  ->  OU={employee['department']}")

        for group_name in groups_for(employee):
            add_to_group(conn, user_dn, group_name)

        dn_by_employee_id[employee["employee_id"]] = user_dn

    # Pass 2: set managers. Done separately because a manager must exist before
    # anyone can point to them.
    for employee in employees:
        if employee["manager_id"]:
            user_dn = dn_by_employee_id[employee["employee_id"]]
            manager_dn = dn_by_employee_id[employee["manager_id"]]
            conn.modify(user_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})

    print(f"\nDone: {len(employees)} employees processed.")
    conn.unbind()


if __name__ == "__main__":
    main()
