#!/usr/bin/env bash
# Create Greenfield's OUs and groups in Samba AD.
# Run on the domain controller (dc1):  sudo bash create_ous_groups.sh
# Safe to re-run: anything that already exists is skipped.
set -euo pipefail

# Folders that users and groups live in.
OUS=(Sales Finance HR IT "Service Accounts" "Disabled Users" Groups)

# name|description (all created in OU=Groups)
# Naming: GRP-<type>-<name>
#   Dept = everyone in a department, Org = company-wide,
#   Role = special responsibility, App = access to one application (Phase 2+)
AD_GROUPS=(
  "GRP-Dept-Sales|All Sales department staff"
  "GRP-Dept-Finance|All Finance department staff"
  "GRP-Dept-HR|All HR department staff"
  "GRP-Dept-IT|All IT department staff"
  "GRP-Org-All-Staff|Every active employee"
  "GRP-Role-IT-Admins|Privileged IT administrators"
  "GRP-Role-Finance-Approvers|Can approve expense payments"
)

existing_ous=$(samba-tool ou list)
for ou in "${OUS[@]}"; do
  if grep -qxF "OU=$ou" <<<"$existing_ous"; then
    echo "OU exists:    $ou"
  else
    samba-tool ou create "OU=$ou" --description="Greenfield $ou"
    echo "OU created:   $ou"
  fi
done

for entry in "${AD_GROUPS[@]}"; do
  name=${entry%%|*}
  desc=${entry#*|}
  if samba-tool group show "$name" >/dev/null 2>&1; then
    echo "Group exists: $name"
  else
    samba-tool group add "$name" --groupou="OU=Groups" --description="$desc"
    echo "Group created: $name"
  fi
done
