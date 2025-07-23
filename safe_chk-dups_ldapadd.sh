#!/bin/bash

# safe_chk-dups_ldapadd.sh
# Adds new users from an LDIF file only if their UID doesn't already exist in LDAP.
# Logs actions to the same directory as the script.
# Use:  ./safe_chk-dups_ldapadd.sh

# LDAP connection settings
LDAP_URI="ldap://localhost"
BASE_DN="ou=people,dc=savagegeek,dc=com"
BIND_DN="cn=admin,dc=savagegeek,dc=com"
LDIF_FILE="users.ldif"  # The LDIF file to import

# Get script directory and set log file
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/safe_chk-dups_ldapadd.log"

# Temporary directory for splitting entries
TEMP_DIR="/tmp/ldap_entries_$$"
mkdir -p "$TEMP_DIR"

# Prompt for LDAP admin password
read -s -p "Enter LDAP password for $BIND_DN: " LDAP_PASS
echo ""

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "Starting LDAP user import from $LDIF_FILE"

# Split LDIF into individual user files
awk '/^dn: /{if (out) print out > file; file="'$TEMP_DIR'/entry_" ++c ".ldif"; out=$0; next} {out=out ORS $0} END{if (out) print out > file}' "$LDIF_FILE"

# Loop through each split entry and check for duplicates
for file in "$TEMP_DIR"/entry_*.ldif; do
    uid=$(grep '^uid:' "$file" | awk '{print $2}')

    if [ -z "$uid" ]; then
        log "WARNING: Skipping $file — UID not found"
        continue
    fi

    # Search for existing user
    if ldapsearch -x -H "$LDAP_URI" -D "$BIND_DN" -w "$LDAP_PASS" -b "$BASE_DN" "uid=$uid" | grep -q "^dn:"; then
        log "User '$uid' already exists. Skipping."
    else
        log "Adding user '$uid'..."
        if ldapadd -x -H "$LDAP_URI" -D "$BIND_DN" -w "$LDAP_PASS" -f "$file" >> "$LOG_FILE" 2>&1; then
            log "User '$uid' added successfully."
        else
            log "ERROR: Failed to add user '$uid'"
        fi
    fi
done

# Clean up temp files
rm -rf "$TEMP_DIR"
log "LDAP user import completed."
