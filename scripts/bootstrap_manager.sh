#!/usr/bin/env bash
# Registers this repo's CDB lists in ossec.conf and restarts the manager.
#
# Why this exists: dropping a file into /var/ossec/etc/lists/ is NOT
# enough for Wazuh to use it - each CDB list must be explicitly declared
# with a <list> entry inside the <ruleset> block of ossec.conf, or the
# <list lookup="..."> references in our rules silently never match anything.
# This is the one piece of setup that can't be done by just bind-mounting
# a directory, so it's scripted and idempotent instead of a manual step
# someone (or CI) will eventually forget.
set -euo pipefail

CONTAINER="${1:-wazuh-manager}"
LISTS=(lsass-access-allowlist app-auth-service-accounts)

echo "Registering CDB lists in ${CONTAINER}:/var/ossec/etc/ossec.conf ..."
for list in "${LISTS[@]}"; do
  docker exec "$CONTAINER" bash -c "
    grep -q 'etc/lists/${list}<' /var/ossec/etc/ossec.conf || \
    sed -i 's#</ruleset>#  <list>etc/lists/${list}</list>\n  </ruleset>#' /var/ossec/etc/ossec.conf
  "
  echo "  - ${list}: ok"
done

echo "Restarting wazuh-manager to load rules/decoders/lists ..."
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control restart

# Poll for the wazuh-logtest socket specifically, not `wazuh-control
# status` - the latter also waits on components (API, indexer-connector)
# this manager-only lab doesn't run and that retry indefinitely without a
# real indexer. See docs/architecture.md "Health check" - the same issue
# tripped up the Docker healthcheck itself before it was fixed the same way.
echo "Waiting for wazuh-logtest socket to come back up ..."
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" test -S /var/ossec/queue/sockets/logtest; then
    echo "Manager ready."
    exit 0
  fi
  sleep 2
done

echo "wazuh-logtest socket did not reappear in time" >&2
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control status >&2 || true
exit 1
