#!/usr/bin/env python3
# Wazuh -> n8n integration
# Install as: /var/ossec/integrations/custom-n8n.py  (owner root:wazuh, mode 750)
#
# Wazuh's integrator (wazuh-integratord) runs this script for every alert that matches
# an <integration> block whose <name> is "custom-n8n". It posts the full alert JSON to
# the n8n webhook given in <hook_url> and writes one line to integrations.log, e.g.:
#   2026-10-01 05:06:13.397556 custom-n8n: sent rule 5712 level 10 -> HTTP 200
#
# Arguments passed by Wazuh: 1 = alert file, 2 = api_key (unused), 3 = hook_url

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime

LOG_FILE = '/var/ossec/logs/integrations.log'
TIMEOUT_SECONDS = 10


def log(message):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')} custom-n8n: {message}\n")
    except OSError:
        pass


def main(args):
    if len(args) < 4:
        log('error: expected <alert_file> <api_key> <hook_url>')
        sys.exit(1)

    alert_file, hook_url = args[1], args[3]

    with open(alert_file) as f:
        alert = json.load(f)

    rule = alert.get('rule', {})
    request = urllib.request.Request(
        hook_url,
        data=json.dumps(alert).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:  # n8n down, wrong URL, timeout...
        log(f"error sending rule {rule.get('id')} to {hook_url}: {e}")
        sys.exit(1)

    log(f"sent rule {rule.get('id')} level {rule.get('level')} -> HTTP {status}")


if __name__ == '__main__':
    main(sys.argv)
