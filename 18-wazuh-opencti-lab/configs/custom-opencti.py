#!/var/ossec/framework/python/bin/python3
# Lab 18: Wazuh -> OpenCTI enrichment.
# Save as /var/ossec/integrations/custom-opencti.py on wazuh-server.
# Wazuh (wazuh-integratord) runs it for every alert listed in <rule_id>,
# with: alert file, API key (OpenCTI token), hook URL (OpenCTI /graphql).
import json
import sys
import time
from socket import socket, AF_UNIX, SOCK_DGRAM

SOCKET_ADDR = '/var/ossec/queue/sockets/queue'
DEBUG = False
LOG_FILE = '/var/ossec/logs/opencti-integration.log'


def debug(msg):
    if DEBUG:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")


def send_event(msg, agent=None):
    """Send the enriched event back into Wazuh's analysis queue."""
    if not agent or agent.get('id') == '000':
        payload = f'1:opencti:{json.dumps(msg)}'
    else:
        name = agent.get('name', '').replace('|', '')
        payload = f"1:[{agent['id']}] ({name}) {agent.get('ip', 'any')}->opencti:{json.dumps(msg)}"
    debug(f"SEND: {payload[:300]}")
    s = socket(AF_UNIX, SOCK_DGRAM)
    s.connect(SOCKET_ADDR)
    s.send(payload.encode())
    s.close()


def query_opencti(url, token, value):
    """Search OpenCTI indicators for the hash (full-text search)."""
    import requests
    query = """
    query Search($search: String) {
      indicators(search: $search, first: 5) {
        edges {
          node {
            id
            name
            pattern
            x_opencti_score
            valid_until
            createdBy { ... on Identity { name } }
            objectLabel { value }
          }
        }
      }
    }
    """
    resp = requests.post(
        url,
        headers={'Content-Type': 'application/json',
                 'Authorization': f'Bearer {token}'},
        json={'query': query, 'variables': {'search': value}},
        timeout=20
    )
    resp.raise_for_status()
    return resp.json()


def exact_match(edges, value):
    """Search is fuzzy: keep only an indicator whose name or pattern holds the exact hash."""
    v = value.lower()
    for edge in edges:
        node = edge.get('node') or {}
        if v == (node.get('name') or '').lower() or v in (node.get('pattern') or '').lower():
            return node
    return None


def extract_hashes(alert):
    """Pull every file hash out of the alert (FIM and decoded fields)."""
    found = []
    syscheck = alert.get('syscheck', {})
    data = alert.get('data', {})
    for key in ('sha256_after', 'sha1_after', 'md5_after'):
        if syscheck.get(key):
            found.append(syscheck[key])
    for key in ('sha256', 'sha1', 'md5'):
        if data.get(key):
            found.append(data[key])
    return list(dict.fromkeys(found))


def main():
    alert_file = sys.argv[1]
    token = sys.argv[2]
    hook_url = sys.argv[3]

    with open(alert_file) as f:
        alert = json.load(f)

    agent = alert.get('agent', {})
    hashes = extract_hashes(alert)
    debug(f"Alert {alert.get('rule', {}).get('id')} -> hashes: {hashes}")

    for value in hashes:
        try:
            result = query_opencti(hook_url, token, value)
        except Exception as e:
            debug(f"QUERY FAILED for {value}: {e}")
            continue

        if result.get('errors'):
            debug(f"GRAPHQL ERROR for {value}: {result['errors']}")
            continue

        edges = ((result.get('data') or {}).get('indicators') or {}).get('edges', [])
        node = exact_match(edges, value)
        if not node:
            debug(f"No match for {value}")
            continue

        labels = [label['value'] for label in (node.get('objectLabel') or [])]
        author = (node.get('createdBy') or {}).get('name', 'unknown')

        send_event({
            'integration': 'opencti',
            'opencti': {
                'found': 1,
                'ioc_type': 'hash',
                'value': value,
                'indicator_id': node.get('id'),
                'score': node.get('x_opencti_score'),
                'valid_until': node.get('valid_until'),
                'author': author,
                'labels': labels,
                'source_rule': alert.get('rule', {}).get('id'),
                'source_description': alert.get('rule', {}).get('description'),
                'source_file': alert.get('syscheck', {}).get('path'),
            }
        }, agent)
        break  # one enriched event per alert


if __name__ == '__main__':
    main()
