# 00 · Setup: n8n next to Wazuh

Everything the other workflows need:

1. n8n running in Docker on the Wazuh server
2. Credentials in n8n for email, the Wazuh indexer, the Wazuh API and the threat-intel services
3. The `custom-n8n` integration script that lets Wazuh push alerts to n8n

---

## 1. Requirements

- Ubuntu 24.04 server running the **Wazuh all-in-one** install (manager + indexer + dashboard). Tested with Wazuh 4.14.8.
- **Docker** and the **Docker Compose plugin**. Install them from the official guide: <https://docs.docker.com/engine/install/ubuntu/>
- About 1 GB of free RAM and a few GB of disk for n8n.
- An SMTP account for sending email (for example Gmail with an app password).

Let your user run Docker without `sudo`, then check the versions:

```bash
sudo usermod -aG docker $USER
newgrp docker
docker --version
docker compose version
```

## 2. Install n8n

```bash
mkdir ~/n8n && cd ~/n8n
nano docker-compose.yml        # paste docker-compose.yml from this folder
docker compose up -d
docker logs -f n8n             # wait for "Editor is now accessible via: ..."  (Ctrl+C to leave)
```

Replace `<WAZUH_SERVER_IP>` in the file with your server's IP first.

Open `http://<WAZUH_SERVER_IP>:5678` and create the owner account.

### Why these settings

| Setting | Why |
|---------|-----|
| `network_mode: host` | The Wazuh indexer and API only listen on the server itself. A container on Docker's default network counts as a different machine and can't reach `127.0.0.1:9200`. Sharing the host network solves this without opening the indexer to the rest of the network. |
| `N8N_CONCURRENCY_PRODUCTION_LIMIT=1` | Live executions run one at a time. Without it, a brute force that produces 10 alerts in 10 seconds starts 10 lookups in parallel (see [06](../06-auto-ioc-lookup/)). |
| `GENERIC_TIMEZONE` / `TZ` | Schedule triggers ("every day at 9 AM") use this timezone. |
| `N8N_EDITOR_BASE_URL` | The "Open failed execution" button in error emails ([07](../07-workflow-error-alerts/)) uses it. |
| `n8n_data` volume | Holds workflows, credentials and the encryption key. `docker compose down` keeps it; **`docker compose down -v` deletes it.** |

After changing the compose file, apply it with `docker compose up -d` (your workflows stay, they're in the volume).

## 3. n8n basics used in every guide

- **Save vs Publish.** Save only stores your changes. The live trigger (webhook, schedule) runs the last **published** version. After every change: Save → **Publish**.
- **Test URL vs Production URL.** Webhook and form nodes have two URLs. `/webhook-test/...` only works right after you click **Execute workflow** (one call, about 2 minutes). `/webhook/...` is the live one Wazuh uses, and it only works when the workflow is published.
- **Executions tab.** Live runs never show on the editor canvas. Open the workflow → **Executions** → click a run to see what every node received and returned. This is the first place to look when something doesn't work.
- **Node names matter.** Code nodes read other nodes by name, e.g. `$('Detect IOC')`. Name nodes exactly as the guides say.

## 4. Credentials

Create these once in n8n under **Credentials → Add credential**. Each guide says which one to pick.

| Name used in the guides | Type | Values |
|---|---|---|
| **SMTP** | SMTP | Your mail server, port, user, password |
| **Wazuh indexer** | Basic Auth | Indexer user + password (see note below) |
| **Wazuh API** | Basic Auth | Wazuh API user + password (see note below) |
| **VirusTotal** | Header Auth | Name `x-apikey`, value = your VirusTotal API key |
| **AbuseIPDB** | Header Auth | Name `Key`, value = your AbuseIPDB API key |
| **MISP** | Header Auth | Name `Authorization`, value = your MISP API key |
| **OpenCTI** | Header Auth | Name `Authorization`, value = `Bearer <your OpenCTI token>` |

**Indexer user.** In my lab I used the indexer `admin` account. For anything beyond a lab, create a read-only user: Wazuh dashboard → *Indexer management → Security → Internal users* → create `n8n_reader`, then map it to the built-in **`readall`** role.

**Wazuh API user.** In my lab I used `wazuh-wui`. Its password is in the dashboard config:

```bash
sudo grep -A8 "hosts:" /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

A dedicated API user for n8n is better, because changing the `wazuh-wui` password also means updating the dashboard config.

**Copying tokens.** Copy API keys and tokens with the service's copy button or a plain text editor. One OpenCTI token stopped working because a tooltip changed some capital letters while I copied it.

## 5. Wazuh → n8n integration script

Wazuh can run a script for every alert that matches an `<integration>` block. The script here posts the full alert JSON to an n8n webhook. Workflows 01, 06 and 08 each add their own `<integration>` block that uses it.

Custom integration names **must start with `custom-`**. Wazuh needs two files: a launcher (no extension) and the Python script (`.py`).

```bash
# 1. Launcher: copy Wazuh's own Slack launcher. It runs <its own name>.py with Wazuh's Python.
sudo cp /var/ossec/integrations/slack /var/ossec/integrations/custom-n8n

# 2. Script: paste custom-n8n.py from the wazuh/ folder
sudo nano /var/ossec/integrations/custom-n8n.py

# 3. Permissions
sudo chown root:wazuh /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
sudo chmod 750 /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
```

Nothing is sent yet. That starts when a workflow guide adds an `<integration>` block to `/var/ossec/etc/ossec.conf`, for example:

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://localhost:5678/webhook/wazuh-alerts</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

After editing `ossec.conf`, always restart the manager and check that the integrations loaded:

```bash
sudo systemctl restart wazuh-manager
sudo grep -i "integratord" /var/ossec/logs/ossec.log | tail -n 5     # "Enabling integration for: 'custom-n8n'"
```

Every alert the script sends is logged:

```bash
sudo tail -f /var/ossec/logs/integrations.log
# 2026-10-01 05:06:13.397556 custom-n8n: sent rule 5712 level 10 -> HTTP 200
```

`HTTP 200` = n8n accepted it. `HTTP 404` = the webhook path is wrong or the workflow isn't published.

## 6. A safe way to create test alerts

Most guides test with a fake SSH brute force. Run it on the manager or any Linux agent:

```bash
for i in $(seq 1 10); do logger -p auth.info -t "sshd[4242]" "Failed password for invalid user admin from 203.0.113.10 port 5555 ssh2"; sleep 1; done
```

This creates rule **5710** (level 5) for each line and **5712** (brute force, level 10) after 8 attempts. `203.0.113.x` is a range reserved for documentation, so it can never be a real attacker.

## Troubleshooting

| Problem | Cause |
|---------|-------|
| `grep: /var/ossec/logs/alerts/alerts.json: Permission denied` | Use `sudo` |
| n8n can't reach `127.0.0.1:9200` | Container not using `network_mode: host` |
| Webhook returns `404 ... is not registered` | Workflow not published, wrong path, or you used `/webhook-test/` without clicking **Execute workflow** |
| Nothing in `integrations.log` | `<integration>` block missing, wrong `<level>`, or the manager wasn't restarted |
| Changes don't seem to take effect | You saved but didn't **Publish** |
| n8n refuses to publish: *conflicting webhook path* | Another workflow (often an old copy) already uses that path. Unpublish the old one. |
