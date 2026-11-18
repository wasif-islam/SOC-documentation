# 01 · Wazuh alert email

> Part of the **Wazuh + n8n SOC Automation** project (9 workflows). Start with [00-setup](00-setup/) if n8n isn't installed yet.

Get an email the moment Wazuh raises a serious alert (level 10 or higher), instead of finding it later in the dashboard.

```
Wazuh alert (level ≥ 10)
   ↓  custom-n8n integration
Webhook  →  If (level ≥ 10)  →  Send Email (HTML)
```

The email shows what happened, which machine, when, how serious it is (HIGH / CRITICAL), the MITRE ATT&CK tactic, and the original log. The log is shown as plain text, so usernames or URLs controlled by an attacker can't turn into clickable links.

**Prerequisites:** [00-setup](00-setup/) done (n8n running, SMTP credential, `custom-n8n` script installed).

**Files**

| File | Used in |
|------|---------|
| `email-template.html` | Send Email node, HTML field |
| `wazuh/ossec-integration.xml` | `/var/ossec/etc/ossec.conf` |

---

## Step 1 · Build the workflow in n8n

Create a workflow named **Wazuh alert email**.

**1. Webhook** (rename it `wazuh-alerts`)

| Setting | Value |
|---------|-------|
| HTTP Method | POST |
| Path | `wazuh-alerts` |
| Authentication | None |
| Respond | Immediately |

n8n puts the posted alert under `body`, so the level is `$json.body.rule.level`.

**2. If** – a second check on the level

| Setting | Value |
|---------|-------|
| Value 1 | `{{ $json.body.rule.level }}` |
| Operator | Number → **is greater than or equal to** |
| Value 2 | `10` |

> My first version used **is equal to** 10. The test passed because the test alert happened to be exactly level 10 – but every alert from 11 to 15, the most serious ones, would have been silently dropped. Use *greater than or equal to*.

**3. Send Email** – connect it to the If node's **true** output

| Setting | Value |
|---------|-------|
| Credential | SMTP |
| From / To | your addresses |
| Subject | `🚨 Wazuh level {{ $json.body.rule.level }}: {{ $json.body.rule.description }} ({{ $json.body.agent.name }})` |
| Email Format | HTML |
| HTML | paste the whole of `email-template.html` (Expression mode) |

Change `https://YOUR-WAZUH-DASHBOARD` near the end of the template to your dashboard URL.

**Save** and **Publish**.

## Step 2 · Tell Wazuh to send alerts

Add the block from `wazuh/ossec-integration.xml` inside `<ossec_config>`:

```bash
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://localhost:5678/webhook/wazuh-alerts</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

## Step 3 · Test

Create a fake SSH brute force (on the manager or any Linux agent):

```bash
for i in $(seq 1 10); do logger -p auth.info -t "sshd[4242]" "Failed password for invalid user admin from 203.0.113.10 port 5555 ssh2"; sleep 1; done
```

After 8 attempts Wazuh raises rule **5712** (level 10, *Credential Access*). Within a few seconds you should get the email.

Check each stage if it doesn't arrive:

```bash
sudo grep "203.0.113.10" /var/ossec/logs/alerts/alerts.json | grep -o '"id":"5712"' | head -n1   # did Wazuh alert?
sudo grep "rule 5712" /var/ossec/logs/integrations.log | tail -n 2                                 # was it sent? HTTP 200?
```

Then open the workflow's **Executions** tab to see whether n8n ran and which node stopped.

## Notes

- Wazuh already filters on `<level>`; the If node is a second safety net in case another integration ever posts to the same webhook.
- Lower `<level>` (and the If value) if you want more alerts, but expect a lot more email.
- Rule levels: 12+ is shown as **CRITICAL** (red), 10–11 as **HIGH** (orange).
