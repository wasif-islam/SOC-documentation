# 08 · MISP feedback

Threat intel usually flows one way: MISP tells you what it knows. This workflow sends **your own findings back**. When [06](../06-auto-ioc-lookup/) decides an attacker IP is malicious, the IP is recorded in MISP:

1. **as an attribute** in a dedicated "lab" event, with a comment holding the verdict, the sources that flagged it, the attacked machine, the Wazuh rule, the scores and the time, and
2. **as a sighting**, which marks *every* MISP record of that IP – including ones from your feeds – as "seen in our lab".

```
Wazuh rule 100951 (MALICIOUS verdict from 06)
   ↓  custom-n8n integration (rule_id 100951 only)
Webhook → Prepare MISP record → Find in lab event → New in lab event?
                                                      ├ true  → Add attribute → Add sighting
                                                      └ false ───────────────→ Add sighting
```

**Prerequisites:** [00-setup](../00-setup/) (MISP credential) and a working [06](../06-auto-ioc-lookup/).

**Files**

| File | Used in |
|------|---------|
| `prepare-misp-record.js` | Code node **Prepare MISP record** |
| `wazuh/ossec-integration.xml` | `/var/ossec/etc/ossec.conf` |

---

## Design choices

- **`to_ids = false`.** The records are history, not detection rules. Your own verdicts shouldn't start triggering detections by themselves.
- **Your own records aren't evidence.** The IOC lookup in 06 ignores attributes in the lab event (`MISP_LAB_EVENT_ID`). Otherwise the next lookup of the same IP would find your own record and call the IP suspicious because of it – the workflow agreeing with itself.
- **Separate workflow, triggered by Wazuh.** Wazuh is the hub: 06 writes the verdict into Wazuh, Wazuh forwards only rule 100951 here. The working IOC workflow stays untouched.

---

## Step 1 · Create the lab event in MISP

**Event Actions → Add Event**

| Field | Value |
|-------|-------|
| Distribution | Your organisation only |
| Threat Level | Medium |
| Analysis | Ongoing |
| Event Info | `Wazuh lab - malicious IPs seen (n8n)` |

Submit and note the **event ID** (in the URL: `/events/view/<ID>`). It doesn't need to be published.

## Step 2 · Test the MISP API by hand

```bash
read -s -p "MISP API key: " MKEY; echo
curl -s -X POST <MISP_URL>/attributes/restSearch \
  -H "Authorization: $MKEY" -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"returnFormat":"json","eventid":"<EVENT_ID>","limit":5}'; echo
```

Expected: `{"response":{"Attribute":[]}}`. HTML or a redirect instead means a wrong key, a missing `Accept` header, or MISP forcing HTTPS.

## Step 3 · Build the workflow

Create a workflow named **MISP feedback** (Settings → Error Workflow → Workflow Error Alerts).

| # | Node | Settings |
|---|------|----------|
| 1 | **Webhook** `wazuh-misp` | POST · Path `wazuh-misp` · Authentication None · Respond Immediately |
| 2 | **Code** `Prepare MISP record` | paste `prepare-misp-record.js`, set `LAB_EVENT_ID` to your event ID |
| 3 | **HTTP Request** `Find in lab event` | **POST** `<MISP_URL>/attributes/restSearch` · Header Auth → MISP · Header `Accept: application/json` · JSON body `{{ JSON.stringify($json.searchBody) }}` |
| 4 | **If** `New in lab event?` | `{{ ($json.response?.Attribute || []).length === 0 }}` is true (Boolean) |
| 5 | **HTTP Request** `Add attribute` (from **true**) | **POST** `<MISP_URL>/attributes/add/{{ $('Prepare MISP record').first().json.eventId }}` · Header Auth → MISP · Header `Accept: application/json` · JSON body `{{ JSON.stringify($('Prepare MISP record').first().json.attributeBody) }}` |
| 6 | **HTTP Request** `Add sighting` (from **Add attribute** *and* from the If's **false**) | **POST** `<MISP_URL>/sightings/add` · Header Auth → MISP · Header `Accept: application/json` · JSON body `{{ JSON.stringify($('Prepare MISP record').first().json.sightingBody) }}` |

> **Check the method is POST on all three MISP nodes.** My Add attribute node was on GET. MISP answered with its *help text* for that endpoint ("POST a MISP Attribute JSON to this API…") with status 200 – nothing turned red and nothing was saved.

**Save.** Publish after the test in Step 4.

## Step 4 · Test in the editor

Click **Execute workflow**, then send a fake verdict alert:

```bash
curl -s -X POST http://127.0.0.1:5678/webhook-test/wazuh-misp -H "Content-Type: application/json" \
  -d '{"rule":{"id":"100951","level":9},"agent":{"id":"000"},"data":{"n8n_ioc":{"source":"n8n","ip":"203.0.113.90","verdict":"MALICIOUS","flagged_by":"TEST","vt_malicious":"0","vt_total":"91","abuse_score":"0","agent":"web-server","trigger_rule_id":"5710","trigger_rule":"sshd: Attempt to login using a non-existent user","checked_at":"2026-10-01T10:30:00.000+06:00"}},"location":"API-Webhook"}'; echo
```

- **First run:** the *true* path runs. In MISP the event shows `203.0.113.90` with a comment starting "TEST ONLY - safe to delete", and **1** sighting.
- **Second run** (Execute workflow again, same curl): the *false* path runs and the sighting count becomes **2**.

Then **Publish**.

## Step 5 · Connect Wazuh

Add `wazuh/ossec-integration.xml` inside `<ossec_config>` – note it uses `<rule_id>`, not `<level>`:

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://localhost:5678/webhook/wazuh-misp</hook_url>
  <rule_id>100951</rule_id>
  <alert_format>json</alert_format>
</integration>
```

```bash
sudo systemctl restart wazuh-manager
```

## Step 6 · Stop counting your own records (in 06)

In the **Automatic IOC lookup** workflow, open **Build verdict** and set:

```js
const MISP_LAB_EVENT_ID = '<EVENT_ID>';
```

Save and **Publish**.

## Step 7 · Test the whole chain

```bash
for i in $(seq 1 10); do logger -p auth.info -t "sshd[4242]" "Failed password for invalid user admin from 203.0.113.91 port 5555 ssh2"; sleep 1; done
sleep 60
sudo grep "rule 100951" /var/ossec/logs/integrations.log | tail -n 2     # sent rule 100951 ... HTTP 200
```

`203.0.113.91` should appear in the MISP event with 1 sighting. Afterwards, delete the `203.0.113.x` test attributes – they're all marked "TEST ONLY".

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| Event stays empty, If always goes *true* | A MISP node is on **GET**, or `Accept: application/json` is missing (MISP returns a login page or help text, which n8n treats as success) |
| Add attribute **403** | The API key's user is read-only – use a user with the *User* role or higher |
| Add attribute **403 "similar attribute already exists"** | The IP is already in the event – the sighting is still added |
| No `100951` at all | 06 didn't decide MALICIOUS – check 06 first (test IPs must be `203.0.113.x`) |
| Many attributes or emails for one attack | See *Why the Data Table* in [06](../06-auto-ioc-lookup/) |
