# Exporting n8n workflows safely

The guides in this repo let you build each workflow from scratch. If you also want to publish the workflow files themselves (so others can import them), export them from n8n and **clean them before committing**.

## 1. Export

**One workflow:** open it in n8n → **⋯** (top right) → **Download**. Save it as `workflow.json` inside that workflow's folder.

**All workflows at once** (on the n8n server):

```bash
docker exec -u node n8n n8n export:workflow --all --separate --output=/home/node/.n8n/exports/
docker cp n8n:/home/node/.n8n/exports ./n8n-exports
```

## 2. What an export contains

| Contains | Safe? |
|----------|-------|
| Nodes, settings, connections, Code node source | Yes, after checking for hard-coded values |
| Credential **names and IDs** (not the secrets) | Yes |
| **Pinned test data** (`pinData`) | **No** – it can hold real alerts, IPs and hostnames |
| Webhook IDs, workflow IDs, instance metadata | Better removed |

## 3. Clean it

```bash
# Remove pinned data and instance metadata, and mark it inactive
jq 'del(.pinData) | del(.meta) | .active = false' workflow.json > workflow.clean.json && mv workflow.clean.json workflow.json

# Replace your own IPs and hostnames with placeholders
sed -i 's/192\.168\.1\.10/<WAZUH_SERVER_IP>/g' workflow.json
```

## 4. Check before you commit

```bash
grep -nEi "password|apikey|api_key|secret|token|Bearer [A-Za-z0-9]|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" workflow.json
```

Look at every match. IP addresses inside Code node logic (like `127.` or `192.168.` in private-range checks) are fine; your own server addresses, keys and tokens are not.

## 5. If a secret was ever committed

Removing it in a new commit isn't enough – it stays in the Git history. **Rotate the key or password immediately**, then clean the history (for example with `git filter-repo`) or recreate the repository.
