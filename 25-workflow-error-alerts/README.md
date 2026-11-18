# 07 · Workflow error alerts

> Part of the **Wazuh + n8n SOC Automation** project (9 workflows). Start with [00-setup](00-setup/) if n8n isn't installed yet.

When any of your n8n workflows fails, get an email that says **which workflow, which step, when, the error, a likely cause in plain language**, and a button that opens the failed run.

Without this, a failed workflow just stops silently – you only notice when a report doesn't arrive.

```
Any workflow fails  →  Error Trigger  →  Format error  →  Send Email
```

**Likely causes it recognises**

| Error contains | Hint in the email |
|----------------|-------------------|
| 401 / 403 / unauthorized | A credential was rejected – an API key, token or password probably changed |
| ECONNREFUSED / timeout / ENOTFOUND | A service couldn't be reached – it may be down or blocked |
| 429 / rate limit | An API rate limit was hit – usually recovers by itself |
| "referenced node" / "not been executed" | A step refers to another step by a name that changed |
| undefined / null | Data arrived in a different shape than expected |

**Prerequisites:** [00-setup](00-setup/) (n8n, SMTP credential). Set `N8N_EDITOR_BASE_URL` in the compose file so the button links to your server, not `localhost`.

**Files:** `format-error.js` – Code node **Format error**.

---

## Step 1 · Build the error workflow

Create a workflow named **Workflow Error Alerts**.

1. **Error Trigger** – no settings.
2. **Code** → `Format error` – paste `format-error.js`. It uses `Asia/Dhaka` for the time; change it if needed.
3. **Send Email** – Subject `{{ $json.subject }}`, Email Format HTML, HTML `{{ $json.html }}`.

**Save** and **Publish**.

## Step 2 · Connect your other workflows to it

In **each** workflow you want watched: **⋯ → Settings → Error Workflow → Workflow Error Alerts** → Save → Publish.

## Step 3 · Test with a workflow that fails on purpose

The Error Trigger only reacts to **real (production) runs**, not to runs you start by hand in the editor. Running the error workflow manually just shows n8n's sample data – that confused me at first.

1. Create a workflow **Error Test**: **Schedule Trigger** (every 1 minute) → **Code** with:
   ```js
   throw new Error('Test failure: checking that error alerts work');
   ```
2. Settings → Error Workflow → **Workflow Error Alerts**. **Publish.**
3. Within a minute you get *"⚠️ n8n workflow failed: Error Test (Code)"*, started by *trigger*, with the execution ID and the button.
4. **Unpublish Error Test**, or it emails you every minute.

## Notes

- Source nodes in the IOC workflows use *Never Error* / *On Error: Continue* on purpose, so a single failing source doesn't stop the lookup. Those failures appear inside the verdict ("incomplete check") instead of here.
- The email shows the first 8 lines of the stack trace for debugging.
