# 04 · Report for any month (form)

> Part of the **Wazuh + n8n SOC Automation** project (9 workflows). Start with [00-setup](00-setup/) if n8n isn't installed yet.

A password-protected form: choose a month and a year, click submit, and the monthly report for that month arrives by email.

```
Form (Month, Year)  →  Prepare dates  →  HTTP Request (Wazuh indexer)  →  Build report  →  Send Email
```

It produces the same report as **03-monthly-report**, without the month-to-month comparison, and with three safety checks:

- A month that **isn't over yet** is labelled "so far" and covers the 1st until now.
- A month **in the future** is refused.
- If the indexer **returns no data**, the workflow stops with an error instead of emailing a report full of zeros.

**Prerequisites:** [00-setup](00-setup/) (n8n, SMTP and **Wazuh indexer** credentials).

**Files**

| File | Used in |
|------|---------|
| `prepare-dates.js` | Code node "Prepare dates" – works out the exact dates and builds the indexer query |
| `build-report.js` | Code node "Build report" |

---

## Step 1 · Build the workflow

Create a workflow named **Wazuh report on demand**.

**1. n8n Form Trigger**

| Setting | Value |
|---------|-------|
| Authentication | Basic Auth (the form can read data about your whole lab, so protect it) |
| Form Title | `Wazuh monthly report` |
| Field 1 | Label **`Month`** · Type *Dropdown* · options `January` … `December` · required |
| Field 2 | Label **`Year`** · Type *Number* · required |

The field labels must be exactly `Month` and `Year` – the code reads them by name.

**2. Code** – name it exactly **`Prepare dates`**, paste `prepare-dates.js`. It uses `Asia/Dhaka`; change `ZONE` at the top and the `'+06:00'` in the daily chart (`per_day`) to your timezone.

**3. HTTP Request** (rename it `Wazuh indexer`)

| Setting | Value |
|---------|-------|
| Method | POST |
| URL | `https://127.0.0.1:9200/wazuh-alerts-*/_search` |
| Authentication | Basic Auth → **Wazuh indexer** |
| Send Body | On · JSON · Using JSON |
| JSON | `{{ JSON.stringify($json.query) }}` (Expression mode) |
| Options → Ignore SSL Issues | On |

**4. Code** – name it **`Build report`**, paste `build-report.js`, set `DASHBOARD_URL` at the top.

**5. Send Email** – Subject `{{ $json.subject }}`, Email Format HTML, HTML `{{ $json.html }}`.

**Save** and **Publish**. Open the form's **Production URL** (in the Form Trigger node) in your browser.

## Step 2 · Test

Submit the form for last month, then for the current month (should say "so far"), then for a future month (should be refused).

## Notes

- I removed a month-to-month comparison I had built. My lab only started collecting alerts halfway through its first month, so every comparison with that month showed a huge increase that wasn't real. The numbers were correct; the story they told wasn't.
- My first test emailed a report full of zeros because the request body wasn't being sent. That's why **Build report** now throws an error when `aggregations.this_month` is missing, and the error message says what to check.
