// ===== n8n Error Alerts: Code node "Format error" =====
// Language: JavaScript, Mode: Run Once for All Items
// Input: the Error Trigger node's data
// Output: { subject, html } for the Send Email node

const d = $input.first().json;
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// n8n sends "execution" when a normal step fails,
// and "trigger" when the trigger itself fails (e.g. a schedule or webhook problem)
const ex = d.execution || {};
const tr = d.trigger || {};
const err = ex.error || tr.error || {};

const workflowName = (d.workflow || {}).name || 'Unknown workflow';
const failedNode = ex.lastNodeExecuted || (err.node && err.node.name) || 'Trigger';
const message = String(err.message || err.description || 'No error message');
const stack = String(err.stack || '').split('\n').slice(0, 8).join('\n');
const when = DateTime.now().setZone('Asia/Dhaka').toFormat('dd MMM yyyy, hh:mm a');
const url = ex.url || '';

// A plain-language hint based on common error types
const m = message.toLowerCase();
let hint = 'Open the failed execution in n8n to see which step failed and what data it received.';
if (/401|403|unauthori[sz]ed|forbidden|invalid api key|logged in|authentication/.test(m))
  hint = 'A credential was rejected. An API key, token or password has probably expired or changed. Check the credential used by the failed step.';
else if (/econnrefused|etimedout|enotfound|ehostunreach|socket hang up|timeout|timed out/.test(m))
  hint = 'A service could not be reached. It may be down, restarting, or blocked by the firewall. Check that the service is running.';
else if (/429|rate limit|too many requests|quota/.test(m))
  hint = 'An API rate limit was reached. Wait a few minutes; it usually recovers by itself.';
else if (/referenced node|doesn\'t exist|not been executed/.test(m))
  hint = 'A step refers to another step by name that no longer exists or did not run. Check node names after any renaming.';
else if (/cannot read|undefined|null/.test(m))
  hint = 'A step expected data that was missing. The incoming data may have changed shape.';

const row = (k, v) => `<tr>
  <td valign="top" style="padding:6px 14px 6px 0;font-size:13px;color:#64748b;white-space:nowrap;">${k}</td>
  <td valign="top" style="padding:6px 0;font-size:13px;color:#1d2433;word-break:break-word;">${v}</td></tr>`;

const html = `
<div style="margin:0;padding:24px 0;background:#f1f5f9;font-family:'Segoe UI',Arial,Helvetica,sans-serif;color:#1d2433;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;">
  <tr><td style="padding:22px 24px;background:#fff7ed;border-bottom:3px solid #ea580c;border-radius:12px 12px 0 0;">
    <div style="font-size:13px;color:#64748b;font-weight:600;">⚙️ n8n automation</div>
    <div style="font-size:22px;font-weight:800;margin-top:6px;">A workflow failed</div>
    <div style="font-size:15px;color:#334155;margin-top:4px;">${esc(workflowName)}</div>
  </td></tr>
  <tr><td style="padding:20px 24px;">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
      ${row('Failed step', `<b>${esc(failedNode)}</b>`)}
      ${row('When', esc(when))}
      ${row('Error', `<span style="color:#b91c1c;">${esc(message)}</span>`)}
      ${ex.id ? row('Execution ID', esc(ex.id)) : ''}
      ${ex.mode ? row('Started by', esc(ex.mode)) : ''}
    </table>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:16px;"><tr>
      <td style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px 14px;font-size:13px;color:#1e3a8a;line-height:1.5;">
        <b>Likely cause:</b> ${esc(hint)}
      </td></tr></table>
    ${stack ? `<div style="font-size:12px;font-weight:700;color:#64748b;margin:16px 0 6px;">Technical details</div>
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px 12px;font-family:Consolas,'Courier New',monospace;font-size:11px;color:#334155;white-space:pre-wrap;word-break:break-all;">${esc(stack)}</div>` : ''}
    ${url ? `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:18px;"><tr>
      <td bgcolor="#ea580c" style="background:#ea580c;border-radius:8px;">
        <a href="${esc(url)}" style="display:inline-block;padding:10px 20px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">Open failed execution</a>
      </td></tr></table>` : ''}
  </td></tr>
</table>
</td></tr></table>
</div>`;

return [{ json: {
  subject: `⚠️ n8n workflow failed: ${workflowName} (${failedNode})`,
  html
} }];
