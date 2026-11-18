// ===== Wazuh daily summary, Code node: "Build daily report" =====
// Language: JavaScript, Mode: Run Once for All Items
// Input:  the HTTP Request node's answer from the Wazuh indexer (daily-query.json)
// Output: { html, subject } for the Send Email node

// ---------- settings you can change ----------
const TZ = 'Asia/Dhaka';                                  // your timezone
const DASHBOARD_URL = 'https://YOUR-WAZUH-DASHBOARD';     // link for the button at the bottom
// ----------------------------------------------

const r = $input.first().json;

// Stop with a clear error instead of emailing a report full of zeros
if (!r || !r.aggregations || !r.hits) {
  const seen = r ? Object.keys(r).join(', ') : 'nothing';
  throw new Error(`The indexer answer has no "aggregations". The HTTP Request node received: [${seen}]. Check Send Body is ON, Body Content Type is JSON, and the indexer credential.`);
}

// ---------- helpers ----------
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const num = n => Number(n || 0).toLocaleString('en-US');
const buckets = a => (a && a.buckets) || [];
const C = { ink: '#1d2433', muted: '#64748b', faint: '#94a3b8', line: '#e2e8f0', teal: '#0f766e',
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#94a3b8' };
const levelColor = l => l >= 12 ? C.critical : l >= 10 ? C.high : l >= 7 ? C.medium : C.low;

// ---------- numbers ----------
const now = DateTime.now().setZone(TZ);
const from = now.minus({ hours: 24 });
const total = r.hits.total?.value ?? r.hits.total ?? 0;
const sev = { low: 0, medium: 0, high: 0, critical: 0 };
for (const b of buckets(r.aggregations.severity)) sev[b.key] = b.doc_count;
const highPlus = sev.high + sev.critical;
const pct = n => total ? `${((n / total) * 100).toFixed(1)}%` : '0%';

// ---------- building blocks ----------
const section = (title, note) => `
  <div style="font-size:16px;font-weight:700;color:${C.ink};margin:26px 0 4px;">${title}</div>
  ${note ? `<div style="font-size:12px;color:${C.muted};margin-bottom:10px;">${note}</div>` : '<div style="height:8px;"></div>'}`;

const card = (label, value, sub, color) => `
  <td width="25%" valign="top" style="padding:4px;">
    <div style="border:1px solid ${C.line};border-radius:10px;padding:12px;">
      <div style="font-size:11px;color:${C.muted};">${label}</div>
      <div style="font-size:22px;font-weight:800;color:${color || C.ink};margin-top:2px;">${value}</div>
      <div style="font-size:11px;color:${C.faint};">${sub}</div>
    </div>
  </td>`;

// Horizontal bars drawn with table cells (email apps don't run scripts)
const barRow = (label, value, max, color, extra = '') => {
  const w = Math.max(2, Math.round((value / (max || 1)) * 100));
  return `<tr>
    <td style="padding:5px 8px 5px 0;font-size:13px;color:${C.ink};width:38%;word-break:break-word;">${label}</td>
    <td style="padding:5px 0;width:47%;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td width="${w}%" style="background:${color};height:10px;border-radius:5px;font-size:1px;line-height:1px;">&nbsp;</td><td style="font-size:1px;">&nbsp;</td>
    </tr></table></td>
    <td align="right" style="padding:5px 0 5px 8px;font-size:13px;font-weight:700;color:${C.ink};white-space:nowrap;">${num(value)}${extra}</td>
  </tr>`;
};

// ---------- 1. severity ----------
const sevRows = [['Critical (12+)', sev.critical, C.critical], ['High (10-11)', sev.high, C.high],
  ['Medium (7-9)', sev.medium, C.medium], ['Low (0-6)', sev.low, C.low]]
  .map(([l, v, c]) => barRow(l, v, total, c, ` <span style="font-weight:400;color:${C.faint};">(${pct(v)})</span>`)).join('');

// ---------- 2. top rules ----------
const topRules = buckets(r.aggregations.top_rules);
const ruleRows = topRules.map(b => {
  const lvl = b.level?.value || 0;
  const d = (b.desc?.buckets?.[0]?.key || '-').trim();
  return `<tr>
    <td valign="top" style="padding:8px;border-bottom:1px solid #eef2f6;font-size:12px;color:${C.muted};">${esc(b.key)}</td>
    <td valign="top" style="padding:8px;border-bottom:1px solid #eef2f6;font-size:13px;color:${C.ink};">${esc(d)}</td>
    <td valign="top" align="center" style="padding:8px;border-bottom:1px solid #eef2f6;"><span style="display:inline-block;padding:2px 8px;border-radius:10px;background:${levelColor(lvl)};color:#fff;font-size:11px;font-weight:700;">${lvl}</span></td>
    <td valign="top" align="right" style="padding:8px;border-bottom:1px solid #eef2f6;font-size:13px;font-weight:700;color:${C.ink};">${num(b.doc_count)}</td>
  </tr>`;
}).join('');

// ---------- 3. agents ----------
const agents = buckets(r.aggregations.top_agents);
const agentRows = agents.map(b => barRow(esc(b.key), b.doc_count, agents[0]?.doc_count, C.teal)).join('');

// ---------- 4. source IPs ----------
const ipRows = buckets(r.aggregations.top_srcips).map(b => {
  const ip = String(b.key);
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(ip);
  const internal = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|fe80:)/i.test(ip);
  const tag = !isIp ? 'Unknown (no real IP in the log)' : internal ? 'Internal' : 'External, check it';
  const tagColor = !isIp ? C.faint : internal ? C.muted : C.critical;
  return `<tr>
    <td style="padding:7px 8px;border-bottom:1px solid #eef2f6;font-family:Consolas,'Courier New',monospace;font-size:12px;color:${C.ink};">${esc(ip)}</td>
    <td style="padding:7px 8px;border-bottom:1px solid #eef2f6;font-size:12px;color:${tagColor};">${tag}</td>
    <td align="right" style="padding:7px 8px;border-bottom:1px solid #eef2f6;font-size:13px;font-weight:700;color:${C.ink};">${num(b.doc_count)}</td>
  </tr>`;
}).join('');

const empty = text => `<div style="font-size:13px;color:${C.faint};">${text}</div>`;
const table = (rows, head) => `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid ${C.line};border-radius:10px;border-collapse:separate;">${head || ''}${rows}</table>`;

const html = `
<div style="margin:0;padding:24px 0;background:#f1f5f9;font-family:'Segoe UI',Arial,Helvetica,sans-serif;color:${C.ink};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;width:100%;background:#ffffff;border:1px solid ${C.line};border-radius:14px;">
  <tr><td style="padding:24px 26px;background:#0f2a3d;border-radius:14px 14px 0 0;">
    <div style="font-size:13px;color:#7dd3c0;font-weight:600;">🛡️ Wazuh SIEM</div>
    <div style="font-size:22px;font-weight:800;color:#ffffff;margin-top:6px;">Daily security summary</div>
    <div style="font-size:14px;color:#cbd5e1;margin-top:4px;">${from.toFormat('dd MMM, hh:mm a')} to ${now.toFormat('dd MMM yyyy, hh:mm a')}</div>
  </td></tr>
  <tr><td style="padding:18px 20px 6px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      ${card('Total alerts', num(total), 'last 24 hours')}
      ${card('High + critical', num(highPlus), `${pct(highPlus)} of all alerts`, highPlus ? C.high : C.ink)}
      ${card('Critical', num(sev.critical), 'level 12 and above', sev.critical ? C.critical : C.ink)}
      ${card('Top machine', esc(agents[0]?.key || '-'), agents[0] ? `${num(agents[0].doc_count)} alerts` : 'no alerts')}
    </tr></table>
  </td></tr>
  <tr><td style="padding:0 26px 10px;">
    ${section('⚠️ Alerts by severity', 'Share of all alerts in the last 24 hours.')}
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${sevRows}</table>

    ${section('🔝 Top rules', 'The rules that fired most.')}
    ${topRules.length ? table(ruleRows, `<tr style="background:#f8fafc;">
      <td style="padding:7px 8px;font-size:11px;color:${C.muted};font-weight:700;">Rule</td>
      <td style="padding:7px 8px;font-size:11px;color:${C.muted};font-weight:700;">Description</td>
      <td align="center" style="padding:7px 8px;font-size:11px;color:${C.muted};font-weight:700;">Level</td>
      <td align="right" style="padding:7px 8px;font-size:11px;color:${C.muted};font-weight:700;">Alerts</td></tr>`) : empty('No alerts in the last 24 hours.')}

    ${section('🖥️ Noisiest machines', 'Alerts per agent.')}
    ${agents.length ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${agentRows}</table>` : empty('No alerts.')}

    ${section('📍 Top source IPs', 'External IPs are marked in red. Values like "?" mean the log had no real address.')}
    ${ipRows ? table(ipRows) : empty('No alerts with a source IP.')}

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 20px;"><tr>
      <td bgcolor="${C.teal}" style="background:${C.teal};border-radius:8px;">
        <a href="${DASHBOARD_URL}" style="display:inline-block;padding:11px 22px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">Open Wazuh dashboard</a>
      </td></tr></table>
  </td></tr>
</table>
</td></tr></table>
</div>`;

return [{ json: {
  html,
  subject: `Wazuh daily summary ${now.toFormat('dd MMM')}: ${num(total)} alerts, ${num(highPlus)} high/critical`
} }];
