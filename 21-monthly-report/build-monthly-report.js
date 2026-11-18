// ===== Wazuh monthly security report: n8n Code node (JavaScript, "Run Once for All Items") =====
// Input: the HTTP Request node's answer from the Wazuh indexer (monthly-query.json)
// Output: { html, subject } for the Send Email node

// Which month to report on:
//   'last_month' = the previous full month (use this for the automatic run on the 1st)
//   'this_month' = the current month so far (for testing or a mid-month check)
// Must match the query you pasted in the HTTP Request node.
const MODE = 'last_month';

// Link for the "Open Wazuh dashboard" button at the bottom of the email
const DASHBOARD_URL = 'https://YOUR-WAZUH-DASHBOARD';

const r = $input.first().json;

// Stop with a clear error instead of emailing an empty report
if (!r || !r.aggregations || !r.aggregations.this_month) {
  const seen = r ? Object.keys(r).join(', ') : 'nothing';
  throw new Error(`The indexer answer has no "aggregations.this_month". The HTTP Request node received: [${seen}]. Check that Send Body is ON, Body Content Type is JSON, and the whole query is pasted.`);
}

const cur = r.aggregations.this_month;
const prev = r.aggregations.prev_month || {};

// ---------- helpers ----------
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const num = n => Number(n || 0).toLocaleString('en-US');
const buckets = a => (a && a.buckets) || [];
const sevOf = agg => {
  const o = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const b of buckets(agg)) o[b.key] = b.doc_count;
  return o;
};
let COMPARE = 'vs last month';
let NOPREV = 'no data last month';
const change = (now, before) => {
  if (!before) return { text: now ? NOPREV : 'none either month', color: '#64748b' };
  const p = Math.round(((now - before) / before) * 100);
  if (p === 0) return { text: 'same as last month', color: '#64748b' };
  // more alerts = red, fewer = green
  return { text: `${p > 0 ? '▲' : '▼'} ${Math.abs(p)}% ${COMPARE}`, color: p > 0 ? '#dc2626' : '#16a34a' };
};

// ---------- colours ----------
const C = {
  ink: '#1d2433', muted: '#64748b', faint: '#94a3b8', line: '#e2e8f0', soft: '#f8fafc',
  teal: '#0f766e', critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#94a3b8'
};
const levelColor = l => l >= 12 ? C.critical : l >= 10 ? C.high : l >= 7 ? C.medium : C.low;

// ---------- numbers ----------
const now = DateTime.now().setZone('Asia/Dhaka');
const monthStart = MODE === 'this_month' ? now.startOf('month') : now.minus({ months: 1 }).startOf('month');
const monthEnd = MODE === 'this_month' ? now : monthStart.endOf('month');
const monthName = monthStart.toFormat('MMMM yyyy') + (MODE === 'this_month' ? ' (so far)' : '');
const prevName = monthStart.minus({ months: 1 }).toFormat('MMMM');
if (MODE === 'this_month') COMPARE = `vs all of ${prevName}`;
NOPREV = `no ${prevName} data`;

const total = cur.doc_count || 0;
const prevTotal = prev.doc_count || 0;
const sev = sevOf(cur.severity);
const prevSev = sevOf(prev.severity);
const highPlus = sev.high + sev.critical;
const prevHighPlus = prevSev.high + prevSev.critical;
const days = buckets(cur.per_day);
const daysInMonth = MODE === 'this_month' ? now.day : monthEnd.day;
const avgPerDay = Math.round(total / daysInMonth);
const busiest = days.reduce((m, d) => (d.doc_count > (m?.doc_count || 0) ? d : m), null);
const busiestLabel = busiest ? DateTime.fromMillis(busiest.key, { zone: 'Asia/Dhaka' }).toFormat('dd MMM') : '-';

const authFail = cur.auth_fail?.doc_count || 0;
const fim = cur.fim?.doc_count || 0;
const suri = cur.suricata?.doc_count || 0;
const vuln = cur.vuln?.doc_count || 0;

// ---------- building blocks ----------
const section = (icon, title, note) => `
  <div style="font-size:16px;font-weight:700;color:${C.ink};margin:30px 0 4px;">${icon} ${title}</div>
  ${note ? `<div style="font-size:12px;color:${C.muted};margin-bottom:12px;">${note}</div>` : '<div style="height:10px;"></div>'}`;

const empty = `<div style="font-size:13px;color:${C.faint};padding:10px 0;">No data for this month.</div>`;

// KPI tile
const tile = (label, value, sub, subColor) => `
  <td width="25%" valign="top" style="padding:4px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td style="background:${C.soft};border:1px solid ${C.line};border-radius:10px;padding:14px 12px;">
        <div style="font-size:12px;color:${C.muted};">${label}</div>
        <div style="font-size:24px;font-weight:800;color:${C.ink};margin-top:4px;">${value}</div>
        <div style="font-size:11px;color:${subColor || C.muted};margin-top:4px;">${sub}</div>
      </td>
    </tr></table>
  </td>`;

// Horizontal bar list: [{label, value, color, extra}]
const barList = (items, max) => {
  if (!items.length) return empty;
  max = max || Math.max(...items.map(i => i.value), 1);
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">${items.map(i => {
    const w = Math.max(2, Math.round((i.value / max) * 100));
    return `<tr>
      <td width="34%" style="padding:6px 10px 6px 0;font-size:13px;color:${C.ink};word-break:break-word;">${i.label}</td>
      <td style="padding:6px 0;">
        <table role="presentation" width="${w}%" cellpadding="0" cellspacing="0" border="0"><tr>
          <td height="14" bgcolor="${i.color || C.teal}" style="height:14px;font-size:0;line-height:0;background:${i.color || C.teal};border-radius:3px;">&nbsp;</td>
        </tr></table>
      </td>
      <td width="92" align="right" style="padding:6px 0 6px 10px;font-size:13px;font-weight:700;color:${C.ink};white-space:nowrap;">${num(i.value)}${i.extra ? `<div style="font-size:11px;font-weight:400;color:${C.muted};">${i.extra}</div>` : ''}</td>
    </tr>`;
  }).join('')}</table>`;
};

// ---------- 1. severity stacked bar ----------
const sevParts = [
  ['Critical (12+)', sev.critical, prevSev.critical, C.critical],
  ['High (10-11)', sev.high, prevSev.high, C.high],
  ['Medium (7-9)', sev.medium, prevSev.medium, C.medium],
  ['Low (0-6)', sev.low, prevSev.low, C.low]
];
const sevBar = total ? `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-radius:6px;overflow:hidden;"><tr>
    ${sevParts.filter(p => p[1] > 0).map(p => {
      const w = Math.max(1, Math.round((p[1] / total) * 100));
      return `<td width="${w}%" height="18" bgcolor="${p[3]}" style="height:18px;font-size:0;line-height:0;background:${p[3]};">&nbsp;</td>`;
    }).join('')}
  </tr></table>` : empty;
const sevLegend = `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:12px;">
    ${sevParts.map(p => {
      const ch = change(p[1], p[2]);
      const pct = total ? ((p[1] / total) * 100).toFixed(1) : '0.0';
      return `<tr>
        <td width="18" style="padding:5px 0;"><div style="width:10px;height:10px;border-radius:2px;background:${p[3]};"></div></td>
        <td style="padding:5px 0;font-size:13px;color:${C.ink};">${p[0]}</td>
        <td align="right" style="padding:5px 0;font-size:13px;font-weight:700;color:${C.ink};">${num(p[1])} <span style="font-weight:400;color:${C.muted};">(${pct}%)</span></td>
        <td align="right" width="150" style="padding:5px 0;font-size:11px;color:${ch.color};">${ch.text}</td>
      </tr>`;
    }).join('')}
  </table>`;

// ---------- 2. daily trend column chart ----------
const maxDay = Math.max(...days.map(d => d.doc_count), 1);
const CHART_H = 120;
const trendChart = days.length ? `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-bottom:1px solid ${C.line};"><tr>
    ${days.map(d => {
      const hp = d.high_plus?.doc_count || 0;
      const rest = d.doc_count - hp;
      const hTotal = Math.round((d.doc_count / maxDay) * CHART_H);
      const hHigh = d.doc_count ? Math.round((hp / d.doc_count) * hTotal) : 0;
      const hRest = Math.max(0, hTotal - hHigh);
      const dayLabel = DateTime.fromMillis(d.key, { zone: 'Asia/Dhaka' }).toFormat('dd MMM');
      return `<td valign="bottom" align="center" style="padding:0 1px;height:${CHART_H}px;" title="${dayLabel}: ${d.doc_count} alerts, ${hp} high or critical">
        ${hHigh ? `<div style="height:${hHigh}px;background:${C.critical};font-size:0;line-height:0;">&nbsp;</div>` : ''}
        ${hRest ? `<div style="height:${hRest}px;background:${C.teal};font-size:0;line-height:0;">&nbsp;</div>` : ''}
      </td>`;
    }).join('')}
  </tr></table>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
    ${days.map((d, i) => {
      const dt = DateTime.fromMillis(d.key, { zone: 'Asia/Dhaka' });
      const show = i === 0 || dt.day % 5 === 0;
      return `<td align="center" style="padding-top:4px;font-size:10px;color:${C.faint};">${show ? dt.day : ''}</td>`;
    }).join('')}
  </tr></table>
  <div style="font-size:11px;color:${C.muted};margin-top:8px;">
    <span style="display:inline-block;width:10px;height:10px;background:${C.teal};border-radius:2px;vertical-align:middle;"></span> Alerts per day
    &nbsp;&nbsp;<span style="display:inline-block;width:10px;height:10px;background:${C.critical};border-radius:2px;vertical-align:middle;"></span> High or critical (level 10+)
    &nbsp;&nbsp;Tallest day: ${num(maxDay)}
  </div>` : empty;

// ---------- 3. key findings (plain sentences) ----------
const topRule = buckets(cur.top_rules)[0];
const topAgent = buckets(cur.top_agents)[0];
const findings = [];
const cmpWord = `${MODE === 'this_month' ? 'all of ' : ''}${prevName}`;
if (prevTotal) {
  findings.push(`${num(total)} alerts this month, ${change(total, prevTotal).text.replace(COMPARE, `compared with ${cmpWord}`)} (${num(prevTotal)}).`);
  findings.push(`${num(highPlus)} alerts were high or critical (level 10+), ${change(highPlus, prevHighPlus).text.replace(COMPARE, `compared with ${cmpWord}`)} (${num(prevHighPlus)}).`);
} else {
  findings.push(`${num(total)} alerts this month. There is no ${prevName} data to compare with yet.`);
  findings.push(`${num(highPlus)} alerts were high or critical (level 10+).`);
}
if (topAgent) findings.push(`${esc(topAgent.key)} was the noisiest agent with ${num(topAgent.doc_count)} alerts (${total ? Math.round(topAgent.doc_count / total * 100) : 0}% of all alerts).`);
if (topRule) {
  const td = (topRule.desc?.buckets?.[0]?.key || '').trim();
  findings.push(`The most frequent rule was ${esc(topRule.key)} (${esc(td.length > 80 ? td.slice(0, 80) + '...' : td)}) with ${num(topRule.doc_count)} alerts.`);
}
if (vuln) findings.push(`${num(vuln)} alerts came from the vulnerability detector (${total ? Math.round(vuln / total * 100) : 0}% of all alerts).`);
if (busiest) findings.push(`The busiest day was ${busiestLabel} with ${num(busiest.doc_count)} alerts.`);
const findingsHtml = `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
    <td style="background:#ecfdf5;border:1px solid #a7f3d0;border-radius:10px;padding:14px 18px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="font-size:13px;line-height:1.55;color:${C.ink};">
        ${findings.map(f => `<tr><td valign="top" style="padding:3px 10px 3px 0;color:${C.teal};font-weight:700;">•</td><td style="padding:3px 0;">${f}</td></tr>`).join('')}
      </table>
    </td>
  </tr></table>`;

// ---------- 4. activity by category tiles ----------
const catTile = (icon, label, value, note) => `
  <td width="50%" valign="top" style="padding:4px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      <td style="border:1px solid ${C.line};border-radius:10px;padding:12px 14px;">
        <div style="font-size:12px;color:${C.muted};">${icon} ${label}</div>
        <div style="font-size:20px;font-weight:800;color:${C.ink};margin-top:2px;">${num(value)}</div>
        <div style="font-size:11px;color:${C.faint};margin-top:2px;">${note}</div>
      </td>
    </tr></table>
  </td>`;
const categories = `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
    <tr>${catTile('🔑', 'Failed logins', authFail, 'SSH and system authentication failures')}${catTile('📁', 'File changes', fim, 'File Integrity Monitoring events')}</tr>
    <tr>${catTile('🌐', 'Network alerts', suri, 'Suricata IDS detections')}${catTile('🩹', 'Vulnerability alerts', vuln, 'Vulnerable or patched packages')}</tr>
  </table>`;

// ---------- 5. top rules table ----------
const ruleRows = buckets(cur.top_rules).map(b => {
  const lvl = b.level?.value || 0;
  const d = (b.desc?.buckets?.[0]?.key || '-').trim();
  const others = b.desc?.sum_other_doc_count || 0;
  const w = Math.max(2, Math.round((b.doc_count / (buckets(cur.top_rules)[0]?.doc_count || 1)) * 100));
  return `<tr>
    <td valign="top" style="padding:9px 8px;border-bottom:1px solid #eef2f6;font-size:12px;color:${C.muted};white-space:nowrap;">${esc(b.key)}</td>
    <td valign="top" style="padding:9px 8px;border-bottom:1px solid #eef2f6;font-size:13px;color:${C.ink};">
      ${esc(d)}${others ? `<div style="font-size:11px;color:${C.faint};margin-top:2px;">Example shown; ${num(others)} alerts had other descriptions</div>` : ''}
      <table role="presentation" width="${w}%" cellpadding="0" cellspacing="0" border="0" style="margin-top:6px;"><tr><td height="4" style="height:4px;font-size:0;line-height:0;background:${levelColor(lvl)};border-radius:2px;">&nbsp;</td></tr></table>
    </td>
    <td valign="top" align="center" style="padding:9px 8px;border-bottom:1px solid #eef2f6;">
      <span style="display:inline-block;min-width:22px;padding:2px 6px;border-radius:10px;background:${levelColor(lvl)};color:#fff;font-size:11px;font-weight:700;">${esc(lvl)}</span>
    </td>
    <td valign="top" align="right" style="padding:9px 8px;border-bottom:1px solid #eef2f6;font-size:13px;font-weight:700;color:${C.ink};">${num(b.doc_count)}</td>
  </tr>`;
});
const rulesTable = ruleRows.length ? `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid ${C.line};border-radius:10px;">
    <tr>
      <td style="padding:8px;background:${C.soft};font-size:11px;font-weight:700;color:${C.muted};">Rule</td>
      <td style="padding:8px;background:${C.soft};font-size:11px;font-weight:700;color:${C.muted};">Description</td>
      <td align="center" style="padding:8px;background:${C.soft};font-size:11px;font-weight:700;color:${C.muted};">Level</td>
      <td align="right" style="padding:8px;background:${C.soft};font-size:11px;font-weight:700;color:${C.muted};">Alerts</td>
    </tr>${ruleRows.join('')}
  </table>` : empty;

// ---------- 6. agents, tactics, suricata, vulns, IPs ----------
const agentBars = barList(buckets(cur.top_agents).map(b => ({
  label: esc(b.key), value: b.doc_count, color: C.teal,
  extra: (b.high_plus?.doc_count || 0) ? `${num(b.high_plus.doc_count)} high+` : ''
})));
const tacticBars = barList(buckets(cur.mitre_tactics).map(b => ({ label: esc(b.key), value: b.doc_count, color: '#7c3aed' })));
const sigBars = barList(buckets(cur.suricata?.top_sigs).map(b => ({ label: esc(b.key), value: b.doc_count, color: '#2563eb' })));
const vSevColor = k => ({ Critical: C.critical, High: C.high, Medium: C.medium, Low: C.low }[k] || C.low);
const vOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const vulnSevBars = barList([...buckets(cur.vuln?.sev)].sort((a, b) => (vOrder[a.key] ?? 9) - (vOrder[b.key] ?? 9)).map(b => ({ label: b.key === '-' ? 'Not rated (mostly "solved" alerts)' : esc(b.key), value: b.doc_count, color: vSevColor(b.key) })));
const vulnPkgBars = barList(buckets(cur.vuln?.top_pkgs).map(b => ({ label: esc(b.key), value: b.doc_count, color: '#db2777' })));
const ipRows = buckets(cur.top_srcips).map(b => {
  const ip = String(b.key);
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(ip);
  const internal = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|fe80:)/i.test(ip);
  const tag = !isIp ? 'Unknown (no real IP in the log)' : internal ? 'Internal' : 'External, check it';
  const tagColor = !isIp ? C.faint : internal ? C.muted : C.critical;
  return `<tr>
    <td style="padding:8px 10px;border-bottom:1px solid #eef2f6;font-size:13px;font-family:Consolas,'Courier New',monospace;color:${C.ink};">${esc(ip)}</td>
    <td style="padding:8px 10px;border-bottom:1px solid #eef2f6;font-size:12px;color:${tagColor};">${tag}</td>
    <td align="right" style="padding:8px 10px;border-bottom:1px solid #eef2f6;font-size:13px;font-weight:700;color:${C.ink};">${num(b.doc_count)}</td>
  </tr>`;
});
const ipTable = ipRows.length ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid ${C.line};border-radius:10px;">${ipRows.join('')}</table>` : empty;

// ---------- assemble ----------
const totalCh = change(total, prevTotal);
const hpCh = change(highPlus, prevHighPlus);

const html = `
<div style="margin:0;padding:24px 0;background:#f1f5f9;font-family:'Segoe UI',Arial,Helvetica,sans-serif;color:${C.ink};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;width:100%;background:#fff;border:1px solid ${C.line};border-radius:14px;">

  <tr><td style="padding:28px 28px 22px;background:#0f2a3a;border-radius:14px 14px 0 0;">
    <div style="font-size:13px;color:#99f6e4;font-weight:600;">🛡️ Wazuh SIEM</div>
    <div style="font-size:26px;font-weight:800;color:#ffffff;margin-top:6px;">Monthly security report</div>
    <div style="font-size:15px;color:#cbd5e1;margin-top:4px;">${monthName} · ${monthStart.toFormat('dd MMM')} to ${monthEnd.toFormat('dd MMM yyyy')}</div>
  </td></tr>

  <tr><td style="padding:18px 24px 30px;">

    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      ${tile('Total alerts', num(total), totalCh.text, totalCh.color)}
      ${tile('High + critical', num(highPlus), hpCh.text, hpCh.color)}
      ${tile('Daily average', num(avgPerDay), `over ${daysInMonth} days`)}
      ${tile('Busiest day', busiestLabel, busiest ? `${num(busiest.doc_count)} alerts` : '')}
    </tr></table>

    ${section('📌', 'Key findings', 'Written automatically from this month\'s numbers.')}
    ${findingsHtml}

    ${section('⚠️', 'Alerts by severity', prevTotal ? `Compared with ${prevName}.` : `No ${prevName} data to compare with yet.`)}
    ${sevBar}
    ${sevLegend}

    ${section('📈', 'Daily trend', 'Each bar is one day. The red part is high or critical alerts.')}
    ${trendChart}

    ${section('🧭', 'Activity by category')}
    ${categories}

    ${section('🔝', 'Top 10 rules', 'The rules that fired most. The coloured line shows count and level.')}
    ${rulesTable}

    ${section('🖥️', 'Alerts by agent', 'Total alerts per machine, with high and critical alerts under the count.')}
    ${agentBars}

    ${section('🎯', 'Attack types (MITRE ATT&CK tactics)', 'What the attacker would be trying to achieve, based on rule mappings.')}
    ${tacticBars}

    ${section('🌐', 'Top Suricata detections', 'Network traffic Suricata flagged most often.')}
    ${sigBars}

    ${section('🩹', 'Vulnerabilities', 'Vulnerability detector alerts by severity, and the packages involved most often.')}
    ${vulnSevBars}
    <div style="font-size:12px;font-weight:700;color:${C.muted};margin:14px 0 6px;">Most affected packages</div>
    ${vulnPkgBars}

    ${section('📍', 'Top source IPs', 'IPs seen most often in alerts. External IPs are marked in red.')}
    ${ipTable}

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:28px;"><tr>
      <td bgcolor="${C.teal}" style="background:${C.teal};border-radius:8px;">
        <a href="${DASHBOARD_URL}" style="display:inline-block;padding:11px 22px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">Open Wazuh dashboard</a>
      </td>
    </tr></table>

  </td></tr>

</table>
</td></tr></table>
</div>`;

return [{ json: {
  html,
  subject: `Wazuh monthly report ${monthName}: ${num(total)} alerts, ${num(highPlus)} high/critical (${totalCh.text})`
} }];
