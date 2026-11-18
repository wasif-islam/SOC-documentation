// ===== Wazuh agent health, Code node: "Check agent health" =====
// Keep this node named exactly:  Check agent health
// Language: JavaScript, Mode: Run Once for All Items
// Input:  the agent list from the node named "Get agents" (Wazuh API: GET /agents)
// Output: { notify, subject, html, summary } for the If + Send Email nodes
//
// It only emails you when something CHANGES (a new problem, or an agent recovered),
// plus a reminder every few hours for agents that are still down.
// Note: this memory only works in the published (scheduled) workflow,
// so every manual test run treats all current problems as new. That's expected.

// ---------- settings you can change ----------
const REMIND_EVERY_HOURS = 6;   // still-disconnected agents are reported again every N hours
const IGNORE_AGENTS = [];       // agent names to ignore, e.g. ['old-test-vm']
const TZ = 'Asia/Dhaka';
// ----------------------------------------------

const res = $('Get agents').first().json;
const agents = (res.data?.affected_items || []).filter(a => !IGNORE_AGENTS.includes(a.name));
if (!agents.length) throw new Error('The Wazuh API returned no agents. Check the "Get agents" step and the API login.');

// ---------- helpers ----------
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const now = DateTime.now().setZone(TZ);
const parseVer = s => (String(s || '').match(/(\d+)\.(\d+)\.(\d+)/) || []).slice(1).map(Number);
const olderThan = (a, b) => { for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] < b[i]; } return false; };
const seen = iso => {
  if (!iso || String(iso).startsWith('9999')) return '-';
  const d = DateTime.fromISO(String(iso));
  if (!d.isValid) return esc(iso);
  const mins = Math.max(0, Math.round(now.diff(d, 'minutes').minutes));
  const ago = mins < 60 ? `${mins} min ago` : mins < 1440 ? `${Math.floor(mins / 60)}h ${mins % 60}m ago` : `${Math.floor(mins / 1440)}d ${Math.floor((mins % 1440) / 60)}h ago`;
  return `${d.setZone(TZ).toFormat('dd MMM, hh:mm a')} (${ago})`;
};

// The manager is agent 000; its version is the one every agent should match
const manager = agents.find(a => a.id === '000');
const mgrVer = parseVer(manager?.version);

// Same name registered more than once (usually a re-installed VM)
const idsByName = {};
agents.forEach(a => (idsByName[a.name] = idsByName[a.name] || []).push(a.id));

// ---------- find problems ----------
// Each problem: { key, id, name, ip, issue, detail, level }
const problems = [];
const add = (a, issue, detail, level) =>
  problems.push({ key: `${a.id}:${issue}`, id: a.id, name: a.name, ip: a.ip, issue, detail, level });

for (const a of agents) {
  if (a.id === '000') continue;
  if (a.status === 'disconnected')
    add(a, 'Disconnected', `No contact since ${seen(a.lastKeepAlive)}. The VM may be off, or the agent service stopped.`, 'high');
  else if (a.status === 'never_connected')
    add(a, 'Never connected', 'Registered on the manager but has never sent anything. Check the agent install and the manager IP in its config.', 'medium');
  else if (a.status === 'pending')
    add(a, 'Pending', 'Started connecting but never finished. Often a firewall or key problem.', 'medium');

  const v = parseVer(a.version);
  if (a.status === 'active' && v.length && mgrVer.length && olderThan(v, mgrVer))
    add(a, 'Outdated', `Runs ${esc(a.version)}, the manager runs ${esc(manager.version)}. Upgrade the agent when convenient.`, 'low');

  if (idsByName[a.name].length > 1)
    add(a, 'Duplicate name', `The name "${esc(a.name)}" is also used by agent ${idsByName[a.name].filter(i => i !== a.id).join(', ')}. Remove the old registration.`, 'low');
}

// ---------- compare with what we reported last time ----------
const memory = $getWorkflowStaticData('global');
memory.known = memory.known || {};
const nowMs = now.toMillis();
const current = Object.fromEntries(problems.map(p => [p.key, p]));

const fresh = problems.filter(p => !memory.known[p.key]);
const reminders = problems.filter(p => memory.known[p.key] && p.level === 'high' &&
  nowMs - memory.known[p.key].lastNotified >= REMIND_EVERY_HOURS * 3600 * 1000);
const recovered = Object.entries(memory.known).filter(([k]) => !current[k]).map(([, v]) => v);

fresh.forEach(p => { memory.known[p.key] = { ...p, firstSeen: nowMs, lastNotified: nowMs }; });
reminders.forEach(p => { memory.known[p.key].lastNotified = nowMs; });
recovered.forEach(p => { delete memory.known[p.key]; });

const notify = fresh.length > 0 || reminders.length > 0 || recovered.length > 0;

// ---------- counts ----------
const count = s => agents.filter(a => a.id !== '000' && a.status === s).length;
const counts = { active: count('active'), disconnected: count('disconnected'), never_connected: count('never_connected'), pending: count('pending') };
const total = agents.filter(a => a.id !== '000').length;

// ---------- email ----------
const levelColor = { high: ['#b91c1c', '#fdecec'], medium: ['#b45309', '#fff7e6'], low: ['#475569', '#f1f5f9'] };
const statusPill = {
  active: ['Active', '#047857', '#ecfdf5'], disconnected: ['Disconnected', '#b91c1c', '#fdecec'],
  never_connected: ['Never connected', '#b45309', '#fff7e6'], pending: ['Pending', '#b45309', '#fff7e6']
};
const pill = (text, fg, bg) => `<span style="display:inline-block;padding:2px 9px;border-radius:10px;background:${bg};color:${fg};font-size:11px;font-weight:700;white-space:nowrap;">${text}</span>`;

const problemRows = (list, extra) => list.map(p => {
  const [fg, bg] = levelColor[p.level] || levelColor.low;
  return `<tr>
    <td valign="top" style="padding:10px 12px;border-top:1px solid #e2e8f0;">
      <div style="font-size:14px;font-weight:700;color:#1d2433;">${esc(p.name)} <span style="font-weight:400;color:#94a3b8;">(${esc(p.id)}, ${esc(p.ip || '-')})</span></div>
      <div style="margin-top:4px;">${pill(esc(p.issue), fg, bg)}${extra ? ` <span style="font-size:12px;color:#64748b;">${extra(p)}</span>` : ''}</div>
      <div style="font-size:13px;color:#334155;margin-top:6px;line-height:1.5;">${p.detail}</div>
    </td></tr>`;
}).join('');

const section = (title, color, list, extra) => list.length ? `
  <div style="font-size:14px;font-weight:700;color:${color};margin:18px 0 6px;">${title} (${list.length})</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #e2e8f0;border-radius:10px;border-collapse:separate;">${problemRows(list, extra)}</table>` : '';

const since = p => memory.known[p.key] ? `down since ${DateTime.fromMillis(memory.known[p.key].firstSeen).setZone(TZ).toFormat('dd MMM, hh:mm a')}` : '';

const agentRows = agents.filter(a => a.id !== '000').sort((x, y) => x.id.localeCompare(y.id)).map(a => {
  const [label, fg, bg] = statusPill[a.status] || [esc(a.status), '#475569', '#f1f5f9'];
  return `<tr>
    <td style="padding:7px 8px;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b;">${esc(a.id)}</td>
    <td style="padding:7px 8px;border-top:1px solid #e2e8f0;font-size:13px;color:#1d2433;font-weight:600;">${esc(a.name)}</td>
    <td style="padding:7px 8px;border-top:1px solid #e2e8f0;font-size:12px;color:#334155;">${esc(a.ip || '-')}</td>
    <td style="padding:7px 8px;border-top:1px solid #e2e8f0;">${pill(label, fg, bg)}</td>
    <td style="padding:7px 8px;border-top:1px solid #e2e8f0;font-size:12px;color:#334155;">${esc(String(a.version || '-').replace('Wazuh ', ''))}</td>
    <td style="padding:7px 8px;border-top:1px solid #e2e8f0;font-size:12px;color:#334155;">${a.status === 'active' ? 'now' : seen(a.lastKeepAlive)}</td>
  </tr>`;
}).join('');

const stat = (n, label, color) => `<td align="center" style="padding:10px 6px;"><div style="font-size:22px;font-weight:800;color:${n ? color : '#94a3b8'};">${n}</div><div style="font-size:11px;color:#64748b;">${label}</div></td>`;

const headline = fresh.length
  ? `${fresh.length} new agent problem${fresh.length > 1 ? 's' : ''}`
  : reminders.length ? `${reminders.length} agent${reminders.length > 1 ? 's' : ''} still disconnected`
  : recovered.length ? `${recovered.length} agent problem${recovered.length > 1 ? 's' : ''} resolved`
  : problems.length ? `No changes (${problems.length} open problem${problems.length > 1 ? 's' : ''})`
  : 'All agents healthy';
const topColor = fresh.some(p => p.level === 'high') || reminders.length ? '#b91c1c' : fresh.length ? '#b45309' : '#047857';

const html = `
<div style="margin:0;padding:24px 0;background:#f1f5f9;font-family:'Segoe UI',Arial,Helvetica,sans-serif;color:#1d2433;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;width:100%;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;">
  <tr><td style="padding:22px 24px;border-bottom:3px solid ${topColor};border-radius:14px 14px 0 0;">
    <div style="font-size:13px;color:#64748b;font-weight:600;">🩺 Wazuh agent health</div>
    <div style="font-size:21px;font-weight:800;margin-top:6px;color:${topColor};">${headline}</div>
    <div style="font-size:13px;color:#64748b;margin-top:4px;">Checked ${now.toFormat('dd MMM yyyy, hh:mm a')} · ${total} agents · manager ${esc(manager?.version || '-')}</div>
  </td></tr>
  <tr><td style="padding:6px 24px 0;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
      ${stat(counts.active, 'Active', '#047857')}${stat(counts.disconnected, 'Disconnected', '#b91c1c')}${stat(counts.never_connected, 'Never connected', '#b45309')}${stat(counts.pending, 'Pending', '#b45309')}
    </tr></table>
  </td></tr>
  <tr><td style="padding:0 24px 8px;">
    ${section('🚨 New problems', '#b91c1c', fresh)}
    ${section('⏰ Still disconnected', '#b91c1c', reminders, since)}
    ${section('✅ Resolved', '#047857', recovered)}
    <div style="font-size:14px;font-weight:700;color:#1d2433;margin:20px 0 6px;">All agents</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #e2e8f0;border-radius:10px;border-collapse:separate;">
      <tr style="background:#f8fafc;">
        <td style="padding:7px 8px;font-size:11px;color:#64748b;font-weight:700;">ID</td>
        <td style="padding:7px 8px;font-size:11px;color:#64748b;font-weight:700;">Name</td>
        <td style="padding:7px 8px;font-size:11px;color:#64748b;font-weight:700;">IP</td>
        <td style="padding:7px 8px;font-size:11px;color:#64748b;font-weight:700;">Status</td>
        <td style="padding:7px 8px;font-size:11px;color:#64748b;font-weight:700;">Version</td>
        <td style="padding:7px 8px;font-size:11px;color:#64748b;font-weight:700;">Last seen</td>
      </tr>${agentRows}
    </table>
    <div style="font-size:12px;color:#94a3b8;margin:14px 0 18px;line-height:1.5;">
      You get this email only when something changes, plus a reminder every ${REMIND_EVERY_HOURS} hours while an agent stays disconnected.
      A disconnected agent can't be restarted from the manager: start the VM or run <span style="font-family:Consolas,monospace;">systemctl restart wazuh-agent</span> on it.
    </div>
  </td></tr>
</table>
</td></tr></table>
</div>`;

const summary = [
  `${headline} (${counts.active}/${total} active)`,
  ...fresh.map(p => `NEW: ${p.name} (${p.id}) - ${p.issue}`),
  ...reminders.map(p => `STILL DOWN: ${p.name} (${p.id})`),
  ...recovered.map(p => `RESOLVED: ${p.name} (${p.id}) - ${p.issue}`)
].join('\n');

return [{ json: {
  notify,
  subject: `${fresh.some(p => p.level === 'high') || reminders.length ? '🔴' : fresh.length ? '🟠' : '🟢'} Wazuh agents: ${headline}`,
  html,
  summary,
  counts,
  problems: problems.map(({ key, ...p }) => p)
} }];
