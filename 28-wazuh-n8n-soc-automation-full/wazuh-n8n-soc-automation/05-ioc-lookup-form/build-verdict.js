// ===== IOC lookup, Code node: "Build verdict" =====
// Language: JavaScript, Mode: Run Once for All Items
// Reads the answers from the nodes named: Detect IOC, VirusTotal, AbuseIPDB, MISP, OpenCTI, Wazuh
// Output: { html, subject, summary, verdict } for the Send Email node and the form's ending page

const D = $('Detect IOC').first().json;
const v = D.ioc;

// ---------- helpers ----------
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// Defang for display, so email apps don't turn the IOC into a clickable link
const defang = s => String(s ?? '').replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
const num = n => Number(n || 0).toLocaleString('en-US');
const day = s => {
  if (!s) return '-';
  const d = typeof s === 'number' ? DateTime.fromSeconds(s) : DateTime.fromISO(String(s));
  return d.isValid ? d.setZone('Asia/Dhaka').toFormat('dd MMM yyyy, hh:mm a') : String(s);
};

// Read one source node's answer. Each HTTP node has "Include Response Headers and Status"
// and "Never Error" turned on, so its output is { statusCode, body }.
// A node that was skipped (AbuseIPDB for non-IPs) returns { ran: false }.
const read = name => {
  let j;
  try { j = $(name).first().json; } catch (e) { return { ran: false, missing: true }; }
  if (!j) return { ran: false, missing: true };
  if (j.error) return { ran: true, failed: true, reason: String(j.error.message || j.error.description || j.error) };
  let body = j.body !== undefined ? j.body : j;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { /* keep text */ } }
  return { ran: true, status: Number(j.statusCode || 200), body };
};
const httpProblem = (r, source) => {
  if (r.failed) return `Could not reach ${source}: ${r.reason}`;
  if (r.status === 401 || r.status === 403) return `${source} rejected the API key (HTTP ${r.status}). Check the credential.`;
  if (r.status === 429) return `${source} rate limit reached (HTTP 429). Try again in a minute.`;
  if (r.status >= 400 && r.status !== 404) return `${source} returned HTTP ${r.status}.`;
  return null;
};

const missingMsg = n => `No answer from a node named "${n}". Check that the node is named exactly ${n} (capital letters matter) and is connected in the chain.`;

// Each source produces: { name, status, headline, details: [[label, value]], link }
// status: bad | suspicious | clean | unknown | seen | skipped | error
const results = [];

// ---------- VirusTotal ----------
(() => {
  const r = read('VirusTotal');
  const link = `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}`;
  if (!r.ran) return results.push({ name: 'VirusTotal', status: 'error', headline: missingMsg('VirusTotal') });
  const p = httpProblem(r, 'VirusTotal');
  if (p) return results.push({ name: 'VirusTotal', status: 'error', headline: p });
  if (r.status === 404) return results.push({ name: 'VirusTotal', status: 'unknown', headline: 'VirusTotal has no record of this IOC.', link });
  const a = r.body?.data?.attributes || {};
  const s = a.last_analysis_stats || {};
  const mal = s.malicious || 0, sus = s.suspicious || 0;
  const total = mal + sus + (s.harmless || 0) + (s.undetected || 0);
  const status = mal >= 3 ? 'bad' : (mal > 0 || sus > 0) ? 'suspicious' : 'clean';
  const details = [['Engines', `${mal} malicious, ${sus} suspicious, out of ${total}`]];
  if (a.reputation !== undefined) details.push(['Community score', a.reputation]);
  if (a.popular_threat_classification?.suggested_threat_label) details.push(['Threat label', esc(a.popular_threat_classification.suggested_threat_label)]);
  if (a.meaningful_name) details.push(['File name', esc(a.meaningful_name)]);
  if (a.type_description) details.push(['File type', esc(a.type_description)]);
  if (a.country) details.push(['Country', esc(a.country)]);
  if (a.as_owner) details.push(['Network owner', esc(a.as_owner)]);
  if (a.registrar) details.push(['Registrar', esc(a.registrar)]);
  if (a.categories && Object.keys(a.categories).length) details.push(['Categories', esc([...new Set(Object.values(a.categories))].slice(0, 4).join(', '))]);
  if (a.last_analysis_date) details.push(['Last analysed', day(a.last_analysis_date)]);
  results.push({ name: 'VirusTotal', status,
    headline: mal ? `${mal} of ${total} security engines flag this as malicious.` : sus ? `${sus} engines flag this as suspicious.` : `No engine flags this as malicious (${total} checked).`,
    details, link });
})();

// ---------- AbuseIPDB ----------
(() => {
  if (!D.isIP) return results.push({ name: 'AbuseIPDB', status: 'skipped', headline: 'Only used for IP addresses.' });
  if (D.isPrivate) return results.push({ name: 'AbuseIPDB', status: 'skipped', headline: 'Private IP. Internet abuse reports don\'t apply.' });
  const r = read('AbuseIPDB');
  if (!r.ran) return results.push({ name: 'AbuseIPDB', status: 'error', headline: missingMsg('AbuseIPDB') });
  const p = httpProblem(r, 'AbuseIPDB');
  if (p) return results.push({ name: 'AbuseIPDB', status: 'error', headline: p });
  const d = r.body?.data || {};
  const score = d.abuseConfidenceScore || 0;
  const status = d.isWhitelisted ? 'clean' : score >= 75 ? 'bad' : score >= 25 ? 'suspicious' : 'clean';
  const details = [
    ['Abuse score', `${score}%`],
    ['Reports', `${num(d.totalReports)} reports from ${num(d.numDistinctUsers)} users (last 90 days)`]
  ];
  if (d.countryCode) details.push(['Country', esc(d.countryCode)]);
  if (d.isp) details.push(['ISP', esc(d.isp)]);
  if (d.usageType) details.push(['Usage type', esc(d.usageType)]);
  if (d.lastReportedAt) details.push(['Last reported', day(d.lastReportedAt)]);
  if (d.isWhitelisted) details.push(['Note', 'On AbuseIPDB\'s allow list']);
  results.push({ name: 'AbuseIPDB', status,
    headline: score ? `Abuse confidence score ${score}% from ${num(d.totalReports)} reports.` : 'No abuse reports in the last 90 days.',
    details, link: `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` });
})();

// ---------- MISP ----------
(() => {
  const r = read('MISP');
  if (!r.ran) return results.push({ name: 'MISP', status: 'error', headline: missingMsg('MISP') });
  const p = httpProblem(r, 'MISP');
  if (p) return results.push({ name: 'MISP', status: 'error', headline: p });
  const attrs = r.body?.response?.Attribute || [];
  if (!attrs.length) return results.push({ name: 'MISP', status: 'clean', headline: 'Not found in your MISP.' });
  const active = attrs.filter(x => x.to_ids === true || x.to_ids === '1' || x.to_ids === 1);
  const details = attrs.slice(0, 5).map(x => [
    `Event ${esc(x.event_id)}`,
    `${esc(x.Event?.info || 'No event title')} <span style="color:#94a3b8;">(${esc(x.category)}, ${esc(x.type)}${(x.to_ids === true || x.to_ids === '1') ? ', marked for detection' : ''})</span>`
  ]);
  if (attrs.length > 5) details.push(['More', `${attrs.length - 5} more matches`]);
  results.push({ name: 'MISP', status: active.length ? 'bad' : 'suspicious',
    headline: `Found in ${attrs.length} MISP record${attrs.length > 1 ? 's' : ''}${active.length ? `, ${active.length} marked for detection` : ''}.`,
    details });
})();

// ---------- OpenCTI ----------
(() => {
  const r = read('OpenCTI');
  if (!r.ran) return results.push({ name: 'OpenCTI', status: 'error', headline: missingMsg('OpenCTI') });
  const p = httpProblem(r, 'OpenCTI');
  if (p) return results.push({ name: 'OpenCTI', status: 'error', headline: p });
  if (r.body?.errors?.length) {
    const m = String(r.body.errors[0].message || '');
    return results.push({ name: 'OpenCTI', status: 'error', headline: /logged in|auth|token/i.test(m)
      ? 'OpenCTI did not accept the API token. Check the OpenCTI credential: the value must be "Bearer " followed by your token.'
      : `OpenCTI query error: ${esc(m)}` });
  }
  const lower = v.toLowerCase();
  const obs = (r.body?.data?.stixCyberObservables?.edges || []).map(e => e.node)
    .filter(n => String(n.observable_value || '').toLowerCase() === lower);
  const inds = (r.body?.data?.indicators?.edges || []).map(e => e.node)
    .filter(n => String(n.pattern || '').toLowerCase().includes(lower) || String(n.name || '').toLowerCase() === lower);
  if (!obs.length && !inds.length) return results.push({ name: 'OpenCTI', status: 'clean', headline: 'Not found in your OpenCTI.' });
  const scores = [...obs, ...inds].map(n => n.x_opencti_score).filter(s => typeof s === 'number');
  const maxScore = scores.length ? Math.max(...scores) : null;
  const labels = [...new Set([...obs, ...inds].flatMap(n => (n.objectLabel || []).map(l => l.value)))];
  const details = [];
  if (maxScore !== null) details.push(['Highest score', `${maxScore} / 100`]);
  if (labels.length) details.push(['Labels', esc(labels.slice(0, 8).join(', '))]);
  inds.slice(0, 3).forEach(n => details.push(['Indicator', `${esc(n.name)}${n.createdBy?.name ? ` <span style="color:#94a3b8;">(source: ${esc(n.createdBy.name)})</span>` : ''}`]));
  results.push({ name: 'OpenCTI', status: (maxScore !== null && maxScore >= 70) || inds.length ? 'bad' : 'suspicious',
    headline: `Found in OpenCTI: ${obs.length} observable${obs.length === 1 ? '' : 's'}, ${inds.length} indicator${inds.length === 1 ? '' : 's'}.`,
    details });
})();

// ---------- Your Wazuh alerts ----------
let seenInLab = 0;
(() => {
  const r = read('Wazuh');
  if (!r.ran) return results.push({ name: 'Your Wazuh alerts', status: 'error', headline: missingMsg('Wazuh') });
  const p = httpProblem(r, 'the Wazuh indexer');
  if (p) return results.push({ name: 'Your Wazuh alerts', status: 'error', headline: p });
  seenInLab = r.body?.hits?.total?.value || 0;
  if (!seenInLab) return results.push({ name: 'Your Wazuh alerts', status: 'clean', headline: 'Not seen in any Wazuh alert in the last 30 days.' });
  const agents = (r.body?.aggregations?.agents?.buckets || []).map(b => `${esc(b.key)} (${num(b.doc_count)})`).join(', ');
  const details = [['Machines', agents || '-']];
  (r.body?.hits?.hits || []).forEach(h => {
    const s = h._source || {};
    details.push([day(s.timestamp), `${esc(s.rule?.description)} <span style="color:#94a3b8;">(level ${esc(s.rule?.level)}, ${esc(s.agent?.name)})</span>`]);
  });
  results.push({ name: 'Your Wazuh alerts', status: 'seen',
    headline: `Seen in ${num(seenInLab)} Wazuh alert${seenInLab === 1 ? '' : 's'} in the last 30 days.`, details });
})();

// ---------- overall verdict ----------
const reputation = results.filter(x => x.name !== 'Your Wazuh alerts');
const bad = reputation.filter(x => x.status === 'bad').map(x => x.name);
const sus = reputation.filter(x => x.status === 'suspicious').map(x => x.name);
const errs = results.filter(x => x.status === 'error').map(x => x.name);
const checked = reputation.filter(x => ['bad', 'suspicious', 'clean', 'unknown'].includes(x.status));

let verdict, vColor, vBg, vText;
if (bad.length) {
  verdict = 'MALICIOUS'; vColor = '#b91c1c'; vBg = '#fdecec';
  vText = `Flagged as malicious by ${bad.join(', ')}.`;
} else if (sus.length) {
  verdict = 'SUSPICIOUS'; vColor = '#b45309'; vBg = '#fff7e6';
  vText = `Some concern from ${sus.join(', ')}. Worth a closer look.`;
} else if (checked.length && errs.filter(n => n !== 'Your Wazuh alerts').length) {
  verdict = 'INCOMPLETE CHECK'; vColor = '#475569'; vBg = '#f1f5f9';
  vText = `Nothing malicious found in ${checked.map(x => x.name).join(', ')}, but ${errs.join(', ')} could not be checked. Fix those before trusting this result.`;
} else if (checked.length) {
  verdict = 'NO KNOWN THREAT'; vColor = '#047857'; vBg = '#ecfdf5';
  vText = 'None of the sources report this as malicious. That doesn\'t prove it is safe, only that nothing is known against it.';
} else {
  verdict = 'NOT CHECKED'; vColor = '#475569'; vBg = '#f1f5f9';
  vText = 'No source returned a usable answer. See the errors below.';
}

let action = '';
if (verdict === 'MALICIOUS' && seenInLab) action = `This IOC appears in ${num(seenInLab)} alert${seenInLab === 1 ? '' : 's'} from your lab. Investigate the machines listed under "Your Wazuh alerts" now.`;
else if (verdict === 'MALICIOUS') action = 'Not seen in your lab in the last 30 days. Consider blocking it before it shows up.';
else if (verdict === 'SUSPICIOUS' && seenInLab) action = `Seen in your lab ${num(seenInLab)} time${seenInLab === 1 ? '' : 's'}. Review those alerts to decide whether it's expected.`;
if (D.isPrivate) action = (action ? action + ' ' : '') + 'This is a private IP, so internet reputation services don\'t apply. Your own alerts matter most here.';

// ---------- HTML ----------
const pill = {
  bad: ['Malicious', '#b91c1c', '#fdecec'],
  suspicious: ['Suspicious', '#b45309', '#fff7e6'],
  clean: ['Nothing found', '#047857', '#ecfdf5'],
  unknown: ['No record', '#475569', '#f1f5f9'],
  seen: ['Seen in your lab', '#1d4ed8', '#eff6ff'],
  skipped: ['Skipped', '#64748b', '#f8fafc'],
  error: ['Error', '#7c2d12', '#ffedd5']
};
const card = r => {
  const [label, fg, bg] = pill[r.status];
  const rows = (r.details || []).map(([k, val]) => `<tr>
      <td valign="top" style="padding:4px 12px 4px 0;font-size:12px;color:#64748b;white-space:nowrap;">${k}</td>
      <td valign="top" style="padding:4px 0;font-size:13px;color:#1d2433;word-break:break-word;">${val}</td></tr>`).join('');
  return `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:12px;"><tr>
    <td style="border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="font-size:15px;font-weight:700;color:#1d2433;">${r.name}</td>
        <td align="right"><span style="display:inline-block;padding:3px 10px;border-radius:12px;background:${bg};color:${fg};font-size:12px;font-weight:700;">${label}</span></td>
      </tr></table>
      <div style="font-size:13px;color:#334155;margin-top:6px;">${r.headline}</div>
      ${rows ? `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:8px;">${rows}</table>` : ''}
      ${r.link ? `<div style="margin-top:8px;font-size:12px;"><a href="${r.link}" style="color:#0f766e;">Open in ${r.name}</a></div>` : ''}
    </td>
  </tr></table>`;
};

const typeName = { ipv4: 'IP address', ipv6: 'IPv6 address', domain: 'Domain', url: 'URL', md5: 'MD5 hash', sha1: 'SHA1 hash', sha256: 'SHA256 hash' }[D.type];
const now = DateTime.now().setZone('Asia/Dhaka');

const html = `
<div style="margin:0;padding:24px 0;background:#f1f5f9;font-family:'Segoe UI',Arial,Helvetica,sans-serif;color:#1d2433;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center">
<table role="presentation" width="620" cellpadding="0" cellspacing="0" border="0" style="max-width:620px;width:100%;background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;">

  <tr><td style="padding:24px 26px 20px;background:${vBg};border-bottom:3px solid ${vColor};border-radius:14px 14px 0 0;">
    <div style="font-size:13px;color:#64748b;font-weight:600;">🔎 IOC lookup · ${typeName}</div>
    <div style="font-family:Consolas,'Courier New',monospace;font-size:17px;font-weight:700;color:#1d2433;margin-top:8px;word-break:break-all;">${esc(defang(v))}</div>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:14px;"><tr>
      <td style="background:${vColor};border-radius:20px;padding:6px 16px;font-size:14px;font-weight:800;color:#ffffff;letter-spacing:0.5px;">${verdict}</td>
    </tr></table>
    <div style="font-size:14px;color:#334155;margin-top:12px;line-height:1.5;">${vText}</div>
  </td></tr>

  <tr><td style="padding:22px 24px 8px;">
    ${action ? `
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:18px;"><tr>
      <td style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:12px 16px;font-size:13px;color:#1e3a8a;line-height:1.5;">
        <b>What to do:</b> ${action}
      </td></tr></table>` : ''}
    ${results.map(card).join('')}
    ${errs.length ? `<div style="font-size:12px;color:#7c2d12;margin:4px 0 12px;">${errs.length} source${errs.length > 1 ? 's' : ''} could not be checked, so this verdict may be incomplete.</div>` : ''}
    <div style="font-size:12px;color:#94a3b8;margin:10px 0 18px;">
      Checked ${now.toFormat('dd MMM yyyy, hh:mm a')}.${D.original !== v ? ` You entered: ${esc(defang(D.original))}` : ''}
      The IOC is shown with [.] so it can't be clicked by accident.
    </div>
  </td></tr>

</table>
</td></tr></table>
</div>`;

// Short plain-text summary for the form's ending page
const summary = [
  `${verdict}: ${defang(v)} (${typeName})`,
  vText,
  ...results.map(r => `${r.name}: ${r.headline}`),
  action ? `What to do: ${action}` : '',
  errs.length ? `Note: ${errs.join(', ')} could not be checked, so this verdict may be incomplete.` : '',
  'The full report has been emailed to you.'
].filter(Boolean).join('\n\n');

return [{ json: {
  verdict,
  html,
  summary,
  subject: `IOC lookup: ${verdict} · ${defang(v)}`
} }];
