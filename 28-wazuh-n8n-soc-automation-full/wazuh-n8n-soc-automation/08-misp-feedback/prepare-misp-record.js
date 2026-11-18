// ===== MISP feedback, Code node: "Prepare MISP record" =====
// Keep this node named exactly:  Prepare MISP record
// Language: JavaScript, Mode: Run Once for All Items
// Input:  a Wazuh verdict alert (rule 100951) that Wazuh posts to the Webhook node
// Output: the three MISP requests (search, add attribute, add sighting),
//         or NOTHING (the workflow stops quietly) if the alert isn't a verdict

// ---------- settings you can change ----------
const LAB_EVENT_ID = '';        // <-- the ID of your "Wazuh lab" event in MISP, e.g. '42'
const RULES = ['100951'];       // add '100952' to also record SUSPICIOUS IPs
const TEST_PREFIX = '203.0.113.'; // test IPs: still recorded, but marked "TEST ONLY"
// ----------------------------------------------

if (!/^\d+$/.test(String(LAB_EVENT_ID))) throw new Error('Set LAB_EVENT_ID at the top of this Code node to the ID of your MISP lab event.');

const alert = $input.first().json.body || $input.first().json;
const rule = alert.rule || {};
const n = (alert.data || {}).n8n_ioc;

// 1. Only verdict alerts from n8n, with an IP in them
if (!RULES.includes(String(rule.id)) || !n || !n.ip) return [];

const ip = String(n.ip).trim();
const isTest = ip.startsWith(TEST_PREFIX);

// Wazuh turns every value into text, so "null" can arrive as the word null
const has = x => x !== undefined && x !== null && x !== '' && x !== 'null';

// 2. When it was checked, in Dhaka time
let when = n.checked_at || alert.timestamp || '';
const dt = DateTime.fromISO(String(when));
if (dt.isValid) when = dt.setZone('Asia/Dhaka').toFormat('dd MMM yyyy, hh:mm a') + ' (Dhaka)';

// 3. A readable comment that is stored with the IP in MISP
const comment = [
  isTest ? 'TEST ONLY - safe to delete.' : '',
  `n8n verdict: ${n.verdict} (flagged by ${n.flagged_by || 'unknown'}).`,
  has(n.agent) ? `Seen on ${n.agent}${has(n.trigger_rule_id) ? `, Wazuh rule ${n.trigger_rule_id}: ${n.trigger_rule || '-'}` : ''}.` : '',
  has(n.vt_total) ? `VirusTotal ${n.vt_malicious}/${n.vt_total}.` : '',
  has(n.abuse_score) ? `AbuseIPDB ${n.abuse_score}%.` : '',
  when ? `Checked ${when}.` : ''
].filter(Boolean).join(' ');

return [{ json: {
  ip,
  isTest,
  eventId: LAB_EVENT_ID,

  // Is this IP already in the lab event?
  searchBody: { returnFormat: 'json', value: ip, eventid: LAB_EVENT_ID, limit: 1 },

  // Add it to the lab event. to_ids = false: it's a record of what we saw,
  // not a detection rule, so it can't start blocking or alerting on its own.
  attributeBody: {
    type: 'ip-src',
    category: 'Network activity',
    value: ip,
    to_ids: false,
    distribution: '5',   // 5 = same as the event
    comment
  },

  // Mark every MISP record of this IP (lab event AND feed events) as "seen in our lab"
  sightingBody: { value: ip, source: 'Wazuh lab (n8n)' }
} }];
