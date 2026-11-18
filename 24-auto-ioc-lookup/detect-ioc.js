// ===== Automatic IOC lookup from Wazuh alerts, Code node: "Detect IOC" =====
// Keep this node named exactly:  Detect IOC
// Language: JavaScript, Mode: Run Once for All Items
// Input: a Wazuh alert posted to the Webhook node (the alert is inside "body")
// Output: the source IP to check plus ready-made requests for each source,
//         or NOTHING (the workflow stops quietly) when there is nothing worth checking

// ---------- settings you can change ----------
const CHECK_DESTINATION_TOO = false;  // true = also check the destination IP (e.g. outbound Suricata alerts)
const RECHECK_AFTER_HOURS = 24;       // the same IP is looked up at most once in this many hours
const SKIP_GROUPS = ['vulnerability-detector', 'sca', 'syscheck', 'rootcheck'];  // alert groups never checked
// ----------------------------------------------

const alert = $input.first().json.body || $input.first().json;
const rule = alert.rule || {};
const data = alert.data || {};

// 1. Skip alert types that never carry a useful attacker IP
if ((rule.groups || []).some(g => SKIP_GROUPS.includes(g))) return [];

// 2. Find the IP. Wazuh decoders use "srcip"; Suricata uses "src_ip".
const candidates = [data.srcip, data.src_ip];
if (CHECK_DESTINATION_TOO) candidates.push(data.dstip, data.dest_ip);

const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const ipv6 = /^[0-9a-f:]+$/i;
const isPrivateIp = ip => ipv4.test(ip)
  ? /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip)
  : /^(::1$|fe80:|fc|fd)/i.test(ip);

// Pick the first real, public IP. Private IPs (your own network) and junk like "?" are ignored.
const v = candidates
  .map(x => String(x ?? '').trim())
  .find(x => (ipv4.test(x) || (x.includes(':') && ipv6.test(x) && x.split(':').length > 2)) && !isPrivateIp(x));
if (!v) return [];

const type = ipv4.test(v) ? 'ipv4' : 'ipv6';

// 3. Don't look up the same IP again within RECHECK_AFTER_HOURS.
//    This memory only works in the published workflow, not in manual test runs.
const memory = $getWorkflowStaticData('global');
memory.checked = memory.checked || {};
const nowMs = Date.now();
for (const [ip, t] of Object.entries(memory.checked)) {
  if (nowMs - t > RECHECK_AFTER_HOURS * 3600 * 1000) delete memory.checked[ip];
}
if (memory.checked[v]) return [];
memory.checked[v] = nowMs;

// 4. Requests for each source (same as the form version)
const mispBody = { returnFormat: 'json', value: v, limit: 20 };
const openctiBody = {
  query: `query IocLookup($search: String) {
    stixCyberObservables(search: $search, first: 5) {
      edges { node { entity_type observable_value x_opencti_score objectLabel { value } } }
    }
    indicators(search: $search, first: 5) {
      edges { node { name pattern x_opencti_score valid_until createdBy { name } objectLabel { value } } }
    }
  }`,
  variables: { search: v }
};
const quoted = '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
const wazuhQuery = {
  size: 5,
  track_total_hits: true,
  sort: [{ timestamp: { order: 'desc' } }],
  _source: ['timestamp', 'rule.id', 'rule.level', 'rule.description', 'agent.name'],
  query: { bool: { filter: [
    { range: { timestamp: { gte: 'now-30d' } } },
    { query_string: { query: quoted, lenient: true } }
  ] } },
  aggs: { agents: { terms: { field: 'agent.name', size: 5 } } }
};

return [{ json: {
  original: v,
  ioc: v,
  type,
  isIP: true,
  isHash: false,
  isPrivate: false,
  isPublicIP: true,
  vtPath: `ip_addresses/${v}`,
  mispBody,
  openctiBody,
  wazuhQuery,
  // the alert that triggered this lookup, shown in the email
  alert: {
    ruleId: rule.id,
    level: rule.level,
    description: rule.description,
    tactic: ((rule.mitre || {}).tactic || []).join(', '),
    agent: (alert.agent || {}).name,
    agentIp: (alert.agent || {}).ip,
    timestamp: alert.timestamp,
    location: alert.location,
    fullLog: alert.full_log,
    ipField: data.srcip === v ? 'data.srcip' : data.src_ip === v ? 'data.src_ip' : 'destination'
  }
} }];
