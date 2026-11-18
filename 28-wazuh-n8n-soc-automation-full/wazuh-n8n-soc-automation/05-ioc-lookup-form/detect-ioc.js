// ===== IOC lookup, Code node: "Detect IOC" =====
// Name this node exactly:  Detect IOC
// Language: JavaScript, Mode: Run Once for All Items
// Input: the form answer (field "IOC")
// Output: the cleaned IOC, its type, and ready-made requests for each source

const input = $input.first().json;
let raw = String(input.IOC ?? '').trim();
if (!raw) throw new Error('The form field must be named exactly "IOC" and must not be empty.');

// 1. Refang: turn safe-to-share forms back into the real value
//    hxxps://evil[.]com  ->  https://evil.com
let v = raw
  .replace(/^["'<\s]+|["'>\s]+$/g, '')
  .replace(/^hxxp/i, 'http')
  .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.')
  .replace(/\[:\]/g, ':')
  .replace(/\[\/\/\]/g, '//');

// 2. Work out what kind of IOC it is
const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const ipv6 = /^[0-9a-f:]+$/i;
let type;
if (ipv4.test(v)) type = 'ipv4';
else if (v.includes(':') && ipv6.test(v) && v.split(':').length > 2) type = 'ipv6';
else if (/^[a-f0-9]{32}$/i.test(v)) type = 'md5';
else if (/^[a-f0-9]{40}$/i.test(v)) type = 'sha1';
else if (/^[a-f0-9]{64}$/i.test(v)) type = 'sha256';
else if (/^https?:\/\//i.test(v)) type = 'url';
else if (/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(v)) type = 'domain';
else throw new Error(`"${raw}" doesn't look like an IP address, domain, URL or MD5/SHA1/SHA256 hash.`);

if (['md5', 'sha1', 'sha256', 'domain'].includes(type)) v = v.toLowerCase();

const isIP = type === 'ipv4' || type === 'ipv6';
const isHash = ['md5', 'sha1', 'sha256'].includes(type);
const isPrivate = type === 'ipv4'
  ? /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(v)
  : type === 'ipv6' ? /^(::1$|fe80:|fc|fd)/i.test(v) : false;

// 3. VirusTotal: each IOC type has its own address
const b64url = s => (typeof Buffer !== 'undefined'
  ? Buffer.from(s, 'utf8').toString('base64')
  : btoa(unescape(encodeURIComponent(s)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const vtPath = isIP ? `ip_addresses/${v}`
  : isHash ? `files/${v}`
  : type === 'domain' ? `domains/${v}`
  : `urls/${b64url(v)}`;

// 4. MISP: search attributes with this exact value
const mispBody = { returnFormat: 'json', value: v, limit: 20 };

// 5. OpenCTI: search observables and indicators
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

// 6. Your own Wazuh alerts: has this value appeared in the last 30 days?
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
  original: raw,
  ioc: v,
  type,
  isIP,
  isHash,
  isPrivate,
  isPublicIP: isIP && !isPrivate,
  vtPath,
  mispBody,
  openctiBody,
  wazuhQuery
} }];
