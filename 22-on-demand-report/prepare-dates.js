// ===== On-demand Wazuh report, node 2 of 5: "Prepare dates" =====
// Name this Code node exactly:  Prepare dates
// Language: JavaScript, Mode: Run Once for All Items
// Input: the form answers (fields "Month" and "Year")
// Output: the chosen month's exact dates plus the full indexer query

const form = $input.first().json;
const ZONE = 'Asia/Dhaka';
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'];

const monthNum = MONTHS.indexOf(String(form.Month || '').trim()) + 1;
const year = Number(form.Year);
if (form.Month === undefined || form.Year === undefined) {
  throw new Error(`Could not find the form answers. The form fields must be named exactly "Month" and "Year". Received: ${Object.keys(form).join(', ')}`);
}
if (!monthNum) throw new Error(`"${form.Month}" is not a month name. Use full names like "August".`);
if (!year) throw new Error(`"${form.Year}" is not a valid year.`);

const now = DateTime.now().setZone(ZONE);
const start = DateTime.fromObject({ year, month: monthNum, day: 1 }, { zone: ZONE });
if (start > now) {
  throw new Error(`${form.Month} ${year} has not started yet. Choose the current month or an earlier one.`);
}

const fullEnd = start.plus({ months: 1 });   // first moment of the next month
const isCurrent = fullEnd > now;             // chosen month is still in progress
const end = isCurrent ? now : fullEnd;       // report up to now, or to the month's end
const prevStart = start.minus({ months: 1 });

// Dates in the format the indexer understands, with the +06:00 offset
const iso = d => d.toISO({ suppressMilliseconds: true });

const severity = { range: { field: 'rule.level', ranges: [
  { key: 'low', to: 7 },
  { key: 'medium', from: 7, to: 10 },
  { key: 'high', from: 10, to: 12 },
  { key: 'critical', from: 12 }
] } };
const highPlus = { filter: { range: { 'rule.level': { gte: 10 } } } };

const query = {
  size: 0,
  track_total_hits: true,
  query: { range: { timestamp: { gte: iso(prevStart), lt: iso(end) } } },
  aggs: {
    prev_month: {
      filter: { range: { timestamp: { gte: iso(prevStart), lt: iso(start) } } },
      aggs: { severity }
    },
    this_month: {
      filter: { range: { timestamp: { gte: iso(start), lt: iso(end) } } },
      aggs: {
        severity,
        per_day: {
          date_histogram: {
            field: 'timestamp', calendar_interval: 'day', time_zone: '+06:00', min_doc_count: 0,
            // show every day of the chosen month on the chart, even days with no alerts
            extended_bounds: { min: start.toMillis(), max: end.minus({ milliseconds: 1 }).toMillis() }
          },
          aggs: { high_plus: highPlus }
        },
        top_rules: {
          terms: { field: 'rule.id', size: 10 },
          aggs: {
            desc: { terms: { field: 'rule.description', size: 1 } },
            level: { max: { field: 'rule.level' } }
          }
        },
        top_agents: { terms: { field: 'agent.name', size: 10 }, aggs: { high_plus: highPlus } },
        top_srcips: { terms: { field: 'data.srcip', size: 10 } },
        mitre_tactics: { terms: { field: 'rule.mitre.tactic', size: 8 } },
        auth_fail: { filter: { terms: { 'rule.groups': ['authentication_failed', 'authentication_failures'] } } },
        fim: { filter: { term: { 'rule.groups': 'syscheck' } } },
        suricata: {
          filter: { term: { 'rule.groups': 'suricata' } },
          aggs: { top_sigs: { terms: { field: 'data.alert.signature', size: 5 } } }
        },
        vuln: {
          filter: { term: { 'rule.groups': 'vulnerability-detector' } },
          aggs: {
            sev: { terms: { field: 'data.vulnerability.severity', size: 5 } },
            top_pkgs: { terms: { field: 'data.vulnerability.package.name', size: 5 } }
          }
        }
      }
    }
  }
};

return [{ json: {
  monthLabel: `${form.Month} ${year}`,
  startMs: start.toMillis(),
  endMs: end.toMillis(),
  isCurrent,
  query
} }];
