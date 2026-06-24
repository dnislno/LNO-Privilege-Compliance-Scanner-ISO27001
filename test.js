const http = require('http');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const BASE = 'http://localhost:9090';
let passed = 0, failed = 0;

function fetch(url) {
  return new Promise((resolve, reject) => {
    http.get(url, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    }).on('error', reject);
  });
}

function request(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE + path);
    const options = {
      hostname: url.hostname,
      port: url.port || 9090,
      path: url.pathname + url.search,
      method: method,
      headers: {}
    };
    if (body) {
      options.headers['Content-Type'] = 'application/json';
      options.headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = http.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

function check(name, ok, detail) {
  if (ok) { passed++; console.log(`  PASS  ${name}`); }
  else { failed++; console.log(`  FAIL  ${name} — ${detail}`); }
}

async function run() {
  console.log('\n=== LNO Integration Tests ===\n');

  // 1. Server responds
  const root = await fetch(BASE + '/');
  check('Server responds 200', root.status === 200, `Got ${root.status}`);
  check('Content-Type HTML', root.headers['content-type'] && root.headers['content-type'].includes('text/html'), root.headers['content-type']);

  // 2. Security headers present
  const apiResp = await fetch(BASE + '/api/overview');
  check('X-Content-Type-Options: nosniff', apiResp.headers['x-content-type-options'] === 'nosniff', apiResp.headers['x-content-type-options']);
  check('X-Frame-Options: DENY', apiResp.headers['x-frame-options'] === 'DENY', apiResp.headers['x-frame-options']);
  check('Referrer-Policy: no-referrer', apiResp.headers['referrer-policy'] === 'no-referrer', apiResp.headers['referrer-policy']);
  check('CORS restricted to localhost', apiResp.headers['access-control-allow-origin'] === 'http://localhost:9090', apiResp.headers['access-control-allow-origin']);
  check('Content-Security-Policy present', apiResp.headers['content-security-policy'] && apiResp.headers['content-security-policy'].includes("default-src 'self'"), apiResp.headers['content-security-policy']);

  // 3. API overview
  const ov = JSON.parse(apiResp.body);
  check('Overview returns object', ov && typeof ov === 'object', typeof ov);
  check('Risk score in 0-100', ov.risk_score >= 0 && ov.risk_score <= 100, ov.risk_score);
  check('Has severity_counts', ov.severity_counts && typeof ov.severity_counts === 'object', JSON.stringify(ov.severity_counts));

  // 4. Findings
  const fResp = await fetch(BASE + '/api/findings');
  const findings = JSON.parse(fResp.body);
  check('Findings is array', Array.isArray(findings), typeof findings);
  findings.forEach(f => {
    check('Finding has required fields', f.type && f.severity && f.title && f.iso, `${f.type} missing fields`);
  });

  // 5. Compliance — 93 controls
  const cResp = await fetch(BASE + '/api/compliance');
  const compliance = JSON.parse(cResp.body);
  check('Compliance is array', Array.isArray(compliance), typeof compliance);
  check('93 Annex A controls', compliance.length === 93, `Got ${compliance.length}`);
  const nonCompliant = compliance.filter(c => c.status === 'non_compliant').length;
  const compliant = compliance.filter(c => c.status === 'compliant').length;
  const notAssessed = compliance.filter(c => c.status === 'not_assessed').length;
  check('Status sum = 93', nonCompliant + compliant + notAssessed === 93, `${nonCompliant}+${compliant}+${notAssessed}`);
  check('Each control has evidence field', compliance.every(c => c.evidence !== undefined), 'Some missing evidence');
  check('Each control has theme field', compliance.every(c => c.theme), 'Some missing theme');

  // 6. Input validation — invalid path
  const badPath = await fetch(BASE + '/api/acl?path=<script>alert(1)</script>');
  check('ACL path injection rejected', badPath.status === 400, `Got ${badPath.status}`);

  // 7. Input validation — invalid pid
  const badPid = await fetch(BASE + '/api/processes/detail?pid=abc');
  check('PID injection rejected', badPid.status === 400, `Got ${badPid.status}`);
  const negPid = await fetch(BASE + '/api/processes/detail?pid=-1');
  check('Negative PID rejected', negPid.status === 400, `Got ${negPid.status}`);

  // 8. 404 handling
  const notFound = await fetch(BASE + '/api/nonexistent');
  check('Unknown endpoint returns 404', notFound.status === 404, `Got ${notFound.status}`);

  // 9. CSV export
  const csv = await fetch(BASE + '/api/export/findings');
  check('CSV returns 200', csv.status === 200, `Got ${csv.status}`);
  check('CSV has BOM', csv.body.charCodeAt(0) === 0xFEFF, 'No BOM');
  check('CSV content type', csv.headers['content-type'] && csv.headers['content-type'].includes('text/csv'), csv.headers['content-type']);
  check('CSV has header row', csv.body.includes('Type'), 'No Type column');
  check('CSV has Content-Disposition', csv.headers['content-disposition'] && csv.headers['content-disposition'].includes('.csv'), csv.headers['content-disposition']);

  // 10. risk-config
  const rc = await fetch(BASE + '/api/risk-config');
  const config = JSON.parse(rc.body);
  check('Risk config loaded', config && !config.error, JSON.stringify(config));
  check('Has severity_weights', config.severity_weights && config.severity_weights.critical !== undefined, 'missing weights');

  // 11. Processes
  const pResp = await fetch(BASE + '/api/processes');
  const procs = JSON.parse(pResp.body);
  check('Processes is array', Array.isArray(procs), typeof procs);
  if (procs.length > 0) {
    check('Process has parent_app', procs.every(p => p.parent_app !== undefined), 'Some missing parent_app');
  }

  // 12. Services
  const sResp = await fetch(BASE + '/api/services');
  const svcs = JSON.parse(sResp.body);
  check('Services is array', Array.isArray(svcs), typeof svcs);
  if (svcs.length > 0) {
    check('Service has parent_app', svcs.every(s => s.parent_app !== undefined), 'Some missing parent_app');
    check('Service has description', svcs.every(s => s.description !== undefined), 'Some missing description');
  }

  // 13. User endpoint
  const uResp = await fetch(BASE + '/api/user');
  const user = JSON.parse(uResp.body);
  check('User returns object', user && typeof user === 'object', typeof user);
  check('User has user field', user.user !== undefined, 'missing user');
  check('User has groups', Array.isArray(user.groups), typeof user.groups);
  check('User has privileges', Array.isArray(user.privileges), typeof user.privileges);

  // 14. Static files
  const logo = await fetch(BASE + '/logo.svg');
  check('Logo serves', logo.status === 200, `Got ${logo.status}`);
  const favicon = await fetch(BASE + '/favicon.svg');
  check('Favicon serves', favicon.status === 200, `Got ${favicon.status}`);

  // 15. Exceptions API tests
  const excGetInitial = await fetch(BASE + '/api/exceptions');
  check('Exceptions initial GET returns 200', excGetInitial.status === 200, `Got ${excGetInitial.status}`);
  const excListInitial = JSON.parse(excGetInitial.body);
  check('Exceptions list is array', Array.isArray(excListInitial), typeof excListInitial);

  // Add an exception
  const addExcResp = await request('POST', '/api/exceptions', JSON.stringify({
    type: 'test_finding',
    detail: 'test_detail',
    justification: 'Unit test justification'
  }));
  check('Exceptions POST returns 200', addExcResp.status === 200, `Got ${addExcResp.status}`);
  const addExcData = JSON.parse(addExcResp.body);
  check('Exceptions POST status is saved', addExcData.status === 'saved', JSON.stringify(addExcData));

  // Verify it is in the list
  const excGetAfter = await fetch(BASE + '/api/exceptions');
  const excListAfter = JSON.parse(excGetAfter.body);
  const foundExc = excListAfter.find(e => e.type === 'test_finding' && e.detail === 'test_detail');
  check('Exception is added to list', !!foundExc, 'Exception not found in list');
  if (foundExc) {
    check('Exception has justification', foundExc.justification === 'Unit test justification', foundExc.justification);
  }

  // Delete/Revoke exception
  const delExcResp = await request('DELETE', '/api/exceptions', JSON.stringify({
    type: 'test_finding',
    detail: 'test_detail'
  }));
  check('Exceptions DELETE returns 200', delExcResp.status === 200, `Got ${delExcResp.status}`);
  const delExcData = JSON.parse(delExcResp.body);
  check('Exceptions DELETE count is 1', delExcData.count === 1, JSON.stringify(delExcData));

  // Verify list is clean
  const excGetFinal = await fetch(BASE + '/api/exceptions');
  const excListFinal = JSON.parse(excGetFinal.body);
  const foundExcFinal = excListFinal.find(e => e.type === 'test_finding' && e.detail === 'test_detail');
  check('Exception is revoked/removed from list', !foundExcFinal, 'Exception still in list');

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);

  process.exit(failed > 0 ? 1 : 0);
}

run().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
