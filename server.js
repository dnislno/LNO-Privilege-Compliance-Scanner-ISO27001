// LNO Privilege Compliance Scanner
// Author  : dnislno (https://github.com/dnislno)
// License : MIT (see LICENSE file)
//
// DISCLAIMER: This software is provided "AS IS" without warranty of any kind.
// The author shall not be held liable for any damages arising from the use
// of this software. Users assume all responsibility and risk. Use only on
// systems you own or have explicit written permission to audit.

const http = require('http');
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const PORT = 9090;
const DB_PATH = path.join(__dirname, 'scan.db');
const INDEX = path.join(__dirname, 'index.html');
const SAFE_ORIGIN = 'http://localhost:9090';

// Load .env file manually (no dotenv dependency)
try {
  const envFile = fs.readFileSync(path.join(__dirname, '.env'), 'utf-8');
  for (const line of envFile.split('\n')) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim();
        if (!process.env[key]) process.env[key] = val;
      }
    }
  }
} catch (_) { /* .env file is optional */ }

const SCAN_TOKEN = process.env.SCAN_TOKEN || 'scan_trigger';
if (SCAN_TOKEN === 'scan_trigger') {
  console.log('  SCAN_TOKEN: default ("scan_trigger") — set SCAN_TOKEN env var for custom token');
} else {
  console.log('  SCAN_TOKEN: custom token configured');
}

// CSV cells starting with these chars can execute formulas in Excel/Sheets
const CSV_FORMULA_CHARS = ['=', '+', '-', '@', '|'];
function csvEscape(v) {
  const s = String(v || '');
  // Neutralize formula injection by prefixing with tab
  const neutralized = CSV_FORMULA_CHARS.some(c => s.startsWith(c)) ? '\t' + s : s;
  return '"' + neutralized.replace(/"/g, '""') + '"';
}

// Validate input to prevent injection/anomaly
function isValidPath(p) {
  if (!p || typeof p !== 'string') return false;
  if (p.length > 500) return false;
  // Allow only safe characters in path queries
  return /^[a-zA-Z0-9_\-\\\/:\. ]+$/.test(p);
}
function isValidPid(v) {
  const n = parseInt(v);
  return Number.isFinite(n) && n > 0 && n < 65536;
}

function queryDB(sql, params = []) {
  return new Promise(async (resolve) => {
    if (!fs.existsSync(DB_PATH)) return resolve([]);
    try {
      const buf = fs.readFileSync(DB_PATH);
      const SQL = await initSqlJs();
      const db = new SQL.Database(buf);
      const stmt = db.prepare(sql);
      stmt.bind(params);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      stmt.free();
      db.close();
      resolve(rows);
    } catch(e) { resolve([]); }
  });
}

function queryOne(sql, params = []) {
  return queryDB(sql, params).then(r => r[0] || null);
}

const LATEST = "(SELECT id FROM scans WHERE status='done' ORDER BY started_at DESC LIMIT 1)";

async function handleAPI(req, res) {
  const parsedUrl = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = parsedUrl.pathname;

  res.setHeader('Access-Control-Allow-Origin', SAFE_ORIGIN);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  if (pathname === '/api/overview') {
    const scan = await queryOne(`SELECT * FROM scans WHERE status='done' ORDER BY started_at DESC LIMIT 1`);
    const findings = await queryDB(`SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ${LATEST} GROUP BY severity`);
    if (scan) {
      const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      findings.forEach(f => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity] = f.cnt; });
      scan.severity_counts = sevCounts;
    }
    res.end(JSON.stringify(scan));
    return;
  }

  if (pathname === '/api/findings') {
    const sev = parsedUrl.searchParams.get('severity');
    const sql = sev
      ? `SELECT * FROM findings WHERE scan_id = ${LATEST} AND severity = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`
      : `SELECT * FROM findings WHERE scan_id = ${LATEST} ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`;
    const params = sev ? [sev] : [];
    const rows = await queryDB(sql, params);
    res.end(JSON.stringify(rows));
    return;
  }

  if (pathname === '/api/compliance') {
    const controls = await queryDB(`SELECT * FROM compliance_status WHERE scan_id = ${LATEST} ORDER BY control`);
    const findings = await queryDB(`SELECT iso, type, severity, title, detail, remediation FROM findings WHERE scan_id = ${LATEST} AND iso IS NOT NULL AND iso != '' ORDER BY iso, severity`);
    // Group findings by ISO control
    const findingsByControl = {};
    for (const f of findings) {
      if (!findingsByControl[f.iso]) findingsByControl[f.iso] = [];
      findingsByControl[f.iso].push({ type: f.type, severity: f.severity, title: f.title, detail: f.detail, remediation: f.remediation });
    }
    // Attach findings to each control
    for (const c of controls) {
      c.findings = findingsByControl[c.control] || [];
    }
    res.end(JSON.stringify(controls));
    return;
  }

  if (pathname === '/api/user') {
    const user = await queryOne(`SELECT * FROM user_account WHERE scan_id = ${LATEST}`);
    const groups = await queryDB(`SELECT * FROM user_groups WHERE scan_id = ${LATEST}`);
    const privs = await queryDB(`SELECT * FROM user_privileges WHERE scan_id = ${LATEST}`);
    res.end(JSON.stringify({ user, groups, privileges: privs }));
    return;
  }

  if (pathname === '/api/local-users') {
    const rows = await queryDB(`SELECT * FROM local_users WHERE scan_id = ${LATEST} ORDER BY name`);
    res.end(JSON.stringify(rows));
    return;
  }

  if (pathname === '/api/local-groups') {
    const groups = await queryDB(`SELECT * FROM local_groups WHERE scan_id = ${LATEST} ORDER BY name`);
    const members = await queryDB(`SELECT * FROM group_members WHERE scan_id = ${LATEST} ORDER BY group_name, member_name`);
    res.end(JSON.stringify({ groups, members }));
    return;
  }

  if (pathname === '/api/acl') {
    const pathFilter = parsedUrl.searchParams.get('path');
    if (pathFilter && !isValidPath(pathFilter)) {
      res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid path parameter' })); return;
    }
    const sql = pathFilter
      ? `SELECT * FROM acl_entries WHERE scan_id = ${LATEST} AND path = ? ORDER BY identity`
      : `SELECT * FROM acl_entries WHERE scan_id = ${LATEST} ORDER BY path, identity`;
    const rows = await queryDB(sql, pathFilter ? [pathFilter] : []);
    res.end(JSON.stringify(rows));
    return;
  }

  if (pathname === '/api/security-policy') {
    const row = await queryOne(`SELECT * FROM security_policy WHERE scan_id = ${LATEST}`);
    res.end(JSON.stringify(row));
    return;
  }

  if (pathname === '/api/processes') {
    const rows = await queryDB(`SELECT * FROM processes WHERE scan_id = ${LATEST} ORDER BY risk_score DESC, pid`);
    res.end(JSON.stringify(rows));
    return;
  }

  if (pathname === '/api/processes/suspicious') {
    const rows = await queryDB(`SELECT * FROM processes WHERE scan_id = ${LATEST} AND risk_score >= 20 ORDER BY risk_score DESC`);
    res.end(JSON.stringify(rows));
    return;
  }

  if (pathname === '/api/processes/detail') {
    const pidRaw = parsedUrl.searchParams.get('pid');
    if (!pidRaw || !isValidPid(pidRaw)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Valid pid required (1-65535)' })); return; }
    const pid = parseInt(pidRaw);
    const proc = await queryOne(`SELECT * FROM processes WHERE scan_id = ${LATEST} AND pid = ?`, [pid]);
    const conns = await queryDB(`SELECT * FROM connections WHERE scan_id = ${LATEST} AND pid = ?`, [pid]);
    res.end(JSON.stringify({ process: proc, connections: conns }));
    return;
  }

  if (pathname === '/api/services') {
    const rows = await queryDB(`SELECT * FROM services WHERE scan_id = ${LATEST} ORDER BY name`);
    res.end(JSON.stringify(rows));
    return;
  }

  if (pathname === '/api/connections') {
    const rows = await queryDB(`SELECT * FROM connections WHERE scan_id = ${LATEST} ORDER BY pid`);
    res.end(JSON.stringify(rows));
    return;
  }

  if (pathname === '/api/system-info') {
    const rows = await queryDB(`SELECT * FROM system_info WHERE scan_id = ${LATEST}`);
    const obj = {};
    rows.forEach(r => obj[r.key] = r.value);
    res.end(JSON.stringify(obj));
    return;
  }

  if (pathname === '/api/scan/latest') {
    const row = await queryOne("SELECT * FROM scans WHERE status='done' ORDER BY started_at DESC LIMIT 1");
    res.end(JSON.stringify(row));
    return;
  }

  // CSV export endpoints
  if (pathname.startsWith('/api/export/')) {
    const format = pathname.replace('/api/export/', '');
    let rows, filename, headers;
    switch (format) {
      case 'findings':
        rows = await queryDB(`SELECT type, severity, category, iso, title, detail, remediation FROM findings WHERE scan_id = ${LATEST} ORDER BY severity`);
        filename = 'findings.csv'; headers = ['Type','Severity','Category','ISO Control','Title','Detail','Remediation'];
        break;
      case 'compliance':
        rows = await queryDB(`SELECT control, title, status, severity, evidence FROM compliance_status WHERE scan_id = ${LATEST} ORDER BY control`);
        filename = 'compliance.csv'; headers = ['ISO Control','Title','Status','Severity','Evidence'];
        break;
      case 'processes':
        rows = await queryDB(`SELECT name, pid, owner, risk_score, is_signed, memory_mb, has_network, risk_reasons, executable_path FROM processes WHERE scan_id = ${LATEST} ORDER BY risk_score DESC`);
        filename = 'processes.csv'; headers = ['Name','PID','Owner','Risk Score','Signed','Memory MB','Network','Risk Reasons','Executable Path'];
        break;
      default:
        res.writeHead(404); res.end(JSON.stringify({ error: 'Unknown export format' })); return;
    }
    let csv = '\uFEFF'; // BOM for Excel
    csv += headers.join(',') + '\n';
    for (const r of rows) {
      const vals = headers.map(h => csvEscape(r[h.toLowerCase().replace(/ /g, '_')] !== undefined ? r[h.toLowerCase().replace(/ /g, '_')] : ''));
      csv += vals.join(',') + '\n';
    }
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.end(csv);
    return;
  }

  if (pathname === '/api/risk-config') {
    try {
      const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'risk-config.json'), 'utf-8'));
      res.end(JSON.stringify(cfg));
    } catch(e) { res.end(JSON.stringify({ error: 'Config not found' })); }
    return;
  }

  if (pathname === '/api/scan/trigger') {
    if (req.method !== 'POST') { res.writeHead(405); res.end(JSON.stringify({ error: 'POST required' })); return; }
    const auth = req.headers['authorization'];
    if (SCAN_TOKEN && (!auth || auth !== `Bearer ${SCAN_TOKEN}`)) {
      res.writeHead(401); res.end(JSON.stringify({ error: 'Unauthorized - set SCAN_TOKEN env or provide Authorization: Bearer <token>' })); return;
    }
    const { scan } = require('./scanner.js');
    try {
      await scan();
      res.end(JSON.stringify({ status: 'done' }));
    } catch (e) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'not found' }));
}

const MIME = { '.html': 'text/html', '.svg': 'image/svg+xml', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) return handleAPI(req, res);
  // Serve static files (logo, favicon, etc.) — with path traversal protection
  const sanitized = req.url === '/' ? 'index.html' : req.url.replace(/^\//, '').replace(/\.\./g, '');
  const filePath = path.resolve(path.join(__dirname, sanitized));
  if (!filePath.startsWith(__dirname + path.sep)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }
  if (fs.existsSync(filePath) && !fs.statSync(filePath).isDirectory()) {
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(fs.readFileSync(filePath));
    return;
  }
  // Fallback to index.html
  if (fs.existsSync(INDEX)) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(fs.readFileSync(INDEX, 'utf-8'));
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(PORT, '127.0.0.1', () => console.log(`Server: http://localhost:${PORT}`));
