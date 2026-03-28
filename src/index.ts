/**
 * Echo Compliance v1.0.0
 * AI-Powered Compliance Management — SOC2/HIPAA/GDPR/ISO27001
 * Cloudflare Worker — D1 + KV
 */

interface Env {
  DB: D1Database;
  CP_CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  EMAIL_SENDER: Fetcher;
  ECHO_API_KEY: string;
}

interface RLState { c: number; t: number }

const WINDOW = 60_000, MAX_REQ = 120;

function sanitize(s: unknown, max = 2000): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max);
}

function authOk(req: Request, env: Env): boolean {
  return req.headers.get('X-Echo-API-Key') === env.ECHO_API_KEY;
}

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', ...SECURITY_HEADERS, ...headers },
  });
}

async function rateLimit(ip: string, kv: KVNamespace): Promise<boolean> {
  const key = `rl:${ip}`;
  const raw = await kv.get(key);
  const now = Date.now();
  let st: RLState = raw ? JSON.parse(raw) : { c: 0, t: now };
  const elapsed = now - st.t;
  const decayed = Math.max(0, st.c - (elapsed / WINDOW) * MAX_REQ);
  if (decayed + 1 > MAX_REQ) return false;
  st = { c: decayed + 1, t: now };
  await kv.put(key, JSON.stringify(st), { expirationTtl: 120 });
  return true;
}

/* ── Framework Templates ── */
const FRAMEWORK_TEMPLATES: Record<string, { name: string; controls: { id: string; title: string; category: string; description: string }[] }> = {
  SOC2: {
    name: 'SOC 2 Type II',
    controls: [
      { id: 'CC1.1', title: 'COSO Principle 1 – Integrity & Ethics', category: 'Control Environment', description: 'The entity demonstrates a commitment to integrity and ethical values.' },
      { id: 'CC1.2', title: 'Board Independence & Oversight', category: 'Control Environment', description: 'The board demonstrates independence from management and exercises oversight.' },
      { id: 'CC2.1', title: 'Internal & External Communication', category: 'Communication', description: 'The entity internally communicates information to support functioning of controls.' },
      { id: 'CC3.1', title: 'Risk Assessment Objectives', category: 'Risk Assessment', description: 'The entity specifies objectives with clarity to identify and assess risks.' },
      { id: 'CC3.2', title: 'Risk Identification & Analysis', category: 'Risk Assessment', description: 'The entity identifies risks to the achievement of objectives and analyzes them.' },
      { id: 'CC4.1', title: 'Monitoring Activities', category: 'Monitoring', description: 'The entity selects and develops monitoring activities.' },
      { id: 'CC5.1', title: 'Control Activities Selection', category: 'Control Activities', description: 'The entity selects and develops control activities that mitigate risks.' },
      { id: 'CC6.1', title: 'Logical Access Security', category: 'Logical & Physical Access', description: 'Logical access security over protected information assets.' },
      { id: 'CC6.2', title: 'User Authentication', category: 'Logical & Physical Access', description: 'Prior to issuing system credentials, the entity registers and authorizes users.' },
      { id: 'CC6.3', title: 'Access Removal', category: 'Logical & Physical Access', description: 'The entity removes access when no longer needed.' },
      { id: 'CC7.1', title: 'Infrastructure Monitoring', category: 'System Operations', description: 'The entity monitors system components and the operation of those components.' },
      { id: 'CC7.2', title: 'Incident Response', category: 'System Operations', description: 'The entity monitors for anomalies indicative of malicious acts and incidents.' },
      { id: 'CC8.1', title: 'Change Management', category: 'Change Management', description: 'The entity authorizes, designs, develops, tests, and implements changes.' },
      { id: 'CC9.1', title: 'Vendor & Business Partner Risk', category: 'Risk Mitigation', description: 'The entity identifies, assesses, and manages risks associated with vendors.' },
      { id: 'A1.1', title: 'Capacity Planning', category: 'Availability', description: 'The entity maintains and monitors processing capacity.' },
      { id: 'A1.2', title: 'Backup & Recovery', category: 'Availability', description: 'The entity authorizes, designs, and implements recovery procedures.' },
      { id: 'PI1.1', title: 'Data Quality', category: 'Processing Integrity', description: 'The entity validates inputs and processing of data.' },
      { id: 'C1.1', title: 'Data Classification', category: 'Confidentiality', description: 'The entity classifies and protects confidential information.' },
      { id: 'P1.1', title: 'Privacy Notice', category: 'Privacy', description: 'The entity provides notice about its privacy practices.' },
    ],
  },
  HIPAA: {
    name: 'HIPAA Security Rule',
    controls: [
      { id: 'ADM-1', title: 'Security Management Process', category: 'Administrative', description: 'Implement policies and procedures to prevent, detect, contain, and correct security violations.' },
      { id: 'ADM-2', title: 'Assigned Security Responsibility', category: 'Administrative', description: 'Identify the security official responsible for developing and implementing policies.' },
      { id: 'ADM-3', title: 'Workforce Security', category: 'Administrative', description: 'Implement policies and procedures to ensure workforce members have appropriate access.' },
      { id: 'ADM-4', title: 'Information Access Management', category: 'Administrative', description: 'Implement policies and procedures for authorizing access to ePHI.' },
      { id: 'ADM-5', title: 'Security Awareness & Training', category: 'Administrative', description: 'Implement a security awareness and training program for all workforce members.' },
      { id: 'ADM-6', title: 'Security Incident Procedures', category: 'Administrative', description: 'Implement policies and procedures to address security incidents.' },
      { id: 'ADM-7', title: 'Contingency Plan', category: 'Administrative', description: 'Establish policies and procedures for responding to an emergency.' },
      { id: 'ADM-8', title: 'Evaluation', category: 'Administrative', description: 'Perform periodic technical and nontechnical evaluation.' },
      { id: 'PHY-1', title: 'Facility Access Controls', category: 'Physical', description: 'Implement policies to limit physical access to electronic information systems.' },
      { id: 'PHY-2', title: 'Workstation Use', category: 'Physical', description: 'Implement policies specifying proper functions and physical attributes of workstations.' },
      { id: 'PHY-3', title: 'Device & Media Controls', category: 'Physical', description: 'Implement policies governing receipt and removal of hardware and electronic media.' },
      { id: 'TEC-1', title: 'Access Control', category: 'Technical', description: 'Implement technical policies to allow access only to authorized persons.' },
      { id: 'TEC-2', title: 'Audit Controls', category: 'Technical', description: 'Implement hardware, software, and procedural mechanisms to record and examine access.' },
      { id: 'TEC-3', title: 'Integrity Controls', category: 'Technical', description: 'Implement policies to protect ePHI from improper alteration or destruction.' },
      { id: 'TEC-4', title: 'Transmission Security', category: 'Technical', description: 'Implement technical security measures to guard against unauthorized access to ePHI in transit.' },
    ],
  },
  GDPR: {
    name: 'GDPR Compliance',
    controls: [
      { id: 'ART-5', title: 'Principles of Processing', category: 'Core Principles', description: 'Personal data shall be processed lawfully, fairly and in a transparent manner.' },
      { id: 'ART-6', title: 'Lawfulness of Processing', category: 'Core Principles', description: 'Processing must have a lawful basis.' },
      { id: 'ART-7', title: 'Conditions for Consent', category: 'Consent', description: 'Controller must demonstrate that data subject has consented.' },
      { id: 'ART-12', title: 'Transparent Information', category: 'Data Subject Rights', description: 'Provide information in a concise, transparent, intelligible form.' },
      { id: 'ART-15', title: 'Right of Access', category: 'Data Subject Rights', description: 'Data subject has right to obtain confirmation of processing.' },
      { id: 'ART-17', title: 'Right to Erasure', category: 'Data Subject Rights', description: 'Data subject has right to obtain erasure of personal data.' },
      { id: 'ART-20', title: 'Right to Data Portability', category: 'Data Subject Rights', description: 'Data subject has right to receive data in structured, machine-readable format.' },
      { id: 'ART-25', title: 'Data Protection by Design', category: 'Technical Measures', description: 'Implement appropriate technical and organizational measures.' },
      { id: 'ART-28', title: 'Processor Requirements', category: 'Third Parties', description: 'Processing by a processor shall be governed by a contract.' },
      { id: 'ART-30', title: 'Records of Processing', category: 'Documentation', description: 'Maintain a record of processing activities.' },
      { id: 'ART-32', title: 'Security of Processing', category: 'Technical Measures', description: 'Implement appropriate technical and organizational security measures.' },
      { id: 'ART-33', title: 'Breach Notification (Authority)', category: 'Incident Response', description: 'Notify supervisory authority within 72 hours of becoming aware of breach.' },
      { id: 'ART-34', title: 'Breach Notification (Subject)', category: 'Incident Response', description: 'Communicate breach to data subject when high risk.' },
      { id: 'ART-35', title: 'Data Protection Impact Assessment', category: 'Risk Assessment', description: 'Carry out DPIA where processing is likely to result in high risk.' },
      { id: 'ART-37', title: 'Data Protection Officer', category: 'Governance', description: 'Designate a DPO where required.' },
    ],
  },
  ISO27001: {
    name: 'ISO 27001:2022',
    controls: [
      { id: 'A5.1', title: 'Policies for Information Security', category: 'Organizational', description: 'Define information security policy and get management approval.' },
      { id: 'A5.2', title: 'Information Security Roles', category: 'Organizational', description: 'Define and allocate information security roles and responsibilities.' },
      { id: 'A5.3', title: 'Segregation of Duties', category: 'Organizational', description: 'Conflicting duties shall be segregated.' },
      { id: 'A6.1', title: 'Screening', category: 'People', description: 'Background verification checks on all candidates shall be carried out.' },
      { id: 'A6.2', title: 'Terms of Employment', category: 'People', description: 'Employment agreements shall state responsibilities for information security.' },
      { id: 'A7.1', title: 'Physical Security Perimeters', category: 'Physical', description: 'Security perimeters shall be defined and used to protect areas.' },
      { id: 'A7.2', title: 'Physical Entry', category: 'Physical', description: 'Secure areas shall be protected by appropriate entry controls.' },
      { id: 'A8.1', title: 'User Endpoint Devices', category: 'Technological', description: 'Information on user endpoint devices shall be protected.' },
      { id: 'A8.2', title: 'Privileged Access Rights', category: 'Technological', description: 'Allocation and use of privileged access rights shall be restricted.' },
      { id: 'A8.3', title: 'Information Access Restriction', category: 'Technological', description: 'Access to information shall be restricted in accordance with policy.' },
      { id: 'A8.5', title: 'Secure Authentication', category: 'Technological', description: 'Secure authentication technologies and procedures shall be established.' },
      { id: 'A8.8', title: 'Technical Vulnerability Management', category: 'Technological', description: 'Information about technical vulnerabilities shall be obtained and evaluated.' },
      { id: 'A8.9', title: 'Configuration Management', category: 'Technological', description: 'Configurations of hardware, software, services and networks shall be managed.' },
      { id: 'A8.15', title: 'Logging', category: 'Technological', description: 'Logs that record activities, exceptions and events shall be produced and stored.' },
      { id: 'A8.16', title: 'Monitoring Activities', category: 'Technological', description: 'Networks, systems and applications shall be monitored for anomalous behaviour.' },
    ],
  },
};

/* ── Compliance Score Calculator ── */
function calcScore(met: number, partial: number, total: number): number {
  if (total === 0) return 0;
  return Math.round(((met + partial * 0.5) / total) * 10000) / 100;
}

function riskScore(likelihood: string, impact: string): number {
  const L: Record<string, number> = { very_low: 1, low: 2, medium: 3, high: 4, very_high: 5 };
  const I: Record<string, number> = { very_low: 1, low: 2, medium: 3, high: 4, very_high: 5 };
  return (L[likelihood] || 3) * (I[impact] || 3);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type,X-Echo-API-Key',
          ...SECURITY_HEADERS,
        },
      });
    }

    const url = new URL(req.url);
    const p = url.pathname;
    const m = req.method;
    const ip = req.headers.get('CF-Connecting-IP') || '0';

    if (!(await rateLimit(ip, env.CP_CACHE))) return json({ error: 'rate limited' }, 429);

    try {
      /* ── Public ── */
      if (p === '/health') return json({ status: 'ok', service: 'echo-compliance', version: '1.0.0', timestamp: new Date().toISOString() });

      /* ── Auth Required ── */
      if (!authOk(req, env)) return json({ error: 'unauthorized' }, 401);
      const db = env.DB;

      /* ══════════════════════════════════════════════════
         ORGANIZATIONS
         ══════════════════════════════════════════════════ */
      if (p === '/orgs' && m === 'GET') {
        const r = await db.prepare('SELECT * FROM organizations ORDER BY created_at DESC').all();
        return json({ organizations: r.results });
      }
      if (p === '/orgs' && m === 'POST') {
        const b = await req.json() as any;
        const name = sanitize(b.name, 200);
        const slug = sanitize(b.slug, 100).toLowerCase().replace(/[^a-z0-9-]/g, '-');
        if (!name || !slug) return json({ error: 'name and slug required' }, 400);
        const r = await db.prepare('INSERT INTO organizations (name, slug, industry, size, tenant_id) VALUES (?,?,?,?,?)').bind(name, slug, sanitize(b.industry, 100), sanitize(b.size, 50), sanitize(b.tenant_id || 'default', 100)).run();
        await db.prepare("INSERT INTO activity_log (org_id,action,target,details) VALUES (?,?,?,?)").bind(r.meta.last_row_id, 'org_created', slug, name).run();
        return json({ id: r.meta.last_row_id, slug });
      }
      if (p.match(/^\/orgs\/(\d+)$/) && m === 'GET') {
        const id = p.split('/')[2];
        const r = await db.prepare('SELECT * FROM organizations WHERE id=?').bind(id).first();
        if (!r) return json({ error: 'not found' }, 404);
        return json(r);
      }
      if (p.match(/^\/orgs\/(\d+)$/) && m === 'PUT') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        await db.prepare("UPDATE organizations SET name=COALESCE(?,name), industry=COALESCE(?,industry), size=COALESCE(?,size), settings=COALESCE(?,settings), updated_at=datetime('now') WHERE id=?").bind(b.name ? sanitize(b.name, 200) : null, b.industry ? sanitize(b.industry, 100) : null, b.size ? sanitize(b.size, 50) : null, b.settings ? JSON.stringify(b.settings) : null, id).run();
        return json({ updated: true });
      }

      /* ══════════════════════════════════════════════════
         FRAMEWORKS
         ══════════════════════════════════════════════════ */
      if (p === '/frameworks' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        const q = orgId ? 'SELECT * FROM frameworks WHERE org_id=? ORDER BY created_at DESC' : 'SELECT * FROM frameworks ORDER BY created_at DESC';
        const r = orgId ? await db.prepare(q).bind(orgId).all() : await db.prepare(q).all();
        return json({ frameworks: r.results });
      }
      if (p === '/frameworks' && m === 'POST') {
        const b = await req.json() as any;
        const orgId = Number(b.org_id);
        const code = sanitize(b.code, 50).toUpperCase();
        if (!orgId || !code) return json({ error: 'org_id and code required' }, 400);
        const tmpl = FRAMEWORK_TEMPLATES[code];
        const name = tmpl ? tmpl.name : sanitize(b.name || code, 200);
        const r = await db.prepare('INSERT INTO frameworks (org_id,name,code,version,description,total_controls) VALUES (?,?,?,?,?,?)').bind(orgId, name, code, sanitize(b.version || '1.0', 20), sanitize(b.description || '', 2000), tmpl ? tmpl.controls.length : 0).run();
        const fwId = r.meta.last_row_id;
        // Auto-populate controls from template
        if (tmpl) {
          const stmt = db.prepare('INSERT INTO controls (framework_id, org_id, control_id, title, description, category, priority) VALUES (?,?,?,?,?,?,?)');
          const batch = tmpl.controls.map(c => stmt.bind(fwId, orgId, c.id, c.title, c.description, c.category, 'medium'));
          await db.batch(batch);
          await db.prepare('UPDATE frameworks SET total_controls=?, controls_not_met=? WHERE id=?').bind(tmpl.controls.length, tmpl.controls.length, fwId).run();
        }
        await db.prepare("INSERT INTO activity_log (org_id,action,target,details) VALUES (?,?,?,?)").bind(orgId, 'framework_added', code, name).run();
        return json({ id: fwId, code, controls_created: tmpl ? tmpl.controls.length : 0 });
      }
      if (p.match(/^\/frameworks\/(\d+)$/) && m === 'GET') {
        const id = p.split('/')[2];
        const fw = await db.prepare('SELECT * FROM frameworks WHERE id=?').bind(id).first();
        if (!fw) return json({ error: 'not found' }, 404);
        const controls = await db.prepare('SELECT * FROM controls WHERE framework_id=? ORDER BY control_id').bind(id).all();
        return json({ ...fw, controls: controls.results });
      }
      if (p.match(/^\/frameworks\/(\d+)\/score$/) && m === 'POST') {
        const id = p.split('/')[2];
        const counts = await db.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN implementation_status='implemented' THEN 1 ELSE 0 END) as met, SUM(CASE WHEN implementation_status='partial' THEN 1 ELSE 0 END) as partial, SUM(CASE WHEN implementation_status='not_implemented' THEN 1 ELSE 0 END) as not_met FROM controls WHERE framework_id=?").bind(id).first() as any;
        const score = calcScore(counts.met || 0, counts.partial || 0, counts.total || 0);
        await db.prepare("UPDATE frameworks SET controls_met=?, controls_partial=?, controls_not_met=?, total_controls=?, score=?, last_assessed=datetime('now') WHERE id=?").bind(counts.met || 0, counts.partial || 0, counts.not_met || 0, counts.total || 0, score, id).run();
        return json({ score, met: counts.met, partial: counts.partial, not_met: counts.not_met, total: counts.total });
      }
      if (p === '/frameworks/templates' && m === 'GET') {
        const templates = Object.entries(FRAMEWORK_TEMPLATES).map(([code, t]) => ({ code, name: t.name, controls_count: t.controls.length }));
        return json({ templates });
      }

      /* ══════════════════════════════════════════════════
         CONTROLS
         ══════════════════════════════════════════════════ */
      if (p === '/controls' && m === 'GET') {
        const fwId = url.searchParams.get('framework_id');
        const orgId = url.searchParams.get('org_id');
        const status = url.searchParams.get('status');
        let q = 'SELECT * FROM controls WHERE 1=1';
        const params: any[] = [];
        if (fwId) { q += ' AND framework_id=?'; params.push(fwId); }
        if (orgId) { q += ' AND org_id=?'; params.push(orgId); }
        if (status) { q += ' AND implementation_status=?'; params.push(status); }
        q += ' ORDER BY control_id';
        const r = await db.prepare(q).bind(...params).all();
        return json({ controls: r.results });
      }
      if (p.match(/^\/controls\/(\d+)$/) && m === 'GET') {
        const id = p.split('/')[2];
        const c = await db.prepare('SELECT * FROM controls WHERE id=?').bind(id).first();
        if (!c) return json({ error: 'not found' }, 404);
        const ev = await db.prepare('SELECT * FROM evidence WHERE control_id=? ORDER BY collected_at DESC').bind(id).all();
        return json({ ...c, evidence: ev.results });
      }
      if (p.match(/^\/controls\/(\d+)$/) && m === 'PUT') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        const fields: string[] = [];
        const vals: any[] = [];
        for (const [k, v] of Object.entries(b)) {
          if (['implementation_status', 'status', 'priority', 'owner', 'due_date', 'notes', 'risk_level'].includes(k)) {
            fields.push(`${k}=?`);
            vals.push(sanitize(String(v), 2000));
          }
        }
        if (fields.length === 0) return json({ error: 'no valid fields' }, 400);
        fields.push("updated_at=datetime('now')");
        vals.push(id);
        await db.prepare(`UPDATE controls SET ${fields.join(',')} WHERE id=?`).bind(...vals).run();
        const ctrl = await db.prepare('SELECT org_id, control_id FROM controls WHERE id=?').bind(id).first() as any;
        if (ctrl) await db.prepare("INSERT INTO activity_log (org_id,action,target,details) VALUES (?,?,?,?)").bind(ctrl.org_id, 'control_updated', ctrl.control_id, JSON.stringify(b)).run();
        return json({ updated: true });
      }
      if (p === '/controls/bulk-update' && m === 'POST') {
        const b = await req.json() as any;
        if (!Array.isArray(b.updates)) return json({ error: 'updates array required' }, 400);
        let count = 0;
        for (const u of b.updates) {
          if (u.id && u.implementation_status) {
            await db.prepare("UPDATE controls SET implementation_status=?, updated_at=datetime('now') WHERE id=?").bind(sanitize(u.implementation_status, 50), u.id).run();
            count++;
          }
        }
        return json({ updated: count });
      }

      /* ══════════════════════════════════════════════════
         EVIDENCE
         ══════════════════════════════════════════════════ */
      if (p === '/evidence' && m === 'GET') {
        const ctrlId = url.searchParams.get('control_id');
        const orgId = url.searchParams.get('org_id');
        let q = 'SELECT * FROM evidence WHERE 1=1';
        const params: any[] = [];
        if (ctrlId) { q += ' AND control_id=?'; params.push(ctrlId); }
        if (orgId) { q += ' AND org_id=?'; params.push(orgId); }
        q += ' ORDER BY collected_at DESC';
        const r = await db.prepare(q).bind(...params).all();
        return json({ evidence: r.results });
      }
      if (p === '/evidence' && m === 'POST') {
        const b = await req.json() as any;
        if (!b.control_id || !b.org_id || !b.title) return json({ error: 'control_id, org_id, title required' }, 400);
        const r = await db.prepare('INSERT INTO evidence (control_id,org_id,title,type,description,file_url,file_name,collector,expires_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(b.control_id, b.org_id, sanitize(b.title, 200), sanitize(b.type || 'document', 50), sanitize(b.description || '', 2000), sanitize(b.file_url || '', 500), sanitize(b.file_name || '', 200), sanitize(b.collector || '', 100), b.expires_at || null).run();
        // Update evidence count on control
        await db.prepare('UPDATE controls SET evidence_count = evidence_count + 1 WHERE id=?').bind(b.control_id).run();
        return json({ id: r.meta.last_row_id });
      }
      if (p.match(/^\/evidence\/(\d+)$/) && m === 'DELETE') {
        const id = p.split('/')[2];
        const ev = await db.prepare('SELECT control_id FROM evidence WHERE id=?').bind(id).first() as any;
        if (ev) {
          await db.prepare('DELETE FROM evidence WHERE id=?').bind(id).run();
          await db.prepare('UPDATE controls SET evidence_count = MAX(0, evidence_count - 1) WHERE id=?').bind(ev.control_id).run();
        }
        return json({ deleted: true });
      }

      /* ══════════════════════════════════════════════════
         ASSESSMENTS
         ══════════════════════════════════════════════════ */
      if (p === '/assessments' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        const q = orgId ? 'SELECT * FROM assessments WHERE org_id=? ORDER BY created_at DESC' : 'SELECT * FROM assessments ORDER BY created_at DESC';
        const r = orgId ? await db.prepare(q).bind(orgId).all() : await db.prepare(q).all();
        return json({ assessments: r.results });
      }
      if (p === '/assessments' && m === 'POST') {
        const b = await req.json() as any;
        if (!b.org_id || !b.title) return json({ error: 'org_id and title required' }, 400);
        const r = await db.prepare('INSERT INTO assessments (org_id,framework_id,title,type,assessor,scope,scheduled_date) VALUES (?,?,?,?,?,?,?)').bind(b.org_id, b.framework_id || null, sanitize(b.title, 200), sanitize(b.type || 'internal', 50), sanitize(b.assessor || '', 100), sanitize(b.scope || '', 2000), b.scheduled_date || null).run();
        return json({ id: r.meta.last_row_id });
      }
      if (p.match(/^\/assessments\/(\d+)$/) && m === 'GET') {
        const id = p.split('/')[2];
        const r = await db.prepare('SELECT * FROM assessments WHERE id=?').bind(id).first();
        if (!r) return json({ error: 'not found' }, 404);
        return json(r);
      }
      if (p.match(/^\/assessments\/(\d+)$/) && m === 'PUT') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        await db.prepare("UPDATE assessments SET title=COALESCE(?,title), type=COALESCE(?,type), assessor=COALESCE(?,assessor), scope=COALESCE(?,scope), findings=COALESCE(?,findings), recommendations=COALESCE(?,recommendations), overall_score=COALESCE(?,overall_score), status=COALESCE(?,status), completed_date=COALESCE(?,completed_date), updated_at=datetime('now') WHERE id=?").bind(
          b.title ? sanitize(b.title, 200) : null,
          b.type ? sanitize(b.type, 50) : null,
          b.assessor ? sanitize(b.assessor, 100) : null,
          b.scope ? sanitize(b.scope, 2000) : null,
          b.findings ? JSON.stringify(b.findings) : null,
          b.recommendations ? JSON.stringify(b.recommendations) : null,
          b.overall_score ?? null,
          b.status ? sanitize(b.status, 50) : null,
          b.completed_date || null,
          id
        ).run();
        return json({ updated: true });
      }
      if (p.match(/^\/assessments\/(\d+)\/complete$/) && m === 'POST') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        await db.prepare("UPDATE assessments SET status='completed', overall_score=?, findings=?, recommendations=?, completed_date=datetime('now'), updated_at=datetime('now') WHERE id=?").bind(b.overall_score || 0, b.findings ? JSON.stringify(b.findings) : '[]', b.recommendations ? JSON.stringify(b.recommendations) : '[]', id).run();
        return json({ completed: true });
      }

      /* ══════════════════════════════════════════════════
         RISKS
         ══════════════════════════════════════════════════ */
      if (p === '/risks' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        const status = url.searchParams.get('status');
        let q = 'SELECT * FROM risks WHERE 1=1';
        const params: any[] = [];
        if (orgId) { q += ' AND org_id=?'; params.push(orgId); }
        if (status) { q += ' AND status=?'; params.push(status); }
        q += ' ORDER BY risk_score DESC';
        const r = await db.prepare(q).bind(...params).all();
        return json({ risks: r.results });
      }
      if (p === '/risks' && m === 'POST') {
        const b = await req.json() as any;
        if (!b.org_id || !b.title) return json({ error: 'org_id and title required' }, 400);
        const lik = sanitize(b.likelihood || 'medium', 20);
        const imp = sanitize(b.impact || 'medium', 20);
        const score = riskScore(lik, imp);
        const r = await db.prepare('INSERT INTO risks (org_id,title,description,category,likelihood,impact,risk_score,mitigation,owner,review_date) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(b.org_id, sanitize(b.title, 200), sanitize(b.description || '', 2000), sanitize(b.category || '', 100), lik, imp, score, sanitize(b.mitigation || '', 2000), sanitize(b.owner || '', 100), b.review_date || null).run();
        await db.prepare("INSERT INTO activity_log (org_id,action,target,details) VALUES (?,?,?,?)").bind(b.org_id, 'risk_created', sanitize(b.title, 200), `Score: ${score}`).run();
        return json({ id: r.meta.last_row_id, risk_score: score });
      }
      if (p.match(/^\/risks\/(\d+)$/) && m === 'PUT') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        const lik = b.likelihood ? sanitize(b.likelihood, 20) : null;
        const imp = b.impact ? sanitize(b.impact, 20) : null;
        let scoreUpdate = '';
        const params: any[] = [];
        if (lik || imp) {
          const existing = await db.prepare('SELECT likelihood, impact FROM risks WHERE id=?').bind(id).first() as any;
          if (existing) {
            const finalLik = lik || existing.likelihood;
            const finalImp = imp || existing.impact;
            scoreUpdate = ', risk_score=?';
            params.push(riskScore(finalLik, finalImp));
          }
        }
        await db.prepare(`UPDATE risks SET title=COALESCE(?,title), description=COALESCE(?,description), category=COALESCE(?,category), likelihood=COALESCE(?,likelihood), impact=COALESCE(?,impact), mitigation=COALESCE(?,mitigation), owner=COALESCE(?,owner), status=COALESCE(?,status), review_date=COALESCE(?,review_date)${scoreUpdate}, updated_at=datetime('now') WHERE id=?`).bind(
          b.title ? sanitize(b.title, 200) : null,
          b.description ? sanitize(b.description, 2000) : null,
          b.category ? sanitize(b.category, 100) : null,
          lik, imp,
          b.mitigation ? sanitize(b.mitigation, 2000) : null,
          b.owner ? sanitize(b.owner, 100) : null,
          b.status ? sanitize(b.status, 50) : null,
          b.review_date || null,
          ...params,
          id
        ).run();
        return json({ updated: true });
      }

      /* ══════════════════════════════════════════════════
         POLICIES
         ══════════════════════════════════════════════════ */
      if (p === '/policies' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        const q = orgId ? 'SELECT * FROM policies WHERE org_id=? ORDER BY title' : 'SELECT * FROM policies ORDER BY title';
        const r = orgId ? await db.prepare(q).bind(orgId).all() : await db.prepare(q).all();
        return json({ policies: r.results });
      }
      if (p === '/policies' && m === 'POST') {
        const b = await req.json() as any;
        if (!b.org_id || !b.title) return json({ error: 'org_id and title required' }, 400);
        const slug = sanitize(b.slug || b.title, 100).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+/g, '-');
        const r = await db.prepare('INSERT INTO policies (org_id,title,slug,category,content,version) VALUES (?,?,?,?,?,?)').bind(b.org_id, sanitize(b.title, 200), slug, sanitize(b.category || '', 100), sanitize(b.content || '', 50000), sanitize(b.version || '1.0', 20)).run();
        return json({ id: r.meta.last_row_id, slug });
      }
      if (p.match(/^\/policies\/(\d+)$/) && m === 'GET') {
        const id = p.split('/')[2];
        const r = await db.prepare('SELECT * FROM policies WHERE id=?').bind(id).first();
        if (!r) return json({ error: 'not found' }, 404);
        return json(r);
      }
      if (p.match(/^\/policies\/(\d+)$/) && m === 'PUT') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        await db.prepare("UPDATE policies SET title=COALESCE(?,title), category=COALESCE(?,category), content=COALESCE(?,content), version=COALESCE(?,version), status=COALESCE(?,status), updated_at=datetime('now') WHERE id=?").bind(
          b.title ? sanitize(b.title, 200) : null,
          b.category ? sanitize(b.category, 100) : null,
          b.content ? sanitize(b.content, 50000) : null,
          b.version ? sanitize(b.version, 20) : null,
          b.status ? sanitize(b.status, 50) : null,
          id
        ).run();
        return json({ updated: true });
      }
      if (p.match(/^\/policies\/(\d+)\/approve$/) && m === 'POST') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        await db.prepare("UPDATE policies SET status='approved', approved_by=?, approved_at=datetime('now'), updated_at=datetime('now') WHERE id=?").bind(sanitize(b.approved_by || 'admin', 100), id).run();
        return json({ approved: true });
      }
      if (p.match(/^\/policies\/(\d+)\/acknowledge$/) && m === 'POST') {
        const id = p.split('/')[2];
        await db.prepare("UPDATE policies SET acknowledgements = acknowledgements + 1, updated_at=datetime('now') WHERE id=?").bind(id).run();
        return json({ acknowledged: true });
      }

      /* ══════════════════════════════════════════════════
         VENDORS
         ══════════════════════════════════════════════════ */
      if (p === '/vendors' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        const tier = url.searchParams.get('risk_tier');
        let q = 'SELECT * FROM vendors WHERE 1=1';
        const params: any[] = [];
        if (orgId) { q += ' AND org_id=?'; params.push(orgId); }
        if (tier) { q += ' AND risk_tier=?'; params.push(tier); }
        q += ' ORDER BY name';
        const r = await db.prepare(q).bind(...params).all();
        return json({ vendors: r.results });
      }
      if (p === '/vendors' && m === 'POST') {
        const b = await req.json() as any;
        if (!b.org_id || !b.name) return json({ error: 'org_id and name required' }, 400);
        const r = await db.prepare('INSERT INTO vendors (org_id,name,category,risk_tier,data_access,contract_expiry,soc2_report,hipaa_baa,gdpr_dpa,notes) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(b.org_id, sanitize(b.name, 200), sanitize(b.category || '', 100), sanitize(b.risk_tier || 'low', 20), sanitize(b.data_access || '', 200), b.contract_expiry || null, b.soc2_report ? 1 : 0, b.hipaa_baa ? 1 : 0, b.gdpr_dpa ? 1 : 0, sanitize(b.notes || '', 2000)).run();
        return json({ id: r.meta.last_row_id });
      }
      if (p.match(/^\/vendors\/(\d+)$/) && m === 'PUT') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        await db.prepare("UPDATE vendors SET name=COALESCE(?,name), category=COALESCE(?,category), risk_tier=COALESCE(?,risk_tier), data_access=COALESCE(?,data_access), contract_expiry=COALESCE(?,contract_expiry), soc2_report=COALESCE(?,soc2_report), hipaa_baa=COALESCE(?,hipaa_baa), gdpr_dpa=COALESCE(?,gdpr_dpa), notes=COALESCE(?,notes), last_reviewed=COALESCE(?,last_reviewed), status=COALESCE(?,status), updated_at=datetime('now') WHERE id=?").bind(
          b.name ? sanitize(b.name, 200) : null,
          b.category ? sanitize(b.category, 100) : null,
          b.risk_tier ? sanitize(b.risk_tier, 20) : null,
          b.data_access ? sanitize(b.data_access, 200) : null,
          b.contract_expiry || null,
          b.soc2_report !== undefined ? (b.soc2_report ? 1 : 0) : null,
          b.hipaa_baa !== undefined ? (b.hipaa_baa ? 1 : 0) : null,
          b.gdpr_dpa !== undefined ? (b.gdpr_dpa ? 1 : 0) : null,
          b.notes ? sanitize(b.notes, 2000) : null,
          b.last_reviewed || null,
          b.status ? sanitize(b.status, 50) : null,
          id
        ).run();
        return json({ updated: true });
      }

      /* ══════════════════════════════════════════════════
         TASKS
         ══════════════════════════════════════════════════ */
      if (p === '/tasks' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        const status = url.searchParams.get('status');
        let q = 'SELECT * FROM tasks WHERE 1=1';
        const params: any[] = [];
        if (orgId) { q += ' AND org_id=?'; params.push(orgId); }
        if (status) { q += ' AND status=?'; params.push(status); }
        q += ' ORDER BY CASE priority WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 END, due_date';
        const r = await db.prepare(q).bind(...params).all();
        return json({ tasks: r.results });
      }
      if (p === '/tasks' && m === 'POST') {
        const b = await req.json() as any;
        if (!b.org_id || !b.title) return json({ error: 'org_id and title required' }, 400);
        const r = await db.prepare('INSERT INTO tasks (org_id,control_id,title,description,assignee,priority,due_date) VALUES (?,?,?,?,?,?,?)').bind(b.org_id, b.control_id || null, sanitize(b.title, 200), sanitize(b.description || '', 2000), sanitize(b.assignee || '', 100), sanitize(b.priority || 'medium', 20), b.due_date || null).run();
        return json({ id: r.meta.last_row_id });
      }
      if (p.match(/^\/tasks\/(\d+)$/) && m === 'PUT') {
        const id = p.split('/')[2];
        const b = await req.json() as any;
        const completedAt = b.status === 'completed' ? "datetime('now')" : 'completed_at';
        await db.prepare(`UPDATE tasks SET title=COALESCE(?,title), description=COALESCE(?,description), assignee=COALESCE(?,assignee), priority=COALESCE(?,priority), due_date=COALESCE(?,due_date), status=COALESCE(?,status), completed_at=CASE WHEN ?='completed' THEN datetime('now') ELSE completed_at END WHERE id=?`).bind(
          b.title ? sanitize(b.title, 200) : null,
          b.description ? sanitize(b.description, 2000) : null,
          b.assignee ? sanitize(b.assignee, 100) : null,
          b.priority ? sanitize(b.priority, 20) : null,
          b.due_date || null,
          b.status ? sanitize(b.status, 50) : null,
          b.status || '',
          id
        ).run();
        return json({ updated: true });
      }

      /* ══════════════════════════════════════════════════
         ANALYTICS & DASHBOARD
         ══════════════════════════════════════════════════ */
      if (p.match(/^\/dashboard\/(\d+)$/) && m === 'GET') {
        const orgId = p.split('/')[2];
        const [fws, ctrlCounts, riskCounts, taskCounts, policyCount, vendorCount] = await Promise.all([
          db.prepare('SELECT id, name, code, score, total_controls, controls_met, controls_partial, controls_not_met FROM frameworks WHERE org_id=?').bind(orgId).all(),
          db.prepare("SELECT implementation_status, COUNT(*) as cnt FROM controls WHERE org_id=? GROUP BY implementation_status").bind(orgId).all(),
          db.prepare("SELECT status, COUNT(*) as cnt, AVG(risk_score) as avg_score FROM risks WHERE org_id=? GROUP BY status").bind(orgId).all(),
          db.prepare("SELECT status, COUNT(*) as cnt FROM tasks WHERE org_id=? GROUP BY status").bind(orgId).all(),
          db.prepare("SELECT COUNT(*) as cnt FROM policies WHERE org_id=?").bind(orgId).first() as any,
          db.prepare("SELECT COUNT(*) as cnt, SUM(CASE WHEN risk_tier='critical' OR risk_tier='high' THEN 1 ELSE 0 END) as high_risk FROM vendors WHERE org_id=?").bind(orgId).first() as any,
        ]);
        // Overall compliance score
        const allCtrls = await db.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN implementation_status='implemented' THEN 1 ELSE 0 END) as met, SUM(CASE WHEN implementation_status='partial' THEN 1 ELSE 0 END) as partial FROM controls WHERE org_id=?").bind(orgId).first() as any;
        const overallScore = calcScore(allCtrls.met || 0, allCtrls.partial || 0, allCtrls.total || 0);
        await db.prepare("UPDATE organizations SET compliance_score=?, updated_at=datetime('now') WHERE id=?").bind(overallScore, orgId).run();
        return json({
          compliance_score: overallScore,
          frameworks: fws.results,
          controls_by_status: ctrlCounts.results,
          risks_by_status: riskCounts.results,
          tasks_by_status: taskCounts.results,
          total_policies: policyCount?.cnt || 0,
          total_vendors: vendorCount?.cnt || 0,
          high_risk_vendors: vendorCount?.high_risk || 0,
        });
      }
      if (p === '/analytics' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        if (!orgId) return json({ error: 'org_id required' }, 400);
        const days = Number(url.searchParams.get('days') || 30);
        const r = await db.prepare('SELECT * FROM analytics_daily WHERE org_id=? ORDER BY date DESC LIMIT ?').bind(orgId, days).all();
        return json({ analytics: r.results });
      }

      /* ══════════════════════════════════════════════════
         ACTIVITY LOG
         ══════════════════════════════════════════════════ */
      if (p === '/activity' && m === 'GET') {
        const orgId = url.searchParams.get('org_id');
        const limit = Math.min(Number(url.searchParams.get('limit') || 50), 200);
        const q = orgId ? 'SELECT * FROM activity_log WHERE org_id=? ORDER BY created_at DESC LIMIT ?' : 'SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ?';
        const r = orgId ? await db.prepare(q).bind(orgId, limit).all() : await db.prepare(q).bind(limit).all();
        return json({ activity: r.results });
      }

      /* ══════════════════════════════════════════════════
         AI — GAP ANALYSIS & RECOMMENDATIONS
         ══════════════════════════════════════════════════ */
      if (p.match(/^\/ai\/gap-analysis\/(\d+)$/) && m === 'POST') {
        const orgId = p.split('/')[3];
        const frameworks = await db.prepare('SELECT * FROM frameworks WHERE org_id=?').bind(orgId).all();
        const controls = await db.prepare("SELECT c.*, f.code as framework_code FROM controls c JOIN frameworks f ON c.framework_id=f.id WHERE c.org_id=? AND c.implementation_status != 'implemented' ORDER BY c.risk_level DESC, c.priority").bind(orgId).all();
        const risks = await db.prepare("SELECT * FROM risks WHERE org_id=? AND status='open' ORDER BY risk_score DESC").bind(orgId).all();
        const vendors = await db.prepare("SELECT * FROM vendors WHERE org_id=? AND (risk_tier='high' OR risk_tier='critical') AND (soc2_report=0 OR last_reviewed IS NULL)").bind(orgId).all();
        const policies = await db.prepare("SELECT * FROM policies WHERE org_id=? AND (status='draft' OR review_date < datetime('now'))").bind(orgId).all();

        const gaps: any[] = [];
        const prioritized: any[] = [];

        // Control gaps
        for (const c of controls.results as any[]) {
          const severity = c.risk_level === 'critical' || c.risk_level === 'high' ? 'critical' : c.risk_level === 'medium' ? 'high' : 'medium';
          gaps.push({
            type: 'control_gap',
            framework: c.framework_code,
            control_id: c.control_id,
            title: c.title,
            status: c.implementation_status,
            severity,
            recommendation: c.implementation_status === 'not_implemented'
              ? `Implement control ${c.control_id} (${c.title}). Assign an owner and set a target date.`
              : `Complete partial implementation of ${c.control_id}. Gather remaining evidence.`,
          });
        }

        // Vendor gaps
        for (const v of vendors.results as any[]) {
          gaps.push({
            type: 'vendor_risk',
            vendor: v.name,
            risk_tier: v.risk_tier,
            severity: 'high',
            recommendation: !v.soc2_report ? `Request SOC2 report from ${v.name}.` : `Schedule vendor review for ${v.name}.`,
          });
        }

        // Policy gaps
        for (const pol of policies.results as any[]) {
          gaps.push({
            type: 'policy_gap',
            policy: pol.title,
            status: pol.status,
            severity: 'medium',
            recommendation: pol.status === 'draft' ? `Finalize and approve policy "${pol.title}".` : `Policy "${pol.title}" is overdue for review.`,
          });
        }

        // Sort by severity
        const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        gaps.sort((a, b) => (sevOrder[a.severity] || 3) - (sevOrder[b.severity] || 3));

        // Try AI enhancement via Engine Runtime
        let aiInsights: string | null = null;
        try {
          const prompt = `Analyze this compliance gap report and provide 5 prioritized recommendations:\n\nFrameworks: ${frameworks.results.length}, Gaps: ${gaps.length}, Open Risks: ${risks.results.length}, High-Risk Vendors: ${vendors.results.length}\n\nTop gaps: ${JSON.stringify(gaps.slice(0, 10))}`;
          const aiResp = await env.ENGINE_RUNTIME.fetch('https://engine/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ engine_id: 'compliance-advisor', query: prompt }),
          });
          if (aiResp.ok) {
            const aiData = await aiResp.json() as any;
            aiInsights = aiData.response || aiData.answer || null;
          }
        } catch { /* AI enhancement is optional */ }

        return json({
          org_id: orgId,
          total_gaps: gaps.length,
          critical_gaps: gaps.filter(g => g.severity === 'critical').length,
          high_gaps: gaps.filter(g => g.severity === 'high').length,
          gaps,
          open_risks: risks.results.length,
          ai_insights: aiInsights,
          generated_at: new Date().toISOString(),
        });
      }

      if (p.match(/^\/ai\/readiness\/(\d+)$/) && m === 'GET') {
        const orgId = p.split('/')[3];
        const fwCode = url.searchParams.get('framework') || 'SOC2';
        const fw = await db.prepare('SELECT * FROM frameworks WHERE org_id=? AND code=?').bind(orgId, fwCode).first() as any;
        if (!fw) return json({ error: `Framework ${fwCode} not found for org` }, 404);
        const controls = await db.prepare('SELECT * FROM controls WHERE framework_id=?').bind(fw.id).all();
        const total = controls.results.length;
        const implemented = (controls.results as any[]).filter(c => c.implementation_status === 'implemented').length;
        const partial = (controls.results as any[]).filter(c => c.implementation_status === 'partial').length;
        const withEvidence = (controls.results as any[]).filter(c => c.evidence_count > 0).length;
        const withOwner = (controls.results as any[]).filter(c => c.owner).length;
        const score = calcScore(implemented, partial, total);
        const readiness = score >= 80 ? 'audit_ready' : score >= 60 ? 'nearly_ready' : score >= 40 ? 'in_progress' : 'early_stage';
        const estimatedWeeks = Math.max(1, Math.ceil((total - implemented - partial * 0.7) * 0.5));
        return json({
          framework: fwCode,
          score,
          readiness,
          total_controls: total,
          implemented,
          partial,
          not_implemented: total - implemented - partial,
          evidence_coverage: total > 0 ? Math.round((withEvidence / total) * 100) : 0,
          ownership_coverage: total > 0 ? Math.round((withOwner / total) * 100) : 0,
          estimated_weeks_to_ready: estimatedWeeks,
        });
      }

      /* ══════════════════════════════════════════════════
         EXPORT
         ══════════════════════════════════════════════════ */
      if (p.match(/^\/export\/(\d+)$/) && m === 'GET') {
        const orgId = p.split('/')[2];
        const format = url.searchParams.get('format') || 'json';
        const org = await db.prepare('SELECT * FROM organizations WHERE id=?').bind(orgId).first();
        const frameworks = await db.prepare('SELECT * FROM frameworks WHERE org_id=?').bind(orgId).all();
        const controls = await db.prepare('SELECT * FROM controls WHERE org_id=? ORDER BY framework_id, control_id').bind(orgId).all();
        const risks = await db.prepare('SELECT * FROM risks WHERE org_id=?').bind(orgId).all();
        const policies = await db.prepare('SELECT * FROM policies WHERE org_id=?').bind(orgId).all();
        const vendors = await db.prepare('SELECT * FROM vendors WHERE org_id=?').bind(orgId).all();

        if (format === 'csv') {
          let csv = 'Framework,Control ID,Title,Category,Status,Priority,Risk Level,Owner,Evidence Count\n';
          for (const c of controls.results as any[]) {
            const fw = (frameworks.results as any[]).find(f => f.id === c.framework_id);
            csv += `"${fw?.code || ''}","${c.control_id}","${(c.title || '').replace(/"/g, '""')}","${c.category || ''}","${c.implementation_status}","${c.priority}","${c.risk_level}","${c.owner || ''}",${c.evidence_count}\n`;
          }
          return new Response(csv, {
            headers: {
              'Content-Type': 'text/csv',
              'Content-Disposition': `attachment; filename="compliance-${orgId}.csv"`,
              'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
            },
          });
        }

        return json({
          organization: org,
          frameworks: frameworks.results,
          controls: controls.results,
          risks: risks.results,
          policies: policies.results,
          vendors: vendors.results,
          exported_at: new Date().toISOString(),
        });
      }

      /* ══════════════════════════════════════════════════
         STATS
         ══════════════════════════════════════════════════ */
      if (p === '/stats' && m === 'GET') {
        const [orgs, fws, ctrls, risks, pols, vendors, tasks] = await Promise.all([
          db.prepare('SELECT COUNT(*) as cnt FROM organizations').first() as any,
          db.prepare('SELECT COUNT(*) as cnt FROM frameworks').first() as any,
          db.prepare('SELECT COUNT(*) as cnt FROM controls').first() as any,
          db.prepare('SELECT COUNT(*) as cnt FROM risks').first() as any,
          db.prepare('SELECT COUNT(*) as cnt FROM policies').first() as any,
          db.prepare('SELECT COUNT(*) as cnt FROM vendors').first() as any,
          db.prepare('SELECT COUNT(*) as cnt FROM tasks').first() as any,
        ]);
        return json({
          organizations: orgs?.cnt || 0,
          frameworks: fws?.cnt || 0,
          controls: ctrls?.cnt || 0,
          risks: risks?.cnt || 0,
          policies: pols?.cnt || 0,
          vendors: vendors?.cnt || 0,
          tasks: tasks?.cnt || 0,
        });
      }

      return json({ error: 'Not found', path: p }, 404);
    } catch (e: any) {
      if (e.message?.includes('JSON')) {
        return json({ error: 'Invalid JSON body' }, 400);
      }
      console.error(`[echo-compliance] Unhandled error: ${e.message}`);
      return json({ error: 'Internal server error' }, 500);
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const db = env.DB;
    // Weekly compliance snapshot for all orgs
    const orgs = await db.prepare('SELECT id FROM organizations WHERE status=?').bind('active').all();
    for (const org of orgs.results as any[]) {
      const counts = await db.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN implementation_status='implemented' THEN 1 ELSE 0 END) as met FROM controls WHERE org_id=?").bind(org.id).first() as any;
      const riskCount = await db.prepare("SELECT COUNT(*) as cnt FROM risks WHERE org_id=? AND status='open'").bind(org.id).first() as any;
      const taskCount = await db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE org_id=? AND status='open'").bind(org.id).first() as any;
      const score = calcScore(counts.met || 0, 0, counts.total || 0);
      const today = new Date().toISOString().split('T')[0];
      await db.prepare('INSERT OR REPLACE INTO analytics_daily (org_id, date, compliance_score, controls_met, controls_total, open_risks, open_tasks) VALUES (?,?,?,?,?,?,?)').bind(org.id, today, score, counts.met || 0, counts.total || 0, riskCount?.cnt || 0, taskCount?.cnt || 0).run();
      await db.prepare("UPDATE organizations SET compliance_score=?, updated_at=datetime('now') WHERE id=?").bind(score, org.id).run();
    }
  },
};
