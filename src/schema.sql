-- Echo Compliance — AI-Powered Compliance Management
-- D1 Schema

CREATE TABLE IF NOT EXISTS organizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  industry TEXT,
  size TEXT,
  settings JSON DEFAULT '{}',
  risk_score REAL DEFAULT 0,
  compliance_score REAL DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS frameworks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  code TEXT NOT NULL,
  version TEXT,
  description TEXT,
  total_controls INTEGER DEFAULT 0,
  controls_met INTEGER DEFAULT 0,
  controls_partial INTEGER DEFAULT 0,
  controls_not_met INTEGER DEFAULT 0,
  score REAL DEFAULT 0,
  status TEXT DEFAULT 'active',
  last_assessed TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(org_id, code)
);

CREATE TABLE IF NOT EXISTS controls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  framework_id INTEGER NOT NULL,
  org_id INTEGER NOT NULL,
  control_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT,
  priority TEXT DEFAULT 'medium',
  status TEXT DEFAULT 'not_started',
  implementation_status TEXT DEFAULT 'not_implemented',
  owner TEXT,
  due_date TEXT,
  evidence_count INTEGER DEFAULT 0,
  notes TEXT,
  risk_level TEXT DEFAULT 'medium',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(framework_id, control_id)
);
CREATE INDEX IF NOT EXISTS idx_controls_framework ON controls(framework_id, status);
CREATE INDEX IF NOT EXISTS idx_controls_org ON controls(org_id);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  control_id INTEGER NOT NULL,
  org_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  type TEXT DEFAULT 'document',
  description TEXT,
  file_url TEXT,
  file_name TEXT,
  collector TEXT,
  collected_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence(control_id);

CREATE TABLE IF NOT EXISTS assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  framework_id INTEGER,
  title TEXT NOT NULL,
  type TEXT DEFAULT 'internal',
  assessor TEXT,
  scope TEXT,
  findings JSON DEFAULT '[]',
  recommendations JSON DEFAULT '[]',
  overall_score REAL DEFAULT 0,
  status TEXT DEFAULT 'planned',
  scheduled_date TEXT,
  completed_date TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS risks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT,
  likelihood TEXT DEFAULT 'medium',
  impact TEXT DEFAULT 'medium',
  risk_score REAL DEFAULT 0,
  mitigation TEXT,
  owner TEXT,
  status TEXT DEFAULT 'open',
  review_date TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  slug TEXT NOT NULL,
  category TEXT,
  content TEXT,
  version TEXT DEFAULT '1.0',
  approved_by TEXT,
  approved_at TEXT,
  review_date TEXT,
  acknowledgements INTEGER DEFAULT 0,
  status TEXT DEFAULT 'draft',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(org_id, slug)
);

CREATE TABLE IF NOT EXISTS vendors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  category TEXT,
  risk_tier TEXT DEFAULT 'low',
  data_access TEXT,
  contract_expiry TEXT,
  last_reviewed TEXT,
  soc2_report INTEGER DEFAULT 0,
  hipaa_baa INTEGER DEFAULT 0,
  gdpr_dpa INTEGER DEFAULT 0,
  notes TEXT,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  control_id INTEGER,
  title TEXT NOT NULL,
  description TEXT,
  assignee TEXT,
  priority TEXT DEFAULT 'medium',
  due_date TEXT,
  status TEXT DEFAULT 'open',
  completed_at TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_org ON tasks(org_id, status);

CREATE TABLE IF NOT EXISTS analytics_daily (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  compliance_score REAL DEFAULT 0,
  controls_met INTEGER DEFAULT 0,
  controls_total INTEGER DEFAULT 0,
  open_risks INTEGER DEFAULT 0,
  open_tasks INTEGER DEFAULT 0,
  UNIQUE(org_id, date)
);

CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER,
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
