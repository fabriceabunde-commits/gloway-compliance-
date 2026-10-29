CREATE TABLE IF NOT EXISTS applications (
 id TEXT PRIMARY KEY,
 reference TEXT NOT NULL UNIQUE,
 business TEXT NOT NULL,
 country TEXT NOT NULL,
 contact TEXT NOT NULL,
 email TEXT NOT NULL,
 service TEXT NOT NULL,
 notes TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'new_request'
 CHECK(status IN ('new_request','information_review','scope_payment','registration_coordination','confirmation_followup','renewal_monitoring')),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_applications_created ON applications(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
