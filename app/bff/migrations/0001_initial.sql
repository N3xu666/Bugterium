-- 0001_initial.sql

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_id INTEGER UNIQUE NOT NULL,
  username TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,              -- UUID
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,      -- epoch seconds
  created_at INTEGER NOT NULL,
  ip_hash TEXT                      -- SHA-256(ip + pepper), for audit only (NULL for mobile-safe)
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE oauth_states (
  state TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

-- Audit log for auth events (no PII: only ip_hash, not raw IP)
CREATE TABLE auth_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,                  -- NULL for failed logins
  event TEXT NOT NULL,              -- 'login_success', 'login_fail', 'logout', 'forbidden'
  ip_hash TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX idx_auth_events_created ON auth_events(created_at);