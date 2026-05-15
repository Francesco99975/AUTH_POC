-- Enable trigram extension
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Username trigram index
CREATE INDEX IF NOT EXISTS idx_users_username_trgm
ON users USING gin (username gin_trgm_ops);

-- Email trigram index
CREATE INDEX IF NOT EXISTS idx_users_email_trgm
ON users USING gin (email gin_trgm_ops);

-- Optional: role index (helps filtering + pagination)
CREATE INDEX IF NOT EXISTS idx_users_role
ON users (role);
