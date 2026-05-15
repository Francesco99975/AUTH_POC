DROP INDEX IF EXISTS idx_users_username_trgm;
DROP INDEX IF EXISTS idx_users_email_trgm;
DROP INDEX IF EXISTS idx_users_role;

-- Only drop extension if you are sure nothing else uses it
DROP EXTENSION IF EXISTS pg_trgm;
