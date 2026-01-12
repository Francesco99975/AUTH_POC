-- Drop the trigger applied to the users table
DROP TRIGGER IF EXISTS trigger_update_updated_users ON users;

-- Drop the apply_update_trigger function
DROP FUNCTION IF EXISTS apply_update_trigger(TEXT);

-- Drop the update_updated trigger function
DROP FUNCTION IF EXISTS update_updated();

DROP TABLE IF EXISTS twofa_backup_codes;
DROP TABLE IF EXISTS email_verifications;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;
