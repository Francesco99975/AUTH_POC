-- +migrate Down

ALTER TABLE email_verifications
    DROP COLUMN IF EXISTS email;
