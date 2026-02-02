-- +migrate Up

ALTER TABLE email_verifications
    ADD COLUMN email TEXT NOT NULL DEFAULT '';
