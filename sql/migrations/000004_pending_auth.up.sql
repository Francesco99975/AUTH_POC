CREATE TABLE pending_auth_challenges (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('totp_registration', 'mfa_challenge')),
    secret TEXT,
    remember_me BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pending_auth_challenges_user_id ON pending_auth_challenges(user_id);
CREATE INDEX idx_pending_auth_challenges_expires_at ON pending_auth_challenges(expires_at);
