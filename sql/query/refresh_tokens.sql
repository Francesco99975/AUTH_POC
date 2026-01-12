-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (
    id, user_id, token_hash, expires_at, ip_address, user_agent
) VALUES (
    $1, $2, $3, $4, $5, $6
);

-- name: GetRefreshTokenByHash :one
SELECT id, user_id, token_hash, expires_at, revoked, created_at
FROM refresh_tokens
WHERE token_hash = $1 AND revoked = FALSE;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = TRUE
WHERE id = $1;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens
SET revoked = TRUE
WHERE user_id = $1 AND revoked = FALSE;

-- name: CleanupExpiredRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < NOW();
