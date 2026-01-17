-- name: CreateUser :one
INSERT INTO users (
    id, role, username, email, password_hash
) VALUES (
    $1, $2, $3, $4, $5
)
RETURNING id, role, username, email, is_active, is_email_verified,
         twofa_enabled, last_login, created_at, updated_at;

-- name: GetUserByID :one
SELECT id, role, username, email, password_hash, is_active,
       is_email_verified, twofa_enabled, last_login,
       created_at, updated_at
FROM users
WHERE id = $1;

-- name: GetUserByEmailOrUsername :one
SELECT
    id,
    role,
    username,
    email,
    password_hash,
    is_active,
    is_email_verified,
    twofa_enabled,
    last_login,
    created_at,
    updated_at
FROM users
WHERE (email = $1 OR username = $1)
  AND is_active = TRUE;

-- name: GetUserByEmail :one
SELECT id, role, username, email, password_hash, is_active,
       is_email_verified, twofa_enabled, last_login,
       created_at, updated_at
FROM users
WHERE email = $1;

-- name: GetUserByUsername :one
SELECT id, role, username, email, password_hash, is_active,
       is_email_verified, twofa_enabled, last_login,
       created_at, updated_at
FROM users
WHERE username = $1;

-- name: UpdateUserLastLogin :exec
UPDATE users
SET last_login = NOW()
WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $1, updated_at = NOW()
WHERE id = $2;

-- name: EnableUser2FA :exec
UPDATE users
SET twofa_secret = $1, twofa_enabled = TRUE, updated_at = NOW()
WHERE id = $2;

-- name: DisableUser2FA :exec
UPDATE users
SET twofa_secret = NULL, twofa_enabled = FALSE, updated_at = NOW()
WHERE id = $1;

-- name: GetUser2FASecret :one
SELECT twofa_secret
FROM users
WHERE id = $1 AND twofa_enabled = TRUE;

-- name: VerifyUserEmail :exec
UPDATE users
SET is_email_verified = TRUE, updated_at = NOW()
WHERE id = $1;

-- name: DeactivateUser :exec
UPDATE users
SET is_active = FALSE, updated_at = NOW()
WHERE id = $1;

-- name: ReactivateUser :exec
UPDATE users
SET is_active = TRUE, updated_at = NOW()
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- name: CleanupInactiveUsers :exec
DELETE FROM users
WHERE is_active = FALSE;

-- name: GetUsers :many
SELECT id, role, username, email, is_active, is_email_verified, twofa_enabled, last_login, created_at, updated_at
FROM users
ORDER BY username
LIMIT $1
OFFSET $2;

-- name: GetUsersCount :one
SELECT COUNT(*)
FROM users;


-- name: GetUsersByRole :many
SELECT id, role, username, email, is_active, is_email_verified, twofa_enabled, last_login, created_at, updated_at
FROM users
WHERE role = $1
ORDER BY username
LIMIT $2
OFFSET $3;

-- name: GetUsersByRoleCount :one
SELECT COUNT(*)
FROM users
WHERE role = $1;


