-- name: GetRoleByID :one
SELECT id, created_at, updated_at
FROM roles
WHERE id = $1;

-- name: ListRoles :many
SELECT id, created_at, updated_at
FROM roles
ORDER BY id;
