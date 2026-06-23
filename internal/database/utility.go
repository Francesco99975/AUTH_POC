package database

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// HandleTransaction ensures that a transaction is committed or rolled back properly.
func HandleTransaction(ctx context.Context, tx pgx.Tx, err *error) {
	if p := recover(); p != nil {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil {
			slog.Error("Failed to rollback transaction", slog.Any("rollbackErr", rollbackErr))
		}
		slog.Error("Transaction rolled back on panic", slog.Any("p", p))
		panic(p) // Re-panic after rollback
	} else if *err != nil {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil {
			slog.Error("Failed to rollback transaction", slog.Any("rollbackErr", rollbackErr))
		}
		slog.Error("Transaction rolled back err not nil", slog.Any("err", *err))
	} else {
		commitErr := tx.Commit(ctx)
		if commitErr != nil {
			slog.Error("Failed to commit transaction", slog.Any("commitErr", commitErr))
			*err = fmt.Errorf("commit failed: %w", commitErr)
		}
		slog.Debug("Transaction committed")
	}
}

func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func IsPKCollision(constraintName string) func(error) bool {
	return func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) &&
			pgErr.Code == "23505" &&
			pgErr.ConstraintName == constraintName
	}
}
