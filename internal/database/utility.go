package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/gommon/log"
)

// HandleTransaction ensures that a transaction is committed or rolled back properly.
func HandleTransaction(ctx context.Context, tx pgx.Tx, err *error) {
	if p := recover(); p != nil {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil {
			log.Errorf("Failed to rollback transaction: %v", rollbackErr)
		}
		log.Errorf("Transaction rolled back: %v", p)
		panic(p) // Re-panic after rollback
	} else if *err != nil {
		rollbackErr := tx.Rollback(ctx)
		if rollbackErr != nil {
			log.Errorf("Failed to rollback transaction: %v", rollbackErr)
		}
		log.Errorf("Transaction rolled back: %v", *err)
	} else {
		commitErr := tx.Commit(ctx)
		if commitErr != nil {
			log.Errorf("Failed to commit transaction: %v", commitErr)
			*err = fmt.Errorf("commit failed: %w", commitErr)
		}
		log.Debug("Transaction committed")
	}
}
