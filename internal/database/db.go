package database

import (
	"context"
	"database/sql"
	"log"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

func Setup(dsn string) {
	var err error
	pool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}

	err = pool.Ping(context.Background())
	if err != nil {
		log.Fatalf("Unable to ping database: %v", err)
	}

	err = runMigrations(dsn)
	if err != nil {
		log.Fatalf("Unable to run migrations: %v", err)
	}
}

func runMigrations(dsn string) error {
	// Open a database/sql connection for migrations
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalln(err)
		}
	}()
	// Initialize the migration driver
	driver, err := pgx.WithInstance(db, &pgx.Config{})
	if err != nil {
		return err
	}

	// Initialize migrate with file source and database driver
	m, err := migrate.NewWithDatabaseInstance(
		"file://sql/migrations",
		"postgres",
		driver,
	)
	if err != nil {
		return err
	}

	// Apply all up migrations
	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return err
	}

	return nil
}

// Pool returns the pgxpool.Pool instance for use with sqlc-generated code.
func Pool() *pgxpool.Pool {
	return pool
}

// Close closes the database connection pool.
func Close() {
	if pool != nil {
		pool.Close()
	}
}
