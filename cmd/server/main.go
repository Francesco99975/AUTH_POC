package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/internal/tools"
	"github.com/labstack/echo/v4"
)

func main() {
	err := boot.LoadEnvVariables()
	if err != nil {
		panic(err)
	}

	slog.SetDefault(boot.NewLogger())

	if err := models.LoadManifest("./static"); err != nil {
		log.Fatalf("Failed to load Vite manifest: %v", err)
	}

	// auth.InitSessionStore()

	// Create a root ctx and a CancelFunc which can be used to cancel retentionMap goroutine
	rootCtx := context.Background()
	ctx, cancel := context.WithCancel(rootCtx)
	defer cancel()

	port := boot.Environment.Port

	database.Setup(boot.Environment.DSN)
	defer database.Close()

	if err != nil {
		panic(err)
	}

	e := createRouter()

	err = tools.AddJob("cleanup", "0 0 * * *", func() {
		repo := repository.New(database.Pool())
		err = repo.CleanupExpiredEmailVerifications(ctx)
		if err != nil {
			slog.Warn("Failed to cleanup expired email verifications", slog.Any("error", err))
		}
		err = repo.CleanupExpiredPasswordResets(ctx)
		if err != nil {
			slog.Warn("Failed to cleanup expired password resets", slog.Any("error", err))
		}
		err = repo.CleanupExpiredRefreshTokens(ctx)
		if err != nil {
			slog.Warn("Failed to cleanup expired refresh tokens", slog.Any("error", err))
		}

		err = repo.DeleteExpiredPendingAuthChallenges(ctx)
		if err != nil {
			slog.Warn("Failed to delete expired pending auth challenges", slog.Any("error", err))
		}

		slog.Info("Cleanup Ran!")
	})

	go func() {
		slog.Info("Starting Server",
			slog.String("framework", "echo"),
			slog.String("version", echo.Version),
			slog.String("port", port),
		)
		slog.Info("Local Access", slog.String("url", fmt.Sprintf("http://localhost:%s", port)))
		slog.Info("Internet Access", slog.String("url", boot.Environment.URL))
		slog.Info("Press Ctrl+C to stop the server and exit.")
		err := e.Start(":" + port)
		boot.FatalLog("Server exited, could not start", err)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	helpers.Notify("authpoc", "Server is shutting down")
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		helpers.Notify("authpoc", fmt.Sprintf("Server forced to shutdown: %v", err))
		log.Fatal(err)
	}
}
