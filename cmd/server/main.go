package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/Francesco99975/authpoc/cmd/boot"
	"github.com/Francesco99975/authpoc/internal/auth"
	"github.com/Francesco99975/authpoc/internal/database"
	"github.com/Francesco99975/authpoc/internal/enums"
	"github.com/Francesco99975/authpoc/internal/helpers"
	"github.com/Francesco99975/authpoc/internal/models"
	"github.com/Francesco99975/authpoc/internal/repository"
	"github.com/Francesco99975/authpoc/internal/tools"
)

func main() {
	err := boot.LoadEnvVariables()
	if err != nil {
		panic(err)
	}

	if err := models.LoadManifest("./static"); err != nil {
		log.Fatalf("Failed to load Vite manifest: %v", err)
	}

	auth.InitSessionStore()

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

	e := createRouter(ctx)

	err = tools.AddJob("cleanup", "0 0 * * *", func() {
		repo := repository.New(database.Pool())
		err = repo.CleanupExpiredEmailVerifications(ctx)
		if err != nil {
			e.Logger.Warnf("Failed to cleanup expired email verifications: %v", err)
		}
		err = repo.CleanupExpiredPasswordResets(ctx)
		if err != nil {
			e.Logger.Warnf("Failed to cleanup expired password resets: %v", err)
		}
		err = repo.CleanupExpiredRefreshTokens(ctx)
		if err != nil {
			e.Logger.Warnf("Failed to cleanup expired refresh tokens: %v", err)
		}

		e.Logger.Infof("Cleanup Runned!")
	})

	go func() {
		e.Logger.Infof("Running Server on port %s", port)
		e.Logger.Infof("Accessible locally at: http://localhost:%s", port)
		e.Logger.Infof("Accessible on the internet at: %s", boot.Environment.URL)
		e.Logger.Infof("Press Ctrl+C to stop the server and exit.")
		e.Logger.Fatal(e.Start(":" + port))

		if boot.Environment.GoEnv == enums.Environments.DEVELOPMENT {
			e.Logger.Infof("Environement: %s", boot.Environment.DSN)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	helpers.Notify("authpoc", "Server is shutting down")
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		helpers.Notify("authpoc", fmt.Sprintf("Server forced to shutdown: %v", err))
		e.Logger.Fatal(err)
	}
}
