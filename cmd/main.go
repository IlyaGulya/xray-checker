package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"xray-checker/app"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Sync()

	application := app.New(app.Options{
		Logger: logger,
		Env:    os.Getenv("APP_ENV"),
	})

	// Start with background context
	if err := application.Start(context.Background()); err != nil {
		logger.Fatal("failed to start application", zap.Error(err))
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	logger.Info("received shutdown signal", zap.String("signal", sig.String()))

	// Stop with timeout for graceful shutdown
	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := application.Stop(stopCtx); err != nil {
		logger.Fatal("failed to stop application gracefully", zap.Error(err))
	}
}
