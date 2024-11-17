package main

import (
	"context"
	"go.uber.org/zap"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"xray-checker/app"
	"xray-checker/internal/common"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Sync()

	application := app.NewApplication(
		common.WithLogger(logger),
		common.WithEnv(os.Getenv("APP_ENV")),
	)

	// Start with background context
	if err := application.Start(context.Background()); err != nil {
		logger.Fatal("failed to start application", zap.Error(err))
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	logger.Info("received shutdown signal", zap.String("signal", sig.String()))

	// Stop with timeout
	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := application.Stop(stopCtx); err != nil {
		logger.Fatal("failed to stop application gracefully", zap.Error(err))
	}
}
