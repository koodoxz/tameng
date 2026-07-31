/*
SVALINN - Security Shield
Advanced WAF with ML-powered threat detection

Part of the AEGIS Ecosystem
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
	"github.com/koodoxz/tameng/internal/server"
)

const banner = `
████████╗ █████╗ ███╗   ███╗███████╗███╗   ██╗ ██████╗
╚══██╔══╝██╔══██╗████╗ ████║██╔════╝████╗  ██║██╔════╝
   ██║   ███████║██╔████╔██║█████╗  ██╔██╗ ██║██║  ███╗
   ██║   ██╔══██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║██║   ██║
   ██║   ██║  ██║██║ ╚═╝ ██║███████╗██║ ╚████║╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝
          Security Shield - MECOB Ecosystem
          Version: v9.0 | Build: Production
`

func main() {
	// Parse command line flags
	configPath := flag.String("config", "configs/svalinn.yaml", "Path to configuration file")
	flag.Parse()

	// Print banner
	fmt.Print(banner)

	// Initialize logger
	log := logger.New("SVALINN")
	log.Info("Starting Tameng Security Shield...")

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration", "error", err)
	}
	log.Info("Configuration loaded", "path", *configPath)

	// Create server
	srv, err := server.New(cfg, log)
	if err != nil {
		log.Fatal("Failed to create server", "error", err)
	}

	// Start server in goroutine
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatal("Server failed", "error", err)
		}
	}()

	log.Info("Tameng is now protecting your infrastructure")
	log.Info("Listening on", "http", cfg.Server.HTTPAddr, "https", cfg.Server.HTTPSAddr)

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down gracefully...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Shutdown error", "error", err)
	}

	log.Info("Tameng stopped. Stay safe!")
}
