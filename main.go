// Command caffeinated-clients is a single-user, self-hosted CRM for an IT
// services operator. This binary is the whole app: one encrypted SQLite file,
// one process, no external services.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/logging"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	bootstrap := flag.Bool("bootstrap-admin", false, "initialise the encrypted database, then exit")
	healthcheck := flag.Bool("healthcheck", false, "open the database, run a decrypting ping, and exit")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logging.New(cfg.LogLevel)

	if cfg.Disable2FA {
		log.Warn("CCLIENTS_DISABLE_2FA=true: TOTP two-factor authentication is disabled; the password is still required. Break-glass only.")
	}

	if *healthcheck {
		return healthcheckRun(cfg)
	}

	db, err := store.Open(cfg.DBPath, cfg.DBKey)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := store.Migrate(ctx, db); err != nil {
		return err
	}

	if *bootstrap {
		log.Info("encrypted database ready", "path", cfg.DBPath)
		// ponytail: the single-user account is created by the auth work in
		// Phase 2; this flag exists now so the CLI surface is stable.
		log.Info("single-user account bootstrap lands with authentication (Phase 2); no user created yet")
		return nil
	}

	return serve(ctx, log, cfg, db)
}

// healthcheckRun validates that the (existing) encrypted database can be
// opened and decrypted, without creating one. It is used by Docker/Compose.
func healthcheckRun(cfg *config.Config) error {
	if _, err := os.Stat(cfg.DBPath); err != nil {
		return fmt.Errorf("database not initialised at %s: %w", cfg.DBPath, err)
	}
	db, err := store.Open(cfg.DBPath, cfg.DBKey)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := store.Health(context.Background(), db); err != nil {
		return fmt.Errorf("database healthcheck: %w", err)
	}
	return nil
}

func serve(ctx context.Context, log *slog.Logger, cfg *config.Config, db *sql.DB) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := store.Health(r.Context(), db); err != nil {
			log.Error("healthz: database ping failed", "err", err)
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, "ok\n")
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL, "db", cfg.DBPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
