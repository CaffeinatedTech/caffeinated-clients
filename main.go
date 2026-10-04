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
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CaffeinatedTech/caffeinated-clients/internal/auth"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/config"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/logging"
	"github.com/CaffeinatedTech/caffeinated-clients/internal/store"
	"github.com/CaffeinatedTech/caffeinated-clients/web"
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

	svc := auth.NewService(db, authParams(cfg), "caffeinated-clients")
	if err := svc.DeleteExpiredSessions(ctx); err != nil {
		return err
	}

	if *bootstrap {
		if cfg.BootstrapUser == "" || cfg.BootstrapPass == "" {
			return errors.New("--bootstrap-admin requires CCLIENTS_BOOTSTRAP_USERNAME and CCLIENTS_BOOTSTRAP_PASSWORD")
		}
		created, err := svc.Bootstrap(ctx, cfg.BootstrapUser, cfg.BootstrapPass)
		if err != nil {
			return err
		}
		if created {
			log.Info("created the single user", "username", cfg.BootstrapUser)
		} else {
			log.Info("single user already exists; nothing to do")
		}
		return nil
	}

	if err := ensureUser(ctx, log, svc, cfg); err != nil {
		return err
	}

	return serve(ctx, log, cfg, db, svc)
}

// ensureUser auto-bootstraps the single account from the environment on first
// run. If no user exists and no bootstrap credentials are set, it warns and
// lets the app start; the login flow simply cannot succeed until a user exists.
func ensureUser(ctx context.Context, log *slog.Logger, svc *auth.Service, cfg *config.Config) error {
	n, err := svc.UserCount(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if cfg.BootstrapUser == "" || cfg.BootstrapPass == "" {
		log.Warn("no user account exists; set CCLIENTS_BOOTSTRAP_USERNAME/PASSWORD or run --bootstrap-admin")
		return nil
	}
	created, err := svc.Bootstrap(ctx, cfg.BootstrapUser, cfg.BootstrapPass)
	if err != nil {
		return err
	}
	if created {
		log.Info("created the single user from bootstrap env", "username", cfg.BootstrapUser)
	}
	return nil
}

// authParams maps configuration onto the Argon2id cost parameters.
func authParams(cfg *config.Config) auth.Params {
	p := auth.DefaultParams()
	p.Memory = cfg.Argon2Memory
	p.Time = cfg.Argon2Time
	p.Threads = cfg.Argon2Threads
	return p
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

func serve(ctx context.Context, log *slog.Logger, cfg *config.Config, db *sql.DB, svc *auth.Service) error {
	srvWeb, err := web.New(svc, cfg, log, db)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srvWeb.Handler(),
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
