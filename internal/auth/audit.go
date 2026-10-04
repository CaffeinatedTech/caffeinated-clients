package auth

import (
	"context"
	"time"
)

const (
	defaultAuditLimit = 100
	maxAuditLimit     = 500
)

// AuditRecord is one row of the append-only audit log (F13). Detail is JSON and
// never contains a secret note body, password, token, or recovery code.
type AuditRecord struct {
	ID       int64
	At       time.Time
	Event    string
	Entity   string
	EntityID *int64
	ClientID *int64
	IP       string
	Detail   string
}

const auditColumns = `id, at, event, entity, entity_id, client_id, ip, detail`

// ListAudit returns recent audit entries across all entities, newest first.
func (s *Service) ListAudit(ctx context.Context, limit int) ([]AuditRecord, error) {
	return s.listAudit(ctx, "", 0, limit)
}

// ListClientAudit returns recent audit entries for one client, newest first,
// for the client Activity tab (F13.3).
func (s *Service) ListClientAudit(ctx context.Context, clientID int64, limit int) ([]AuditRecord, error) {
	return s.listAudit(ctx, " WHERE client_id = ?", clientID, limit)
}

// AllAudit returns every audit entry, newest first, for the JSON export.
func (s *Service) AllAudit(ctx context.Context) ([]AuditRecord, error) {
	return s.queryAudit(ctx, `SELECT `+auditColumns+` FROM audit_log ORDER BY id DESC`)
}

func (s *Service) listAudit(ctx context.Context, where string, clientID int64, limit int) ([]AuditRecord, error) {
	if limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}
	q := `SELECT ` + auditColumns + ` FROM audit_log` + where + ` ORDER BY id DESC LIMIT ?`
	args := []any{}
	if where != "" {
		args = append(args, clientID)
	}
	args = append(args, limit)
	return s.queryAudit(ctx, q, args...)
}

func (s *Service) queryAudit(ctx context.Context, q string, args ...any) ([]AuditRecord, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRecord
	for rows.Next() {
		var (
			r         AuditRecord
			at        string
			entityID  *int64
			clientRef *int64
		)
		if err := rows.Scan(&r.ID, &at, &r.Event, &r.Entity, &entityID, &clientRef, &r.IP, &r.Detail); err != nil {
			return nil, err
		}
		r.At = parseTS(at)
		r.EntityID = entityID
		r.ClientID = clientRef
		out = append(out, r)
	}
	return out, rows.Err()
}
