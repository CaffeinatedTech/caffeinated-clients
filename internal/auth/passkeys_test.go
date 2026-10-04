package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPasswordLoginEnabledAndRemovePassword(t *testing.T) {
	svc, _ := openTestService(t)
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx, "admin", "correct horse battery"); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if ok, err := svc.PasswordLoginEnabled(ctx); err != nil || !ok {
		t.Fatalf("PasswordLoginEnabled = %v, %v; want true", ok, err)
	}
	u, err := svc.GetUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RemovePassword(ctx, u.ID); err != nil {
		t.Fatalf("RemovePassword: %v", err)
	}
	if ok, err := svc.PasswordLoginEnabled(ctx); err != nil || ok {
		t.Fatalf("PasswordLoginEnabled after remove = %v, %v; want false", ok, err)
	}
	// A passkey-only account must not authenticate with any password.
	if _, ok, err := svc.Authenticate(ctx, "admin", "correct horse battery"); err != nil || ok {
		t.Fatalf("Authenticate on passkey-only account = %v, %v; want false", ok, err)
	}
}

func TestPasskeyCRUD(t *testing.T) {
	svc, _ := openTestService(t)
	ctx := context.Background()
	u, err := svc.CreateUserNoPassword(ctx, "Adam")
	if err != nil {
		t.Fatalf("CreateUserNoPassword: %v", err)
	}
	id, err := svc.AddPasskey(ctx, Passkey{
		UserID: u.ID, CredentialID: []byte("cred-1"), PublicKey: []byte("pub"),
		AttestationType: "none", AAGUID: []byte{1, 2, 3}, SignCount: 0,
		BackupEligible: true, Transports: []string{"usb", "hybrid"}, Name: "YubiKey",
	})
	if err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	list, err := svc.ListPasskeys(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListPasskeys = %d, %v; want 1", len(list), err)
	}
	p := list[0]
	if string(p.CredentialID) != "cred-1" || !p.BackupEligible || len(p.Transports) != 2 || p.Name != "YubiKey" {
		t.Fatalf("stored passkey round-trip mismatch: %+v", p)
	}
	if n, err := svc.PasskeyCount(ctx, u.ID); err != nil || n != 1 {
		t.Fatalf("PasskeyCount = %d, %v; want 1", n, err)
	}
	if err := svc.RenamePasskey(ctx, u.ID, id, "Phone"); err != nil {
		t.Fatalf("RenamePasskey: %v", err)
	}
	if err := svc.UpdatePasskeyUse(ctx, id, 7); err != nil {
		t.Fatalf("UpdatePasskeyUse: %v", err)
	}
	list, _ = svc.ListPasskeys(ctx, u.ID)
	if list[0].Name != "Phone" || list[0].SignCount != 7 || list[0].LastUsedAt == "" {
		t.Fatalf("rename/use not persisted: %+v", list[0])
	}
	// A duplicate credential id is rejected by the unique index.
	if _, err := svc.AddPasskey(ctx, Passkey{UserID: u.ID, CredentialID: []byte("cred-1"), PublicKey: []byte("x")}); err == nil {
		t.Fatal("duplicate credential_id was accepted")
	}
	if err := svc.DeletePasskey(ctx, u.ID, id); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	if n, _ := svc.PasskeyCount(ctx, u.ID); n != 0 {
		t.Fatalf("PasskeyCount after delete = %d, want 0", n)
	}
}

func TestChallengeSingleUseKindAndExpiry(t *testing.T) {
	svc, _ := openTestService(t)
	ctx := context.Background()
	u, err := svc.CreateUserNoPassword(ctx, "Adam")
	if err != nil {
		t.Fatal(err)
	}

	token, err := svc.StoreChallenge(ctx, &u.ID, "login", `{"challenge":"abc"}`, time.Minute)
	if err != nil {
		t.Fatalf("StoreChallenge: %v", err)
	}
	// Wrong kind consumes and rejects.
	if _, err := svc.TakeChallenge(ctx, token, "register"); !errors.Is(err, ErrChallenge) {
		t.Fatalf("TakeChallenge wrong kind = %v, want ErrChallenge", err)
	}
	// Already consumed.
	if _, err := svc.TakeChallenge(ctx, token, "login"); !errors.Is(err, ErrChallenge) {
		t.Fatalf("TakeChallenge reuse = %v, want ErrChallenge", err)
	}

	expired, err := svc.StoreChallenge(ctx, &u.ID, "login", "{}", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TakeChallenge(ctx, expired, "login"); !errors.Is(err, ErrChallenge) {
		t.Fatalf("TakeChallenge expired = %v, want ErrChallenge", err)
	}

	fresh, err := svc.StoreChallenge(ctx, &u.ID, "register", `{"challenge":"ok"}`, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	data, err := svc.TakeChallenge(ctx, fresh, "register")
	if err != nil || data != `{"challenge":"ok"}` {
		t.Fatalf("TakeChallenge = %q, %v", data, err)
	}
}
