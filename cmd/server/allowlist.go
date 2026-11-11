package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/morcheh/backend/internal/config"
	"github.com/morcheh/backend/internal/database"
	"github.com/morcheh/backend/internal/database/sqlc"
)

const allowlistUsage = `Usage: server allowlist show|off

The panel's allowed addresses, for when the allowlist keeps everyone out.

  show  print whether it's on and what's in it
  off   turn it off (the list is kept); the running server notices within a minute

Run it where the server's environment is (DATABASE_URL, .env).
`

// allowlist runs "server allowlist". Reaching the database with the server's
// own settings is the proof of authority, as for reset-admin.
func allowlist(args []string) error {
	fs := flag.NewFlagSet("allowlist", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), allowlistUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 || (fs.Arg(0) != "show" && fs.Arg(0) != "off") {
		fs.Usage()
		return errors.New("say show or off")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	q := sqlc.New(db)

	st, err := q.GetSettings(ctx)
	if err != nil {
		return err
	}
	if fs.Arg(0) == "off" {
		if st, err = q.SetAllowlistEnabled(ctx, false); err != nil {
			return err
		}
		fmt.Println("The allowlist is off: every address can reach the panel again (within a minute).")
		return nil
	}
	state := "off"
	if st.IpAllowlistEnabled {
		state = "on"
	}
	fmt.Printf("Allowlist: %s\n", state)
	var entries []struct{ Address, Note string }
	_ = json.Unmarshal(st.IpAllowlist, &entries)
	if len(entries) == 0 {
		fmt.Println("  (no addresses)")
	}
	for _, e := range entries {
		if e.Note != "" {
			fmt.Printf("  %-40s %s\n", e.Address, e.Note)
		} else {
			fmt.Printf("  %s\n", e.Address)
		}
	}
	return nil
}
