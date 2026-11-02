package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/morcheh/backend/internal/api"
	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/cache"
	"github.com/morcheh/backend/internal/config"
	"github.com/morcheh/backend/internal/database"
	"github.com/morcheh/backend/internal/database/sqlc"
)

const resetAdminUsage = `Usage: server reset-admin [flags]

Sets a new password on an admin account, for when nobody can sign in to do it
from the panel. Unblocks the account and signs it out everywhere. Run it where
the server's environment is (DATABASE_URL, .env). The server can stay running.

The password is asked for twice, or read from one line of stdin when piped. It
is never a flag, so it stays out of the shell history and the process list.

Flags:
`

// resetAdmin runs "server reset-admin". Being able to reach the database with
// the server's own settings is the proof of authority here, as it already
// gives everything the panel guards.
func resetAdmin(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), resetAdminUsage)
		fs.PrintDefaults()
	}
	user := fs.String("user", "", "the admin's username; only needed when there are several admins")
	rename := fs.String("rename", "", "also change the username to this")
	temporary := fs.Bool("temporary", false, "make them choose a new password at next sign-in")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
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
	queries := sqlc.New(db)

	users, err := queries.ListUsers(ctx, sqlc.ListUsersParams{})
	if err != nil {
		return err
	}
	target, err := pickAdmin(users, *user)
	if err != nil {
		return err
	}
	username := target.Username
	if *rename != "" {
		if err := checkRename(users, target, *rename); err != nil {
			return err
		}
		username = *rename
	}

	fmt.Fprintf(os.Stderr, "Resetting %s\n", target.Username)
	password, err := readNewPassword(os.Stdin)
	if err != nil {
		return err
	}
	if err := auth.CheckPassword(password, username); err != nil {
		return fmt.Errorf("password: %w", err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := queries.WithTx(tx)
	if err := q.LockAuth(ctx); err != nil {
		return err
	}
	if _, err := q.SetUserPassword(ctx, sqlc.SetUserPasswordParams{
		ID: target.ID, PasswordHash: hash, MustChangePassword: *temporary,
	}); err != nil {
		return err
	}
	if target.Status != "active" {
		if _, err := q.SetUserStatus(ctx, sqlc.SetUserStatusParams{ID: target.ID, Status: "active"}); err != nil {
			return err
		}
	}
	if username != target.Username {
		if _, err := q.SetUsername(ctx, sqlc.SetUsernameParams{ID: target.ID, Username: username}); err != nil {
			return err
		}
	}
	if err := q.DeleteUserSessions(ctx, target.ID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("Password changed for %s. It is signed out everywhere.\n", target.Username)
	if username != target.Username {
		fmt.Printf("Username is now %s.\n", username)
	}
	if target.Status != "active" {
		fmt.Println("The account was blocked and is active again.")
	}
	if *temporary {
		fmt.Println("A new password has to be chosen at next sign-in.")
	}
	if err := forgetLimits(ctx, cfg.RedisURL, target, username); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't clear the sign-in limits, so a recent lockout can last up to 15 minutes:", err)
	}
	return nil
}

// pickAdmin finds the account to reset: the one named, or the only admin.
func pickAdmin(users []sqlc.User, name string) (sqlc.User, error) {
	if len(users) == 0 {
		return sqlc.User{}, errors.New("there are no accounts yet: open the panel and create the first one")
	}
	var admins []sqlc.User
	var names []string
	for _, u := range users {
		if u.Role == "admin" {
			admins = append(admins, u)
			names = append(names, u.Username)
		}
	}
	list := strings.Join(names, ", ")
	if name != "" {
		for _, u := range users {
			if !strings.EqualFold(u.Username, name) {
				continue
			}
			if u.Role != "admin" {
				return sqlc.User{}, fmt.Errorf("%s isn't an admin: an admin can reset it under Settings › Members (admins: %s)", u.Username, list)
			}
			return u, nil
		}
		return sqlc.User{}, fmt.Errorf("no account called %q (admins: %s)", name, list)
	}
	switch len(admins) {
	case 0:
		return sqlc.User{}, errors.New("no account is an admin")
	case 1:
		return admins[0], nil
	}
	return sqlc.User{}, fmt.Errorf("there are several admins, choose one with -user (%s)", list)
}

// checkRename says why target can't take this username.
func checkRename(users []sqlc.User, target sqlc.User, name string) error {
	if !auth.ValidUsername(name) {
		return fmt.Errorf("rename: %s", auth.UsernameRule)
	}
	for _, u := range users {
		if u.ID != target.ID && strings.EqualFold(u.Username, name) {
			return fmt.Errorf("rename: %s is taken", name)
		}
	}
	return nil
}

func readNewPassword(in *os.File) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return readPasswordLine(in)
	}
	restore, err := restoreEchoOnInterrupt(fd)
	if err != nil {
		return "", err
	}
	defer restore()
	first, err := askHidden(fd, "New password: ")
	if err != nil {
		return "", err
	}
	second, err := askHidden(fd, "Again: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("the passwords don't match, nothing was changed")
	}
	return first, nil
}

func askHidden(fd int, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// readPasswordLine reads a piped password: one line, without its line ending.
func readPasswordLine(in io.Reader) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// restoreEchoOnInterrupt turns echo back on if Ctrl-C lands in a hidden prompt,
// which would otherwise leave the shell not showing what's typed.
func restoreEchoOnInterrupt(fd int) (func(), error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-signals:
			_ = term.Restore(fd, state)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(signals)
		close(done)
	}, nil
}

// forgetLimits lifts a lockout left by failed attempts, so the new password
// works straight away. The old name counts too: that's what was being tried.
func forgetLimits(ctx context.Context, redisURL string, target sqlc.User, username string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rdb, err := cache.Connect(ctx, redisURL)
	if err != nil {
		return err
	}
	defer rdb.Close()
	if err := api.ForgetLoginLimits(ctx, rdb, target.ID, target.Username); err != nil {
		return err
	}
	return api.ForgetLoginLimits(ctx, rdb, target.ID, username)
}
