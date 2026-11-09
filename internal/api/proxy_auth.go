package api

import (
	"fmt"

	"github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/morcheh/backend/internal/proxy"
)

// hashPasswords turns the passwords sent for basic auth into hashes. A user
// sent without one keeps the hash saved under the same name in old (nil for
// a new site); a new name needs a password. Hashes sent by the client are
// never trusted.
func hashPasswords(c *proxy.HostConfig, old *proxy.HostConfig) error {
	saved := map[string]string{}
	if old != nil {
		for _, u := range old.Auth.Users {
			saved[u.Name] = u.Hash
		}
	}
	for i := range c.Auth.Users {
		u := &c.Auth.Users[i]
		u.Hash = ""
		if c.Auth.Mode != "basic" {
			u.Password = ""
			continue
		}
		if u.Password != "" {
			hash, err := sha512_crypt.New().Generate([]byte(u.Password), nil)
			if err != nil {
				return internalError(err)
			}
			u.Hash, u.Password = hash, ""
			continue
		}
		if h := saved[u.Name]; h != "" {
			u.Hash = h
			continue
		}
		return fieldError(fmt.Sprintf("body.config.auth.users[%d].password", i), "Set a password for "+u.Name+".", nil)
	}
	return nil
}

// withoutPasswords drops every password and hash, for answers.
func withoutPasswords(c proxy.HostConfig) proxy.HostConfig {
	if len(c.Auth.Users) == 0 {
		return c
	}
	users := make([]proxy.AuthUser, len(c.Auth.Users))
	for i, u := range c.Auth.Users {
		users[i] = proxy.AuthUser{Name: u.Name}
	}
	c.Auth.Users = users
	return c
}
