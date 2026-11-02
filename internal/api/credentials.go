package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"golang.org/x/crypto/ssh"

	"github.com/morcheh/backend/internal/sshprobe"
)

type ServerCredentials struct {
	AuthMethod string `json:"auth_method" enum:"password,private_key"`
	Host       string `json:"host"`
	Port       int32  `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password" doc:"Empty unless auth_method=password"`
	PrivateKey string `json:"private_key" doc:"Empty unless auth_method=private_key"`
	Passphrase string `json:"passphrase" doc:"The private key's passphrase; empty when it has none"`
	PublicKey  string `json:"public_key" doc:"authorized_keys line derived from the private key; empty when it can't be parsed"`

	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	HostKey              string `json:"host_key" doc:"Trusted host key in authorized_keys format; empty until the first successful check"`
	HostKeyFingerprint   string `json:"host_key_fingerprint"`
}

type CredentialsOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         ServerCredentials
}

// StorageCredentials is everything a client needs to connect to a storage by
// hand. Only the secrets of the chosen auth method are filled.
type StorageCredentials struct {
	Protocol   string `json:"protocol" enum:"s3,ftp,sftp,webdav"`
	AuthMethod string `json:"auth_method" enum:"password,private_key"`
	Host       string `json:"host"`
	Port       int32  `json:"port" doc:"0 = the protocol's default"`
	Username   string `json:"username" doc:"Access key for S3"`
	Secret     string `json:"secret" doc:"Password, or S3 secret key. Empty unless auth_method=password"`
	PrivateKey string `json:"private_key" doc:"Empty unless auth_method=private_key"`
	Passphrase string `json:"passphrase" doc:"The private key's passphrase; empty when it has none"`
	PublicKey  string `json:"public_key" doc:"authorized_keys line derived from the private key; empty when it can't be parsed"`

	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	HostKey              string `json:"host_key" doc:"SFTP: trusted host key in authorized_keys format; empty until the first successful check"`
	HostKeyFingerprint   string `json:"host_key_fingerprint"`
}

type StorageCredentialsOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         StorageCredentials
}

// publicKeyOf derives the authorized_keys line and fingerprint; both empty
// when there's no key or it can't be parsed.
func publicKeyOf(privateKey, passphrase string) (line, fingerprint string) {
	if privateKey == "" {
		return "", ""
	}
	signer, err := sshprobe.ParseSigner(privateKey, passphrase)
	if err != nil {
		return "", ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), ssh.FingerprintSHA256(signer.PublicKey())
}

func registerStorageCredentials(api huma.API, h *storageHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "reveal-storage-credentials",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/credentials",
		Summary:     "Reveal a storage's credentials",
		Description: "Opens the stored secrets of the chosen auth method. POST and `Cache-Control: no-store` so nothing caches them.",
		Tags:        []string{"Storage"},
	}, func(ctx context.Context, in *StorageIDPath) (*StorageCredentialsOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		cfg, err := h.config(s)
		if err != nil {
			return nil, internalError(err)
		}
		out := &StorageCredentialsOutput{CacheControl: "no-store", Body: StorageCredentials{
			Protocol:           s.Protocol,
			AuthMethod:         s.AuthMethod,
			Host:               s.Host,
			Port:               s.Port,
			Username:           s.Username,
			Secret:             cfg.Secret,
			PrivateKey:         cfg.PrivateKey,
			Passphrase:         cfg.Passphrase,
			HostKey:            s.HostKey,
			HostKeyFingerprint: sshprobe.Fingerprint(s.HostKey),
		}}
		out.Body.PublicKey, out.Body.PublicKeyFingerprint = publicKeyOf(cfg.PrivateKey, cfg.Passphrase)
		return out, nil
	})
}

func registerCredentials(api huma.API, h *serverHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "reveal-server-credentials",
		Method:      http.MethodPost,
		Path:        "/servers/{id}/credentials",
		Summary:     "Reveal a server's SSH credentials",
		Description: "Opens the stored secrets of the chosen auth method. POST and `Cache-Control: no-store` so nothing caches them.",
		Tags:        []string{"Servers"},
	}, func(ctx context.Context, in *ServerIDPath) (*CredentialsOutput, error) {
		s, err := h.get(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		t, err := h.target(s)
		if err != nil {
			return nil, internalError(err)
		}
		out := &CredentialsOutput{CacheControl: "no-store", Body: ServerCredentials{
			AuthMethod:         s.AuthMethod,
			Host:               s.Host,
			Port:               s.Port,
			Username:           s.Username,
			Password:           t.Password,
			PrivateKey:         t.PrivateKey,
			Passphrase:         t.Passphrase,
			HostKey:            s.HostKey,
			HostKeyFingerprint: sshprobe.Fingerprint(s.HostKey),
		}}
		out.Body.PublicKey, out.Body.PublicKeyFingerprint = publicKeyOf(t.PrivateKey, t.Passphrase)
		return out, nil
	})
}
