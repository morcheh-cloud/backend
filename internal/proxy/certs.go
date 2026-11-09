package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Where a certificate comes from.
const (
	CertACME       = "acme"        // a CA over ACME (Let's Encrypt…), renewed by certbot
	CertSelfSigned = "self-signed" // made on the server, for tests and internal names
	CertUpload     = "upload"      // a certificate and key the user already has
)

// SelfDir holds the certificates Morcheh made or was given, one folder each
// (fullchain.pem + privkey.pem). certbot's own stay in /etc/letsencrypt/live.
const SelfDir = "/etc/ssl/morcheh"

// ACMEWebroot is where certbot leaves HTTP-01 answers; every managed site
// serves /.well-known/acme-challenge/ from it on port 80.
const ACMEWebroot = "/var/www/morcheh-acme"

// CA is a certificate authority reachable over ACME.
type CA struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Directory string `json:"directory"`
	EAB       bool   `json:"eab" doc:"Needs External Account Binding (a key ID and HMAC key from the CA's dashboard)"`
	Test      bool   `json:"test,omitempty" doc:"Issues untrusted test certificates, with high limits"`
	Note      string `json:"note,omitempty"`
}

// CAs are the authorities offered by name; "custom" takes any directory URL.
var CAs = []CA{
	{ID: "letsencrypt", Label: "Let's Encrypt", Directory: "https://acme-v02.api.letsencrypt.org/directory",
		Note: "Free, 90-day certificates renewed automatically. At most 5 identical certificates a week."},
	{ID: "letsencrypt-staging", Label: "Let's Encrypt (staging)", Directory: "https://acme-staging-v02.api.letsencrypt.org/directory", Test: true,
		Note: "Untrusted test certificates: browsers warn. Use it to check the setup without touching the real limits."},
	{ID: "zerossl", Label: "ZeroSSL", Directory: "https://acme.zerossl.com/v2/DV90", EAB: true,
		Note: "Free 90-day certificates. Get the EAB key ID and HMAC key under Developer in your ZeroSSL account."},
	{ID: "google", Label: "Google Trust Services", Directory: "https://dv.acme-v02.api.pki.goog/directory", EAB: true,
		Note: "Free. Create the EAB key with gcloud: gcloud publicca external-account-keys create."},
	{ID: "sslcom", Label: "SSL.com", Directory: "https://acme.ssl.com/sslcom-dv-ecc", EAB: true,
		Note: "Free 90-day certificates. The EAB credentials are in your SSL.com account under API credentials."},
}

const CustomCA = "custom"

// CAByID finds a named authority.
func CAByID(id string) (CA, bool) {
	i := slices.IndexFunc(CAs, func(c CA) bool { return c.ID == id })
	if i < 0 {
		return CA{}, false
	}
	return CAs[i], true
}

// CertRequest asks for one certificate on the proxy's server.
type CertRequest struct {
	Source  string   `json:"source" enum:"acme,self-signed,upload"`
	Name    string   `json:"name,omitempty" maxLength:"100" doc:"Folder name; empty = the first domain"`
	Domains []string `json:"domains,omitempty" maxItems:"100" doc:"Names it covers. Uploads read them from the certificate when left out"`

	// ACME
	CA        string `json:"ca,omitempty" doc:"One of the listed CAs, or custom"`
	Directory string `json:"directory,omitempty" doc:"ACME directory URL, for ca = custom"`
	Email     string `json:"email,omitempty" doc:"Where the CA sends expiry warnings; optional"`
	EABKid    string `json:"eab_kid,omitempty" maxLength:"500"`
	EABHMAC   string `json:"eab_hmac,omitempty" maxLength:"500" doc:"Kept sealed with the job (so Retry works), never in plain text"`
	Force     bool   `json:"force,omitempty" doc:"Get a new one even when the current one isn't due for renewal"`

	// ACME and self-signed
	KeyType string `json:"key_type,omitempty" enum:",ecdsa,rsa" doc:"empty = ecdsa"`
	// self-signed
	Days int `json:"days,omitempty" minimum:"0" maximum:"3650" doc:"Validity of a self-signed certificate; 0 = 365"`

	// upload
	Certificate string `json:"certificate,omitempty" maxLength:"200000" doc:"PEM: the certificate, then its intermediates"`
	Key         string `json:"key,omitempty" maxLength:"100000" doc:"PEM private key, without a password; kept sealed with the job, never in plain text"`
}

var (
	certNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)
	eabRe      = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]+$`)
)

// NameFor turns a domain into a folder name: *.example.com → wildcard.example.com.
func NameFor(domain string) string {
	if rest, ok := strings.CutPrefix(domain, "*."); ok {
		return "wildcard." + rest
	}
	return domain
}

// Normalize tidies the request and fills what can be worked out. Uploads take
// their names from the certificate when none are given.
func (r *CertRequest) Normalize() {
	var domains []string
	for _, d := range r.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !slices.Contains(domains, d) {
			domains = append(domains, d)
		}
	}
	r.Domains = domains
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	r.CA = strings.TrimSpace(r.CA)
	r.Directory = strings.TrimSpace(r.Directory)
	r.Email = strings.TrimSpace(r.Email)
	r.EABKid, r.EABHMAC = strings.TrimSpace(r.EABKid), strings.TrimSpace(r.EABHMAC)
	r.Certificate = strings.TrimSpace(strings.ReplaceAll(r.Certificate, "\r\n", "\n"))
	r.Key = strings.TrimSpace(strings.ReplaceAll(r.Key, "\r\n", "\n"))
	if r.Source == CertUpload && len(r.Domains) == 0 {
		if leaf := leafOf(r.Certificate); leaf != nil {
			r.Domains = append(r.Domains, leaf.DNSNames...)
			for _, ip := range leaf.IPAddresses {
				r.Domains = append(r.Domains, ip.String())
			}
			if len(r.Domains) == 0 && leaf.Subject.CommonName != "" {
				r.Domains = []string{strings.ToLower(leaf.Subject.CommonName)}
			}
		}
	}
	if r.Name == "" && len(r.Domains) > 0 {
		r.Name = NameFor(r.Domains[0])
	}
	if r.Source != CertACME {
		r.CA, r.Directory, r.Email, r.EABKid, r.EABHMAC, r.Force = "", "", "", "", "", false
	}
	if r.Source != CertUpload {
		r.Certificate, r.Key = "", ""
	}
	if r.Source == CertUpload {
		r.KeyType = ""
	}
	if r.Source == CertACME && r.CA == "" {
		r.CA = "letsencrypt"
	}
	if r.CA != CustomCA {
		r.Directory = ""
	}
	if r.Source == CertSelfSigned && r.Days == 0 {
		r.Days = 365
	}
}

func leafOf(text string) *x509.Certificate {
	b, _ := pem.Decode([]byte(text))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// DirectoryURL is the ACME directory the request goes to.
func (r CertRequest) DirectoryURL() string {
	if r.CA == CustomCA {
		return r.Directory
	}
	ca, _ := CAByID(r.CA)
	return ca.Directory
}

// Paths are where the certificate and key end up.
func (r CertRequest) Paths() (cert, key string) {
	dir := SelfDir + "/" + r.Name
	if r.Source == CertACME {
		dir = "/etc/letsencrypt/live/" + r.Name
	}
	return dir + "/fullchain.pem", dir + "/privkey.pem"
}

// Validate checks a normalized request; fields are named as in the JSON.
func (r CertRequest) Validate() []Problem {
	var out []Problem
	add := func(field, msg, value string) {
		out = append(out, Problem{Field: field, Message: msg, Value: value})
	}
	switch r.Source {
	case CertACME, CertSelfSigned, CertUpload:
	default:
		add("source", "Choose acme, self-signed or upload.", r.Source)
		return out
	}
	if len(r.Domains) == 0 {
		msg := "Add at least one domain."
		if r.Source == CertUpload {
			msg = "The certificate names no domain; add them."
		}
		add("domains", msg, "")
	}
	for i, d := range r.Domains {
		field := fmt.Sprintf("domains[%d]", i)
		_, ipErr := netip.ParseAddr(d)
		switch {
		case !validDomain(d):
			add(field, "Not a domain name.", d)
		case r.Source == CertACME && strings.HasPrefix(d, "*."):
			add(field, "Wildcard names need DNS validation, which isn't available here yet. List the names, or use a self-signed or uploaded certificate.", d)
		case r.Source == CertACME && ipErr == nil:
			add(field, "Certificate authorities issue for names, not addresses. Use a self-signed certificate for an address.", d)
		case r.Source == CertACME && !strings.Contains(d, "."):
			add(field, "A public certificate needs a full domain name, like app.example.com.", d)
		}
	}
	if !certNameRe.MatchString(r.Name) || strings.Contains(r.Name, "..") {
		add("name", "Use lowercase letters, digits, dots, dashes and underscores.", r.Name)
	}
	switch r.Source {
	case CertACME:
		ca, named := CAByID(r.CA)
		switch {
		case r.CA == CustomCA:
			u, err := url.Parse(r.Directory)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				add("directory", "Use the CA's https:// ACME directory address.", r.Directory)
			}
		case !named:
			add("ca", "Choose a certificate authority.", r.CA)
		}
		if r.Email != "" {
			if a, err := mail.ParseAddress(r.Email); err != nil || a.Address != r.Email || strings.ContainsAny(r.Email, "'\"\\ ") {
				add("email", "Not an email address.", r.Email)
			}
		}
		needEAB := named && ca.EAB
		if needEAB || r.EABKid != "" || r.EABHMAC != "" {
			if r.EABKid == "" || !eabRe.MatchString(r.EABKid) {
				add("eab_kid", "Paste the EAB key ID from the CA.", "")
			}
			if r.EABHMAC == "" || !eabRe.MatchString(r.EABHMAC) {
				add("eab_hmac", "Paste the EAB HMAC key from the CA.", "")
			}
		}
	case CertUpload:
		if leafOf(r.Certificate) == nil {
			add("certificate", "Paste the certificate in PEM form (-----BEGIN CERTIFICATE-----).", "")
		} else if _, err := tls.X509KeyPair([]byte(r.Certificate), []byte(r.Key)); err != nil {
			msg := "This key doesn't belong to the certificate."
			if b, _ := pem.Decode([]byte(r.Key)); b == nil || !strings.HasSuffix(b.Type, "PRIVATE KEY") {
				msg = "Paste the private key in PEM form (-----BEGIN PRIVATE KEY-----), without a password."
			}
			add("key", msg, "")
		}
	}
	return out
}
