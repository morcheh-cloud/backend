package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morcheh/backend/internal/database/sqlc"
	"github.com/morcheh/backend/internal/storage"
)

// Bucket settings of an S3 storage: versioning, who can read it, lifecycle
// rules, tags, default encryption, CORS and object lock retention.

// ---- Types ----

type BucketLifecycleRule struct {
	ID               string `json:"id" maxLength:"255" doc:"Empty = a new rule (an id is made up)"`
	Enabled          bool   `json:"enabled"`
	Prefix           string `json:"prefix" maxLength:"1024" doc:"Only objects whose key starts with this; empty = the whole bucket"`
	ExpireDays       int    `json:"expire_days" minimum:"0" maximum:"36500" doc:"Delete objects this many days after they were written (0 = never)"`
	NoncurrentDays   int    `json:"noncurrent_days" minimum:"0" maximum:"36500" doc:"Delete old versions this many days after they were replaced (0 = never)"`
	AbortUploadsDays int    `json:"abort_uploads_days" minimum:"0" maximum:"36500" doc:"Drop unfinished multipart uploads after this many days (0 = never)"`
	DeleteMarkers    bool   `json:"delete_markers" doc:"Remove delete markers with no versions left behind them"`
	TransitionDays   int    `json:"transition_days" minimum:"0" maximum:"36500" doc:"Move objects to transition_class after this many days (0 = never)"`
	TransitionClass  string `json:"transition_class" maxLength:"64" doc:"Storage class to move to (GLACIER, STANDARD_IA…)"`
	Advanced         bool   `json:"advanced" readOnly:"true" doc:"Has parts Morcheh doesn't show (tag or size filters, dates…); they're kept when saved"`
}

type BucketCORSRule struct {
	Origins       []string `json:"origins" minItems:"1" maxItems:"100"`
	Methods       []string `json:"methods" minItems:"1" maxItems:"5"`
	Headers       []string `json:"headers" maxItems:"100"`
	ExposeHeaders []string `json:"expose_headers" maxItems:"100"`
	MaxAgeSeconds int      `json:"max_age_seconds" minimum:"0" maximum:"86400"`
}

type BucketDetails struct {
	Name    string     `json:"name"`
	Region  string     `json:"region"`
	Created *time.Time `json:"created" nullable:"true"`
	// The storage shows only this bucket: it can't be emptied from here
	// with others, deleted or renamed.
	Fixed      bool   `json:"fixed" doc:"The storage is set to this one bucket"`
	Versioning string `json:"versioning" enum:"off,enabled,suspended"`
	Access     string `json:"access" enum:"private,download,public,custom" doc:"Who can read without a key: nobody, anyone with a file's link, or anyone (and list it); custom = a policy Morcheh doesn't recognise"`
	// Anonymous users may write or delete: always worth a warning.
	PublicWrite   bool                  `json:"public_write" doc:"The policy lets anyone write or delete"`
	Policy        string                `json:"policy" doc:"The raw bucket policy (JSON); empty = none"`
	Lifecycle     []BucketLifecycleRule `json:"lifecycle"`
	Tags          map[string]string     `json:"tags"`
	Encryption    string                `json:"encryption" enum:"none,sse-s3,sse-kms"`
	KMSKey        string                `json:"kms_key"`
	ObjectLock    bool                  `json:"object_lock" doc:"Object lock is on (set when the bucket is made, can't be turned off)"`
	RetentionMode string                `json:"retention_mode" enum:",GOVERNANCE,COMPLIANCE" doc:"Default retention for new objects; empty = none"`
	RetentionDays int                   `json:"retention_days"`
	CORS          []BucketCORSRule      `json:"cors"`
	Problems      map[string]string     `json:"problems" doc:"Settings that couldn't be read (versioning, policy, lifecycle, tags, encryption, object_lock, cors, region) and why"`
}

type BucketOutput struct{ Body BucketDetails }

type BucketPath struct {
	StorageIDPath
	Bucket string `path:"bucket" minLength:"1" maxLength:"255"`
}

// ---- Policies ----

const anyone = "*"

type policyDoc struct {
	Version   string            `json:"Version,omitempty"`
	ID        string            `json:"Id,omitempty"`
	Statement []json.RawMessage `json:"Statement"`
}

type policyStatement struct {
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Condition json.RawMessage `json:"Condition"`
	NotAction json.RawMessage `json:"NotAction"`
}

// strs reads a string or a list of strings.
func strs(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

// anonymous reports whether a statement's principal is everyone.
func anonymous(raw json.RawMessage) bool {
	if slices.Contains(strs(raw), anyone) {
		return true
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	return slices.Contains(strs(obj["AWS"]), anyone)
}

// splitPolicy parses a policy into its anonymous Allow statements and the
// rest. ok is false when it isn't JSON Morcheh can read.
func splitPolicy(policy string) (anon []policyStatement, others []json.RawMessage, ok bool) {
	if strings.TrimSpace(policy) == "" {
		return nil, nil, true
	}
	var doc policyDoc
	if json.Unmarshal([]byte(policy), &doc) != nil {
		return nil, nil, false
	}
	for _, raw := range doc.Statement {
		var st policyStatement
		if json.Unmarshal(raw, &st) != nil {
			return nil, nil, false
		}
		if st.Effect == "Allow" && anonymous(st.Principal) {
			anon = append(anon, st)
		} else {
			others = append(others, raw)
		}
	}
	return anon, others, true
}

// classify sums up what a policy lets anyone do with a bucket.
func classify(bucket, policy string) (access string, publicWrite bool) {
	anon, _, ok := splitPolicy(policy)
	if !ok {
		return "custom", false
	}
	if len(anon) == 0 {
		return "private", false
	}
	objects := "arn:aws:s3:::" + bucket + "/*"
	whole := "arn:aws:s3:::" + bucket
	get, list, other := false, false, false
	for _, st := range anon {
		if len(st.Condition) > 0 && string(st.Condition) != "null" || len(st.NotAction) > 0 {
			other = true
		}
		for _, a := range strs(st.Action) {
			low := strings.ToLower(a)
			if strings.Contains(low, "put") || strings.Contains(low, "delete") || strings.HasSuffix(low, "*") {
				publicWrite = true
			}
			res := strs(st.Resource)
			switch low {
			case "s3:getobject":
				get = get || slices.Contains(res, objects)
				other = other || !slices.Contains(res, objects)
			case "s3:listbucket", "s3:getbucketlocation":
				list = list || slices.Contains(res, whole)
				other = other || !slices.Contains(res, whole)
			default:
				other = true
			}
		}
	}
	switch {
	case other || publicWrite:
		return "custom", publicWrite
	case get && list:
		return "public", false
	case get:
		return "download", false
	}
	return "custom", false
}

// withAccess swaps the anonymous statements of a policy for access's, and
// keeps everything else in it. An empty answer = no policy.
func withAccess(bucket, policy, access string) (string, error) {
	_, others, ok := splitPolicy(policy)
	if !ok {
		return "", huma.Error422UnprocessableEntity("The bucket's policy isn't JSON Morcheh can read: edit it as a custom policy instead")
	}
	stmt := func(actions []string, resource string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{
			"Effect": "Allow", "Principal": map[string]any{"AWS": []string{anyone}},
			"Action": actions, "Resource": []string{resource},
		})
		return b
	}
	switch access {
	case "download":
		others = append(others, stmt([]string{"s3:GetObject"}, "arn:aws:s3:::"+bucket+"/*"))
	case "public":
		others = append(others,
			stmt([]string{"s3:GetBucketLocation", "s3:ListBucket"}, "arn:aws:s3:::"+bucket),
			stmt([]string{"s3:GetObject"}, "arn:aws:s3:::"+bucket+"/*"))
	}
	if len(others) == 0 {
		return "", nil
	}
	b, err := json.Marshal(policyDoc{Version: "2012-10-17", Statement: others})
	return string(b), err
}

// ---- Helpers ----

func toBucketDetails(info storage.BucketInfo, fixed bool) BucketDetails {
	out := BucketDetails{
		Name: info.Name, Region: info.Region, Fixed: fixed, Versioning: info.Versioning,
		Policy: info.Policy, Tags: info.Tags, Encryption: info.Encryption, KMSKey: info.KMSKey,
		ObjectLock: info.ObjectLock, RetentionMode: info.RetentionMode, RetentionDays: info.RetentionDays,
		Lifecycle: []BucketLifecycleRule{}, CORS: []BucketCORSRule{}, Problems: info.Problems,
	}
	if !info.Created.IsZero() {
		t := info.Created
		out.Created = &t
	}
	out.Access, out.PublicWrite = classify(info.Name, info.Policy)
	if _, failed := info.Problems["policy"]; failed {
		out.Access = "custom"
	}
	for _, r := range info.Lifecycle {
		out.Lifecycle = append(out.Lifecycle, BucketLifecycleRule{
			ID: r.ID, Enabled: r.Enabled, Prefix: r.Prefix, ExpireDays: r.ExpireDays,
			NoncurrentDays: r.NoncurrentDays, AbortUploadsDays: r.AbortUploadsDays,
			DeleteMarkers: r.DeleteMarkers, TransitionDays: r.TransitionDays,
			TransitionClass: r.TransitionClass, Advanced: r.Advanced,
		})
	}
	for _, r := range info.CORS {
		out.CORS = append(out.CORS, BucketCORSRule{
			Origins: nonNil(r.Origins), Methods: nonNil(r.Methods), Headers: nonNil(r.Headers),
			ExposeHeaders: nonNil(r.ExposeHeaders), MaxAgeSeconds: r.MaxAgeSeconds,
		})
	}
	return out
}

// withBucket runs fn with the storage's bucket admin, after checking the
// bucket is one this storage shows. write also needs a writable storage.
func (h *storageHandler) withBucket(ctx context.Context, in BucketPath, write bool, fn func(b storage.Buckets, fixed bool) error) error {
	return h.withFS(ctx, in.ID, func(row sqlc.Storage, f storage.FS) error {
		if write {
			if err := writable(row); err != nil {
				return err
			}
		}
		b, fixed, ok := storage.BucketsOf(f)
		if !ok {
			return huma.Error422UnprocessableEntity("Only S3 storages have buckets")
		}
		if fixed != "" && in.Bucket != fixed {
			return huma.Error404NotFound("This storage only shows the bucket " + fixed)
		}
		return fn(b, fixed != "")
	})
}

// change applies one setting and answers the bucket as it is afterwards.
func (h *storageHandler) change(ctx context.Context, in BucketPath, fn func(b storage.Buckets) error) (*BucketOutput, error) {
	out := &BucketOutput{}
	err := h.withBucket(ctx, in, true, func(b storage.Buckets, fixed bool) error {
		if err := fn(b); err != nil {
			return bucketProblem(in.Bucket, err)
		}
		info, err := b.BucketInfo(ctx, in.Bucket)
		if err != nil {
			return storageProblem(in.Bucket, err)
		}
		out.Body = toBucketDetails(info, fixed)
		return nil
	})
	return out, err
}

// bucketProblem is storageProblem, with the provider's own words for what
// it refused (a bad rule, a feature it lacks).
func bucketProblem(bucket string, err error) error {
	var se huma.StatusError
	if errors.As(err, &se) {
		return err
	}
	switch code := storage.S3Code(err); code {
	case "NotImplemented", "XNotImplemented":
		return huma.Error422UnprocessableEntity("This provider doesn't support that setting")
	case "MalformedXML", "InvalidRequest", "InvalidArgument", "MalformedPolicy", "InvalidBucketState", "InvalidStorageClass":
		return huma.Error422UnprocessableEntity(storage.S3Message(err))
	}
	return storageProblem(bucket, err)
}

// S3 bucket names: 3–63 lowercase letters, digits, dots and hyphens,
// starting and ending with a letter or digit.
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

var ipLike = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

func checkBucketName(name string) error {
	switch {
	case !bucketName.MatchString(name):
		return huma.Error422UnprocessableEntity("Use 3–63 lowercase letters, digits, dots or hyphens, starting and ending with a letter or digit")
	case strings.Contains(name, ".."):
		return huma.Error422UnprocessableEntity("Two dots in a row aren't allowed")
	case ipLike.MatchString(name):
		return huma.Error422UnprocessableEntity("A bucket name can't look like an IP address")
	}
	return nil
}

var corsMethods = []string{"GET", "PUT", "POST", "DELETE", "HEAD"}

// ---- Handlers ----

func registerStorageBuckets(api huma.API, h *storageHandler) {
	tags := []string{"Storage buckets"}

	huma.Register(api, huma.Operation{
		OperationID: "get-storage-bucket",
		Method:      http.MethodGet,
		Path:        "/storages/{id}/buckets/{bucket}",
		Summary:     "A bucket's settings",
		Description: "Each setting is read on its own; one the provider doesn't support is listed in problems.",
		Tags:        tags,
	}, func(ctx context.Context, in *BucketPath) (*BucketOutput, error) {
		out := &BucketOutput{}
		err := h.withBucket(ctx, *in, false, func(b storage.Buckets, fixed bool) error {
			info, err := b.BucketInfo(ctx, in.Bucket)
			if err != nil {
				return storageProblem(in.Bucket, err)
			}
			out.Body = toBucketDetails(info, fixed)
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID:   "create-storage-bucket",
		Method:        http.MethodPost,
		Path:          "/storages/{id}/buckets",
		Summary:       "Make a bucket",
		Description:   "Only on an S3 storage that shows every bucket. Object lock can only be chosen now; it also turns versioning on.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, in *struct {
		StorageIDPath
		Body struct {
			Name       string `json:"name" minLength:"3" maxLength:"63"`
			Region     string `json:"region,omitempty" maxLength:"64" doc:"Empty = the storage's region"`
			Versioning bool   `json:"versioning,omitempty"`
			ObjectLock bool   `json:"object_lock,omitempty"`
		}
	}) (*BucketOutput, error) {
		name := strings.TrimSpace(in.Body.Name)
		if err := checkBucketName(name); err != nil {
			return nil, err
		}
		out := &BucketOutput{}
		err := h.withFS(ctx, in.ID, func(row sqlc.Storage, f storage.FS) error {
			if err := writable(row); err != nil {
				return err
			}
			b, fixed, ok := storage.BucketsOf(f)
			if !ok {
				return huma.Error422UnprocessableEntity("Only S3 storages have buckets")
			}
			if fixed != "" {
				return huma.Error422UnprocessableEntity("This storage is set to the bucket " + fixed + ": add another storage to reach other buckets")
			}
			err := b.CreateBucket(ctx, name, storage.NewBucket{
				Region: strings.TrimSpace(in.Body.Region), Versioning: in.Body.Versioning, ObjectLock: in.Body.ObjectLock,
			})
			if err != nil {
				return bucketProblem(name, err)
			}
			info, err := b.BucketInfo(ctx, name)
			if err != nil {
				return storageProblem(name, err)
			}
			out.Body = toBucketDetails(info, false)
			return nil
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "empty-storage-bucket",
		Method:      http.MethodPost,
		Path:        "/storages/{id}/buckets/{bucket}/empty",
		Summary:     "Empty a bucket",
		Description: "Deletes every object, old versions and delete markers included, and keeps the bucket and its settings. Objects under object lock retention stay.",
		Tags:        tags,
	}, func(ctx context.Context, in *BucketPath) (*StorageAffectedOutput, error) {
		out := &StorageAffectedOutput{}
		err := h.withBucket(ctx, *in, true, func(b storage.Buckets, _ bool) error {
			n, err := b.EmptyBucket(ctx, in.Bucket)
			out.Body.Affected = n
			return bucketProblem(in.Bucket, err)
		})
		return out, err
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-bucket-versioning",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/buckets/{bucket}/versioning",
		Summary:     "Turn versioning on or pause it",
		Description: "Once on, versioning can only be suspended: old versions stay until deleted.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BucketPath
		Body struct {
			Enabled bool `json:"enabled"`
		}
	}) (*BucketOutput, error) {
		return h.change(ctx, in.BucketPath, func(b storage.Buckets) error {
			return b.SetVersioning(ctx, in.Bucket, in.Body.Enabled)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-bucket-access",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/buckets/{bucket}/access",
		Summary:     "Who can read a bucket without a key",
		Description: "private / download / public replace only the policy's anonymous statements and keep the rest; custom sets policy as given (empty removes it). Some providers (R2, B2) refuse bucket policies.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BucketPath
		Body struct {
			Access string `json:"access" enum:"private,download,public,custom"`
			Policy string `json:"policy,omitempty" maxLength:"20480" doc:"custom only: the whole policy (JSON)"`
		}
	}) (*BucketOutput, error) {
		if in.Body.Access == "custom" && strings.TrimSpace(in.Body.Policy) != "" && !json.Valid([]byte(in.Body.Policy)) {
			return nil, huma.Error422UnprocessableEntity("The policy isn't valid JSON")
		}
		return h.change(ctx, in.BucketPath, func(b storage.Buckets) error {
			policy := strings.TrimSpace(in.Body.Policy)
			if in.Body.Access != "custom" {
				info, err := b.BucketInfo(ctx, in.Bucket)
				if err != nil {
					return err
				}
				if msg, failed := info.Problems["policy"]; failed {
					return huma.Error422UnprocessableEntity("Couldn't read the current policy: " + msg)
				}
				if policy, err = withAccess(in.Bucket, info.Policy, in.Body.Access); err != nil {
					return err
				}
			}
			return b.SetPolicy(ctx, in.Bucket, policy)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-bucket-lifecycle",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/buckets/{bucket}/lifecycle",
		Summary:     "Replace a bucket's lifecycle rules",
		Description: "The whole list; an empty list removes them. A rule with an existing id keeps its parts not shown here.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BucketPath
		Body struct {
			Rules []BucketLifecycleRule `json:"rules" maxItems:"100"`
		}
	}) (*BucketOutput, error) {
		rules := make([]storage.LifecycleRule, 0, len(in.Body.Rules))
		seen := map[string]bool{}
		for i, r := range in.Body.Rules {
			id := strings.TrimSpace(r.ID)
			for n := i + 1; id == "" || seen[id]; n++ {
				id = "rule-" + strconv.Itoa(n)
			}
			seen[id] = true
			if r.DeleteMarkers && r.ExpireDays > 0 {
				return nil, huma.Error422UnprocessableEntity("Rule " + id + ": removing delete markers can't go with deleting objects after some days; use two rules")
			}
			if r.TransitionDays > 0 && strings.TrimSpace(r.TransitionClass) == "" {
				return nil, huma.Error422UnprocessableEntity("Rule " + id + ": pick a storage class to move objects to")
			}
			if r.ExpireDays == 0 && r.NoncurrentDays == 0 && r.AbortUploadsDays == 0 && !r.DeleteMarkers && r.TransitionDays == 0 && !r.Advanced {
				return nil, huma.Error422UnprocessableEntity("Rule " + id + " doesn't do anything: set at least one action")
			}
			rules = append(rules, storage.LifecycleRule{
				ID: id, Enabled: r.Enabled, Prefix: strings.TrimPrefix(r.Prefix, "/"), ExpireDays: r.ExpireDays,
				NoncurrentDays: r.NoncurrentDays, AbortUploadsDays: r.AbortUploadsDays, DeleteMarkers: r.DeleteMarkers,
				TransitionDays: r.TransitionDays, TransitionClass: strings.ToUpper(strings.TrimSpace(r.TransitionClass)),
			})
		}
		return h.change(ctx, in.BucketPath, func(b storage.Buckets) error {
			return b.SetLifecycle(ctx, in.Bucket, rules)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-bucket-tags",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/buckets/{bucket}/tags",
		Summary:     "Replace a bucket's tags",
		Description: "At most 50; an empty map removes them.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BucketPath
		Body struct {
			Tags map[string]string `json:"tags"`
		}
	}) (*BucketOutput, error) {
		if len(in.Body.Tags) > 50 {
			return nil, huma.Error422UnprocessableEntity("At most 50 tags")
		}
		for k, v := range in.Body.Tags {
			if k == "" || len(k) > 128 || len(v) > 256 {
				return nil, huma.Error422UnprocessableEntity("Tag keys are 1–128 characters, values up to 256")
			}
		}
		return h.change(ctx, in.BucketPath, func(b storage.Buckets) error {
			return b.SetBucketTags(ctx, in.Bucket, in.Body.Tags)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-bucket-encryption",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/buckets/{bucket}/encryption",
		Summary:     "Default encryption for new objects",
		Description: "Objects already there keep the encryption they were written with. MinIO needs a KMS set up for either kind.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BucketPath
		Body struct {
			Mode   string `json:"mode" enum:"none,sse-s3,sse-kms"`
			KMSKey string `json:"kms_key,omitempty" maxLength:"2048" doc:"sse-kms only; empty = the provider's default key"`
		}
	}) (*BucketOutput, error) {
		return h.change(ctx, in.BucketPath, func(b storage.Buckets) error {
			return b.SetEncryption(ctx, in.Bucket, in.Body.Mode, strings.TrimSpace(in.Body.KMSKey))
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-bucket-cors",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/buckets/{bucket}/cors",
		Summary:     "Replace a bucket's CORS rules",
		Description: "Which web pages may call the bucket from a browser. An empty list removes them.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BucketPath
		Body struct {
			Rules []BucketCORSRule `json:"rules" maxItems:"100"`
		}
	}) (*BucketOutput, error) {
		rules := make([]storage.CORSRule, 0, len(in.Body.Rules))
		for _, r := range in.Body.Rules {
			methods := make([]string, 0, len(r.Methods))
			for _, m := range r.Methods {
				m = strings.ToUpper(strings.TrimSpace(m))
				if !slices.Contains(corsMethods, m) {
					return nil, huma.Error422UnprocessableEntity("Unknown method " + m + ": use GET, PUT, POST, DELETE or HEAD")
				}
				methods = append(methods, m)
			}
			rules = append(rules, storage.CORSRule{
				Origins: trimAll(r.Origins), Methods: methods, Headers: trimAll(r.Headers),
				ExposeHeaders: trimAll(r.ExposeHeaders), MaxAgeSeconds: r.MaxAgeSeconds,
			})
		}
		return h.change(ctx, in.BucketPath, func(b storage.Buckets) error {
			return b.SetCORS(ctx, in.Bucket, rules)
		})
	})

	huma.Register(api, huma.Operation{
		OperationID: "set-storage-bucket-retention",
		Method:      http.MethodPut,
		Path:        "/storages/{id}/buckets/{bucket}/retention",
		Summary:     "Default retention for new objects",
		Description: "Only on a bucket made with object lock. COMPLIANCE can't be shortened or lifted by anyone, root included, until it runs out.",
		Tags:        tags,
	}, func(ctx context.Context, in *struct {
		BucketPath
		Body struct {
			Mode string `json:"mode" enum:",GOVERNANCE,COMPLIANCE" doc:"Empty = no default retention"`
			Days int    `json:"days" minimum:"0" maximum:"36500"`
		}
	}) (*BucketOutput, error) {
		if in.Body.Mode != "" && in.Body.Days < 1 {
			return nil, huma.Error422UnprocessableEntity("Keep objects at least 1 day")
		}
		return h.change(ctx, in.BucketPath, func(b storage.Buckets) error {
			return b.SetRetention(ctx, in.Bucket, in.Body.Mode, in.Body.Days)
		})
	})
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
