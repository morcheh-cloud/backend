package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/cors"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
	"github.com/minio/minio-go/v7/pkg/sse"
	"github.com/minio/minio-go/v7/pkg/tags"
)

// Bucket settings for S3 storages. Every setting is read on its own: a
// provider that doesn't implement one (R2 has no versioning, Wasabi no
// CORS…) only blanks that part, reported in Problems.

// Buckets is what an S3 storage can do with its buckets.
type Buckets interface {
	BucketInfo(ctx context.Context, bucket string) (BucketInfo, error)
	CreateBucket(ctx context.Context, name string, opts NewBucket) error
	EmptyBucket(ctx context.Context, bucket string) (int, error)
	SetVersioning(ctx context.Context, bucket string, on bool) error
	SetPolicy(ctx context.Context, bucket, policy string) error
	SetLifecycle(ctx context.Context, bucket string, rules []LifecycleRule) error
	SetBucketTags(ctx context.Context, bucket string, t map[string]string) error
	SetEncryption(ctx context.Context, bucket, mode, kmsKey string) error
	SetCORS(ctx context.Context, bucket string, rules []CORSRule) error
	SetRetention(ctx context.Context, bucket, mode string, days int) error
}

// BucketsOf returns the bucket admin behind a storage and, when the storage
// is pinned to one bucket (a fixed bucket, or a root folder inside one),
// that bucket's name. ok is false for anything but S3.
func BucketsOf(f FS) (b Buckets, fixed string, ok bool) {
	if r, isRooted := f.(*rooted); isRooted {
		b, fixed, ok = BucketsOf(r.FS)
		if ok && fixed == "" {
			fixed, _, _ = strings.Cut(strings.TrimPrefix(r.root, "/"), "/")
		}
		return b, fixed, ok
	}
	s, isS3 := f.(*s3fs)
	if !isS3 {
		return nil, "", false
	}
	return s, s.bucket, true
}

type BucketInfo struct {
	Name    string
	Region  string
	Created time.Time
	// "off" (never turned on), "enabled" or "suspended".
	Versioning string
	// The raw bucket policy (JSON); empty = none.
	Policy    string
	Lifecycle []LifecycleRule
	Tags      map[string]string
	// "none", "sse-s3" or "sse-kms".
	Encryption string
	KMSKey     string
	ObjectLock bool
	// Default retention for new objects when ObjectLock: "" (none),
	// "GOVERNANCE" or "COMPLIANCE".
	RetentionMode string
	RetentionDays int
	CORS          []CORSRule
	// Settings that couldn't be read, by name (versioning, policy,
	// lifecycle, tags, encryption, object_lock, cors, region).
	Problems map[string]string
}

// LifecycleRule is the part of a lifecycle rule people usually set. Other
// parts of an existing rule (tag or size filters, dates…) are kept as they
// are when it's saved again; Advanced says it has some.
type LifecycleRule struct {
	ID      string
	Enabled bool
	Prefix  string
	// Delete current objects this many days after they were written.
	ExpireDays int
	// Delete old versions this many days after they were replaced.
	NoncurrentDays int
	// Drop unfinished multipart uploads after this many days.
	AbortUploadsDays int
	// Remove delete markers that have no versions left behind them.
	DeleteMarkers bool
	// Move objects to TransitionClass this many days after they were written.
	TransitionDays  int
	TransitionClass string
	Advanced        bool
}

type CORSRule struct {
	Origins       []string
	Methods       []string
	Headers       []string
	ExposeHeaders []string
	MaxAgeSeconds int
}

type NewBucket struct {
	Region     string
	ObjectLock bool
	Versioning bool
}

// Error codes S3 answers when a setting simply isn't set.
var notSet = map[string]bool{
	"NoSuchBucketPolicy":                             true,
	"NoSuchLifecycleConfiguration":                   true,
	"NoSuchTagSet":                                   true,
	"NoSuchTagSetError":                              true,
	"ServerSideEncryptionConfigurationNotFoundError": true,
	"NoSuchCORSConfiguration":                        true,
	"ObjectLockConfigurationNotFoundError":           true,
	"NoSuchObjectLockConfiguration":                  true,
}

func isNotSet(err error) bool {
	return err != nil && notSet[minio.ToErrorResponse(err).Code]
}

// problemText is a short reason a setting couldn't be read.
func problemText(err error) string {
	switch minio.ToErrorResponse(err).Code {
	case "NotImplemented", "XNotImplemented":
		return "This provider doesn't support it"
	case "AccessDenied":
		return "The access key isn't allowed to read it"
	}
	return s3Text(err)
}

func (s *s3fs) BucketInfo(ctx context.Context, bucket string) (BucketInfo, error) {
	info := BucketInfo{Name: bucket, Versioning: "off", Encryption: "none", Tags: map[string]string{}, Problems: map[string]string{}}
	ok, err := s.c.BucketExists(ctx, bucket)
	if err != nil {
		return info, s3Err(err)
	}
	if !ok {
		return info, fmt.Errorf("no bucket %s: %w", bucket, fs.ErrNotExist)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	read := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := fn()
			if err != nil && !isNotSet(err) {
				mu.Lock()
				info.Problems[name] = problemText(err)
				mu.Unlock()
			}
		}()
	}
	// Each reader writes only its own fields.
	read("region", func() error {
		r, err := s.c.GetBucketLocation(ctx, bucket)
		info.Region = r
		return err
	})
	read("created", func() error {
		list, err := s.c.ListBuckets(ctx)
		for _, b := range list {
			if b.Name == bucket {
				info.Created = b.CreationDate
			}
		}
		return err
	})
	read("versioning", func() error {
		v, err := s.c.GetBucketVersioning(ctx, bucket)
		switch v.Status {
		case "Enabled":
			info.Versioning = "enabled"
		case "Suspended":
			info.Versioning = "suspended"
		}
		return err
	})
	read("policy", func() error {
		p, err := s.c.GetBucketPolicy(ctx, bucket)
		info.Policy = p
		return err
	})
	read("lifecycle", func() error {
		cfg, err := s.c.GetBucketLifecycle(ctx, bucket)
		if cfg != nil {
			for _, r := range cfg.Rules {
				info.Lifecycle = append(info.Lifecycle, fromLifecycle(r))
			}
		}
		return err
	})
	read("tags", func() error {
		t, err := s.c.GetBucketTagging(ctx, bucket)
		if t != nil {
			info.Tags = t.ToMap()
		}
		return err
	})
	read("encryption", func() error {
		cfg, err := s.c.GetBucketEncryption(ctx, bucket)
		if cfg != nil && len(cfg.Rules) > 0 {
			a := cfg.Rules[0].Apply
			if strings.EqualFold(a.SSEAlgorithm, "aws:kms") {
				info.Encryption, info.KMSKey = "sse-kms", a.KmsMasterKeyID
			} else if a.SSEAlgorithm != "" {
				info.Encryption = "sse-s3"
			}
		}
		return err
	})
	read("object_lock", func() error {
		enabled, mode, validity, unit, err := s.c.GetObjectLockConfig(ctx, bucket)
		info.ObjectLock = enabled == "Enabled"
		if mode != nil && validity != nil {
			info.RetentionMode = string(*mode)
			info.RetentionDays = int(*validity)
			if unit != nil && *unit == minio.Years {
				info.RetentionDays *= 365
			}
		}
		return err
	})
	read("cors", func() error {
		cfg, err := s.c.GetBucketCors(ctx, bucket)
		if cfg != nil {
			for _, r := range cfg.CORSRules {
				info.CORS = append(info.CORS, CORSRule{
					Origins: r.AllowedOrigin, Methods: r.AllowedMethod, Headers: r.AllowedHeader,
					ExposeHeaders: r.ExposeHeader, MaxAgeSeconds: r.MaxAgeSeconds,
				})
			}
		}
		return err
	})
	wg.Wait()
	// The listing is only for the date; not worth a warning.
	delete(info.Problems, "created")
	return info, nil
}

func fromLifecycle(r lifecycle.Rule) LifecycleRule {
	out := LifecycleRule{
		ID:               r.ID,
		Enabled:          r.Status == "Enabled",
		Prefix:           r.RuleFilter.Prefix,
		ExpireDays:       int(r.Expiration.Days),
		NoncurrentDays:   int(r.NoncurrentVersionExpiration.NoncurrentDays),
		AbortUploadsDays: int(r.AbortIncompleteMultipartUpload.DaysAfterInitiation),
		DeleteMarkers:    r.Expiration.DeleteMarker.IsEnabled(),
		TransitionDays:   int(r.Transition.Days),
		TransitionClass:  r.Transition.StorageClass,
	}
	if out.Prefix == "" {
		out.Prefix = r.Prefix
	}
	if out.Prefix == "" {
		out.Prefix = r.RuleFilter.And.Prefix
	}
	f := r.RuleFilter
	out.Advanced = !f.Tag.IsEmpty() || len(f.And.Tags) > 0 || f.And.ObjectSizeLessThan > 0 ||
		f.And.ObjectSizeGreaterThan > 0 || f.ObjectSizeLessThan > 0 || f.ObjectSizeGreaterThan > 0 ||
		!r.Expiration.IsDateNull() || !r.Transition.IsDateNull() || r.Expiration.DeleteAll.IsEnabled() ||
		!r.NoncurrentVersionTransition.IsStorageClassEmpty() || r.NoncurrentVersionExpiration.NewerNoncurrentVersions > 0 ||
		!r.DelMarkerExpiration.IsNull() || !r.AllVersionsExpiration.IsNull() ||
		r.Compression != nil || r.NoncurrentVersionCompression != nil
	return out
}

// toLifecycle writes rule's fields over base (the stored rule with the same
// ID, or a blank one), so whatever Morcheh doesn't show survives.
func toLifecycle(base lifecycle.Rule, rule LifecycleRule) lifecycle.Rule {
	r := base
	r.ID = rule.ID
	r.Status = "Disabled"
	if rule.Enabled {
		r.Status = "Enabled"
	}
	switch {
	case !r.RuleFilter.And.IsEmpty():
		r.RuleFilter.And.Prefix = rule.Prefix
	case r.Prefix != "" && r.RuleFilter.IsNull():
		r.Prefix = rule.Prefix
	default:
		r.RuleFilter.Prefix = rule.Prefix
	}
	if r.Expiration.IsDateNull() {
		r.Expiration.Days = lifecycle.ExpirationDays(rule.ExpireDays)
	}
	r.Expiration.DeleteMarker = lifecycle.ExpireDeleteMarker(rule.DeleteMarkers)
	r.NoncurrentVersionExpiration.NoncurrentDays = lifecycle.ExpirationDays(rule.NoncurrentDays)
	r.AbortIncompleteMultipartUpload.DaysAfterInitiation = lifecycle.ExpirationDays(rule.AbortUploadsDays)
	if r.Transition.IsDateNull() {
		r.Transition.Days = lifecycle.ExpirationDays(rule.TransitionDays)
		r.Transition.StorageClass = ""
		if rule.TransitionDays > 0 {
			r.Transition.StorageClass = rule.TransitionClass
		}
	}
	return r
}

func (s *s3fs) CreateBucket(ctx context.Context, name string, opts NewBucket) error {
	if s.bucket != "" {
		return fmt.Errorf("this storage is set to one bucket: %w", ErrUnsupported)
	}
	region := opts.Region
	if region == "" {
		region = s.region
	}
	if err := s.c.MakeBucket(ctx, name, minio.MakeBucketOptions{Region: region, ObjectLocking: opts.ObjectLock}); err != nil {
		return s3Err(err)
	}
	// Object lock turns versioning on by itself.
	if opts.Versioning && !opts.ObjectLock {
		if err := s.c.EnableVersioning(ctx, name); err != nil {
			return fmt.Errorf("the bucket was made, but versioning couldn't be turned on: %w", s3Err(err))
		}
	}
	return nil
}

// EmptyBucket deletes every object in a bucket, old versions and delete
// markers included, and keeps the bucket. It answers how many it removed.
func (s *s3fs) EmptyBucket(ctx context.Context, bucket string) (int, error) {
	return s.removeAll(ctx, bucket)
}

func (s *s3fs) removeAll(ctx context.Context, bucket string) (int, error) {
	n, err := s.removeObjects(ctx, bucket, true)
	if n == 0 && err != nil && strings.Contains(minio.ToErrorResponse(err).Code, "NotImplemented") {
		// No version listing on this provider (R2…): plain objects only.
		return s.removeObjects(ctx, bucket, false)
	}
	return n, err
}

func (s *s3fs) removeObjects(ctx context.Context, bucket string, versions bool) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan minio.ObjectInfo)
	listErr := make(chan error, 1)
	go func() {
		defer close(ch)
		for o := range s.c.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: versions}) {
			if o.Err != nil {
				listErr <- o.Err
				return
			}
			select {
			case ch <- minio.ObjectInfo{Key: o.Key, VersionID: o.VersionID}:
			case <-ctx.Done():
				listErr <- ctx.Err()
				return
			}
		}
		listErr <- nil
	}()
	n := 0
	var first error
	for e := range s.c.RemoveObjectsWithResult(ctx, bucket, ch, minio.RemoveObjectsOptions{}) {
		if e.Err != nil {
			if first == nil {
				first = s3Err(e.Err)
			}
			continue
		}
		n++
	}
	if err := <-listErr; err != nil {
		if versions && n == 0 && strings.Contains(minio.ToErrorResponse(err).Code, "NotImplemented") {
			return 0, err // the caller retries without versions
		}
		return n, s3Err(err)
	}
	return n, first
}

func (s *s3fs) SetVersioning(ctx context.Context, bucket string, on bool) error {
	if on {
		return s3Err(s.c.EnableVersioning(ctx, bucket))
	}
	return s3Err(s.c.SuspendVersioning(ctx, bucket))
}

func (s *s3fs) SetPolicy(ctx context.Context, bucket, policy string) error {
	return s3Err(s.c.SetBucketPolicy(ctx, bucket, policy))
}

func (s *s3fs) SetLifecycle(ctx context.Context, bucket string, rules []LifecycleRule) error {
	old := map[string]lifecycle.Rule{}
	if cfg, err := s.c.GetBucketLifecycle(ctx, bucket); err == nil && cfg != nil {
		for _, r := range cfg.Rules {
			old[r.ID] = r
		}
	} else if err != nil && !isNotSet(err) {
		return s3Err(err)
	}
	cfg := lifecycle.NewConfiguration()
	for _, r := range rules {
		cfg.Rules = append(cfg.Rules, toLifecycle(old[r.ID], r))
	}
	return s3Err(s.c.SetBucketLifecycle(ctx, bucket, cfg))
}

func (s *s3fs) SetBucketTags(ctx context.Context, bucket string, t map[string]string) error {
	if len(t) == 0 {
		err := s.c.RemoveBucketTagging(ctx, bucket)
		if isNotSet(err) {
			return nil
		}
		return s3Err(err)
	}
	tt, err := tags.MapToBucketTags(t)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), fs.ErrInvalid)
	}
	return s3Err(s.c.SetBucketTagging(ctx, bucket, tt))
}

func (s *s3fs) SetEncryption(ctx context.Context, bucket, mode, kmsKey string) error {
	switch mode {
	case "sse-s3":
		return s3Err(s.c.SetBucketEncryption(ctx, bucket, sse.NewConfigurationSSES3()))
	case "sse-kms":
		return s3Err(s.c.SetBucketEncryption(ctx, bucket, sse.NewConfigurationSSEKMS(kmsKey)))
	}
	err := s.c.RemoveBucketEncryption(ctx, bucket)
	if isNotSet(err) {
		return nil
	}
	return s3Err(err)
}

func (s *s3fs) SetCORS(ctx context.Context, bucket string, rules []CORSRule) error {
	out := make([]cors.Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, cors.Rule{
			AllowedOrigin: r.Origins, AllowedMethod: r.Methods, AllowedHeader: r.Headers,
			ExposeHeader: r.ExposeHeaders, MaxAgeSeconds: r.MaxAgeSeconds,
		})
	}
	if len(out) == 0 {
		// An empty configuration removes it.
		return s3Err(s.c.SetBucketCors(ctx, bucket, nil))
	}
	return s3Err(s.c.SetBucketCors(ctx, bucket, cors.NewConfig(out)))
}

func (s *s3fs) SetRetention(ctx context.Context, bucket, mode string, days int) error {
	if mode == "" {
		return s3Err(s.c.SetObjectLockConfig(ctx, bucket, nil, nil, nil))
	}
	m := minio.RetentionMode(mode)
	if !m.IsValid() {
		return fmt.Errorf("unknown retention mode %s: %w", mode, fs.ErrInvalid)
	}
	v := uint(days)
	unit := minio.Days
	return s3Err(s.c.SetObjectLockConfig(ctx, bucket, &m, &v, &unit))
}

// ErrNotS3 is answered for bucket settings on a storage without buckets.
var ErrNotS3 = errors.New("only S3 storages have buckets")

// S3Code is the provider's error code behind err ("" if none).
func S3Code(err error) string {
	var r minio.ErrorResponse
	if errors.As(err, &r) {
		return r.Code
	}
	return minio.ToErrorResponse(err).Code
}

// S3Message is the provider's own words for err.
func S3Message(err error) string {
	var r minio.ErrorResponse
	if errors.As(err, &r) && r.Message != "" {
		return r.Message
	}
	return s3Text(err)
}
