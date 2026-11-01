package storage

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 and compatibles (MinIO, R2, Wasabi, Spaces, ArvanCloud…). Folders are
// key prefixes; an empty folder is a zero-byte "name/" marker object.
// Without a fixed bucket, "/" lists the buckets and paths are /bucket/key.
type s3fs struct {
	c      *minio.Client
	tr     *http.Transport
	bucket string
	region string
}

// Unknown sizes are uploaded in parts this big (minio's default for an
// unknown size would buffer 512 MB per part).
const s3PartSize = 16 << 20

func openS3(ctx context.Context, cfg Config) (FS, Info, error) {
	var info Info
	host, secure, err := s3Endpoint(cfg.Host, cfg.Port)
	if err != nil {
		return nil, info, &ConnError{StatusError, err.Error(), err}
	}
	tr, err := minio.DefaultTransport(secure)
	if err != nil {
		return nil, info, err
	}
	if cfg.InsecureTLS && tr.TLSClientConfig != nil {
		tr.TLSClientConfig.InsecureSkipVerify = true
	} else if cfg.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // the user asked for it
	}
	lookup := minio.BucketLookupAuto
	if cfg.PathStyle {
		lookup = minio.BucketLookupPath
	}
	c, err := minio.New(host, &minio.Options{
		Creds:        credentials.NewStaticV4(cfg.Username, cfg.Secret, ""),
		Secure:       secure,
		Region:       cfg.Region,
		BucketLookup: lookup,
		Transport:    tr,
	})
	if err != nil {
		return nil, info, &ConnError{StatusError, err.Error(), err}
	}
	s := &s3fs{c: c, tr: tr, bucket: cfg.Bucket, region: cfg.Region}

	if cfg.Bucket != "" {
		ok, err := c.BucketExists(ctx, cfg.Bucket)
		if err != nil {
			return nil, info, s3ConnError(err)
		}
		if !ok {
			return nil, info, &ConnError{StatusError, "Bucket " + cfg.Bucket + " doesn't exist", nil}
		}
		info.Detail = "Bucket " + cfg.Bucket
	} else {
		buckets, err := c.ListBuckets(ctx)
		if err != nil {
			return nil, info, s3ConnError(err)
		}
		info.Detail = plural(len(buckets), "bucket")
	}
	return s, info, nil
}

// "https://s3.example.com", "s3.example.com:9000" (https) or
// "http://127.0.0.1:9000" → host[:port] and whether to use TLS.
func s3Endpoint(raw string, port int) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false, fmt.Errorf("Endpoint: expected a URL like https://s3.example.com")
	}
	host := u.Host
	if port > 0 && u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	}
	return host, u.Scheme == "https", nil
}

func s3ConnError(err error) error {
	code := minio.ToErrorResponse(err).Code
	switch code {
	case "InvalidAccessKeyId", "SignatureDoesNotMatch", "AccessDenied", "InvalidToken", "ExpiredToken":
		return &ConnError{StatusAuthFailed, s3Text(err), err}
	}
	var ne net.Error
	var ue *url.Error
	if errors.As(err, &ne) || errors.As(err, &ue) {
		return &ConnError{StatusUnreachable, netMessage(err), err}
	}
	return &ConnError{StatusError, s3Text(err), err}
}

func s3Text(err error) string {
	if r := minio.ToErrorResponse(err); r.Message != "" {
		return r.Message
	}
	return err.Error()
}

func s3Err(err error) error {
	if err == nil {
		return nil
	}
	switch minio.ToErrorResponse(err).Code {
	case "NoSuchKey", "NoSuchBucket", "NotFound":
		return fmt.Errorf("%s: %w", s3Text(err), fs.ErrNotExist)
	case "AccessDenied":
		return fmt.Errorf("%s: %w", s3Text(err), fs.ErrPermission)
	case "BucketAlreadyExists", "BucketAlreadyOwnedByYou":
		return fmt.Errorf("%s: %w", s3Text(err), fs.ErrExist)
	case "BucketNotEmpty":
		return fmt.Errorf("%s: %w", s3Text(err), ErrNotEmpty)
	}
	return err
}

// split turns a path into bucket and key. Without a fixed bucket the first
// segment is the bucket.
func (s *s3fs) split(p string) (bucket, key string) {
	p = strings.TrimPrefix(Clean(p), "/")
	if s.bucket != "" {
		return s.bucket, p
	}
	bucket, key, _ = strings.Cut(p, "/")
	return bucket, key
}

func (s *s3fs) join(bucket, key string) string {
	if s.bucket != "" {
		return Clean(key)
	}
	return Clean(bucket + "/" + key)
}

func (s *s3fs) objectEntry(bucket string, o minio.ObjectInfo) Entry {
	dir := strings.HasSuffix(o.Key, "/")
	key := strings.TrimSuffix(o.Key, "/")
	return Entry{
		Name:         path.Base(key),
		Path:         s.join(bucket, key),
		Dir:          dir,
		Size:         o.Size,
		Modified:     o.LastModified,
		ContentType:  o.ContentType,
		ETag:         strings.Trim(o.ETag, `"`),
		StorageClass: o.StorageClass,
	}
}

func (s *s3fs) List(ctx context.Context, dir string, limit int) ([]Entry, error) {
	bucket, key := s.split(dir)
	if bucket == "" {
		buckets, err := s.c.ListBuckets(ctx)
		if err != nil {
			return nil, s3Err(err)
		}
		out := make([]Entry, 0, len(buckets))
		for _, b := range buckets {
			out = append(out, Entry{Name: b.Name, Path: "/" + b.Name, Dir: true, Modified: b.CreationDate, Bucket: true})
		}
		return out, nil
	}
	prefix := ""
	if key != "" {
		prefix = key + "/"
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := []Entry{}
	marker := false
	for o := range s.c.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix}) {
		if o.Err != nil {
			return nil, s3Err(o.Err)
		}
		if o.Key == prefix {
			marker = true
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, s.objectEntry(bucket, o))
	}
	if len(out) == 0 && !marker && key != "" {
		// Prefixes only exist while something is under them.
		if _, err := s.c.StatObject(ctx, bucket, key, minio.StatObjectOptions{}); err == nil {
			return nil, fmt.Errorf("not a folder: %w", fs.ErrInvalid)
		}
		return nil, fmt.Errorf("no folder %s: %w", dir, fs.ErrNotExist)
	}
	return out, nil
}

func (s *s3fs) Stat(ctx context.Context, p string) (Entry, error) {
	bucket, key := s.split(p)
	if bucket == "" {
		return Entry{Name: "/", Path: "/", Dir: true}, nil
	}
	if key == "" {
		ok, err := s.c.BucketExists(ctx, bucket)
		if err != nil {
			return Entry{}, s3Err(err)
		}
		if !ok {
			return Entry{}, fmt.Errorf("no bucket %s: %w", bucket, fs.ErrNotExist)
		}
		name := bucket
		if s.bucket != "" {
			name = "/"
		}
		return Entry{Name: name, Path: s.join(bucket, ""), Dir: true, Bucket: s.bucket == ""}, nil
	}
	o, err := s.c.StatObject(ctx, bucket, key, minio.StatObjectOptions{})
	if err == nil {
		return s.objectEntry(bucket, o), nil
	}
	if code := minio.ToErrorResponse(err).Code; code != "NoSuchKey" && code != "NotFound" {
		return Entry{}, s3Err(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for o := range s.c.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: key + "/", MaxKeys: 1}) {
		if o.Err != nil {
			return Entry{}, s3Err(o.Err)
		}
		return Entry{Name: path.Base(key), Path: s.join(bucket, key), Dir: true}, nil
	}
	return Entry{}, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
}

type s3File struct {
	*minio.Object
	e Entry
}

func (f *s3File) Entry() Entry { return f.e }

func (s *s3fs) Open(ctx context.Context, p string) (File, error) {
	bucket, key := s.split(p)
	if key == "" {
		return nil, fmt.Errorf("that's a folder: %w", fs.ErrInvalid)
	}
	o, err := s.c.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, s3Err(err)
	}
	st, err := o.Stat()
	if err != nil {
		o.Close()
		return nil, s3Err(err)
	}
	return &s3File{o, s.objectEntry(bucket, st)}, nil
}

func (s *s3fs) Put(ctx context.Context, p string, r io.Reader, size int64) error {
	bucket, key := s.split(p)
	if key == "" {
		return fmt.Errorf("files go inside a bucket: %w", fs.ErrInvalid)
	}
	ctype := mime.TypeByExtension(path.Ext(key))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	_, err := s.c.PutObject(ctx, bucket, key, r, size, minio.PutObjectOptions{ContentType: ctype, PartSize: s3PartSize})
	return s3Err(err)
}

func (s *s3fs) Mkdir(ctx context.Context, p string) error {
	bucket, key := s.split(p)
	if bucket == "" {
		return nil
	}
	if key == "" {
		if s.bucket != "" {
			return nil
		}
		ok, err := s.c.BucketExists(ctx, bucket)
		if err != nil || ok {
			return s3Err(err)
		}
		return s3Err(s.c.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: s.region}))
	}
	_, err := s.c.PutObject(ctx, bucket, key+"/", strings.NewReader(""), 0, minio.PutObjectOptions{})
	return s3Err(err)
}

// keys lists every object key under a file or folder path: the object
// itself, and everything under "key/" (folder marker included).
func (s *s3fs) keys(ctx context.Context, bucket, key string, fn func(minio.ObjectInfo) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if key != "" {
		if o, err := s.c.StatObject(ctx, bucket, key, minio.StatObjectOptions{}); err == nil {
			o.Key = key
			if err := fn(o); err != nil {
				return err
			}
		}
	}
	prefix := ""
	if key != "" {
		prefix = key + "/"
	}
	for o := range s.c.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return s3Err(o.Err)
		}
		if err := fn(o); err != nil {
			return err
		}
	}
	return nil
}

func (s *s3fs) Remove(ctx context.Context, p string) error {
	bucket, key := s.split(p)
	if bucket == "" || (key == "" && s.bucket != "") {
		return fmt.Errorf("can't remove the root: %w", fs.ErrPermission)
	}
	ch := make(chan minio.ObjectInfo)
	errs := s.c.RemoveObjects(ctx, bucket, ch, minio.RemoveObjectsOptions{})
	listErr := make(chan error, 1)
	go func() {
		defer close(ch)
		listErr <- s.keys(ctx, bucket, key, func(o minio.ObjectInfo) error {
			select {
			case ch <- minio.ObjectInfo{Key: o.Key}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	var first error
	for e := range errs {
		if first == nil {
			first = s3Err(e.Err)
		}
	}
	if err := <-listErr; err != nil {
		return err
	}
	if first != nil {
		return first
	}
	if key == "" {
		return s3Err(s.c.RemoveBucket(ctx, bucket))
	}
	return nil
}

// copyKeys copies every object under from to the same place under to.
func (s *s3fs) copyKeys(ctx context.Context, from, to string, each func(minio.ObjectInfo) error) error {
	fb, fk := s.split(from)
	tb, tk := s.split(to)
	if fk == "" || tk == "" {
		return fmt.Errorf("buckets can't be copied or renamed: %w", ErrUnsupported)
	}
	found := false
	err := s.keys(ctx, fb, fk, func(o minio.ObjectInfo) error {
		found = true
		dst := tk + strings.TrimPrefix(o.Key, fk)
		_, err := s.c.CopyObject(ctx,
			minio.CopyDestOptions{Bucket: tb, Object: dst},
			minio.CopySrcOptions{Bucket: fb, Object: o.Key})
		if err != nil {
			return s3Err(err)
		}
		if each != nil {
			return each(o)
		}
		return nil
	})
	if err == nil && !found {
		return fmt.Errorf("%s: %w", from, fs.ErrNotExist)
	}
	return err
}

func (s *s3fs) Rename(ctx context.Context, from, to string) error {
	fb, _ := s.split(from)
	// Delete each source object right after its copy; a failure midway
	// leaves both halves readable rather than losing anything.
	return s.copyKeys(ctx, from, to, func(o minio.ObjectInfo) error {
		return s3Err(s.c.RemoveObject(ctx, fb, o.Key, minio.RemoveObjectOptions{}))
	})
}

func (s *s3fs) Copy(ctx context.Context, from, to string) error {
	return s.copyKeys(ctx, from, to, nil)
}

func (s *s3fs) Walk(ctx context.Context, dir string, fn func(Entry) error) error {
	bucket, key := s.split(dir)
	if bucket == "" {
		buckets, err := s.c.ListBuckets(ctx)
		if err != nil {
			return s3Err(err)
		}
		for _, b := range buckets {
			if err := fn(Entry{Name: b.Name, Path: "/" + b.Name, Dir: true, Modified: b.CreationDate, Bucket: true}); err != nil {
				return err
			}
			if err := s.Walk(ctx, "/"+b.Name, fn); err != nil {
				return err
			}
		}
		return nil
	}
	prefix := ""
	if key != "" {
		prefix = key + "/"
	}
	// A flat listing has no entries for folders without markers: report
	// each folder once, the first time something inside it shows up.
	seen := map[string]bool{}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for o := range s.c.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return s3Err(o.Err)
		}
		if o.Key == prefix {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimPrefix(o.Key, prefix), "/")
		parts := strings.Split(rest, "/")
		for i := 1; i < len(parts); i++ {
			sub := prefix + strings.Join(parts[:i], "/")
			if !seen[sub] {
				seen[sub] = true
				if err := fn(Entry{Name: parts[i-1], Path: s.join(bucket, sub), Dir: true}); err != nil {
					return err
				}
			}
		}
		e := s.objectEntry(bucket, o)
		if e.Dir {
			if seen[strings.TrimSuffix(o.Key, "/")] {
				continue
			}
			seen[strings.TrimSuffix(o.Key, "/")] = true
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (s *s3fs) Share(ctx context.Context, p string, expiry time.Duration, filename string) (string, error) {
	bucket, key := s.split(p)
	if key == "" {
		return "", fmt.Errorf("only files can be shared: %w", fs.ErrInvalid)
	}
	params := url.Values{}
	if filename != "" {
		params.Set("response-content-disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	}
	u, err := s.c.PresignedGetObject(ctx, bucket, key, expiry, params)
	if err != nil {
		return "", s3Err(err)
	}
	return u.String(), nil
}

func (s *s3fs) Capabilities() Capabilities {
	return Capabilities{Buckets: s.bucket == "", ShareLinks: true, ServerCopy: true, Ranges: true}
}

func (s *s3fs) Close() error {
	s.tr.CloseIdleConnections()
	return nil
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}
