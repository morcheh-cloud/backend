package api

import (
	"context"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/morcheh/backend/internal/auth"
	"github.com/morcheh/backend/internal/proxy"
	"github.com/morcheh/backend/internal/storage"
)

// resolveStorage fills in where a storage site reads its files from: the
// storage's address, and whether the bucket goes in the path or the host
// name. It needs the person to see the storage, and an S3 one. The answer
// is a problem to show on the form (nil when fine) or an internal error.
func (h *proxyHandler) resolveStorage(ctx context.Context, c *proxy.HostConfig) (*proxy.Problem, error) {
	if strings.TrimSpace(c.Type) != proxy.TypeStorage {
		return nil, nil
	}
	s := &c.Storage
	s.Endpoint, s.PathStyle = "", false
	raw := strings.TrimSpace(s.StorageID)
	if raw == "" {
		return nil, nil // Validate asks for one.
	}
	field := "storage.storage_id"
	id, err := uuid.Parse(raw)
	if err != nil {
		return &proxy.Problem{Field: field, Message: "Choose a storage.", Value: raw}, nil
	}
	level, err := h.s.authz.storageLevel(ctx, principalOf(ctx).Access, id)
	if err != nil {
		return nil, internalError(err)
	}
	if level < auth.Viewer {
		return &proxy.Problem{Field: field, Message: "Storage not found.", Value: raw}, nil
	}
	row, err := h.s.q.GetStorage(ctx, id)
	if isNotFound(err) {
		return &proxy.Problem{Field: field, Message: "Storage not found.", Value: raw}, nil
	}
	if err != nil {
		return nil, internalError(err)
	}
	if row.Protocol != "s3" {
		return &proxy.Problem{Field: field, Message: "Only S3 storages can be served as a site.", Value: raw}, nil
	}
	if row.Bucket != "" {
		s.Bucket = row.Bucket // a storage pinned to one bucket
	}
	origin, err := storage.S3Origin(row.Host, int(row.Port))
	if err != nil {
		return &proxy.Problem{Field: field, Message: err.Error(), Value: raw}, nil
	}
	s.Endpoint, s.PathStyle = origin, true
	u, _ := url.Parse(origin)
	bucket := strings.TrimSpace(s.Bucket)
	// AWS wants new buckets by host name; elsewhere (MinIO and most others)
	// the path always works.
	if host := u.Hostname(); strings.HasSuffix(host, ".amazonaws.com") && !row.PathStyle &&
		bucket != "" && !strings.Contains(bucket, ".") {
		if host == "s3.amazonaws.com" && row.Region != "" && row.Region != "us-east-1" {
			host = "s3." + row.Region + ".amazonaws.com"
		}
		u.Host = bucket + "." + host
		if p := u.Port(); p != "" {
			u.Host += ":" + p
		}
		s.Endpoint, s.PathStyle = u.Scheme+"://"+u.Host, false
	}
	return nil, nil
}

// withStorage is resolveStorage for the save paths: a problem is a 422 on
// its field, like cleanHost's.
func (h *proxyHandler) withStorage(ctx context.Context, c *proxy.HostConfig) error {
	p, err := h.resolveStorage(ctx, c)
	if err != nil || p == nil {
		return err
	}
	return huma.Error422UnprocessableEntity(p.Message, &huma.ErrorDetail{
		Location: "body.config." + p.Field, Message: p.Message, Value: p.Value,
	})
}
