package storage

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/minio/madmin-go/v4"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/replication"
)

// MinIO bucket replication: the source MinIO copies every new or changed
// object to the destination by itself, as it happens. Morche only sets it up
// (a remote target holding the destination's keys + a rule on the source
// bucket) and reads its numbers. Object keys stay the same on both sides, so
// the destination folder has the same path inside its bucket.

// ReplicationPlan is what a replication should do.
type ReplicationPlan struct {
	// Rule ID on the source bucket; only this rule is ever touched.
	RuleID string
	// Paths inside each storage (before its root folder).
	SourcePath, DestPath string
	Enabled              bool
	// Copy deletions too (versioned delete markers and permanent deletes).
	Deletes bool
	// Copy what the bucket already held, not only new writes.
	Existing bool
	// Write to the destination before answering the client.
	Synchronous bool
	// Bytes per second, 0 = no limit.
	Bandwidth int64
	// Where the source MinIO reaches the destination, when that's not the
	// address Morche uses (another network). Empty = the destination's own.
	TargetEndpoint string
}

// ReplicationSetup is what was set up, kept to change or remove it later.
type ReplicationSetup struct {
	Arn          string `json:"arn"`
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix,omitempty"`
	TargetBucket string `json:"target_bucket"`
	Endpoint     string `json:"endpoint"`
	RuleID       string `json:"rule_id"`
}

// S3Place says which bucket and key prefix a storage path is: the fixed
// bucket, or the first path segment. prefix has no leading slash and ends
// in "/" unless empty.
func S3Place(cfg Config, p string) (bucket, prefix string, err error) {
	full := strings.TrimPrefix(Clean(path.Join("/", cfg.Root, p)), "/")
	if cfg.Bucket != "" {
		bucket = cfg.Bucket
		prefix = full
	} else {
		bucket, prefix, _ = strings.Cut(full, "/")
	}
	if bucket == "" {
		return "", "", errors.New("pick a bucket (or a folder in one): replication works per bucket")
	}
	if prefix != "" {
		prefix = strings.Trim(prefix, "/") + "/"
	}
	return bucket, prefix, nil
}

type s3Clients struct {
	c     *minio.Client
	admin *madmin.AdminClient
	host  string
	tls   bool
}

func openClients(cfg Config) (*s3Clients, error) {
	host, secure, err := s3Endpoint(cfg.Host, cfg.Port)
	if err != nil {
		return nil, err
	}
	tr, err := minio.DefaultTransport(secure)
	if err != nil {
		return nil, err
	}
	tr.DialContext = guardedDialer().DialContext
	if cfg.InsecureTLS {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{} //nolint:gosec // set below
		}
		tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // the user asked for it
	}
	creds := credentials.NewStaticV4(cfg.Username, cfg.Secret, "")
	lookup := minio.BucketLookupAuto
	if cfg.PathStyle {
		lookup = minio.BucketLookupPath
	}
	c, err := minio.New(host, &minio.Options{Creds: creds, Secure: secure, Region: cfg.Region, BucketLookup: lookup, Transport: tr})
	if err != nil {
		return nil, err
	}
	admin, err := madmin.NewWithOptions(host, &madmin.Options{Creds: creds, Secure: secure, Transport: http.RoundTripper(tr)})
	if err != nil {
		return nil, err
	}
	return &s3Clients{c: c, admin: admin, host: host, tls: secure}, nil
}

func replicationErr(what string, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if r := minio.ToErrorResponse(err); r.Message != "" {
		msg = r.Message
	} else if r := madmin.ToErrorResponse(err); r.Message != "" {
		msg = r.Message
	}
	return fmt.Errorf("%s: %s", what, msg)
}

// SetUpReplication (re)creates the replication from src to dst. prev is
// the earlier setup, removed first; nil = none.
func SetUpReplication(ctx context.Context, src, dst Config, plan ReplicationPlan, prev *ReplicationSetup) (ReplicationSetup, error) {
	var out ReplicationSetup
	bucket, prefix, err := S3Place(src, plan.SourcePath)
	if err != nil {
		return out, err
	}
	tbucket, tprefix, err := S3Place(dst, plan.DestPath)
	if err != nil {
		return out, err
	}
	if prefix != tprefix {
		return out, fmt.Errorf("MinIO keeps object names as they are, so the destination folder must be %q inside its bucket", "/"+prefix)
	}
	sc, err := openClients(src)
	if err != nil {
		return out, err
	}
	dc, err := openClients(dst)
	if err != nil {
		return out, err
	}
	endpoint, secure := dc.host, dc.tls
	if strings.TrimSpace(plan.TargetEndpoint) != "" {
		if endpoint, secure, err = s3Endpoint(plan.TargetEndpoint, 0); err != nil {
			return out, err
		}
	}
	if sc.host == endpoint && bucket == tbucket {
		return out, errors.New("the source and destination are the same bucket")
	}

	// Both buckets need versioning.
	if ok, err := dc.c.BucketExists(ctx, tbucket); err != nil {
		return out, replicationErr("Destination", s3ConnError(err))
	} else if !ok {
		if err := dc.c.MakeBucket(ctx, tbucket, minio.MakeBucketOptions{Region: dst.Region}); err != nil {
			return out, replicationErr("Couldn't create the destination bucket", err)
		}
	}
	if err := dc.c.EnableVersioning(ctx, tbucket); err != nil {
		return out, replicationErr("Couldn't turn on versioning on the destination bucket", err)
	}
	if err := sc.c.EnableVersioning(ctx, bucket); err != nil {
		return out, replicationErr("Couldn't turn on versioning on the source bucket", err)
	}

	if prev != nil {
		if err := removeReplication(ctx, sc, *prev); err != nil {
			return out, err
		}
	}

	target := &madmin.BucketTarget{
		SourceBucket:    bucket,
		Endpoint:        endpoint,
		Credentials:     &madmin.Credentials{AccessKey: dst.Username, SecretKey: dst.Secret},
		TargetBucket:    tbucket,
		Secure:          secure,
		API:             "s3v4",
		Type:            madmin.ReplicationService,
		Region:          dst.Region,
		BandwidthLimit:  plan.Bandwidth,
		ReplicationSync: plan.Synchronous,
		InsecureTLS:     dst.InsecureTLS,
	}
	if dst.PathStyle {
		target.Path = "on"
	}
	arn, err := sc.admin.SetRemoteTarget(ctx, bucket, target)
	if err != nil {
		return out, replicationErr("The source MinIO refused the destination", err)
	}
	out = ReplicationSetup{Arn: arn, Bucket: bucket, Prefix: prefix, TargetBucket: tbucket, Endpoint: endpoint, RuleID: plan.RuleID}

	cfg, err := sc.c.GetBucketReplication(ctx, bucket)
	if err != nil && !isNoReplication(err) {
		_ = sc.admin.RemoveRemoteTarget(context.WithoutCancel(ctx), bucket, arn)
		return out, replicationErr("Couldn't read the bucket's replication", err)
	}
	cfg.Rules = slices.DeleteFunc(cfg.Rules, func(r replication.Rule) bool { return r.ID == plan.RuleID })
	priority := 1
	for _, r := range cfg.Rules {
		priority = max(priority, r.Priority+1)
	}
	cfg.Rules = append(cfg.Rules, ruleFor(plan, prefix, arn, priority))
	if cfg.Role != "" && !strings.HasPrefix(cfg.Role, "arn:") {
		cfg.Role = ""
	}
	if err := sc.c.SetBucketReplication(ctx, bucket, cfg); err != nil {
		_ = sc.admin.RemoveRemoteTarget(context.WithoutCancel(ctx), bucket, arn)
		return ReplicationSetup{}, replicationErr("The source MinIO refused the replication rule", err)
	}
	return out, nil
}

func ruleFor(plan ReplicationPlan, prefix, arn string, priority int) replication.Rule {
	on := func(b bool) replication.Status {
		if b {
			return replication.Enabled
		}
		return replication.Disabled
	}
	return replication.Rule{
		ID:                        plan.RuleID,
		Status:                    on(plan.Enabled),
		Priority:                  priority,
		DeleteMarkerReplication:   replication.DeleteMarkerReplication{Status: on(plan.Deletes)},
		DeleteReplication:         replication.DeleteReplication{Status: on(plan.Deletes)},
		Destination:               replication.Destination{Bucket: arn},
		Filter:                    replication.Filter{Prefix: prefix},
		SourceSelectionCriteria:   replication.SourceSelectionCriteria{ReplicaModifications: replication.ReplicaModifications{Status: replication.Enabled}},
		ExistingObjectReplication: replication.ExistingObjectReplication{Status: on(plan.Existing)},
	}
}

func isNoReplication(err error) bool {
	code := minio.ToErrorResponse(err).Code
	return code == "ReplicationConfigurationNotFoundError" || code == "XMinioReplicationConfigNotFoundError"
}

// SetReplicationEnabled pauses or resumes the rule.
func SetReplicationEnabled(ctx context.Context, src Config, s ReplicationSetup, on bool) error {
	sc, err := openClients(src)
	if err != nil {
		return err
	}
	cfg, err := sc.c.GetBucketReplication(ctx, s.Bucket)
	if err != nil {
		return replicationErr("Couldn't read the bucket's replication", err)
	}
	found := false
	for i := range cfg.Rules {
		if cfg.Rules[i].ID == s.RuleID {
			found = true
			cfg.Rules[i].Status = replication.Disabled
			if on {
				cfg.Rules[i].Status = replication.Enabled
			}
		}
	}
	if !found {
		return errors.New("the replication rule is gone from the source bucket; save the sync again to put it back")
	}
	return replicationErr("The source MinIO refused the change", sc.c.SetBucketReplication(ctx, s.Bucket, cfg))
}

// RemoveReplication takes the rule and the remote target away; other rules
// on the bucket stay.
func RemoveReplication(ctx context.Context, src Config, s ReplicationSetup) error {
	sc, err := openClients(src)
	if err != nil {
		return err
	}
	return removeReplication(ctx, sc, s)
}

func removeReplication(ctx context.Context, sc *s3Clients, s ReplicationSetup) error {
	cfg, err := sc.c.GetBucketReplication(ctx, s.Bucket)
	switch {
	case err != nil && !isNoReplication(err):
		return replicationErr("Couldn't read the bucket's replication", err)
	case err == nil:
		n := len(cfg.Rules)
		cfg.Rules = slices.DeleteFunc(cfg.Rules, func(r replication.Rule) bool { return r.ID == s.RuleID })
		if len(cfg.Rules) == 0 && n > 0 {
			if err := sc.c.RemoveBucketReplication(ctx, s.Bucket); err != nil {
				return replicationErr("Couldn't remove the replication rule", err)
			}
		} else if len(cfg.Rules) != n {
			if err := sc.c.SetBucketReplication(ctx, s.Bucket, cfg); err != nil {
				return replicationErr("Couldn't remove the replication rule", err)
			}
		}
	}
	if s.Arn != "" {
		if err := sc.admin.RemoveRemoteTarget(ctx, s.Bucket, s.Arn); err != nil {
			if r := madmin.ToErrorResponse(err); r.Code != "XMinioAdminRemoteTargetNotFoundError" && r.Code != "XMinioAdminRemoteArnInvalid" {
				return replicationErr("Couldn't remove the remote target", err)
			}
		}
	}
	return nil
}

// ReplicationState is what the source MinIO says about a replication.
type ReplicationState struct {
	RuleFound   bool      `json:"rule_found" doc:"The rule is still on the source bucket"`
	Enabled     bool      `json:"enabled"`
	Online      bool      `json:"online" doc:"The source MinIO reaches the destination"`
	LastOnline  time.Time `json:"last_online,omitempty"`
	LatencyMs   int64     `json:"latency_ms,omitempty"`
	Downtime    int64     `json:"downtime_seconds,omitempty" doc:"Seconds the destination was unreachable in all"`
	Replicated  int64     `json:"replicated" doc:"Objects copied since the source MinIO started"`
	Bytes       int64     `json:"bytes" doc:"Bytes copied since the source MinIO started"`
	Pending     int64     `json:"pending" doc:"Objects waiting to be copied"`
	PendingSize int64     `json:"pending_bytes"`
	Failed      int64     `json:"failed" doc:"Objects that failed to copy"`
	FailedSize  int64     `json:"failed_bytes"`
	FailedHour  int64     `json:"failed_last_hour"`
	Bandwidth   float64   `json:"bandwidth" doc:"Bytes per second right now"`
	Limit       int64     `json:"bandwidth_limit,omitempty"`
	Uptime      int64     `json:"uptime_seconds,omitempty" doc:"Since when the numbers count"`
	// The last "copy what's already there" run.
	Resync *ResyncState `json:"resync,omitempty"`
}

type ResyncState struct {
	Status     string    `json:"status"`
	Started    time.Time `json:"started,omitempty"`
	Ended      time.Time `json:"ended,omitempty"`
	Replicated int64     `json:"replicated"`
	Bytes      int64     `json:"bytes"`
	Failed     int64     `json:"failed"`
	Object     string    `json:"object,omitempty"`
}

// ReadReplication asks the source MinIO how the replication is doing.
func ReadReplication(ctx context.Context, src Config, s ReplicationSetup) (ReplicationState, error) {
	var st ReplicationState
	sc, err := openClients(src)
	if err != nil {
		return st, err
	}
	cfg, err := sc.c.GetBucketReplication(ctx, s.Bucket)
	if err != nil && !isNoReplication(err) {
		return st, replicationErr("Couldn't read the bucket's replication", s3ConnError(err))
	}
	for _, r := range cfg.Rules {
		if r.ID == s.RuleID {
			st.RuleFound, st.Enabled = true, r.Status == replication.Enabled
		}
	}
	if targets, err := sc.admin.ListRemoteTargets(ctx, s.Bucket, string(madmin.ReplicationService)); err == nil {
		for _, t := range targets {
			if t.Arn == s.Arn {
				st.Online, st.LastOnline = t.Online, t.LastOnline
				st.LatencyMs = t.Latency.Curr.Milliseconds()
				st.Downtime = int64(t.TotalDowntime.Seconds())
			}
		}
	}
	if m, err := sc.c.GetBucketReplicationMetricsV2(ctx, s.Bucket); err == nil {
		st.Uptime = m.Uptime
		if t, ok := m.CurrentStats.Stats[s.Arn]; ok {
			st.Replicated = int64(t.ReplicatedCount)
			st.Bytes = int64(t.ReplicatedSize)
			st.Pending = int64(t.PendingCount)
			st.PendingSize = int64(t.PendingSize)
			st.Failed = int64(t.Failed.Totals.Count)
			st.FailedSize = t.Failed.Totals.Bytes
			st.FailedHour = int64(t.Failed.LastHour.Count)
			st.Bandwidth = t.CurrentBandwidthInBytesPerSecond
			st.Limit = t.BandWidthLimitInBytesPerSecond
		}
	}
	if r, err := sc.c.GetBucketReplicationResyncStatus(ctx, s.Bucket, s.Arn); err == nil {
		for _, t := range r.Targets {
			if t.Arn == s.Arn && t.ResyncStatus != "" {
				st.Resync = &ResyncState{
					Status: t.ResyncStatus, Started: t.StartTime, Ended: t.EndTime,
					Replicated: t.ReplicatedCount, Bytes: t.ReplicatedSize, Failed: t.FailedCount,
					Object: t.Object,
				}
			}
		}
	}
	return st, nil
}

// ResyncReplication has the source MinIO copy everything the bucket already
// holds again (what isn't on the destination yet).
func ResyncReplication(ctx context.Context, src Config, s ReplicationSetup) error {
	sc, err := openClients(src)
	if err != nil {
		return err
	}
	_, err = sc.c.ResetBucketReplicationOnTarget(ctx, s.Bucket, 0, s.Arn)
	return replicationErr("The source MinIO refused to copy existing files", err)
}
