package dbmon

import (
	"fmt"
	"strings"
)

// search judges what a search engine reports (DatabaseSearch).
func (e *evaluator) search(s *DatabaseSnapshot) {
	x := s.Search
	if x == nil {
		return
	}
	switch e.in.Engine {
	case Elastic:
		e.elasticChecks(x)
	case Meili:
		e.meiliChecks(x)
	}
}

func (e *evaluator) elasticChecks(x *DatabaseSearch) {
	switch x.Status {
	case "green":
		e.add("cluster_health", LevelOK, fmt.Sprintf("Green: every shard is placed (%d nodes)", x.Nodes), "", nil)
	case "yellow":
		e.add("cluster_health", LevelWarning, "Yellow: every primary is placed, but some replicas aren't",
			"Data is searchable, but a node lost now could lose some. A single-node cluster is always yellow when indices ask for replicas: set number_of_replicas to 0 on them, or add a node.", nil)
	case "red":
		e.add("cluster_health", LevelCritical, "Red: some primary shards aren't placed, so part of the data can't be searched or written",
			"Look at GET _cluster/allocation/explain for why. Common causes: a node down, a full disk (flood stage), or a corrupted shard.", nil)
	}
	n := float64(x.Unassigned)
	level := e.grade("shards", n)
	if x.Unassigned == 0 {
		e.add("shards", LevelOK, fmt.Sprintf("%d active shards, none unassigned", x.ActiveShards), "", &n)
	} else {
		e.add("shards", level, fmt.Sprintf("%d unassigned, %d initializing, %d relocating", x.Unassigned, x.Initializing, x.Relocating),
			"GET _cluster/allocation/explain tells why a shard isn't placed. On one node, replicas can never be placed.", &n)
	}
	if x.HeapRatio != nil {
		h := *x.HeapRatio
		e.add("heap", e.grade("heap", h), pct(h)+" of the fullest node's heap in use",
			"Give the JVM more heap (at most half the machine's memory, under 32 GB), close or shrink indices, or add nodes.", &h)
	}
	if x.DiskRatio != nil {
		d := *x.DiskRatio
		switch {
		case len(x.ReadOnlyIndices) > 0:
			e.add("watermark", LevelCritical, "Read-only: "+joinMax(x.ReadOnlyIndices, 3),
				"Free disk space, then remove the block: PUT */_settings {\"index.blocks.read_only_allow_delete\": null} (newer versions lift it themselves once below the high watermark).", &d)
		case x.FloodStage != nil && d >= *x.FloodStage:
			e.add("watermark", LevelCritical, fmt.Sprintf("%s used: past the flood stage (%s), indices turn read-only", pct(d), pct(*x.FloodStage)),
				"Free disk space or add nodes now.", &d)
		case x.HighWatermark != nil && d >= *x.HighWatermark:
			e.add("watermark", LevelWarning, fmt.Sprintf("%s used: past the high watermark (%s), shards move off the node", pct(d), pct(*x.HighWatermark)),
				"Free disk space, delete old indices or add nodes.", &d)
		default:
			e.add("watermark", LevelOK, pct(d)+" used on the fullest data node", "", &d)
		}
	}
}

func (e *evaluator) meiliChecks(x *DatabaseSearch) {
	if x.OldestWait != nil {
		w := *x.OldestWait
		e.add("task_queue", e.grade("task_queue", w), fmt.Sprintf("%d waiting, %d running; the oldest has waited %s", x.Enqueued, x.Processing, humanSeconds(w)),
			"Meilisearch runs one batch at a time. Send documents in bigger batches, fewer settings changes, or give it more CPU.", &w)
	} else {
		zero := 0.0
		e.add("task_queue", LevelOK, "Nothing is waiting", "", &zero)
	}
	f := float64(x.Failed)
	reason := fmt.Sprintf("%d failed in the last 24 hours", x.Failed)
	if x.Failed > 0 && x.LastFailure != "" {
		reason += ": " + strings.TrimSpace(x.LastFailure)
	}
	e.add("failed_tasks", e.grade("failed_tasks", f), reason,
		"Open the failed task (GET /tasks?statuses=failed) to see which documents or settings were refused.", &f)
}
