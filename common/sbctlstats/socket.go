// Package sbctlstats exposes local sing-box statistics without a network listener.
package sbctlstats

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
)

const (
	SchemaVersion = 1
	historySize   = 16384
	maxBatch      = 128
)

type Options struct {
	SocketPath string
	NodeID     string
}

type Service struct {
	manager *trafficcontrol.Manager
	options Options
	epoch   string
	reads   atomic.Uint64

	mutex    sync.Mutex
	closed   totals
	history  []connection
	sequence uint64
}

func New(manager *trafficcontrol.Manager, options Options) *Service {
	s := &Service{manager: manager, options: options, epoch: time.Now().UTC().Format(time.RFC3339Nano), closed: newTotals(), history: make([]connection, historySize)}
	// Installed before the router starts. The callback is synchronous so bursts
	// of short connections still contribute after the replay window fills.
	manager.OnClosed = s.recordClose
	return s
}

func (s *Service) Name() string { return "sbctl statistics" }

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	path := s.options.SocketPath
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("statistics socket path is occupied")
		}
		conn, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			conn.Close()
			return errors.New("statistics socket already active")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0660); err != nil {
		listener.Close()
		return err
	}
	scope.Add(listener.Close)
	go s.accept(listener)
	return nil
}

func (s *Service) accept(listener net.Listener) {
	slots := make(chan struct{}, 8)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				s.serve(conn)
			}()
		default:
			conn.Close()
		}
	}
}

type request struct {
	Action        string `json:"action"`
	AfterSequence uint64 `json:"after_sequence,omitempty"`
	RuntimeEpoch  string `json:"runtime_epoch,omitempty"`
	Limit         int    `json:"limit,omitempty"`
}

type response struct {
	SchemaVersion        int             `json:"schema_version"`
	NodeID               string          `json:"node_id"`
	RuntimeEpoch         string          `json:"runtime_epoch"`
	Sequence             uint64          `json:"sequence"`
	SampledAt            string          `json:"sampled_at"`
	Capabilities         map[string]bool `json:"capabilities,omitempty"`
	Counters             *counters       `json:"counters,omitempty"`
	Inbounds             []counterItem   `json:"inbounds,omitempty"`
	Outbounds            []counterItem   `json:"outbounds,omitempty"`
	LocalUsers           []counterItem   `json:"local_users,omitempty"`
	Connections          []connection    `json:"connections,omitempty"`
	ConnectionSequence   uint64          `json:"connection_sequence"`
	ConnectionsTruncated bool            `json:"connections_truncated,omitempty"`
	More                 bool            `json:"more,omitempty"`
	Error                string          `json:"error,omitempty"`
}

type counters struct {
	UploadBytes       int64 `json:"upload_bytes"`
	DownloadBytes     int64 `json:"download_bytes"`
	ActiveConnections int   `json:"active_connections"`
}

type counterItem struct {
	Tag           string `json:"tag"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
}

type connection struct {
	Sequence      uint64   `json:"sequence"`
	ID            string   `json:"id"`
	Inbound       string   `json:"inbound,omitempty"`
	InboundType   string   `json:"inbound_type,omitempty"`
	Network       string   `json:"network,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	Destination   string   `json:"destination,omitempty"`
	Outbound      string   `json:"outbound,omitempty"`
	OutboundType  string   `json:"outbound_type,omitempty"`
	Chain         []string `json:"chain,omitempty"`
	Rule          string   `json:"rule,omitempty"`
	UploadBytes   int64    `json:"upload_bytes"`
	DownloadBytes int64    `json:"download_bytes"`
	StartedAt     string   `json:"started_at"`
	ClosedAt      string   `json:"closed_at"`
}

func (s *Service) serve(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	var req request
	if json.NewDecoder(io.LimitReader(conn, 1024)).Decode(&req) != nil {
		return
	}
	result := response{SchemaVersion: SchemaVersion, NodeID: s.options.NodeID, RuntimeEpoch: s.epoch, Sequence: s.reads.Add(1)}
	switch req.Action {
	case "capabilities":
		result.Capabilities = map[string]bool{"counters": true, "connections": true, "domains": true, "rules": true, "outbounds": true}
	case "counters", "snapshot", "connections":
		if req.Action != "connections" {
			s.readCounters(&result)
		}
		if req.Action != "counters" {
			s.readConnections(req, &result)
		}
	default:
		result.Error = "unsupported action"
	}
	result.SampledAt = time.Now().UTC().Format(time.RFC3339Nano)
	_ = json.NewEncoder(conn).Encode(result)
}

func (s *Service) readCounters(r *response) {
	// VisitActive serializes with OnClosed. Initialize the closed totals under
	// that same lock, even when no active connection remains.
	all := newTotals()
	s.manager.VisitStats(func() {
		s.mutex.Lock()
		all.copyFrom(s.closed)
		s.mutex.Unlock()
	}, func(item *trafficcontrol.TrackerMetadata) {
		all.count(item, item.Upload.Load(), item.Download.Load())
		all.total.ActiveConnections++
	})
	r.Counters = &all.total
	r.Inbounds, r.Outbounds, r.LocalUsers = counterItems(all.inbounds), counterItems(all.outbounds), counterItems(all.users)
}

func (s *Service) readConnections(req request, r *response) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	after := req.AfterSequence
	if req.RuntimeEpoch != s.epoch {
		after = 0
	}
	if after > s.sequence {
		r.Error = "invalid connection cursor"
		return
	}
	oldest := s.sequence - min(s.sequence, uint64(len(s.history)))
	if after < oldest {
		r.ConnectionsTruncated = true
		after = oldest
	}
	limit := req.Limit
	if limit <= 0 || limit > maxBatch {
		limit = maxBatch
	}
	r.ConnectionSequence = min(s.sequence, after+uint64(limit))
	r.More = r.ConnectionSequence < s.sequence
	for seq := after + 1; seq <= r.ConnectionSequence; seq++ {
		r.Connections = append(r.Connections, s.history[(seq-1)%uint64(len(s.history))])
	}
}

func (s *Service) recordClose(item *trafficcontrol.TrackerMetadata) {
	up, down := item.Upload.Load(), item.Download.Load()
	c := connection{
		ID: item.ID.String(), Inbound: item.Metadata.Inbound, InboundType: item.Metadata.InboundType,
		Network: item.Metadata.Network, Domain: item.Metadata.Domain, Destination: item.Metadata.Destination.String(),
		Outbound: item.Outbound, OutboundType: item.OutboundType,
		Chain: append([]string(nil), item.Chain[:min(16, len(item.Chain))]...), UploadBytes: up, DownloadBytes: down,
		StartedAt: item.CreatedAt.UTC().Format(time.RFC3339Nano), ClosedAt: item.ClosedAt.UTC().Format(time.RFC3339Nano),
	}
	if item.Rule != nil {
		rule := item.Rule.String()
		c.Rule = strings.ToValidUTF8(rule[:min(512, len(rule))], "")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.closed.count(item, up, down)
	s.sequence++
	c.Sequence = s.sequence
	s.history[(s.sequence-1)%uint64(len(s.history))] = c
}

type pair struct{ up, down int64 }

type totals struct {
	total                      counters
	inbounds, outbounds, users map[string]pair
}

func newTotals() totals {
	return totals{inbounds: map[string]pair{}, outbounds: map[string]pair{}, users: map[string]pair{}}
}

func (t *totals) copyFrom(closed totals) {
	t.total = closed.total
	for k, v := range closed.inbounds {
		t.inbounds[k] = v
	}
	for k, v := range closed.outbounds {
		t.outbounds[k] = v
	}
	for k, v := range closed.users {
		t.users[k] = v
	}
}

func (t *totals) count(item *trafficcontrol.TrackerMetadata, up, down int64) {
	t.total.UploadBytes += up
	t.total.DownloadBytes += down
	add := func(group map[string]pair, key string) {
		if key != "" {
			before := group[key]
			group[key] = pair{before.up + up, before.down + down}
		}
	}
	add(t.inbounds, item.Metadata.Inbound)
	add(t.outbounds, item.Outbound)
	if name := item.Metadata.User; name != "sys_probe" && !strings.HasPrefix(name, "usr_") {
		add(t.users, name)
	}
}

func counterItems(values map[string]pair) []counterItem {
	result := make([]counterItem, 0, len(values))
	for tag, value := range values {
		result = append(result, counterItem{tag, value.up, value.down})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Tag < result[j].Tag })
	return result
}

var _ adapter.LifecycleService = (*Service)(nil)
