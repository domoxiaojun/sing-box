// Package sbctlstats exposes local sing-box statistics and in-process telemetry.
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
	M "github.com/sagernet/sing/common/metadata"
)

const (
	SchemaVersion  = 1
	historySize    = 16384
	maxBatch       = 256
	maxActiveItems = 100
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
	history  []Connection
	sequence uint64

	rateMutex     sync.Mutex
	rateAt        time.Time
	prevTotal     pair
	prevInbounds  map[string]pair
	prevOutbounds map[string]pair
	curTotalBps   pair
	curInboundBps map[string]pair
	curOutboundBps map[string]pair
}

func New(manager *trafficcontrol.Manager, options Options) *Service {
	s := &Service{
		manager: manager, options: options, epoch: time.Now().UTC().Format(time.RFC3339Nano),
		closed: newTotals(), history: make([]Connection, historySize),
		prevInbounds: map[string]pair{}, prevOutbounds: map[string]pair{},
		curInboundBps: map[string]pair{}, curOutboundBps: map[string]pair{},
	}
	// Installed before the router starts. The callback is synchronous so bursts
	// of short connections still contribute after the replay window fills.
	manager.OnClosed = s.recordClose
	return s
}

func (s *Service) Name() string  { return "sbctl statistics" }
func (s *Service) Epoch() string { return s.epoch }

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	path := s.options.SocketPath
	if path == "" {
		return nil
	}
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

type Request struct {
	Action        string `json:"action"`
	AfterSequence uint64 `json:"after_sequence,omitempty"`
	RuntimeEpoch  string `json:"runtime_epoch,omitempty"`
	Limit         int    `json:"limit,omitempty"`
}

type Response struct {
	SchemaVersion        int             `json:"schema_version"`
	NodeID               string          `json:"node_id"`
	RuntimeEpoch         string          `json:"runtime_epoch"`
	Sequence             uint64          `json:"sequence"`
	SampledAt            string          `json:"sampled_at"`
	Capabilities         map[string]bool `json:"capabilities,omitempty"`
	Counters             *Counters       `json:"counters,omitempty"`
	Inbounds             []CounterItem   `json:"inbounds,omitempty"`
	Outbounds            []CounterItem   `json:"outbounds,omitempty"`
	LocalUsers           []CounterItem   `json:"local_users,omitempty"`
	ActiveConnections    []Connection    `json:"active_connections_list,omitempty"`
	Connections          []Connection    `json:"connections,omitempty"`
	ConnectionSequence   uint64          `json:"connection_sequence"`
	ConnectionsTruncated bool            `json:"connections_truncated,omitempty"`
	More                 bool            `json:"more,omitempty"`
	Error                string          `json:"error,omitempty"`
}

type Counters struct {
	UploadBytes       int64 `json:"upload_bytes"`
	DownloadBytes     int64 `json:"download_bytes"`
	UploadBps         int64 `json:"upload_bps"`
	DownloadBps       int64 `json:"download_bps"`
	ActiveConnections int   `json:"active_connections"`
}

type CounterItem struct {
	Tag           string `json:"tag"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	UploadBps     int64  `json:"upload_bps,omitempty"`
	DownloadBps   int64  `json:"download_bps,omitempty"`
}

type Connection struct {
	Sequence      uint64   `json:"sequence"`
	ID            string   `json:"id"`
	Inbound       string   `json:"inbound,omitempty"`
	InboundType   string   `json:"inbound_type,omitempty"`
	Network       string   `json:"network,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	Destination   string   `json:"destination,omitempty"`
	Source        string   `json:"source,omitempty"`
	Outbound      string   `json:"outbound,omitempty"`
	OutboundType  string   `json:"outbound_type,omitempty"`
	Chain         []string `json:"chain,omitempty"`
	Rule          string   `json:"rule,omitempty"`
	UploadBytes   int64    `json:"upload_bytes"`
	DownloadBytes int64    `json:"download_bytes"`
	StartedAt     string   `json:"started_at"`
	ClosedAt      string   `json:"closed_at"`
}

type (
	request    = Request
	response   = Response
	counters   = Counters
	connection = Connection
)

func (s *Service) Query(req Request) Response {
	result := Response{SchemaVersion: SchemaVersion, NodeID: s.options.NodeID, RuntimeEpoch: s.epoch, Sequence: s.reads.Add(1)}
	switch req.Action {
	case "capabilities":
		result.Capabilities = map[string]bool{"counters": true, "connections": true, "active_connections": true, "rates": true, "domains": true, "rules": true, "outbounds": true}
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
	return result
}

func (s *Service) serve(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	var req Request
	if json.NewDecoder(io.LimitReader(conn, 1024)).Decode(&req) != nil {
		return
	}
	_ = json.NewEncoder(conn).Encode(s.Query(req))
}

func addrString(addr M.Socksaddr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func buildConnection(item *trafficcontrol.TrackerMetadata, up, down int64, closed bool) Connection {
	c := Connection{
		ID: item.ID.String(), Inbound: item.Metadata.Inbound, InboundType: item.Metadata.InboundType,
		Network: item.Metadata.Network, Domain: item.Metadata.Domain, Destination: addrString(item.Metadata.Destination),
		Source: addrString(item.Metadata.Source), Outbound: item.Outbound, OutboundType: item.OutboundType,
		Chain: append([]string(nil), item.Chain[:min(16, len(item.Chain))]...), UploadBytes: up, DownloadBytes: down,
		StartedAt: item.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if closed && !item.ClosedAt.IsZero() {
		c.ClosedAt = item.ClosedAt.UTC().Format(time.RFC3339Nano)
	}
	if item.Rule != nil {
		rule := item.Rule.String()
		c.Rule = strings.ToValidUTF8(rule[:min(512, len(rule))], "")
	}
	return c
}

func (s *Service) readCounters(r *Response) {
	all := newTotals()
	var active []Connection
	s.manager.VisitStats(func() {
		s.mutex.Lock()
		all.copyFrom(s.closed)
		s.mutex.Unlock()
	}, func(item *trafficcontrol.TrackerMetadata) {
		up, down := item.Upload.Load(), item.Download.Load()
		all.count(item, up, down)
		all.total.ActiveConnections++
		active = append(active, buildConnection(item, up, down, false))
	})
	nowTime := time.Now()
	totalBps, inBps, outBps := s.sampleRates(nowTime, pair{all.total.UploadBytes, all.total.DownloadBytes}, all.inbounds, all.outbounds)
	all.total.UploadBps = totalBps.up
	all.total.DownloadBps = totalBps.down
	r.Counters = &all.total
	r.Inbounds = counterItems(all.inbounds, inBps)
	r.Outbounds = counterItems(all.outbounds, outBps)
	r.LocalUsers = counterItems(all.users, nil)
	if len(active) > 0 {
		sort.Slice(active, func(i, j int) bool {
			ti := active[i].UploadBytes + active[i].DownloadBytes
			tj := active[j].UploadBytes + active[j].DownloadBytes
			if ti != tj {
				return ti > tj
			}
			return active[i].StartedAt > active[j].StartedAt
		})
		if len(active) > maxActiveItems {
			active = active[:maxActiveItems]
		}
		r.ActiveConnections = active
	}
}

func computeBps(cur, prev pair, elapsed time.Duration) pair {
	if elapsed <= 0 {
		return pair{}
	}
	ns := elapsed.Nanoseconds()
	var out pair
	if cur.up > prev.up {
		out.up = (cur.up - prev.up) * 1_000_000_000 / ns
	}
	if cur.down > prev.down {
		out.down = (cur.down - prev.down) * 1_000_000_000 / ns
	}
	return out
}

func (s *Service) sampleRates(at time.Time, total pair, inbounds, outbounds map[string]pair) (pair, map[string]pair, map[string]pair) {
	s.rateMutex.Lock()
	defer s.rateMutex.Unlock()
	if s.rateAt.IsZero() {
		s.rateAt = at
		s.prevTotal = total
		s.prevInbounds = clonePairs(inbounds)
		s.prevOutbounds = clonePairs(outbounds)
		return pair{}, nil, nil
	}
	elapsed := at.Sub(s.rateAt)
	if elapsed >= 200*time.Millisecond {
		s.curTotalBps = computeBps(total, s.prevTotal, elapsed)
		inRates := make(map[string]pair, len(inbounds))
		for k, v := range inbounds {
			if prev, ok := s.prevInbounds[k]; ok {
				inRates[k] = computeBps(v, prev, elapsed)
			}
		}
		outRates := make(map[string]pair, len(outbounds))
		for k, v := range outbounds {
			if prev, ok := s.prevOutbounds[k]; ok {
				outRates[k] = computeBps(v, prev, elapsed)
			}
		}
		s.curInboundBps = inRates
		s.curOutboundBps = outRates
		s.rateAt = at
		s.prevTotal = total
		s.prevInbounds = clonePairs(inbounds)
		s.prevOutbounds = clonePairs(outbounds)
	}
	return s.curTotalBps, clonePairs(s.curInboundBps), clonePairs(s.curOutboundBps)
}

func clonePairs(src map[string]pair) map[string]pair {
	if len(src) == 0 {
		return map[string]pair{}
	}
	dst := make(map[string]pair, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (s *Service) readConnections(req Request, r *Response) {
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
	c := buildConnection(item, up, down, true)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.closed.count(item, up, down)
	s.sequence++
	c.Sequence = s.sequence
	s.history[(s.sequence-1)%uint64(len(s.history))] = c
}

type pair struct{ up, down int64 }

type totals struct {
	total                      Counters
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

func counterItems(values map[string]pair, rates map[string]pair) []CounterItem {
	result := make([]CounterItem, 0, len(values))
	for tag, value := range values {
		item := CounterItem{Tag: tag, UploadBytes: value.up, DownloadBytes: value.down}
		if r, ok := rates[tag]; ok {
			item.UploadBps = r.up
			item.DownloadBps = r.down
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Tag < result[j].Tag })
	return result
}

var _ adapter.LifecycleService = (*Service)(nil)
