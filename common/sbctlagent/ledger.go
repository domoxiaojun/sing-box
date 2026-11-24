// Package sbctlagent embeds the zero-SSH node control supervisor, hot-reload
// coordinator and durable traffic ledger inside a single sing-box container.
package sbctlagent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/sbctlstats"
)

type M = map[string]any

func nowUTC() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func randomID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

func canonicalBytes(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func digestValue(v any) string { return sha256Hex(canonicalBytes(v)) }

func decodeObject(b []byte) (M, error) {
	var m M
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		m = M{}
	}
	return m, nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func legacyInboundID(protocol, tag string) string {
	return "inb_legacy_" + sha256Hex([]byte(protocol+":"+tag))[:24]
}

type InboundSpec struct {
	Tag       string
	Protocol  string
	Port      int
	InboundID string
}

type ManifestSpec struct {
	Inbounds      []InboundSpec
	Outbounds     []string
	LocalUsers    []string
	ManagedUsers  []string
	TotalInbounds int
}

type LedgerInbound struct {
	Tag        string `json:"tag"`
	Protocol   string `json:"protocol"`
	Upload     string `json:"upload_bytes"`
	Download   string `json:"download_bytes"`
	Port       int    `json:"port"`
	StartedAt  string `json:"started_at"`
	Active     bool   `json:"active"`
	InboundID  string `json:"inbound_id,omitempty"`
	HistoryTag string `json:"history_tag,omitempty"`
}

type LedgerOutbound struct {
	Tag       string `json:"tag"`
	Upload    string `json:"upload_bytes"`
	Download  string `json:"download_bytes"`
	StartedAt string `json:"started_at"`
	Active    bool   `json:"active"`
}

type LedgerLocalUser struct {
	Name      string `json:"name"`
	Upload    string `json:"upload_bytes"`
	Download  string `json:"download_bytes"`
	StartedAt string `json:"started_at"`
	Active    bool   `json:"active"`
}

type DataQuality struct {
	Integrity string `json:"integrity_state"`
	HasGap    bool   `json:"has_historical_gap"`
	Gaps      int64  `json:"gap_count"`
}

type TrafficConnection struct {
	Sequence     uint64   `json:"sequence,omitempty"`
	ID           string   `json:"id"`
	InboundID    string   `json:"inbound_id,omitempty"`
	Inbound      string   `json:"inbound,omitempty"`
	InboundType  string   `json:"inbound_type,omitempty"`
	Network      string   `json:"network,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	Destination  string   `json:"destination,omitempty"`
	Source       string   `json:"source,omitempty"`
	Outbound     string   `json:"outbound,omitempty"`
	OutboundType string   `json:"outbound_type,omitempty"`
	Chain        []string `json:"chain,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	Upload       string   `json:"upload_bytes"`
	Download     string   `json:"download_bytes"`
	StartedAt    string   `json:"started_at"`
	ClosedAt     string   `json:"closed_at,omitempty"`
}

type Snapshot struct {
	SchemaVersion  int                 `json:"schema_version"`
	NodeID         string              `json:"node_id"`
	LedgerID       string              `json:"ledger_id"`
	Seq            int64               `json:"snapshot_seq"`
	StartedAt      string              `json:"started_at"`
	SampledAt      *string             `json:"sampled_at"`
	SourceEpoch    *string             `json:"source_epoch"`
	ConfigHash     *string             `json:"config_hash"`
	Inbounds       []LedgerInbound     `json:"inbounds,omitempty"`
	Outbounds      []LedgerOutbound    `json:"outbounds,omitempty"`
	LocalUsers     []LedgerLocalUser   `json:"local_users,omitempty"`
	Connections    []TrafficConnection `json:"connections,omitempty"`
	ConnectionSeq  uint64              `json:"connection_sequence,omitempty"`
	ConnectionFeed bool                `json:"connection_feed,omitempty"`
	TotalInbounds  int                 `json:"total_inbounds,omitempty"`
	Quality        DataQuality         `json:"data_quality"`
	Checksum       string              `json:"checksum"`
}

func (s *Snapshot) Seal() {
	m, _ := decodeObject(canonicalBytes(s))
	delete(m, "checksum")
	s.Checksum = digestValue(m)
}

type seriesTotal struct {
	Scope      string `json:"scope"`
	Key        string `json:"key"`
	Protocol   string `json:"protocol,omitempty"`
	Port       int    `json:"port,omitempty"`
	Upload     int64  `json:"upload"`
	Download   int64  `json:"download"`
	StartedAt  string `json:"started_at"`
	Active     bool   `json:"active"`
	Tag        string `json:"tag,omitempty"`
	HistoryTag string `json:"history_tag,omitempty"`
}

type cursorEntry struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
	Seen bool  `json:"seen"`
}

type ledgerDisk struct {
	LedgerID      string                 `json:"ledger_id"`
	NodeID        string                 `json:"node_id"`
	StartedAt     string                 `json:"started_at"`
	Seq           int64                  `json:"snapshot_seq"`
	GapCount      int64                  `json:"gap_count"`
	Integrity     string                 `json:"integrity_state"`
	SourceEpoch   string                 `json:"source_epoch"`
	SampledAt     string                 `json:"sampled_at"`
	ConfigHash    string                 `json:"config_hash"`
	TotalInbounds  int                    `json:"total_inbounds"`
	Epoch          string                 `json:"cursor_epoch"`
	GracefulClosed bool                   `json:"graceful_closed,omitempty"`
	StatsConnSeq   uint64                 `json:"stats_conn_seq"`
	Series        map[string]seriesTotal `json:"series"`
	Cursors       map[string]cursorEntry `json:"cursors"`
	ConnNextSeq   int64                  `json:"conn_next_seq"`
	ConnGap       bool                   `json:"conn_gap"`
}

type queuedConn struct {
	Seq  int64             `json:"seq"`
	Item TrafficConnection `json:"item"`
}

const maxQueuedConnections = 16384

type DurableLedger struct {
	mu       sync.Mutex
	path     string
	connPath string
	nodeID   string
	data     ledgerDisk
	conns    []queuedConn
}

func OpenLedger(dir, nodeID string) (*DurableLedger, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	l := &DurableLedger{
		path:     filepath.Join(dir, "ledger.json"),
		connPath: filepath.Join(dir, "connections.json"),
		nodeID:   nodeID,
	}
	if raw, err := os.ReadFile(l.path); err == nil {
		if err := json.Unmarshal(raw, &l.data); err != nil {
			return nil, fmt.Errorf("parse ledger: %w", err)
		}
		if l.data.NodeID != "" && nodeID != "" && l.data.NodeID != nodeID {
			return nil, fmt.Errorf("ledger node_id mismatch: have %s want %s", l.data.NodeID, nodeID)
		}
	} else if os.IsNotExist(err) {
		l.data = ledgerDisk{
			LedgerID:  randomID("ledger"),
			NodeID:    nodeID,
			StartedAt: nowUTC(),
			Integrity: "ok",
			Series:    map[string]seriesTotal{},
			Cursors:   map[string]cursorEntry{},
		}
		if nodeID != "" {
			if err := l.saveLocked(); err != nil {
				return nil, err
			}
		}
	} else {
		return nil, err
	}
	if l.data.Series == nil {
		l.data.Series = map[string]seriesTotal{}
	}
	if l.data.Cursors == nil {
		l.data.Cursors = map[string]cursorEntry{}
	}
	if raw, err := os.ReadFile(l.connPath); err == nil {
		_ = json.Unmarshal(raw, &l.conns)
	}
	return l, nil
}

func (l *DurableLedger) BindNodeID(nodeID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.data.NodeID != "" && l.data.NodeID != nodeID {
		return fmt.Errorf("ledger already bound to %s", l.data.NodeID)
	}
	l.nodeID = nodeID
	l.data.NodeID = nodeID
	return l.saveLocked()
}

func (l *DurableLedger) saveLocked() error {
	return atomicWriteFile(l.path, canonicalBytes(l.data), 0600)
}

func (l *DurableLedger) saveConnsLocked() error {
	return atomicWriteFile(l.connPath, canonicalBytes(l.conns), 0600)
}

// IngestStats folds an in-process sbctlstats sample into the durable ledger.
// When gracefulFlush is true (before a controlled reload), the subsequent new
// box.Box epoch is recorded cleanly without incrementing gap_count.
func (l *DurableLedger) IngestStats(svc *sbctlstats.Service, configHash string, manifest ManifestSpec, gracefulFlush bool) error {
	if svc == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.data.NodeID == "" {
		return nil
	}
	epoch := svc.Epoch()
	afterSeq := l.data.StatsConnSeq
	if l.data.Epoch != epoch {
		afterSeq = 0
	}

	resp := svc.Query(sbctlstats.Request{
		Action:        "snapshot",
		RuntimeEpoch:  epoch,
		AfterSequence: afterSeq,
		Limit:         256,
	})
	if resp.Error != "" || resp.Counters == nil {
		return fmt.Errorf("stats query failed: %s", resp.Error)
	}

	if l.data.SourceEpoch != "" && l.data.Epoch != "" && l.data.Epoch != epoch {
		if !l.data.GracefulClosed {
			l.data.GapCount++
		}
		l.data.Cursors = map[string]cursorEntry{}
	}
	l.data.Epoch = epoch
	l.data.GracefulClosed = gracefulFlush

	inMap := map[string]sbctlstats.CounterItem{}
	for _, it := range resp.Inbounds {
		inMap[it.Tag] = it
	}
	outMap := map[string]sbctlstats.CounterItem{}
	for _, it := range resp.Outbounds {
		outMap[it.Tag] = it
	}
	userMap := map[string]sbctlstats.CounterItem{}
	for _, it := range resp.LocalUsers {
		userMap[it.Tag] = it
	}

	for k, st := range l.data.Series {
		st.Active = false
		l.data.Series[k] = st
	}

	inboundIDByTag := map[string]string{}
	apply := func(scope, key, tag, protocol string, port int, curUp, curDown int64, found bool) {
		seriesKey := scope + ">>>" + key
		rec, exists := l.data.Series[seriesKey]
		if !exists {
			histTag := ""
			if scope == "inbound" && key == legacyInboundID(protocol, tag) {
				histTag = tag
			}
			rec = seriesTotal{
				Scope: scope, Key: key, Protocol: protocol, Port: port,
				StartedAt: nowUTC(), Active: true, Tag: tag, HistoryTag: histTag,
			}
		}
		cur := l.data.Cursors[seriesKey]
		if !found {
			curUp, curDown = cur.Up, cur.Down
		} else {
			cur.Seen = true
		}
		deltaUp := max(int64(0), curUp-cur.Up)
		deltaDown := max(int64(0), curDown-cur.Down)
		rec.Upload += deltaUp
		rec.Download += deltaDown
		rec.Port = port
		rec.Tag = tag
		rec.Active = true
		l.data.Series[seriesKey] = rec
		l.data.Cursors[seriesKey] = cursorEntry{Up: curUp, Down: curDown, Seen: cur.Seen}
	}

	for _, in := range manifest.Inbounds {
		id := in.InboundID
		if id == "" {
			id = legacyInboundID(in.Protocol, in.Tag)
		}
		inboundIDByTag[in.Tag] = id
		item, ok := inMap[in.Tag]
		apply("inbound", id, in.Tag, in.Protocol, in.Port, item.UploadBytes, item.DownloadBytes, ok)
	}
	for _, tag := range manifest.Outbounds {
		item, ok := outMap[tag]
		apply("outbound", tag, tag, "", 0, item.UploadBytes, item.DownloadBytes, ok)
	}
	for _, user := range manifest.LocalUsers {
		item, ok := userMap[user]
		apply("user", user, user, "", 0, item.UploadBytes, item.DownloadBytes, ok)
	}

	connsChanged := false
	for {
		if resp.ConnectionsTruncated {
			l.data.ConnGap = true
		}
		for _, c := range resp.Connections {
			l.data.ConnNextSeq++
			tc := TrafficConnection{
				ID: c.ID, InboundID: inboundIDByTag[c.Inbound], Inbound: c.Inbound, InboundType: c.InboundType,
				Network: c.Network, Domain: c.Domain, Destination: c.Destination, Source: c.Source,
				Outbound: c.Outbound, OutboundType: c.OutboundType, Chain: c.Chain, Rule: c.Rule,
				Upload: strconv.FormatInt(c.UploadBytes, 10), Download: strconv.FormatInt(c.DownloadBytes, 10),
				StartedAt: c.StartedAt, ClosedAt: c.ClosedAt,
			}
			l.conns = append(l.conns, queuedConn{Seq: l.data.ConnNextSeq, Item: tc})
			connsChanged = true
		}
		l.data.StatsConnSeq = resp.ConnectionSequence
		if !resp.More {
			break
		}
		resp = svc.Query(sbctlstats.Request{
			Action:        "connections",
			RuntimeEpoch:  epoch,
			AfterSequence: l.data.StatsConnSeq,
			Limit:         256,
		})
		if resp.Error != "" {
			break
		}
	}
	if len(l.conns) > maxQueuedConnections {
		l.conns = append([]queuedConn(nil), l.conns[len(l.conns)-maxQueuedConnections:]...)
		l.data.ConnGap = true
		connsChanged = true
	}

	l.data.SourceEpoch = epoch
	l.data.ConfigHash = configHash
	l.data.SampledAt = nowUTC()
	l.data.Integrity = "ok"
	l.data.TotalInbounds = manifest.TotalInbounds
	l.data.Seq++

	if connsChanged {
		_ = l.saveConnsLocked()
	}
	return l.saveLocked()
}

func (l *DurableLedger) Snapshot() (Snapshot, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.data.Seq == 0 || l.data.NodeID == "" {
		return Snapshot{}, false
	}
	keys := make([]string, 0, len(l.data.Series))
	for k := range l.data.Series {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := l.data.Series[keys[i]], l.data.Series[keys[j]]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Tag != b.Tag {
			return a.Tag < b.Tag
		}
		return a.Key < b.Key
	})
	var inbounds []LedgerInbound
	var outbounds []LedgerOutbound
	var localUsers []LedgerLocalUser
	for _, k := range keys {
		r := l.data.Series[k]
		switch r.Scope {
		case "inbound":
			in := LedgerInbound{
				Tag: r.Tag, Protocol: r.Protocol,
				Upload: strconv.FormatInt(r.Upload, 10), Download: strconv.FormatInt(r.Download, 10),
				Port: r.Port, StartedAt: r.StartedAt, Active: r.Active,
			}
			if r.Key != legacyInboundID(r.Protocol, r.Tag) {
				in.InboundID, in.HistoryTag = r.Key, r.HistoryTag
			}
			inbounds = append(inbounds, in)
		case "outbound":
			outbounds = append(outbounds, LedgerOutbound{
				Tag: r.Tag, Upload: strconv.FormatInt(r.Upload, 10), Download: strconv.FormatInt(r.Download, 10),
				StartedAt: r.StartedAt, Active: r.Active,
			})
		case "user":
			localUsers = append(localUsers, LedgerLocalUser{
				Name: r.Key, Upload: strconv.FormatInt(r.Upload, 10), Download: strconv.FormatInt(r.Download, 10),
				StartedAt: r.StartedAt, Active: r.Active,
			})
		}
	}
	sampled := l.data.SampledAt
	srcEpoch := l.data.Epoch
	cfgHash := l.data.ConfigHash
	var sampledPtr, epochPtr, cfgPtr *string
	if sampled != "" {
		sampledPtr = &sampled
	}
	if srcEpoch != "" {
		epochPtr = &srcEpoch
	}
	if cfgHash != "" {
		cfgPtr = &cfgHash
	}
	snap := Snapshot{
		SchemaVersion:  1,
		NodeID:         l.data.NodeID,
		LedgerID:       l.data.LedgerID,
		Seq:            l.data.Seq,
		StartedAt:      l.data.StartedAt,
		SampledAt:      sampledPtr,
		SourceEpoch:    epochPtr,
		ConfigHash:     cfgPtr,
		Inbounds:       inbounds,
		Outbounds:      outbounds,
		LocalUsers:     localUsers,
		ConnectionFeed: true,
		ConnectionSeq:  uint64(l.data.ConnNextSeq),
		TotalInbounds:  l.data.TotalInbounds,
		Quality: DataQuality{
			Integrity: l.data.Integrity,
			HasGap:    l.data.GapCount > 0,
			Gaps:      l.data.GapCount,
		},
	}
	snap.Seal()
	return snap, true
}

func (l *DurableLedger) ConnectionPage(after int64, limit int) (items []TrafficConnection, next int64, gap bool, more bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > 256 {
		limit = 256
	}
	next = after
	gap = l.data.ConnGap
	if len(l.conns) > 0 && l.conns[0].Seq > after+1 {
		gap = true
	}
	if len(l.conns) == 0 && l.data.ConnNextSeq > after {
		gap = true
	}
	for _, entry := range l.conns {
		if entry.Seq <= after {
			continue
		}
		if len(items) >= limit {
			more = true
			break
		}
		if entry.Seq != next+1 {
			gap = true
		}
		items = append(items, entry.Item)
		next = entry.Seq
	}
	return items, next, gap, more
}

func (l *DurableLedger) AckConnections(ackedSeq int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ackedSeq <= 0 || len(l.conns) == 0 {
		return
	}
	cut := 0
	for cut < len(l.conns) && l.conns[cut].Seq <= ackedSeq {
		cut++
	}
	if cut > 0 {
		l.conns = append([]queuedConn(nil), l.conns[cut:]...)
		_ = l.saveConnsLocked()
	}
}
