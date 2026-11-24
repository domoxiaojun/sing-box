package sbctlagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sbctlstats"
	"github.com/sagernet/sing-box/option"
)

type BoxInstance interface {
	Close() error
	Inbound() adapter.InboundManager
	SBCTLStats() *sbctlstats.Service
}

type InstanceFactory func(rawJSON []byte) (BoxInstance, context.CancelFunc, error)

type SupervisorConfig struct {
	ControlURL       string
	NodeID           string
	AgentToken       string
	RegistrationCode string
	StateDir         string
	ConfigPath       string
	Version          string
	BuildID          string
	Factory          InstanceFactory
}

type agentCredDisk struct {
	NodeID     string `json:"node_id"`
	ControlURL string `json:"control_url"`
	AgentToken string `json:"agent_token"`
}

type LiveRateItem struct {
	Tag         string `json:"tag"`
	UploadBps   int64  `json:"upload_bps"`
	DownloadBps int64  `json:"download_bps"`
}

type LivePayload struct {
	SampledAt         string              `json:"sampled_at"`
	UploadBps         int64               `json:"upload_bps"`
	DownloadBps       int64               `json:"download_bps"`
	ActiveConnections int                 `json:"active_connections"`
	Inbounds          []LiveRateItem      `json:"inbounds,omitempty"`
	Outbounds         []LiveRateItem      `json:"outbounds,omitempty"`
	ActiveItems       []TrafficConnection `json:"active_items,omitempty"`
}

type Supervisor struct {
	cfg        SupervisorConfig
	configPath string
	stateDir   string
	version    string
	buildID    string
	httpClient *http.Client

	rpcMu  sync.Mutex
	state  nodeStateDisk
	ledger *DurableLedger

	instMu     sync.RWMutex
	instance   BoxInstance
	instCancel context.CancelFunc
	activeRaw  []byte
	startedAt  string
	epoch      string

	registerMu sync.Mutex
	credMu     sync.RWMutex
	agentToken string
	ackedConn  int64
}

func computeExecutableHash() string {
	if envHash := strings.TrimSpace(os.Getenv("SBCTL_ENGINE_BUILD_ID")); hashRE.MatchString(envHash) {
		return envHash
	}
	exe, err := os.Executable()
	if err == nil {
		if f, err := os.Open(exe); err == nil {
			defer f.Close()
			if data, err := io.ReadAll(io.LimitReader(f, 128<<20)); err == nil && len(data) > 0 {
				return sha256Hex(data)
			}
		}
	}
	return sha256Hex([]byte("sing-box-embedded"))
}

func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.StateDir == "" {
		cfg.StateDir = "/var/lib/sing-box/sbctl"
	}
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return nil, err
	}
	if cfg.BuildID == "" {
		cfg.BuildID = computeExecutableHash()
	}
	cfg.ControlURL = strings.TrimRight(strings.TrimSpace(cfg.ControlURL), "/")

	s := &Supervisor{
		cfg:        cfg,
		configPath: cfg.ConfigPath,
		stateDir:   cfg.StateDir,
		version:    cfg.Version,
		buildID:    cfg.BuildID,
		agentToken: strings.TrimSpace(cfg.AgentToken),
		httpClient: &http.Client{Timeout: 35 * time.Second},
	}
	if raw, err := os.ReadFile(s.statePath()); err == nil {
		_ = json.Unmarshal(raw, &s.state)
	}
	if s.state.Revoked == nil {
		s.state.Revoked = map[string]bool{}
	}
	if s.state.RetiringInbounds == nil {
		s.state.RetiringInbounds = map[string]string{}
	}
	if s.state.MaintenanceReceipts == nil {
		s.state.MaintenanceReceipts = map[string]MaintenanceReceipt{}
	}
	if raw, err := os.ReadFile(s.agentCredPath()); err == nil {
		var saved agentCredDisk
		if json.Unmarshal(raw, &saved) == nil {
			if s.agentToken == "" && saved.ControlURL == cfg.ControlURL && (s.cfg.NodeID == "" || saved.NodeID == s.cfg.NodeID) {
				s.agentToken = saved.AgentToken
			}
			if s.cfg.NodeID == "" && saved.NodeID != "" {
				s.cfg.NodeID = saved.NodeID
			}
		}
	}
	if s.cfg.NodeID == "" {
		s.cfg.NodeID = s.state.NodeID
	}
	if !identityRE.MatchString(s.cfg.NodeID) || (s.state.NodeID != "" && s.state.NodeID != s.cfg.NodeID) {
		return nil, errors.New("invalid node ID or state belongs to another node")
	}
	ledger, err := OpenLedger(cfg.StateDir, s.cfg.NodeID)
	if err != nil {
		return nil, err
	}
	s.ledger = ledger
	return s, nil
}

func (s *Supervisor) statePath() string     { return filepath.Join(s.stateDir, "state.json") }
func (s *Supervisor) templatePath() string  { return filepath.Join(s.stateDir, "template.json") }
func (s *Supervisor) agentCredPath() string { return filepath.Join(s.stateDir, "agent.json") }

func (s *Supervisor) nodeID() string {
	return s.cfg.NodeID
}

func (s *Supervisor) containerLabel() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "sing-box"
}

func (s *Supervisor) saveStateLocked() error {
	return atomicWriteFile(s.statePath(), canonicalBytes(s.state), 0600)
}

func (s *Supervisor) readDiskConfig() ([]byte, M, error) {
	raw, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, nil, rpcFail("CONFIG_READ", "读取配置文件失败: "+err.Error())
	}
	cfg, err := decodeObject(raw)
	if err != nil {
		return nil, nil, rpcFail("INVALID_JSON", "配置文件 JSON 无效: "+err.Error())
	}
	return raw, cfg, nil
}

func (s *Supervisor) isRunning() bool {
	s.instMu.RLock()
	defer s.instMu.RUnlock()
	return s.instance != nil
}

func (s *Supervisor) activeConfigHash() string {
	s.instMu.RLock()
	defer s.instMu.RUnlock()
	if len(s.activeRaw) == 0 {
		return ""
	}
	return sha256Hex(s.activeRaw)
}

func (s *Supervisor) activeEpoch() string {
	s.instMu.RLock()
	defer s.instMu.RUnlock()
	return s.epoch
}

func (s *Supervisor) runtimeInfoLocked(rev int64) M {
	s.instMu.RLock()
	running := s.instance != nil
	started := s.startedAt
	cfgHash := ""
	semHash := ""
	if len(s.activeRaw) > 0 {
		cfgHash = sha256Hex(s.activeRaw)
		if obj, err := decodeObject(s.activeRaw); err == nil {
			semHash = digestValue(obj)
		}
	}
	s.instMu.RUnlock()
	var users []string
	if s.state.LatestRequest != nil {
		for _, u := range s.state.LatestRequest.Document.Users {
			users = append(users, u.UserID)
		}
	}
	if users == nil {
		users = []string{}
	}
	return M{
		"container_id":  s.containerLabel(),
		"started_at":    started,
		"running":       running,
		"paused":        false,
		"restarting":    false,
		"config_hash":   cfgHash,
		"semantic_hash": semHash,
		"node_revision": rev,
		"users":         users,
		"image_digest":  "sha256:" + s.buildID,
	}
}

func (s *Supervisor) recordControlledLocked(cfg M) {
	h := digestValue(cfg)
	if s.state.ConfigEventSeq == 0 || h != s.state.SemanticHash {
		s.state.ConfigEventSeq++
	}
	s.state.SemanticHash = h
	s.state.AdoptedHash = h
	s.state.PendingSync = false
}

func (s *Supervisor) refreshObservationLocked(cfg M) {
	h := digestValue(cfg)
	if s.state.ConfigEventSeq == 0 || h != s.state.SemanticHash {
		s.state.ConfigEventSeq++
		s.state.SemanticHash = h
	}
	if s.state.AdoptedHash != "" && h != s.state.AdoptedHash {
		s.state.PendingSync = true
	}
}

func (s *Supervisor) observedExternalChangeLocked() bool {
	if s.state.AdoptedHash == "" {
		return false
	}
	_, cfg, err := s.readDiskConfig()
	if err != nil {
		return false
	}
	return digestValue(cfg) != s.state.AdoptedHash || s.state.PendingSync
}

func (s *Supervisor) StartInitial() error {
	raw, cfg, err := s.readDiskConfig()
	if err != nil {
		return err
	}
	inst, cancel, createErr := s.cfg.Factory(raw)
	if createErr != nil {
		return createErr
	}
	started := nowUTC()
	epoch := s.containerLabel() + "@" + started
	if st := inst.SBCTLStats(); st != nil {
		epoch = st.Epoch()
	}
	s.instMu.Lock()
	s.instance = inst
	s.instCancel = cancel
	s.activeRaw = append([]byte(nil), raw...)
	s.startedAt = started
	s.epoch = epoch
	s.instMu.Unlock()

	s.rpcMu.Lock()
	s.refreshObservationLocked(cfg)
	_ = s.saveStateLocked()
	_ = s.flushStatsLocked(false)
	s.rpcMu.Unlock()
	return nil
}

func (s *Supervisor) StopInstance() {
	s.rpcMu.Lock()
	_ = s.flushStatsLocked(true)
	s.rpcMu.Unlock()

	s.instMu.Lock()
	inst, cancel := s.instance, s.instCancel
	s.instance, s.instCancel = nil, nil
	s.instMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if inst != nil {
		_ = inst.Close()
	}
}

func (s *Supervisor) flushStatsLocked(graceful bool) error {
	s.instMu.RLock()
	inst := s.instance
	raw := append([]byte(nil), s.activeRaw...)
	s.instMu.RUnlock()
	if inst == nil || inst.SBCTLStats() == nil || len(raw) == 0 {
		return nil
	}
	cfg, err := decodeObject(raw)
	if err != nil {
		return err
	}
	manifest := buildManifest(cfg, s.state)
	return s.ledger.IngestStats(inst.SBCTLStats(), sha256Hex(raw), manifest, graceful)
}

// reloadInProcessLocked flushes stats from the active instance, closes it to
// release bound sockets, starts the new instance, and automatically restores
// the previous configuration in memory if startup fails.
func (s *Supervisor) reloadInProcessLocked(newRaw []byte) error {
	_ = s.flushStatsLocked(true)

	s.instMu.Lock()
	oldInst, oldCancel := s.instance, s.instCancel
	oldRaw := append([]byte(nil), s.activeRaw...)
	s.instance, s.instCancel = nil, nil
	s.instMu.Unlock()

	if oldCancel != nil {
		oldCancel()
	}
	if oldInst != nil {
		_ = oldInst.Close()
	}

	nextInst, nextCancel, err := s.cfg.Factory(newRaw)
	if err != nil {
		if len(oldRaw) > 0 {
			if recInst, recCancel, recErr := s.cfg.Factory(oldRaw); recErr == nil {
				started := nowUTC()
				ep := s.containerLabel() + "@" + started
				if st := recInst.SBCTLStats(); st != nil {
					ep = st.Epoch()
				}
				s.instMu.Lock()
				s.instance, s.instCancel, s.activeRaw, s.startedAt, s.epoch = recInst, recCancel, oldRaw, started, ep
				s.instMu.Unlock()
			}
		}
		return rpcFail("PREFLIGHT_FAILED", "候选配置启动失败，已自动回滚原运行实例: "+err.Error())
	}

	started := nowUTC()
	epoch := s.containerLabel() + "@" + started
	if st := nextInst.SBCTLStats(); st != nil {
		epoch = st.Epoch()
	}
	s.instMu.Lock()
	s.instance = nextInst
	s.instCancel = nextCancel
	s.activeRaw = append([]byte(nil), newRaw...)
	s.startedAt = started
	s.epoch = epoch
	s.instMu.Unlock()

	_ = s.flushStatsLocked(false)
	return nil
}

func (s *Supervisor) applyNewConfigBytes(newRaw []byte) error {
	if err := s.reloadInProcessLocked(newRaw); err != nil {
		return err
	}
	if err := atomicWriteFile(s.configPath, newRaw, 0640); err != nil {
		return rpcFail("IO_ERROR", "保存配置文件失败: "+err.Error())
	}
	return nil
}

func stripManagedUsers(cfg M, managedTags map[string]bool) M {
	cloned, _ := decodeObject(canonicalBytes(cfg))
	for _, rv := range sliceVal(cloned["inbounds"]) {
		in := mapVal(rv)
		if managedTags[strVal(in["tag"])] {
			delete(in, "users")
		}
	}
	return cloned
}

// applyAuthorizationConfigLocked updates inbound users in-memory with zero
// connection interruption when only managed inbound user lists changed.
func (s *Supervisor) applyAuthorizationConfigLocked(eps []Endpoint, newRaw []byte) error {
	s.instMu.RLock()
	inst := s.instance
	curRaw := append([]byte(nil), s.activeRaw...)
	s.instMu.RUnlock()

	if inst != nil && inst.Inbound() != nil && len(curRaw) > 0 {
		curCfg, err1 := decodeObject(curRaw)
		nextCfg, err2 := decodeObject(newRaw)
		if err1 == nil && err2 == nil {
			managedTags := map[string]bool{}
			for _, ep := range eps {
				managedTags[ep.Tag] = true
			}
			if digestValue(stripManagedUsers(curCfg, managedTags)) == digestValue(stripManagedUsers(nextCfg, managedTags)) {
				canHotUpdate := true
				for _, ep := range eps {
					inb, ok := inst.Inbound().Get(ep.Tag)
					if !ok {
						canHotUpdate = false
						break
					}
					switch ep.Protocol {
					case "anytls":
						if _, ok := inb.(adapter.ManagedAnyTLSInbound); !ok {
							canHotUpdate = false
						}
					case "tuic":
						if _, ok := inb.(adapter.ManagedTUICInbound); !ok {
							canHotUpdate = false
						}
					default:
						canHotUpdate = false
					}
				}
				if canHotUpdate {
					for _, ep := range eps {
						inObj := findInboundByTag(nextCfg, ep.Tag)
						inb, _ := inst.Inbound().Get(ep.Tag)
						switch ep.Protocol {
						case "anytls":
							var users []option.AnyTLSUser
							for _, ru := range sliceVal(inObj["users"]) {
								u := mapVal(ru)
								users = append(users, option.AnyTLSUser{Name: strVal(u["name"]), Password: strVal(u["password"])})
							}
							if err := inb.(adapter.ManagedAnyTLSInbound).UpdateSBCTLUsers(users); err != nil {
								return rpcFail("APPLY_FAILED", err.Error())
							}
						case "tuic":
							var users []option.TUICUser
							for _, ru := range sliceVal(inObj["users"]) {
								u := mapVal(ru)
								users = append(users, option.TUICUser{Name: strVal(u["name"]), UUID: strVal(u["uuid"]), Password: strVal(u["password"])})
							}
							if err := inb.(adapter.ManagedTUICInbound).UpdateSBCTLUsers(users); err != nil {
								return rpcFail("APPLY_FAILED", err.Error())
							}
						}
					}
					if err := atomicWriteFile(s.configPath, newRaw, 0640); err != nil {
						return rpcFail("IO_ERROR", err.Error())
					}
					s.instMu.Lock()
					s.activeRaw = append([]byte(nil), newRaw...)
					s.instMu.Unlock()
					_ = s.flushStatsLocked(false)
					return nil
				}
			}
		}
	}
	return s.applyNewConfigBytes(newRaw)
}

func (s *Supervisor) handleStatsRPC(body M) (M, error) {
	s.rpcMu.Lock()
	_ = s.flushStatsLocked(false)
	s.rpcMu.Unlock()

	if len(body) == 0 {
		snap, ok := s.ledger.Snapshot()
		if !ok {
			return nil, rpcFail("NO_SAMPLE", "账本尚无采样")
		}
		m, _ := decodeObject(canonicalBytes(snap))
		return m, nil
	}
	action := strVal(body["action"])
	switch action {
	case "inspect":
		return M{
			"ready":          true,
			"version":        s.version,
			"schema_version": sbctlstats.SchemaVersion,
			"node_id":        s.nodeID(),
			"runtime_epoch":  s.activeEpoch(),
		}, nil
	case "connections":
		after := intVal(body["after"])
		if after < 0 {
			return nil, rpcFail("ACTION_REJECTED", "连接游标无效")
		}
		items, next, gap, more := s.ledger.ConnectionPage(after, 128)
		snap, _ := s.ledger.Snapshot()
		if items == nil {
			items = []TrafficConnection{}
		}
		return M{
			"node_id":   s.nodeID(),
			"ledger_id": snap.LedgerID,
			"next":      next,
			"gap":       gap,
			"more":      more,
			"items":     items,
		}, nil
	default:
		return nil, rpcFail("ACTION_REJECTED", "未知统计动作")
	}
}

func (s *Supervisor) token() string {
	s.credMu.RLock()
	defer s.credMu.RUnlock()
	return s.agentToken
}

func (s *Supervisor) ensureRegistered(ctx context.Context) error {
	if s.token() != "" {
		return nil
	}
	// Both loops start concurrently, but a registration code can be consumed only once.
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	if s.token() != "" {
		return nil
	}
	if s.cfg.RegistrationCode == "" || s.nodeID() == "" {
		return errors.New("missing SBCTL_AGENT_TOKEN or (SBCTL_NODE_ID + SBCTL_REGISTRATION_CODE)")
	}
	var rnd [16]byte
	_, _ = rand.Read(rnd[:])
	pubKey := "sbctl-singbox-" + hex.EncodeToString(rnd[:])
	resp, err := s.requestJSON(ctx, http.MethodPost, "/api/v1/agent/register", "", M{
		"node_id":           s.nodeID(),
		"registration_code": s.cfg.RegistrationCode,
		"public_key":        pubKey,
		"version":           s.version,
		"capabilities":      M{"embedded": true, "hot_reload": true, "hot_users": true, "live_telemetry": true, "stats": true},
	}, 15*time.Second)
	if err != nil {
		return err
	}
	tok := strVal(resp["agent_token"])
	if tok == "" {
		return errors.New("controller returned empty agent_token")
	}
	if err := atomicWriteFile(s.agentCredPath(), canonicalBytes(agentCredDisk{
		NodeID:     s.nodeID(),
		ControlURL: s.cfg.ControlURL,
		AgentToken: tok,
	}), 0600); err != nil {
		return err
	}
	s.credMu.Lock()
	s.agentToken = tok
	s.credMu.Unlock()
	return nil
}

func (s *Supervisor) requestJSON(ctx context.Context, method, path, tok string, payload any, timeout time.Duration) (M, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(canonicalBytes(payload))
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, s.cfg.ControlURL+path, body)
	if err != nil {
		return nil, err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return decodeObject(data)
}

func (s *Supervisor) BuildTelemetryPayload() (M, bool) {
	s.rpcMu.Lock()
	_ = s.flushStatsLocked(false)
	raw, cfg, cfgErr := s.readDiskConfig()
	if cfgErr == nil {
		s.refreshObservationLocked(cfg)
	}
	eventSeq := s.state.ConfigEventSeq
	semHash := s.state.SemanticHash
	extDrift := s.observedExternalChangeLocked()
	var inboundIDMap = map[string]string{}
	for _, ep := range s.state.Endpoints {
		inboundIDMap[ep.Tag] = ep.InboundID
	}
	s.rpcMu.Unlock()

	snap, ok := s.ledger.Snapshot()
	if !ok {
		return nil, false
	}
	s.credMu.RLock()
	after := s.ackedConn
	s.credMu.RUnlock()
	conns, nextSeq, connGap, connMore := s.ledger.ConnectionPage(after, 128)
	if conns == nil {
		conns = []TrafficConnection{}
	}

	var live LivePayload
	s.instMu.RLock()
	inst := s.instance
	s.instMu.RUnlock()
	if inst != nil && inst.SBCTLStats() != nil {
		q := inst.SBCTLStats().Query(sbctlstats.Request{Action: "counters"})
		live.SampledAt = q.SampledAt
		if q.Counters != nil {
			live.UploadBps = q.Counters.UploadBps
			live.DownloadBps = q.Counters.DownloadBps
			live.ActiveConnections = q.Counters.ActiveConnections
		}
		for _, in := range q.Inbounds {
			live.Inbounds = append(live.Inbounds, LiveRateItem{Tag: in.Tag, UploadBps: in.UploadBps, DownloadBps: in.DownloadBps})
		}
		for _, out := range q.Outbounds {
			live.Outbounds = append(live.Outbounds, LiveRateItem{Tag: out.Tag, UploadBps: out.UploadBps, DownloadBps: out.DownloadBps})
		}
		for _, ac := range q.ActiveConnections {
			live.ActiveItems = append(live.ActiveItems, TrafficConnection{
				ID: ac.ID, InboundID: inboundIDMap[ac.Inbound], Inbound: ac.Inbound, InboundType: ac.InboundType,
				Network: ac.Network, Domain: ac.Domain, Destination: ac.Destination, Source: ac.Source,
				Outbound: ac.Outbound, OutboundType: ac.OutboundType, Chain: ac.Chain, Rule: ac.Rule,
				Upload: strconv.FormatInt(ac.UploadBytes, 10), Download: strconv.FormatInt(ac.DownloadBytes, 10),
				StartedAt: ac.StartedAt,
			})
		}
	}

	cfgHash := ""
	if cfgErr == nil {
		cfgHash = sha256Hex(raw)
	}
	return M{
		"node_id":          s.nodeID(),
		"version":          s.version,
		"engine_build_id":  s.buildID,
		"runtime_epoch":    s.activeEpoch(),
		"config_hash":      cfgHash,
		"config_event_seq": eventSeq,
		"semantic_hash":    semHash,
		"config_external":  extDrift,
		"snapshot":         snap,
		"connections":      conns,
		"connection_after": after,
		"connection_next":  nextSeq,
		"connection_gap":   connGap,
		"connection_more":  connMore,
		"live":             live,
	}, true
}

func (s *Supervisor) PushTelemetryOnce(ctx context.Context) (time.Duration, error) {
	if err := s.ensureRegistered(ctx); err != nil {
		return 5 * time.Second, err
	}
	payload, ok := s.BuildTelemetryPayload()
	if !ok {
		return 2 * time.Second, nil
	}
	resp, err := s.requestJSON(ctx, http.MethodPost, "/api/v1/agent/telemetry", s.token(), payload, 15*time.Second)
	if err != nil {
		return 5 * time.Second, err
	}
	acked := intVal(resp["acked_connection_seq"])
	if acked > 0 {
		s.credMu.Lock()
		if acked > s.ackedConn {
			s.ackedConn = acked
		}
		s.credMu.Unlock()
		s.ledger.AckConnections(acked)
	}
	if boolVal(payload["connection_more"]) {
		return 200 * time.Millisecond, nil
	}
	if ms := intVal(resp["next_interval_ms"]); ms >= 500 && ms <= 30000 {
		return time.Duration(ms) * time.Millisecond, nil
	}
	if intVal(resp["live_subscribers"]) > 0 {
		return 1500 * time.Millisecond, nil
	}
	return 5 * time.Second, nil
}

func (s *Supervisor) PollControlOnce(ctx context.Context, waitSec int) (time.Duration, error) {
	if err := s.ensureRegistered(ctx); err != nil {
		return 3 * time.Second, err
	}
	tok := s.token()
	poll, err := s.requestJSON(ctx, http.MethodGet, fmt.Sprintf("/api/v1/agent/poll?wait=%d", waitSec), tok, nil, time.Duration(waitSec+10)*time.Second)
	if err != nil {
		return 3 * time.Second, err
	}
	cmd := mapVal(poll["command"])
	if len(cmd) == 0 {
		delay := time.Duration(intVal(poll["poll_after_seconds"])) * time.Second
		if delay < 200*time.Millisecond || delay > 10*time.Second {
			delay = 500 * time.Millisecond
		}
		return delay, nil
	}
	cmdID := strVal(cmd["id"])
	req := mapVal(cmd["request"])
	var res M
	var execErr error
	if boolVal(req["stats"]) {
		res, execErr = s.handleStatsRPC(mapVal(req["body"]))
	} else {
		res, execErr = s.HandleRPC(mapVal(req["body"]))
	}
	receiptBody := M{"command_id": cmdID}
	if execErr != nil {
		var fault *RPCFault
		if errors.As(execErr, &fault) {
			receiptBody["error"] = fault
		} else {
			receiptBody["error"] = &RPCFault{Code: "AGENT_EXECUTION_FAILED", Message: execErr.Error()}
		}
	} else {
		if res == nil {
			res = M{}
		}
		receiptBody["result"] = res
	}
	_, _ = s.requestJSON(ctx, http.MethodPost, "/api/v1/agent/receipt", tok, receiptBody, 15*time.Second)
	return 0, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() != nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}

func (s *Supervisor) Run(ctx context.Context) error {
	if err := s.StartInitial(); err != nil {
		return err
	}
	defer s.StopInstance()

	sigCtx, stopSig := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSig()

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		backoff := time.Second
		for {
			if sigCtx.Err() != nil {
				return
			}
			delay, err := s.PollControlOnce(sigCtx, 20)
			if err != nil {
				if sleepCtx(sigCtx, backoff) {
					return
				}
				backoff = min(backoff*2, 15*time.Second)
				continue
			}
			backoff = time.Second
			if sleepCtx(sigCtx, delay) {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			if sigCtx.Err() != nil {
				return
			}
			delay, _ := s.PushTelemetryOnce(sigCtx)
			if sleepCtx(sigCtx, delay) {
				return
			}
		}
	}()

	for {
		select {
		case <-sigCtx.Done():
			wg.Wait()
			return nil
		case <-hupCh:
			s.rpcMu.Lock()
			if raw, cfg, err := s.readDiskConfig(); err == nil {
				if s.reloadInProcessLocked(raw) == nil {
					s.refreshObservationLocked(cfg)
					_ = s.saveStateLocked()
				}
			}
			s.rpcMu.Unlock()
		}
	}
}
