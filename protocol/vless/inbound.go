package vless

import (
	"context"
	"net"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/ratelimit"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.VLESSInboundOptions](registry, C.TypeVLESS, NewInbound)
}

var (
	_ adapter.TCPInjectableInbound = (*Inbound)(nil)
	_ adapter.ManagedUsersInbound  = (*Inbound)(nil)
)

// userEntry holds a user's options together with its rate limiter. Entries
// are keyed by a stable numeric ID that survives UpdateUsers calls (the same
// UUID keeps the same ID), so connections authenticated against an older
// user table still resolve to the right entry.
type userEntry struct {
	user    option.VLESSUser
	limiter *ratelimit.Limiter
}

type Inbound struct {
	inbound.Adapter
	ctx       context.Context
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	service   *vless.Service[int]
	tlsConfig tls.ServerConfig
	transport adapter.V2RayServerTransport

	// Hot-updatable user state — see UpdateUsers.
	userAccess  sync.RWMutex
	userEntries map[int]*userEntry
	userIDByKey map[string]int // UUID → stable ID
	nextUserID  int
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter:     inbound.NewAdapter(C.TypeVLESS, tag),
		ctx:         ctx,
		router:      uot.NewRouter(router, logger),
		logger:      logger,
		userEntries: make(map[int]*userEntry),
		userIDByKey: make(map[string]int),
	}
	var err error
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	service := vless.NewService[int](logger, adapter.NewUpstreamContextHandlerEx(inbound.newConnectionEx, inbound.newPacketConnectionEx))
	ids, uuids, flows := inbound.applyUsersLocked(options.Users)
	service.UpdateUsers(ids, uuids, flows)
	inbound.service = service
	if options.TLS != nil {
		inbound.tlsConfig, err = tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			// Users can be hot-added at runtime (UpdateUsers) with flows
			// unknown at construction time, so KTLS is only enabled when the
			// initial set is non-empty and flow-free.
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled &&
				len(options.Users) > 0 &&
				common.All(options.Users, func(it option.VLESSUser) bool {
					return it.Flow == ""
				}),
		})
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		inbound.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), inbound.tlsConfig, (*inboundTransportHandler)(inbound))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

// applyUsersLocked replaces the user table, reusing stable IDs and limiter
// instances for users that persist (matched by UUID), and returns the
// parallel slices for service.UpdateUsers. Caller must hold userAccess for
// writing (or have exclusive access during construction).
func (h *Inbound) applyUsersLocked(users []option.VLESSUser) (ids []int, uuids []string, flows []string) {
	newEntries := make(map[int]*userEntry, len(users))
	newIDs := make(map[string]int, len(users))
	for _, user := range users {
		if _, dup := newIDs[user.UUID]; dup {
			h.logger.Warn("duplicate user UUID ignored: ", user.UUID)
			continue
		}
		id, exists := h.userIDByKey[user.UUID]
		var limiter *ratelimit.Limiter
		if exists {
			if old := h.userEntries[id]; old != nil {
				limiter = old.limiter
			}
		} else {
			id = h.nextUserID
			h.nextUserID++
		}
		if user.SpeedLimit > 0 {
			if limiter != nil {
				// Reuse the limiter so already-established connections pick
				// up the new rate live.
				limiter.SetRate(user.SpeedLimit)
			} else {
				limiter = ratelimit.NewLimiter(user.SpeedLimit)
			}
		} else {
			limiter = nil
		}
		newEntries[id] = &userEntry{user: user, limiter: limiter}
		newIDs[user.UUID] = id
		ids = append(ids, id)
		uuids = append(uuids, user.UUID)
		flows = append(flows, user.Flow)
	}
	h.userEntries = newEntries
	h.userIDByKey = newIDs
	return
}

// UpdateUsers atomically replaces the inbound's user table at runtime — no
// restart, established connections of persisting users are untouched.
// Removed users only lose the ability to open NEW connections; close their
// existing ones via the Clash API connections endpoint if required.
func (h *Inbound) UpdateUsers(users []option.VLESSUser) error {
	h.userAccess.Lock()
	ids, uuids, flows := h.applyUsersLocked(users)
	h.userAccess.Unlock()
	h.service.UpdateUsers(ids, uuids, flows)
	h.logger.Info("hot-updated user table: ", len(ids), " users")
	return nil
}

// UpdateUsersJSON implements adapter.ManagedUsersInbound.
func (h *Inbound) UpdateUsersJSON(data []byte) error {
	var users []option.VLESSUser
	if err := json.Unmarshal(data, &users); err != nil {
		return E.Cause(err, "decode users")
	}
	return h.UpdateUsers(users)
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	if h.transport == nil {
		return h.listener.Start()
	}
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.Serve(tcpListener)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	if common.Contains(h.transport.Network(), N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.ServePacket(udpConn)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	return nil
}

func (h *Inbound) Close() error {
	return common.Close(
		h.service,
		h.listener,
		h.tlsConfig,
		h.transport,
	)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil && h.transport == nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func (h *Inbound) newConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	h.userAccess.RLock()
	entry := h.userEntries[userIndex]
	h.userAccess.RUnlock()
	if entry == nil {
		// User was removed between auth and dispatch.
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := entry.user.Name
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)

	// Apply per-user rate limiting if configured
	if entry.limiter != nil {
		destHost := metadata.Destination.Fqdn
		allowedHosts := entry.user.AllowedHosts
		conn = ratelimit.NewLimitedConn(conn, entry.limiter, destHost, func(host string) bool {
			for _, ah := range allowedHosts {
				if host == ah {
					return true
				}
			}
			return false
		})
	}

	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIndex, loaded := auth.UserFromContext[int](ctx)
	if !loaded {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	h.userAccess.RLock()
	entry := h.userEntries[userIndex]
	h.userAccess.RUnlock()
	if entry == nil {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
		return
	}
	user := entry.user.Name
	if user == "" {
		user = F.ToString(userIndex)
	} else {
		metadata.User = user
	}
	if metadata.Destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		metadata.Destination = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), metadata.Destination)
		h.logger.InfoContext(ctx, "[", user, "] inbound packet addr connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}

	// Note: packet connections (UDP) are not rate-limited — rate limiting TCP is sufficient
	// for traffic enforcement since most bandwidth-heavy traffic is TCP (streams, downloads).
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

var _ adapter.V2RayServerTransportHandler = (*inboundTransportHandler)(nil)

type inboundTransportHandler Inbound

func (h *inboundTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	h.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	(*Inbound)(h).NewConnectionEx(ctx, conn, metadata, onClose)
}
