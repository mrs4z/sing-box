package trojan

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
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TrojanInboundOptions](registry, C.TypeTrojan, NewInbound)
}

var (
	_ adapter.TCPInjectableInbound = (*Inbound)(nil)
	_ adapter.ManagedUsersInbound  = (*Inbound)(nil)
)

// userEntry holds a user's options together with its rate limiter. Entries
// are keyed by a stable numeric ID that survives UpdateUsers calls (the same
// password keeps the same ID), so connections authenticated against an older
// user table still resolve to the right entry.
type userEntry struct {
	user    option.TrojanUser
	limiter *ratelimit.Limiter
}

type Inbound struct {
	inbound.Adapter
	router                   adapter.ConnectionRouterEx
	logger                   log.ContextLogger
	listener                 *listener.Listener
	service                  *trojan.Service[int]
	tlsConfig                tls.ServerConfig
	fallbackAddr             M.Socksaddr
	fallbackAddrTLSNextProto map[string]M.Socksaddr
	transport                adapter.V2RayServerTransport

	// Hot-updatable user state — see UpdateUsers.
	userAccess  sync.RWMutex
	userEntries map[int]*userEntry
	userIDByKey map[string]int // password → stable ID
	nextUserID  int
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter:     inbound.NewAdapter(C.TypeTrojan, tag),
		router:      router,
		logger:      logger,
		userEntries: make(map[int]*userEntry),
		userIDByKey: make(map[string]int),
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled,
		})
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	var fallbackHandler N.TCPConnectionHandlerEx
	if options.Fallback != nil && options.Fallback.Server != "" || len(options.FallbackForALPN) > 0 {
		if options.Fallback != nil && options.Fallback.Server != "" {
			inbound.fallbackAddr = options.Fallback.Build()
			if !inbound.fallbackAddr.IsValid() {
				return nil, E.New("invalid fallback address: ", inbound.fallbackAddr)
			}
		}
		if len(options.FallbackForALPN) > 0 {
			if inbound.tlsConfig == nil {
				return nil, E.New("fallback for ALPN is not supported without TLS")
			}
			fallbackAddrNextProto := make(map[string]M.Socksaddr)
			for nextProto, destination := range options.FallbackForALPN {
				fallbackAddr := destination.Build()
				if !fallbackAddr.IsValid() {
					return nil, E.New("invalid fallback address for ALPN ", nextProto, ": ", fallbackAddr)
				}
				fallbackAddrNextProto[nextProto] = fallbackAddr
			}
			inbound.fallbackAddrTLSNextProto = fallbackAddrNextProto
		}
		fallbackHandler = adapter.NewUpstreamContextHandlerEx(inbound.fallbackConnection, nil)
	}
	service := trojan.NewService[int](adapter.NewUpstreamContextHandlerEx(inbound.newConnection, inbound.newPacketConnection), fallbackHandler, logger)
	ids, passwords := inbound.applyUsersLocked(options.Users)
	err := service.UpdateUsers(ids, passwords)
	if err != nil {
		return nil, err
	}
	if options.Transport != nil {
		inbound.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), inbound.tlsConfig, (*inboundTransportHandler)(inbound))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	inbound.service = service
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
// instances for users that persist (matched by password), and returns the
// parallel slices for service.UpdateUsers. Caller must hold userAccess for
// writing (or have exclusive access during construction).
func (h *Inbound) applyUsersLocked(users []option.TrojanUser) (ids []int, passwords []string) {
	newEntries := make(map[int]*userEntry, len(users))
	newIDs := make(map[string]int, len(users))
	for _, user := range users {
		if _, dup := newIDs[user.Password]; dup {
			h.logger.Warn("duplicate user password ignored for user: ", user.Name)
			continue
		}
		id, exists := h.userIDByKey[user.Password]
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
		newIDs[user.Password] = id
		ids = append(ids, id)
		passwords = append(passwords, user.Password)
	}
	h.userEntries = newEntries
	h.userIDByKey = newIDs
	return
}

// UpdateUsers atomically replaces the inbound's user table at runtime — no
// restart, established connections of persisting users are untouched.
// Removed users only lose the ability to open NEW connections; close their
// existing ones via the Clash API connections endpoint if required.
func (h *Inbound) UpdateUsers(users []option.TrojanUser) error {
	h.userAccess.Lock()
	ids, passwords := h.applyUsersLocked(users)
	h.userAccess.Unlock()
	err := h.service.UpdateUsers(ids, passwords)
	if err != nil {
		return err
	}
	h.logger.Info("hot-updated user table: ", len(ids), " users")
	return nil
}

// UpdateUsersJSON implements adapter.ManagedUsersInbound.
func (h *Inbound) UpdateUsersJSON(data []byte) error {
	var users []option.TrojanUser
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
			return E.Cause(err, "create TLS config")
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

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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

func (h *Inbound) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
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
	h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) fallbackConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var fallbackAddr M.Socksaddr
	if len(h.fallbackAddrTLSNextProto) > 0 {
		if tlsConn, loaded := common.Cast[tls.Conn](conn); loaded {
			connectionState := tlsConn.ConnectionState()
			if connectionState.NegotiatedProtocol != "" {
				if fallbackAddr, loaded = h.fallbackAddrTLSNextProto[connectionState.NegotiatedProtocol]; !loaded {
					h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled for ALPN: ", connectionState.NegotiatedProtocol)
					N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
					return
				}
			}
		}
	}
	if !fallbackAddr.IsValid() {
		if !h.fallbackAddr.IsValid() {
			h.logger.DebugContext(ctx, "process connection from ", metadata.Source, ": fallback disabled by default")
			N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
			return
		}
		fallbackAddr = h.fallbackAddr
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = fallbackAddr
	h.logger.InfoContext(ctx, "fallback connection to ", fallbackAddr)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
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
