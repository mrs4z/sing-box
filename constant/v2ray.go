package constant

const (
	V2RayTransportTypeHTTP        = "http"
	V2RayTransportTypeWebsocket   = "ws"
	V2RayTransportTypeQUIC        = "quic"
	V2RayTransportTypeGRPC        = "grpc"
	V2RayTransportTypeHTTPUpgrade = "httpupgrade"
	// XHTTP is Xray's transport, client-side only here: our inbounds are Xray
	// and a CDN in front of them is the point of using it.
	V2RayTransportTypeXHTTP = "xhttp"
)
