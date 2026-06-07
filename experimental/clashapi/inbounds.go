package clashapi

import (
	"io"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing/common/json"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// inboundRouter exposes runtime inbound management:
//
//	PUT    /inbounds/{tag}/users        — hot-replace the inbound's user table
//	                                      (body: {"users":[...]} in config shape)
//	DELETE /inbounds/{tag}/connections  — close tracked connections of this
//	                                      inbound; ?user=<name> narrows to one user
//
// Both are no-restart operations: established connections of unaffected
// users keep flowing.
func inboundRouter(inboundManager adapter.InboundManager, trafficManager *trafficontrol.Manager) http.Handler {
	r := chi.NewRouter()
	r.Put("/{tag}/users", updateInboundUsers(inboundManager))
	r.Delete("/{tag}/connections", closeInboundConnections(trafficManager))
	return r
}

type updateUsersRequest struct {
	Users json.RawMessage `json:"users"`
}

func updateInboundUsers(inboundManager adapter.InboundManager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		in, exist := inboundManager.Get(tag)
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}
		managed, ok := in.(adapter.ManagedUsersInbound)
		if !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("inbound does not support user updates: "+tag))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var req updateUsersRequest
		if err = json.Unmarshal(body, &req); err != nil || len(req.Users) == 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("body must be {\"users\": [...]}"))
			return
		}
		if err = managed.UpdateUsersJSON(req.Users); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func closeInboundConnections(trafficManager *trafficontrol.Manager) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		user := r.URL.Query().Get("user")
		closed := 0
		snapshot := trafficManager.Snapshot()
		for _, c := range snapshot.Connections {
			metadata := c.Metadata()
			if metadata.Metadata.Inbound != tag {
				continue
			}
			if user != "" && metadata.Metadata.User != user {
				continue
			}
			c.Close()
			closed++
		}
		render.JSON(w, r, render.M{"closed": closed})
	}
}
