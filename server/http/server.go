package http

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/havce/H4ppyFarm/config"
	"github.com/havce/H4ppyFarm/http/assets"
	"github.com/havce/H4ppyFarm/sqlite"
)

const ShutDownTimeout = time.Second * 5

type Server struct {
	ln     net.Listener
	server *http.Server
	router chi.Router

	HashKey  string
	BlockKey string

	Config      config.Config
	FlagService *sqlite.FlagService
}

func (s *Server) handleApiConfig(w http.ResponseWriter, req *http.Request) {
	v := map[string]any{
		"flagFormat":   s.Config.FlagFormat,
		"flagLifetime": s.Config.FlagLifetime,
		"tickDuration": s.Config.TickDuration,
		"teams":        1, // TODO: Implement teams range in config
	}

	w.Header().Add("Content-Type", "application/json")
	js, err := json.Marshal(v)
	if err != nil {
		return
	}

	fmt.Fprint(w, string(js))
}

func (s *Server) handleApiAuth(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Password string `json:"password"`
	}

	err := json.NewDecoder(req.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if body.Password != s.Config.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleApiFlags(w http.ResponseWriter, req *http.Request) {
	exploit := chi.URLParam(req, "exploit_name")
	fmt.Println(exploit)

	var body struct {
		Flags []string `json:"flags"`
	}

	err := json.NewDecoder(req.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO: insert flags in queue

	w.WriteHeader(http.StatusOK)
}

func NewServer(cfg config.Config, flagService *sqlite.FlagService) (s *Server) {
	s = &Server{
		server:      &http.Server{},
		router:      chi.NewRouter(),
		Config:      cfg,
		FlagService: flagService,
	}

	router := chi.NewRouter()

	router.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.FS(assets.FS))))

	router.Post("/api/flags/{exploit_name}", s.handleApiFlags)
	router.Get("/api/config", s.handleApiConfig)
	router.Post("/api/auth", s.handleApiAuth)

	s.router.Mount("/", router)

	s.server.Handler = s.router

	return
}

// ListenAndServe binds the server to addr and starts serving requests.
func (s *Server) ListenAndServe(addr string) error {
	s.server.Addr = addr
	return s.server.ListenAndServe()
}
