package http

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/havce/H4ppyFarm/config"
	"github.com/havce/H4ppyFarm/http/assets"
	"github.com/havce/H4ppyFarm/log"
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
		"teams":        s.Config.Teams,
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

func (s *Server) handleApiGetFlags(w http.ResponseWriter, req *http.Request) {
	params := req.URL.Query()

	offset, err := strconv.Atoi(params.Get("start"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	count, err := strconv.Atoi(params.Get("count"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if count > 100 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	flags, err := s.FlagService.GetTotPending(req.Context(), offset, count) // ([]Flag, err)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	toReturn := make([]string, 0, len(flags))
	for _, fl := range flags {
		if fl.Flag != "" {
			toReturn = append(toReturn, fl.Flag)
		}
	}

	js, err := json.Marshal(toReturn)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(js))
}

func (s *Server) handleApiFlags(w http.ResponseWriter, req *http.Request) {
	exploit := chi.URLParam(req, "exploit_name")

	var body []struct {
		Flag string  `json:"flag"`
		Ts   float64 `json:"ts"`
	}

	err := json.NewDecoder(req.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Error(err)
		return
	}

	if len(body) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	for _, fl := range body {
		if fl.Flag == "" {
			continue
		}

		err := s.FlagService.Create(req.Context(), &sqlite.Flag{
			Flag:      fl.Flag,
			Exploit:   exploit,
			Status:    0, // TODO: imparare go e capire come fixare l'import
			Timestamp: time.Now().Unix(),
		})

		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

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
	router.Get("/api/flags", s.handleApiGetFlags)
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
