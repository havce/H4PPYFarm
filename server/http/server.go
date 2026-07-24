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
	"github.com/havce/H4ppyFarm/http/html"
	"github.com/havce/H4ppyFarm/log"
	"github.com/havce/H4ppyFarm/sqlite"
	"golang.org/x/crypto/bcrypt"
)

const ScriptPath = "./client/start_sploit.py"

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

	err = bcrypt.CompareHashAndPassword(
		[]byte(body.Password),
		[]byte(s.Config.Password),
	)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Error("invalid password")
		return
	}

	expiry := time.Now().Add(24 * time.Hour).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sign(s.HashKey, expiry),
		Path:     "/",
		Expires:  time.Unix(expiry, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleApiGetFlags(w http.ResponseWriter, req *http.Request) {
	params := req.URL.Query()

	offset, err := strconv.Atoi(params.Get("start"))
	if err != nil {
		offset = 0
	}

	count, err := strconv.Atoi(params.Get("count"))
	if err != nil {
		count = 10
	}

	if count > 100 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	flags, err := s.FlagService.GetFlags(req.Context(), offset, count) // ([]Flag, err)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	js, err := json.Marshal(flags)
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

		tm := fl.Ts
		if tm == 0 {
			tm = float64(time.Now().Unix())
		}

		err := s.FlagService.Create(req.Context(), &sqlite.Flag{
			Flag:      fl.Flag,
			Exploit:   exploit,
			Status:    0, // TODO: imparare go e capire come fixare l'import
			Timestamp: tm,
		})

		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePage(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		page, err := html.FS.ReadFile(name)
		if err != nil {
			log.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	}
}

func (s *Server) handleScript(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/x-python")
	w.Header().Set("Content-Disposition", `attachment; filename="start_sploit.py"`)
	http.ServeFile(w, req, ScriptPath)
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, err := req.Cookie(sessionCookie)
		if err != nil || !valid(s.HashKey, c.Value) {
			http.Redirect(w, req, "/auth", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (s *Server) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info("-> %s %s", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)

		log.Info("<- HTTP ", r.Response.Status)
	})
}

func NewServer(cfg config.Config, flagService *sqlite.FlagService) (s *Server) {
	s = &Server{
		server:      &http.Server{},
		router:      chi.NewRouter(),
		Config:      cfg,
		HashKey:     config.RandomHex(32),
		FlagService: flagService,
	}

	router := chi.NewRouter()

	router.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.FS(assets.FS))))

	router.Get("/", s.handlePage("index.html"))
	router.Get("/auth", s.handlePage("auth.html"))
	router.Post("/api/auth", s.handleApiAuth)

	router.Group(func(r chi.Router) {
		r.Use(s.Logger)
		r.Use(s.requireAuth)
		r.Get("/", s.handlePage("index.html"))
		r.Get("/api/flags", s.handleApiGetFlags)
		r.Get("/api/config", s.handleApiConfig)
		r.Post("/api/flags/{exploit_name}", s.handleApiFlags)
		r.Put("/api/flags/{exploit_name}", s.handleApiFlags)
		r.Get("/script", s.handleScript)
	})

	s.router.Mount("/", router)

	s.server.Handler = s.router

	return
}

func (s *Server) ListenAndServe(addr string) error {
	s.server.Addr = addr
	return s.server.ListenAndServe()
}
