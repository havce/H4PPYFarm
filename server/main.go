package main

import (
	"fmt"

	"github.com/havce/H4ppyFarm/config"
	nethttp "github.com/havce/H4ppyFarm/http"
	"github.com/havce/H4ppyFarm/log"
	"github.com/havce/H4ppyFarm/sqlite"
)

var cfg config.Config
var flagService *sqlite.FlagService

func main() {

	cfg = config.New()

	db := sqlite.NewDB(cfg.Database)
	if err := db.Open(); err != nil {
		log.Fatal(err)
	}
	if err := db.CreateSchema(); err != nil {
		log.Fatal(err)
	}
	flagService = sqlite.NewFlagService(db, cfg.BatchLimit, int64(cfg.FlagLifetime))

	server := nethttp.NewServer(cfg, flagService)

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	log.Info("Running on ", addr)

	if err := server.ListenAndServe(addr); err != nil {
		log.Fatal(err)
	}

}
