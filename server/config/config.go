package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"

	"github.com/havce/H4ppyFarm/log"
	"golang.org/x/crypto/bcrypt"
)

type ConfigValue struct {
	String *string
	Int    *int
}

type Config struct {
	Address       string
	Port          int
	Password      string
	Teams         int
	TeamToken     string
	FlagLifetime  int
	TickDuration  int
	SubmitPeriod  int
	SubmitTimeout int
	BatchLimit    int
	Database      string
	SystemType    string
	SystemURL     string
	SecretKey     string
	FlagFormat    string
	HFISource     string
	HFICache      string
}

var defaults = Config{
	Address:       "0.0.0.0",
	Port:          6969,
	Password:      "",
	Teams:         10,
	TeamToken:     "",
	FlagLifetime:  5,
	TickDuration:  120,
	SubmitPeriod:  10,
	SubmitTimeout: 10,
	BatchLimit:    1000,
	Database:      ":memory:",
	SystemType:    "forcad",
	FlagFormat:    "[A-Z0-9]{31}=",
	HFISource:     "../hfi",
	HFICache:      "../hfi-cache",
}

func New() Config {

	cfg := defaults

	cfg.Address = getStringConfigValue("ADDRESS", defaults.Address)
	cfg.Port = getIntConfigValue("PORT", defaults.Port)

	pass := getStringConfigValue("PASSWORD", defaults.Password)
	log.Ensure(pass != "", "Inserisci una password.")
	serverPassword, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Password inserita non valida")
	}
	cfg.Password = string(serverPassword)

	cfg.Teams = getIntConfigValue("TEAMS", defaults.Teams)
	cfg.TeamToken = getStringConfigValue("TEAM_TOKEN", defaults.TeamToken)
	cfg.FlagLifetime = getIntConfigValue("FLAG_LIFETIME", defaults.FlagLifetime)
	cfg.TickDuration = getIntConfigValue("TICK_DURATION", defaults.TickDuration)
	cfg.SubmitPeriod = getIntConfigValue("SUBMIT_PERIOD", defaults.SubmitPeriod)
	cfg.SubmitTimeout = getIntConfigValue("SUBMIT_TIMEOUT", defaults.SubmitTimeout)
	cfg.BatchLimit = getIntConfigValue("BATCH_LIMIT", defaults.BatchLimit)
	cfg.Database = getStringConfigValue("DATABASE", defaults.Database)
	cfg.SystemType = getStringConfigValue("SYSTEM_TYPE", defaults.SystemType)
	cfg.SystemURL = getStringConfigValue("SYSTEM_URL", defaults.SystemURL)
	cfg.FlagFormat = getStringConfigValue("FLAG_FORMAT", defaults.FlagFormat)
	cfg.HFISource = getStringConfigValue("HFI_SOURCE", defaults.HFISource)
	cfg.HFICache = getStringConfigValue("HFI_CACHE", defaults.HFICache)
	cfg.SecretKey = getStringConfigValue("SECRET_KEY", RandomHex(32))

	return cfg
}

func getStringConfigValue(key string, def string) string {
	key = "FARM_" + strings.ToUpper(key)

	val, ret := os.LookupEnv(key)
	if !ret {
		return def
	}

	return val
}

func getIntConfigValue(key string, def int) int {
	key = "FARM_" + strings.ToUpper(key)

	buff, ret := os.LookupEnv(key)
	if !ret {
		return def
	}

	val, err := strconv.Atoi(buff)
	if err != nil {
		return def
	}

	return val
}

func RandomHex(n int) string {
	b := make([]byte, (n+1)/2)

	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)[:n]
}
