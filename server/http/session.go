package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const sessionCookie = "session"

func sign(secret string, expiry int64) string {
	payload := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return payload + "|" + hex.EncodeToString(mac.Sum(nil))
}

func valid(secret, value string) bool {
	parts := strings.SplitN(value, "|", 2)
	if len(parts) != 2 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expiry < time.Now().Unix() {
		return false
	}
	expected := sign(secret, expiry)
	return hmac.Equal([]byte(value), []byte(expected))
}
