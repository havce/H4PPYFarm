package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/havce/H4ppyFarm/log"
	"github.com/havce/H4ppyFarm/sqlite"
)

type SubmitterResponse struct {
	Flag    string `json:"flag"`
	Status  string `json:"status"`
	Message string `json:"msg"`
}

// stripMessage removes the "[<flag>] " prefix that ForcAD prepends to
// its response messages, keeping everything after the first "] ".
func stripMessage(msg string) string {
	if _, after, found := strings.Cut(msg, "] "); found {
		return after
	}
	return msg
}

func ParseResponse(ctx context.Context, flagsMap map[string]sqlite.Flag, obj SubmitterResponse) {
	flag, ok := flagsMap[obj.Flag]

	if !ok {
		return
	}

	message := stripMessage(obj.Message)

	flag.Flag = obj.Flag
	flag.Status = sqlite.StatusFromString(obj.Status)
	flag.SystemMessage = &message
	now := time.Now().Unix()
	flag.SubmissionTimestamp = &now

	if err := flagService.UpdateResult(ctx, &flag); err != nil {
		log.Error(err)
	}
}

func doSend(ctx context.Context, batch []sqlite.Flag) error {
	flagsMap := make(map[string]sqlite.Flag, len(batch))
	arr := make([]string, 0, len(batch))
	for _, b := range batch {
		flagsMap[b.Flag] = b
		arr = append(arr, b.Flag)
	}

	body, err := json.Marshal(arr)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, cfg.SystemURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Team-Token", cfg.TeamToken)

	client := &http.Client{Timeout: time.Duration(cfg.SubmitTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result []SubmitterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	for _, obj := range result {
		ParseResponse(ctx, flagsMap, obj)
	}

	return nil
}

func Send(ctx context.Context) {
	batch, err := flagService.GetPending(ctx)
	if err != nil {
		log.Error(err)
		return
	}

	if len(batch) == 0 {
		return
	}

	if err := doSend(ctx, batch); err != nil {
		log.Error(err)
	}
}

func StartWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(cfg.SubmitPeriod) * time.Second)
	defer ticker.Stop()

	sendOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendOnce(ctx)
		}
	}
}

func sendOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("recovered from panic in worker Send: ", r)
		}
	}()

	Send(ctx)
}
