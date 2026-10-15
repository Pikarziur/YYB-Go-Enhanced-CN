package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQingLongDriverReadsLargeLogIndex(t *testing.T) {
	children := make([]qingLongLogEntry, 0, 30000)
	for i := 0; i < cap(children); i++ {
		children = append(children, qingLongLogEntry{Title: strings.Repeat("x", 90), Key: "logs/file.log", Type: "file"})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open/auth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"token": "token", "expiration": 3600}})
		case "/open/logs":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": []qingLongLogEntry{{Title: "large", Key: "large", Type: "directory", Children: children}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	driver := newQingLongDriver(server.URL, "id", "secret", 5*time.Second)
	logs, err := driver.ListLogs(context.Background())
	if err != nil {
		t.Fatalf("ListLogs() error = %v", err)
	}
	if len(logs) != 1 || len(logs[0].Children) != len(children) {
		t.Fatalf("ListLogs() returned %d roots and %d children", len(logs), len(logs[0].Children))
	}
}

func TestQingLongDriverLogDetailUsesCanonicalEndpointOnce(t *testing.T) {
	requestCount := 0
	requestedPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open/auth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"token": "token", "expiration": 3600}})
		case "/open/logs/detail":
			requestCount++
			requestedPath = r.URL.Query().Get("path")
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": "log content"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	driver := newQingLongDriver(server.URL, "id", "secret", 5*time.Second)
	content, err := driver.LogDetail(context.Background(), "logs/task", "2026-08-21.log")
	if err != nil {
		t.Fatalf("LogDetail() error = %v", err)
	}
	if content != "log content" || requestCount != 1 {
		t.Fatalf("LogDetail() content = %q, requests = %d", content, requestCount)
	}
	if requestedPath != "logs/task/2026-08-21.log" {
		t.Fatalf("log detail path = %q", requestedPath)
	}
}

func TestQingLongDriverLogDetailDoesNotRetryFailedRequest(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open/auth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"token": "token", "expiration": 3600}})
		case "/open/logs/detail":
			requestCount++
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte(`{"code":504,"message":"timeout"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	driver := newQingLongDriver(server.URL, "id", "secret", 5*time.Second)
	if _, err := driver.LogDetail(context.Background(), "logs/task", "2026-08-21.log"); err == nil {
		t.Fatal("LogDetail() unexpectedly succeeded")
	}
	if requestCount != 1 {
		t.Fatalf("LogDetail() requests = %d, want 1", requestCount)
	}
}

func TestQingLongDriverRetriesCronWithoutUnsupportedLogName(t *testing.T) {
	var createBodies []map[string]any
	var updateBodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/open/auth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"token": "token", "expiration": 3600}})
		case "/open/crons":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode cron body: %v", err)
			}
			if r.Method == http.MethodPost {
				createBodies = append(createBodies, body)
				if _, exists := body["log_name"]; exists {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"statusCode":400,"error":"Bad Request","message":"Validation failed","validation":{"body":{"keys":["log_name"],"message":"\\\"log_name\\\" is not allowed"}}}`))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": map[string]any{"id": 7, "name": body["name"]}})
				return
			}
			updateBodies = append(updateBodies, body)
			if _, exists := body["log_name"]; exists {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"statusCode":400,"error":"Bad Request","message":"Validation failed","validation":{"body":{"keys":["log_name"],"message":"\\\"log_name\\\" is not allowed"}}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": nil})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	driver := newQingLongDriver(server.URL, "id", "secret", 5*time.Second)
	cron, err := driver.CreateCron(context.Background(), "test", "task test.py", "0 8 * * *", "", "managed-log")
	if err != nil || cron.ID != 7 {
		t.Fatalf("CreateCron() = %+v, %v", cron, err)
	}
	if err := driver.UpdateCron(context.Background(), 7, "test", "task test.py", "0 8 * * *", "", "managed-log"); err != nil {
		t.Fatalf("UpdateCron() error = %v", err)
	}
	if len(createBodies) != 2 || len(updateBodies) != 2 {
		t.Fatalf("retry counts: create=%d update=%d", len(createBodies), len(updateBodies))
	}
	if _, ok := createBodies[1]["log_name"]; ok {
		t.Fatal("retry create still included unsupported log_name")
	}
	if _, ok := updateBodies[1]["log_name"]; ok {
		t.Fatal("retry update still included unsupported log_name")
	}
}
