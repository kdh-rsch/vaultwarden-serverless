package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestDetermineRegion(t *testing.T) {
	tests := []struct {
		endpoint string
		explicit string
		expected string
	}{
		{"s3.us-west-004.backblazeb2.com", "", "us-west-004"},
		{"s3.eu-central-003.backblazeb2.com", "", "eu-central-003"},
		{"s3.us-east-2.amazonaws.com", "", "us-east-2"},
		{"https://abc12345.r2.cloudflarestorage.com", "", "auto"},
		{"minio.example.com", "", "us-east-1"},
		{"s3.us-west-004.backblazeb2.com", "custom-region", "custom-region"},
	}

	for _, tt := range tests {
		got := DetermineRegion(tt.endpoint, tt.explicit)
		if got != tt.expected {
			t.Errorf("DetermineRegion(%q, %q) = %q, expected %q", tt.endpoint, tt.explicit, got, tt.expected)
		}
	}
}

func TestCleanEndpoint(t *testing.T) {
	host, baseURL := CleanEndpoint("https://s3.us-west-004.backblazeb2.com/")
	if host != "s3.us-west-004.backblazeb2.com" {
		t.Errorf("expected host s3.us-west-004.backblazeb2.com, got %s", host)
	}
	if baseURL != "https://s3.us-west-004.backblazeb2.com" {
		t.Errorf("expected baseURL https://s3.us-west-004.backblazeb2.com, got %s", baseURL)
	}

	hostHTTP, baseURLHTTP := CleanEndpoint("http://localhost:9000")
	if hostHTTP != "localhost:9000" || baseURLHTTP != "http://localhost:9000" {
		t.Errorf("unexpected HTTP endpoint parse: host=%s, base=%s", hostHTTP, baseURLHTTP)
	}
}

func TestS3Client_PutAndGetWithSigV4(t *testing.T) {
	var mu sync.Mutex
	storage := make(map[string][]byte)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify AWS SigV4 Headers (In Go's http server, Host header is in r.Host)
		if r.Host == "" {
			t.Errorf("missing Host header in request")
		}
		if r.Header.Get("X-Amz-Date") == "" {
			t.Errorf("missing X-Amz-Date header in request")
		}
		if r.Header.Get("X-Amz-Content-Sha256") == "" {
			t.Errorf("missing X-Amz-Content-Sha256 header in request")
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") {
			t.Errorf("invalid or missing Authorization header: %s", auth)
		}

		path := r.URL.Path

		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			storage[path] = body
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			data, ok := storage[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		case http.MethodDelete:
			delete(storage, path)
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client := NewS3Client(server.URL, "us-east-1", "test-key-id", "test-secret-key")
	ctx := context.Background()

	bucket := "test-bucket"
	key := "vaultwarden/rsa_key.pem.enc"
	payload := []byte("encrypted-binary-rsa-data")

	// 1. GetObject before Put should return ErrObjectNotFound
	_, status, err := client.GetObject(ctx, bucket, key)
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound, got err=%v (status=%d)", err, status)
	}

	// 2. PutObject should succeed
	if err := client.PutObject(ctx, bucket, key, payload); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// 3. GetObject after Put should return the payload
	gotData, status, err := client.GetObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	if string(gotData) != string(payload) {
		t.Errorf("expected payload %q, got %q", string(payload), string(gotData))
	}

	// 4. DeleteObject should remove the object
	if err := client.DeleteObject(ctx, bucket, key); err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	// 5. GetObject after Delete should return ErrObjectNotFound
	_, _, err = client.GetObject(ctx, bucket, key)
	if !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("expected ErrObjectNotFound after deletion, got %v", err)
	}
}

func TestS3Client_ListObjectsV2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>test-bucket</Name>
    <Prefix>vaultwarden/</Prefix>
    <KeyCount>2</KeyCount>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>vaultwarden/rsa_key.pem.enc</Key>
        <Size>1234</Size>
    </Contents>
    <Contents>
        <Key>vaultwarden/test.db</Key>
        <Size>5678</Size>
    </Contents>
</ListBucketResult>`))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	client := NewS3Client(server.URL, "us-east-1", "test-key-id", "test-secret-key")
	keys, err := client.ListObjectsV2(context.Background(), "test-bucket", "vaultwarden/")
	if err != nil {
		t.Fatalf("ListObjectsV2 failed: %v", err)
	}

	if len(keys) != 2 || keys[0] != "vaultwarden/rsa_key.pem.enc" || keys[1] != "vaultwarden/test.db" {
		t.Errorf("unexpected keys returned: %v", keys)
	}
}

