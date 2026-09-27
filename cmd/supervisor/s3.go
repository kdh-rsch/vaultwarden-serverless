package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var (
	ErrObjectNotFound = errors.New("s3 object not found (404)")
)

// S3Client is a lightweight, zero-dependency S3-compatible client supporting AWS SigV4.
type S3Client struct {
	Host            string
	BaseURL         string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	HTTPClient      *http.Client
}

// CleanEndpoint parses the raw endpoint string, determining host and protocol.
func CleanEndpoint(raw string) (host, baseURL string) {
	raw = strings.TrimSpace(raw)
	useHTTPS := true
	if strings.HasPrefix(raw, "http://") {
		useHTTPS = false
		raw = strings.TrimPrefix(raw, "http://")
	} else if strings.HasPrefix(raw, "https://") {
		useHTTPS = true
		raw = strings.TrimPrefix(raw, "https://")
	}
	raw = strings.TrimRight(raw, "/")

	if useHTTPS {
		return raw, "https://" + raw
	}
	return raw, "http://" + raw
}

// DetermineRegion infers the S3 region from endpoint or falls back intelligently.
func DetermineRegion(endpoint, explicitRegion string) string {
	if explicitRegion != "" {
		return explicitRegion
	}

	host, _ := CleanEndpoint(endpoint)
	parts := strings.Split(host, ".")

	// Backblaze B2: s3.<region>.backblazeb2.com (e.g. s3.us-west-004.backblazeb2.com -> us-west-004)
	if len(parts) >= 4 && strings.HasSuffix(host, "backblazeb2.com") && parts[0] == "s3" {
		return parts[1]
	}

	// AWS S3: s3.<region>.amazonaws.com
	if len(parts) >= 4 && strings.HasSuffix(host, "amazonaws.com") && parts[0] == "s3" {
		return parts[1]
	}

	// Cloudflare R2
	if strings.Contains(host, "r2.cloudflarestorage.com") {
		return "auto"
	}

	// Default fallback
	return "us-east-1"
}

// NewS3Client creates a new S3 client configured for AWS SigV4.
func NewS3Client(endpoint, explicitRegion, accessKeyID, secretAccessKey string) *S3Client {
	host, baseURL := CleanEndpoint(endpoint)
	region := DetermineRegion(endpoint, explicitRegion)

	return &S3Client{
		Host:            host,
		BaseURL:         baseURL,
		Region:          region,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSigV4Key(secretKey, dateStamp, regionName, serviceName string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(regionName))
	kService := hmacSHA256(kRegion, []byte(serviceName))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// signRequest applies AWS Signature Version 4 to an HTTP request.
func (c *S3Client) signRequest(req *http.Request, payload []byte, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	payloadHash := sha256Hex(payload)

	req.Header.Set("Host", c.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Canonical headers (alphabetically sorted, lowercase)
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		c.Host, payloadHash, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	)

	signingKey := getSigV4Key(c.SecretAccessKey, dateStamp, c.Region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)

	req.Header.Set("Authorization", authHeader)
}

// GetObject downloads an object from S3.
// Returns data and status code. If 404, returns ErrObjectNotFound.
func (c *S3Client) GetObject(ctx context.Context, bucket, key string) ([]byte, int, error) {
	objectPath := path.Clean("/" + bucket + "/" + strings.TrimLeft(key, "/"))
	reqURL := c.BaseURL + objectPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create GET request: %w", err)
	}
	req.Host = c.Host

	c.signRequest(req, nil, time.Now())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to execute GET request to %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, http.StatusNotFound, ErrObjectNotFound
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("GET %s failed with status %d: %s", reqURL, resp.StatusCode, string(body))
	}

	return body, http.StatusOK, nil
}

// PutObject uploads data to S3 at the given bucket and key.
func (c *S3Client) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	objectPath := path.Clean("/" + bucket + "/" + strings.TrimLeft(key, "/"))
	reqURL := c.BaseURL + objectPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create PUT request: %w", err)
	}
	req.Host = c.Host
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	req.Header.Set("Content-Type", "application/octet-stream")

	c.signRequest(req, data, time.Now())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute PUT request to %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT %s failed with status %d: %s", reqURL, resp.StatusCode, string(body))
	}

	return nil
}

// DeleteObject deletes an object from S3.
func (c *S3Client) DeleteObject(ctx context.Context, bucket, key string) error {
	objectPath := path.Clean("/" + bucket + "/" + strings.TrimLeft(key, "/"))
	reqURL := c.BaseURL + objectPath

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create DELETE request: %w", err)
	}
	req.Host = c.Host

	c.signRequest(req, nil, time.Now())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute DELETE request to %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DELETE %s failed with status %d: %s", reqURL, resp.StatusCode, string(body))
	}

	return nil
}

type listObjectsResponse struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated bool `xml:"IsTruncated"`
}

// ListObjectsV2 lists object keys matching a prefix.
func (c *S3Client) ListObjectsV2(ctx context.Context, bucket, prefix string) ([]string, error) {
	canonicalURI := path.Clean("/" + bucket)
	// Query params must be strictly sorted alphabetically for AWS SigV4:
	// 'list-type=2' comes before 'prefix=...'
	rawQuery := "list-type=2"
	if prefix != "" {
		rawQuery += "&prefix=" + url.QueryEscape(prefix)
	}
	reqURL := c.BaseURL + canonicalURI + "?" + rawQuery

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create LIST request: %w", err)
	}
	req.Host = c.Host

	c.signRequest(req, nil, time.Now())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute LIST request to %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LIST request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var res listObjectsResponse
	if err := xml.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to parse LIST XML: %w", err)
	}

	var keys []string
	for _, item := range res.Contents {
		keys = append(keys, item.Key)
	}
	return keys, nil
}

// DeletePrefix deletes all objects under a given prefix.
func (c *S3Client) DeletePrefix(ctx context.Context, bucket, prefix string) (int, error) {
	keys, err := c.ListObjectsV2(ctx, bucket, prefix)
	if err != nil {
		return 0, err
	}

	deletedCount := 0
	for _, k := range keys {
		if err := c.DeleteObject(ctx, bucket, k); err != nil {
			return deletedCount, fmt.Errorf("failed to delete object %q: %w", k, err)
		}
		deletedCount++
	}
	return deletedCount, nil
}
