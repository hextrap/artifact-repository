package blob

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 for S3, implemented on the standard library so
// the binary needs no AWS SDK.

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	// Expires is zero for credentials that don't expire.
	Expires time.Time
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == '~'
}

// uriEncodePath encodes a path the way S3 canonicalizes it: everything but
// unreserved characters and "/" is percent-encoded.
func uriEncodePath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if isUnreserved(c) || c == '/' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// signV4 signs req for S3. Every header already on the request is signed,
// so callers set headers (Range, SSE, ...) before signing. payloadHash is
// the hex SHA-256 of the body.
func signV4(req *http.Request, creds Credentials, region string, now time.Time, payloadHash string) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" {
			continue
		}
		headers[lk] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")

	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{
		req.Method,
		uriEncodePath(path),
		canonicalQuery(req),
		canonHeaders.String(),
		signed,
		payloadHash,
	}, "\n")

	scope := day + "/" + region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])

	key := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, "s3")
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s,SignedHeaders=%s,Signature=%s",
		creds.AccessKeyID, scope, signed, sig))
}

func canonicalQuery(req *http.Request) string {
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, queryEscape(k)+"="+queryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func queryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isUnreserved(s[i]) {
			b.WriteByte(s[i])
		} else {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
	}
	return b.String()
}
