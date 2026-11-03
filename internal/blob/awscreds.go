package blob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

type CredentialsProvider interface {
	Retrieve(ctx context.Context) (Credentials, error)
}

type StaticCredentials Credentials

func (s StaticCredentials) Retrieve(context.Context) (Credentials, error) { return Credentials(s), nil }

// DefaultCredentials finds AWS credentials the way AWS tools do, in order:
// AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN, then the ECS
// task role (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or _FULL_URI).
func DefaultCredentials(client *http.Client, now func() time.Time) (CredentialsProvider, error) {
	if id, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); id != "" && secret != "" {
		return StaticCredentials{AccessKeyID: id, SecretAccessKey: secret, SessionToken: os.Getenv("AWS_SESSION_TOKEN")}, nil
	}
	var url string
	if rel := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
		url = "http://169.254.170.2" + rel
	} else if full := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full != "" {
		url = full
	}
	if url != "" {
		return &cachedCredentials{now: now, src: &ecsCredentials{
			client: client, url: url, token: os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"),
		}}, nil
	}
	return nil, errors.New("no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or run on ECS with a task role")
}

// ecsCredentials fetches task-role credentials from the ECS agent.
type ecsCredentials struct {
	client *http.Client
	url    string
	token  string
}

func (e *ecsCredentials) Retrieve(ctx context.Context) (Credentials, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url, nil)
	if err != nil {
		return Credentials{}, err
	}
	if e.token != "" {
		req.Header.Set("Authorization", e.token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return Credentials{}, fmt.Errorf("fetching ECS credentials: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Credentials{}, fmt.Errorf("fetching ECS credentials: %s", resp.Status)
	}
	var body struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Expiration      time.Time
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return Credentials{}, fmt.Errorf("decoding ECS credentials: %w", err)
	}
	if body.AccessKeyID == "" || body.SecretAccessKey == "" {
		return Credentials{}, errors.New("ECS credentials response is missing keys")
	}
	return Credentials{AccessKeyID: body.AccessKeyID, SecretAccessKey: body.SecretAccessKey,
		SessionToken: body.Token, Expires: body.Expiration}, nil
}

// refreshBefore renews temporary credentials this long before they expire.
const refreshBefore = 5 * time.Minute

type cachedCredentials struct {
	src  CredentialsProvider
	now  func() time.Time
	mu   sync.Mutex
	cur  Credentials
	have bool
}

func (c *cachedCredentials) Retrieve(ctx context.Context) (Credentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.have && (c.cur.Expires.IsZero() || c.now().Before(c.cur.Expires.Add(-refreshBefore))) {
		return c.cur, nil
	}
	creds, err := c.src.Retrieve(ctx)
	if err != nil {
		c.have = false
		return Credentials{}, err
	}
	c.cur, c.have = creds, true
	return creds, nil
}
