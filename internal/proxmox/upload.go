package proxmox

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"time"
)

// Upload streams a file to a node's storage (content iso or vztmpl). The
// file isn't held in memory: the multipart body is written as it's sent.
func (c *Client) Upload(ctx context.Context, node, storage, content, filename string, size int64, body io.Reader) (string, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		err := func() error {
			if err := mw.WriteField("content", content); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("filename", filename)
			if err != nil {
				return err
			}
			if _, err := io.Copy(part, body); err != nil {
				return err
			}
			return mw.Close()
		}()
		pw.CloseWithError(err)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/nodes/"+url.PathEscape(node)+"/storage/"+url.PathEscape(storage)+"/upload", pr)
	if err != nil {
		pr.Close()
		return "", err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// An upload takes as long as it takes: only the context limits it.
	hc := *c.http
	hc.Timeout = 6 * time.Hour
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body = io.NopCloser(resp.Body)
	var out any
	cl := &Client{base: c.base, auth: c.auth, http: &hc, cfg: c.cfg}
	if err := cl.decode(resp, &out); err != nil {
		return "", err
	}
	if s, ok := out.(string); ok {
		return s, nil
	}
	return "", nil
}
