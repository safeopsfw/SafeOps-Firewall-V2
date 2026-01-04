package injector

import (
	"fmt"

	"tls_proxy/internal/packet"
)

// HTTPRedirectInjector creates HTTP 302 redirect responses
type HTTPRedirectInjector struct {
	redirectURL string
}

// NewHTTPRedirectInjector creates a new HTTP redirect injector
func NewHTTPRedirectInjector(redirectURL string) *HTTPRedirectInjector {
	return &HTTPRedirectInjector{
		redirectURL: redirectURL,
	}
}

// BuildHTTP302Redirect creates an HTTP 302 redirect response packet
func (i *HTTPRedirectInjector) BuildHTTP302Redirect(info *packet.PacketInfo) ([]byte, error) {
	// Build HTTP 302 Found response
	response := fmt.Sprintf(
		"HTTP/1.1 302 Found\r\n"+
			"Location: %s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"Cache-Control: no-cache, no-store, must-revalidate\r\n"+
			"Pragma: no-cache\r\n"+
			"Expires: 0\r\n"+
			"\r\n"+
			"%s",
		i.redirectURL,
		len(buildRedirectHTML(i.redirectURL)),
		buildRedirectHTML(i.redirectURL),
	)

	return []byte(response), nil
}

// buildRedirectHTML creates a simple HTML page for redirect
func buildRedirectHTML(redirectURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="0;url=%s">
</head>
<body>
    <p>Redirecting to SafeOps Captive Portal...</p>
    <p>If you are not redirected, <a href="%s">click here</a>.</p>
</body>
</html>`, redirectURL, redirectURL)
}

// BuildHTTP403Blocked creates an HTTP 403 Forbidden response
func (i *HTTPRedirectInjector) BuildHTTP403Blocked(info *packet.PacketInfo, reason string) ([]byte, error) {
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Access Blocked</title>
</head>
<body>
    <h1>Access Blocked</h1>
    <p>%s</p>
</body>
</html>`, reason)

	response := fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"Cache-Control: no-cache\r\n"+
			"\r\n"+
			"%s",
		len(body),
		body,
	)

	return []byte(response), nil
}

// UpdateRedirectURL updates the captive portal URL
func (i *HTTPRedirectInjector) UpdateRedirectURL(url string) {
	i.redirectURL = url
}

// GetRedirectURL returns the current redirect URL
func (i *HTTPRedirectInjector) GetRedirectURL() string {
	return i.redirectURL
}
