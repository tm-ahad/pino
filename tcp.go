package pino

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func (res *Response) TcpResponse() []byte {
	if res.Stream {
		return []byte{}
	}

	var tcpHeader bytes.Buffer

	for key, header := range res.Headers {
		for _, value := range header {
			tcpHeader.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	for _, cookie := range res.Cookies {
		var cookieHeader strings.Builder
		cookieHeader.WriteString(fmt.Sprintf("%s=%s; Path=%s; ", cookie.name, cookie.value, cookie.Path))

		if cookie.HttpOnly {cookieHeader.WriteString("HttpOnly; ")}
		if cookie.Secure {cookieHeader.WriteString("Secure; ")}
		
		if !cookie.Expire.IsZero() {
			cookieHeader.WriteString(fmt.Sprintf("Expires=%s; ", cookie.Expire.Format(time.RFC1123)))
		}

		tcpHeader.WriteString(fmt.Sprintf("Set-Cookie: %s\r\n", cookieHeader.String()))
	}

	var tcpResponse bytes.Buffer
	tcpResponse.WriteString(fmt.Sprintf("%s %d %s\r\n", res.Protocol, res.Status, res.StatusMsg))
	tcpResponse.Write(tcpHeader.Bytes())
	tcpResponse.Write([]byte("\r\n"))
	tcpResponse.Write(res.Body)

	return tcpResponse.Bytes()
}


func (req *Request) Parse(raw string, conn net.Conn) {
	lines := strings.Split(raw, "\n")
	requestLine := strings.Fields(lines[0])
	req.conn = conn;

	if len(requestLine) >= 3 {
		req.Method = parseMethod(requestLine[0])
		req.Url = requestLine[1]
		req.Protocol = requestLine[2]

		index := strings.LastIndex(requestLine[1], "?")

		RawQueries := requestLine[1][index+1:]
		Queries := strings.Split(RawQueries, "&")

		req.Query = map[string]string{}
		for _, query := range Queries {
			split := strings.Split(query, "=")

			if len(split) > 1 {
				req.Query[split[0]] = split[1]
			}
		}
	}

	req.Headers = http.Header{}
	for _, line := range lines[1:] {
		if line == "\r" || line == "" {
			break
		}

		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			req.Headers.Add(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
		}
	}
}