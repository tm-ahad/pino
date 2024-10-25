package pino

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
)

const ChunkSize uint = 32768;

type Status uint16

var ExtentionCTMap map[string]string = map[string]string{
	"html":  "text/html",
	"htm":   "text/html",
	"css":   "text/css",
	"js":    "application/javascript",
	"json":  "application/json",
	"xml":   "application/xml",
	"jpg":   "image/jpeg",
	"jpeg":  "image/jpeg",
	"png":   "image/png",
	"gif":   "image/gif",
	"svg":   "image/svg+xml",
	"txt":   "text/plain",
	"pdf":   "application/pdf",
	"zip":   "application/zip",
	"tar":   "application/x-tar",
	"mp3":   "audio/mpeg",
	"mp4":   "video/mp4",
	"mpeg":  "video/mpeg",
	"avi":   "video/x-msvideo",
	"wav":   "audio/wav",
	"ico":   "image/x-icon",
	"webp":  "image/webp",
	"woff":  "font/woff",
	"woff2": "font/woff2",
	"ttf":   "font/ttf",
	"otf":   "font/otf",
	"csv":   "text/csv",
	"bmp":   "image/bmp",
	"apk":   "application/vnd.android.package-archive",
	"exe":   "application/octet-stream",
}

func GetContentType(extension string) string {
	val := ExtentionCTMap[extension]

	if len(val) == 0 {
		return "text/plain"
	} else {
		return val;
	}
}

func startsWithSubarray(arr, subarr []string) bool {
    if len(subarr) > len(arr) {
        return false
    }

    for i := 0; i < len(subarr); i++ {
        if arr[i] != subarr[i] {
            return false
        }
    }
    return true
}

type Method uint8

const (
	GET Method = iota
	POST
	DELETE
	PUT
	OPTIONS
)

type Cookie struct {
	name     string
	value    string
	HttpOnly bool
	Secure   bool
	Expire   time.Time
	Path     string
	Domain   string
}

type Request struct {
	Headers       http.Header
	Query         map[string]string
	Cookies       map[string]string
	conn 	  	  net.Conn
	Method        Method
	ContentType   string
	Authorization string
	Protocol      string
	Body          string
	Host          string
	Url           string
}

type Response struct {
	Headers   http.Header
	Cookies   map[string]Cookie
	Status    Status
	Protocol  string
	StatusMsg string
	Body      []byte
	Stream 	  bool
}

type Handler func(ctx *Request) Response

type Route struct {
	handler Handler
	method  Method
	Path 	string
	Use  	bool
}

type Pino struct {
	NotFoundHandler Handler
	Listener  		net.Listener
	WaitGroup 		sync.WaitGroup
	StopChan  		chan os.Signal
	FileCache 		map[string][]byte
	Routes    		[]Route
	Port      		uint16
	Host      		string
}

type Cors struct {
	Origins []string
	Methods []Method
	Headers []string
	Path    string
	MaxAge	uint64
}

func (res *Response) CompressBody() {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	defer gz.Close()

	gz.Write([]byte(res.Body))
	res.Body = b.Bytes()

	res.Headers.Add("Content-Encoding", "gzip")
}

func parseMethod(method string) Method {
	switch method {
	case "GET":    	return GET
	case "POST":   	return POST
	case "PUT":	   	return PUT
	case "DELETE": 	return DELETE
	case "OPTIONS": return OPTIONS
	default:	   	return GET
	}
}

func (method Method) toString() string {
	switch method {
	case GET:     return "GET"
	case POST:    return "POST"
	case PUT: 	  return "PUT"
	case DELETE:  return "DELETE"
	case OPTIONS: return "OPTIONS"
	}

	return "GO GET A GIRL."
}

func NewPino(host string, port uint16) Pino {
	return Pino{
		Host: host,
		Port: uint16(port),
		FileCache: map[string][]byte{},
		NotFoundHandler: func(req *Request) Response {
			return Text("Route not found", 404)
		},
	}
}

func (server *Pino) findHandle(url string, method Method) Handler {
	index := strings.LastIndex(url, "?")
	if index == -1 {
		index = len(url)
	}

	pathSplits := strings.Split(url[:index], "/")
	for _, route := range server.Routes {
		routeSplits := strings.Split(route.Path, "/")

		if startsWithSubarray(pathSplits, routeSplits) {
			hasPrefix := strings.HasPrefix(pathSplits[len(pathSplits)-1], routeSplits[len(routeSplits)-1])

			if route.Use {
				return route.handler
			} else if !route.Use && route.method == method && hasPrefix {
				return route.handler
			}
		}
	}

	return server.NotFoundHandler;
}

func (server *Pino) Static(endpoint string, folder string) {
	server.Routes = append(server.Routes, Route{
		Use: true,
		handler: func(req *Request) Response {
			path := folder + "/" + req.Url[len(endpoint):]
			file, err := os.Open(path)

			if err != nil {
				return NewResponse(Response{
					Body: []byte("File not found"),
					Status: 404,
				})
			}

			stats, _ := file.Stat()
			if stats.Size() > int64(ChunkSize) {
				resp := NewResponse(Response{
					StatusMsg: http.StatusText(http.StatusOK),
					Status: http.StatusOK,
				})

				extSplits := strings.Split(path, ".")
				ext := extSplits[len(extSplits)-1]

				resp.Headers.Set("Transfer-Encoding", "chunked")
				resp.Headers.Set("Content-Type", ext)

				req.conn.Write([]byte(resp.TcpResponse()))
				content := make([]byte, ChunkSize);

				for {
					n, _err := file.Read(content)

					if _err != nil && _err != io.EOF {
						resp.Status = http.StatusInternalServerError;
						resp.StatusMsg = http.StatusText(http.StatusInternalServerError);
						return resp;
					}

					if n == 0 {
						break
					}
					
					req.Stream(content, uint64(n))
				}
				
				req.TerminateStream()
				return Response{Stream: true};
			} else {
				content := server.FileCache[path]
				var err error = nil;

				if len(content) == 0 {
					content = make([]byte, ChunkSize)
					_, err = file.Read(content)

					if err != nil {
						fmt.Println("Error reading file.")
						return NewResponse(Response{
							Body: []byte("File not found"),
							Status: 404,
						})
					}

					server.FileCache[path] = content
				} 

				if err != nil {
					return NewResponse(Response{
						Body: []byte("File not found"),
						Status: 404,
					})
				}


				extSplits := strings.Split(path, ".")
				ext := extSplits[len(extSplits)-1]

				return NewResponse(Response{
					Body: content,
					StatusMsg: http.StatusText(http.StatusOK),
					Status: http.StatusOK,
					Headers: http.Header{
						"Content-Length": {fmt.Sprint(stats.Size())},
						"Content-Type": {GetContentType(ext)},
					},
				})
			}
		},
	})
}

func (server *Pino) Serve() {
	host := fmt.Sprintf("%s:%d", server.Host, server.Port);
	listener, err := net.Listen("tcp", host);

	if err != nil {
		fmt.Printf("Error listening: %v", err)
	}
	
	server._serve(listener)
}

func (server *Pino) ServeWithTLS(tlsConfig *tls.Config) {
	host := fmt.Sprintf("%s:%d", server.Host, server.Port)
	listener, err := tls.Listen("tcp", host, tlsConfig)
	
	if err != nil {
		fmt.Printf("failed to start TLS listener: %v", err)
	}

	server._serve(listener)
}

func (server *Pino) _serve(listener net.Listener) {
	workers := NewWorkers(4)
	workers.Start()
	
	req := Request{}
	buf := make([]byte, 4096)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stop
		listener.Close()
		workers.ShutDown()
	}()

	for {
		conn, _ := listener.Accept()
		if conn == nil {
			break;
		}

		conn.Read(buf);
		workers.Do(func () {
			defer conn.Close()
			req.Parse(string(buf), conn)

			handler := server.findHandle(req.Url, req.Method)
			resp := handler(&req)

			if resp.Stream {
				return
			}

			if (strings.ToLower(req.Headers.Get("Connection")) == "keep-alive") {
				keepAliveValues := req.Headers.Values("Keep-Alive")

				if len(keepAliveValues) == 0 {
					resp.Headers.Set("Connection", "keep-alive")
					resp.Headers.Set("Keep-Alive", "timeout=5, max=100")
					conn.SetDeadline(time.Now().Add(5 * time.Second))
				} else {
					keepAliveSeconds, err := strconv.Atoi(strings.Split(keepAliveValues[0], "=")[1])
					if err != nil {
						fmt.Println("Invalid header");
					}
					
					resp.Headers.Set("Connection", "keep-alive")
					resp.Headers.Set("Keep-Alive", fmt.Sprintf("timeout=%d, max=100", keepAliveSeconds))
					conn.SetDeadline(time.Now().Add(time.Duration(keepAliveSeconds) * time.Second))
				}
				
			} else {
				resp.Headers.Set("Connection", "close")
			}

			_, err := conn.Write([]byte(resp.TcpResponse()))
			if err != nil {
				fmt.Printf("Failed to write.");
			}
		})
	}
}

func (server *Pino) ShutDown() {
    <-server.StopChan
    fmt.Println("Shutting down the server...")

    if server.Listener != nil {
        server.Listener.Close()
    }

    server.WaitGroup.Wait()
    fmt.Println("Server gracefully shut down.")
}


func (server *Pino) Get(path string, handler Handler) {
	server.Routes = append(server.Routes, Route{
		Path: path,
		handler: handler,
		Use: false,
		method: GET,
	})
}

func (server *Pino) Post(path string, handler Handler) {
	server.Routes = append(server.Routes, Route{
		Path: path,
		handler: handler,
		Use: false,
		method: POST,
	})
}

func (server *Pino) Put(path string, handler Handler) {
	server.Routes = append(server.Routes, Route{
		Path: path,
		handler: handler,
		Use: false,
		method: PUT,
	})
}

func (server *Pino) Delete(path string, handler Handler) {
	server.Routes = append(server.Routes, Route{
		Path: path,
		handler: handler,
		Use: false,
		method: DELETE,
	})
}

func (server *Pino) Use(path string, handler Handler) {
	server.Routes = append(server.Routes, Route{
		Path: path,
		handler: handler,
		Use: true,
	})
}

func (server *Pino) UseCors(cors *Cors) {
	server.Routes = append(server.Routes, Route{
		Path: cors.Path,
		method: OPTIONS,
		handler: func(req *Request) Response {
			headers := http.Header{}

			var methods strings.Builder;

			for _, method := range cors.Methods {
				methods.WriteString(method.toString());
			}

			headers.Set("Access-Control-Allow-Origin", strings.Join(cors.Origins, ","))
			headers.Set("Access-Control-Allow-Headers", strings.Join(cors.Headers, ","))
			headers.Set("Access-Control-Allow-Methods", methods.String())
			headers.Set("Access-Control-Max-Age", fmt.Sprint(cors.MaxAge))

			return Response{
				Headers: headers, 
				Protocol: "HTTP/1.1", 
				Status: http.StatusNoContent, 
				StatusMsg: http.StatusText(http.StatusNoContent),
			}
		},
	})
}

func (server *Pino) SetNotFoundHandler(handler Handler) {
	server.NotFoundHandler = handler
}

func Text(text string, status Status) Response {
	return Response{
		Body: []byte(text),
		Status: status,
		StatusMsg: http.StatusText(int(status)),
		Protocol: "HTTP/1.1",
		Headers: http.Header{
			"Content-Type": {"text/plain"},
			"Content-Length": {fmt.Sprint(len(text))},
		},
	}
}

func NewResponse(res Response) Response {
	response := Response{
		Protocol:  "HTTP/1.1",
		Status:    http.StatusOK,
		StatusMsg: "OK",
		Headers: http.Header{
			"Content-Type":   {"text/plain"},
			"Content-Length": {"0"},
		},
	}

	if res.Protocol != "" {
		response.Protocol = res.Protocol
	}

	if res.Status != 0 {
		response.Status = res.Status
		response.StatusMsg = http.StatusText(int(res.Status))
	}

	if res.StatusMsg != "" {
		response.StatusMsg = res.StatusMsg
	}

	if len(res.Body) != 0 {
		response.Headers.Set("Content-Length", fmt.Sprint(len(res.Body)))
		response.Body = res.Body
	}
	
	if len(res.Headers) != 0 {
		for key, value := range res.Headers {
			response.Headers[key] = value
		}
	}

	return response
}

func Json(json string, status Status) Response {
	return Response{
		Body: []byte(json),
		Status: status,
		StatusMsg: http.StatusText(int(status)),
		Protocol: "HTTP/1.1",
		Headers: http.Header{
			"Content-Type": {"application/json"},
			"Content-Length": {fmt.Sprint(len(json))},
		},
	}
}

func (res *Response) Render(templateFile string, data interface{}) {
	template, err := template.ParseFiles(templateFile)
	if err != nil {
		res.Status = http.StatusInternalServerError
		res.Body = []byte("Error rendering template")
		return
	}

	var output bytes.Buffer
	err = template.Execute(&output, data)
	if err != nil {
		res.Status = http.StatusInternalServerError
		res.Body = []byte("Error rendering template")
		return
	}

	res.Body = output.Bytes()
	res.Protocol = "HTTP/1.1"
	res.Status = http.StatusOK
	res.StatusMsg = "OK"
}

func (req *Request) Stream(data []byte, len uint64) {
	req.conn.Write([]byte(fmt.Sprintf("%x\r\n", len)))
	req.conn.Write(data);
	req.conn.Write([]byte("\r\n"));
}

func (req *Request) TerminateStream() {
	req.conn.Write([]byte("0\r\n"))
}
