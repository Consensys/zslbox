package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/consensys/zslbox/snark"
	"github.com/consensys/zslbox/zsl"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// -------------------------------------------------------------------------------------------------
// flags
var (
	fCertFile  = flag.String("cert_file", "server.crt", "TLS cert file")
	fKeyFile   = flag.String("key_file", "server.key", "TLS key file")
	fHTTPPort  = flag.Int("http", 9001, "gRPC server http port")
	fHTTPSPort = flag.Int("https", 9000, "gRPC server https port")
)

// -------------------------------------------------------------------------------------------------
// logger
var (
	logger *zap.Logger
	log    *zap.SugaredLogger
)

// -------------------------------------------------------------------------------------------------
// init logger
func init() {
	var err error
	logger, err = newZapConfig().Build()
	if err != nil {
		fmt.Println("unable to create logger")
		os.Exit(1)
	}
	log = logger.Sugar()
}

//go:generate protoc -I zsl/ zsl/zslbox.proto --go_out=plugins=grpc:zsl
//go:generate go install ./zsl/
//go:generate echo generated zsl/zslbox.pb.go
//go:generate protoc -I zsl/ zsl/zslbox.proto --gopherjs_out=plugins=grpc:zsl/gopherjs
//go:generate mv zsl/gopherjs/zslbox.pb.gopherjs.go zsl/gopherjs/zslbox.pb.gopherjs
//go:generate echo generated zsl/gopherjs/zslbox.pb.gopherjs
func main() {
	log.Info("starting zslbox")
	defer log.Warn("stopping zslbox")
	defer logger.Sync() // flushes buffer, if any

	// Init snark module (will create params if mounted volume on /keys doesn't exist. )
	snark.Init(zsl.TreeDepth, "/keys")

	// Parse flags
	flag.Parse()

	// init gRPC server
	grpcServer := grpc.NewServer()
	zsl.RegisterZSLBoxServer(grpcServer, NewZSLServer())

	wrappedServer := grpcweb.WrapServer(grpcServer, grpcweb.WithWebsockets(true))
	handler := func(resp http.ResponseWriter, req *http.Request) {
		wrappedServer.ServeHTTP(resp, req)
	}

	httpServer := http.Server{
		Addr:    fmt.Sprintf(":%d", *fHTTPPort),
		Handler: http.HandlerFunc(handler),
	}
	httpsServer := http.Server{
		Addr:    fmt.Sprintf(":%d", *fHTTPSPort),
		Handler: http.HandlerFunc(handler),
	}
	go func() {
		log.Fatal(httpServer.ListenAndServe())
	}()

	log.Fatal(httpsServer.ListenAndServeTLS(*fCertFile, *fKeyFile))
}

func newZapConfig() zap.Config {
	return zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.DebugLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          "console",
		EncoderConfig:     zap.NewDevelopmentEncoderConfig(),
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
}
