package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/consensys/zslbox/snark"
	"github.com/consensys/zslbox/zsl"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// -------------------------------------------------------------------------------------------------
// flags
var (
	fCertFile = flag.String("cert_file", "server.crt", "TLS cert file")
	fKeyFile  = flag.String("key_file", "server.key", "TLS key file")
	fGrpcPort = flag.Int("port", 9000, "gRPC server port")
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
func main() {
	log.Info("starting zslbox")
	defer log.Warn("stopping zslbox")
	defer logger.Sync() // flushes buffer, if any

	// Init snark module (will create params if mounted volume on /keys doesn't exist. )
	snark.Init(zsl.TreeDepth, "/keys")

	// Parse flags
	flag.Parse()

	// Configure gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *fGrpcPort))
	if err != nil {
		log.Fatalw("failed to listen to tcp port", "error", err)
	} else {
		log.Debugw("grpc server listening", "port", *fGrpcPort)
	}
	creds, err := credentials.NewServerTLSFromFile(*fCertFile, *fKeyFile)
	if err != nil {
		log.Fatalw("failed to generate credentials for tls grpc", "error", err)
	}

	// starts gRPC server
	grpcServer := grpc.NewServer([]grpc.ServerOption{grpc.Creds(creds)}...)
	zsl.RegisterZSLBoxServer(grpcServer, NewZSLServer())
	log.Fatal(grpcServer.Serve(lis))
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
