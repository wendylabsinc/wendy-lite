// tinycloud is a development tunnel-broker server: devices (wendy_cloud)
// dial in on the device port, gRPC tunnel clients connect on the gRPC port
// and reach a device through WendyComTunnelBrokerService.WendyComTunnel. TLS only —
// no authentication, no certificate checks.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"

	"github.com/wendylabsinc/wendy/go/proto/gen/tunnelpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"tinycloud/internal/broker"
	"tinycloud/internal/selfsigned"
)

func main() {
	grpcAddr := flag.String("grpc-addr", ":5054", "gRPC listen address (tunnel clients)")
	deviceAddr := flag.String("device-addr", ":5055", "TLS listen address (reverse device connections)")
	flag.Parse()

	cert, err := selfsigned.NewCert()
	if err != nil {
		log.Fatalf("cert generation: %v", err)
	}

	b := broker.New()

	devLn, err := tls.Listen("tcp", *deviceAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Devices dial in with their mTLS client cert; accepted but not
		// verified for now (the asset id will eventually come from it).
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		log.Fatalf("device listener: %v", err)
	}
	log.Printf("device listener on %s", *deviceAddr)
	go b.ServeDevices(devLn)

	grpcLn, err := net.Listen("tcp", *grpcAddr)
	if err != nil {
		log.Fatalf("grpc listener: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})))
	tunnelpb.RegisterWendyComTunnelBrokerServiceServer(s, broker.NewTunnelServer(b))
	log.Printf("gRPC listener on %s", *grpcAddr)
	log.Fatal(s.Serve(grpcLn))
}
