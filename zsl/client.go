// Copyright 2018 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zsl

import (
	"crypto/tls"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Client connects to a ZSLBox gRPC server
type Client struct {
	conn   *grpc.ClientConn
	ZSLBox ZSLBoxClient
}

// NewClient connects to a gRPC endpoint (ZSLBox) and return the gRPC connection and ZSLBox service
func NewClient(serverAddr string) (*Client, error) {
	var err error
	toReturn := &Client{}

	// Setup gRPC TLS parameters
	var opts []grpc.DialOption
	creds := credentials.NewTLS(&tls.Config{ServerName: "", RootCAs: nil, InsecureSkipVerify: true})
	opts = append(opts, grpc.WithTransportCredentials(creds))

	// connect to gRPC server (ZSLBox)
	toReturn.conn, err = grpc.Dial(serverAddr, opts...)
	if err != nil {
		return nil, err
	}
	toReturn.ZSLBox = NewZSLBoxClient(toReturn.conn)

	return toReturn, nil
}

// Context returns a golang.org/x/net/context. TODO: add authentication metadata
func (c *Client) Context() context.Context {
	return context.Background()
}

// Close should be call to release the connection
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
