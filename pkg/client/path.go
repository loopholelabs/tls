/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

var _ Loader = (*PathLoader)(nil)

type PathLoader struct {
	rootCA     string
	clientCert string
	clientKey  string
}

func NewPathLoader(rootCA string, clientCert string, clientKey string) *PathLoader {
	return &PathLoader{
		rootCA:     rootCA,
		clientCert: clientCert,
		clientKey:  clientKey,
	}
}

func (p *PathLoader) RootCA(_ context.Context) (*x509.CertPool, error) {
	rootCAPool := x509.NewCertPool()
	rootCAPEM, err := os.ReadFile(p.rootCA)
	if err != nil {
		return nil, fmt.Errorf("failed to read root CA: %w", err)
	}
	rootCAPool.AppendCertsFromPEM(rootCAPEM)
	return rootCAPool, nil
}

func (p *PathLoader) ClientCertificate(_ context.Context) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(p.clientCert, p.clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	return &cert, nil
}
