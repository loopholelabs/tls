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

package loader

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

var _ Loader = (*PathLoader)(nil)

type PathLoader struct {
	caPath   string
	certPath string
	keyPath  string
}

func NewPathLoader(caPath string, certPath string, keyPath string) *PathLoader {
	return &PathLoader{
		caPath:   caPath,
		certPath: certPath,
		keyPath:  keyPath,
	}
}

func (p *PathLoader) RootCA(_ context.Context) (*x509.CertPool, error) {
	rootCAPool := x509.NewCertPool()
	rootCAPEM, err := os.ReadFile(p.caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca certificate: %w", err)
	}
	rootCAPool.AppendCertsFromPEM(rootCAPEM)
	return rootCAPool, nil
}

func (p *PathLoader) Certificate(_ context.Context) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(p.certPath, p.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	return &cert, nil
}
