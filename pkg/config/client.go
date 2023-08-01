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

package config

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/loopholelabs/tls/pkg/loader"
	"time"
)

// Client contains a set of TLS configuration options for loading and caching a
// Client TLS Certificate and Root CA Pool, and then reloading them on a given interval
type Client struct {
	*config
}

func NewClient(loader loader.Loader, interval time.Duration) (*Client, error) {
	t := &Client{
		config: &config{
			interval: interval,
			loader:   loader,
		},
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())

	rootCA, err := t.loader.RootCA(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load root ca: %w", err)
	}

	t.certificate, err = t.loader.Certificate(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	t.tlsConfig = &tls.Config{
		RootCAs: rootCA,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (cert *tls.Certificate, err error) {
			t.mu.RLock()
			cert = t.certificate
			err = t.err
			t.mu.RUnlock()
			return
		},
	}

	t.wg.Add(1)
	go t.rotate()

	return t, nil
}
