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
	"sync"
	"time"
)

// Loader is an interface that allows for loading a Client TLS Certificate as required
type Loader interface {
	// RootCA loads the Root CA Pool for the Client Certificate
	//
	// This will only be called once when creating the TLS Config and not on an interval
	RootCA(ctx context.Context) (*x509.CertPool, error)

	// ClientCertificate loads the Client Certificate
	//
	// This will be called once when creating the TLS Config and then continuously on an interval
	ClientCertificate(ctx context.Context) (*tls.Certificate, error)
}

// Config contains a set of TLS configuration options for loading and caching a
// client TLS Certificate and Root CA Pool, and then reloading them on a given interval
type Config struct {
	interval time.Duration

	certificate *tls.Certificate
	config      *tls.Config

	loader Loader

	mu     sync.RWMutex
	err    error
	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

func NewConfig(loader Loader, interval time.Duration) (*Config, error) {
	t := &Config{
		interval: interval,
		loader:   loader,
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())

	rootCA, err := t.loader.RootCA(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA: %w", err)
	}

	t.certificate, err = t.loader.ClientCertificate(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	t.config = &tls.Config{
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

// Config returns the generated TLS Config
func (t *Config) Config() *tls.Config {
	return t.config
}

// Stop stops the TLS Config from reloading certificates and shuts down all goroutines
func (t *Config) Stop() {
	t.cancel()
	t.wg.Wait()
}

// rotate is a goroutine that reloads the TLS Certificate and Root CA Pool on a given interval
func (t *Config) rotate() {
	defer t.wg.Done()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(t.interval):
			certificate, err := t.loader.ClientCertificate(t.ctx)
			if err != nil {
				t.mu.Lock()
				t.err = fmt.Errorf("failed to load client certificate and key: %w", err)
				t.mu.Unlock()
				continue
			}
			t.mu.Lock()
			t.certificate = certificate
			t.err = nil
			t.mu.Unlock()
		}
	}
}
