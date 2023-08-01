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
	"sync"
	"time"
)

type config struct {
	interval time.Duration
	loader   loader.Loader

	certificate *tls.Certificate
	tlsConfig   *tls.Config

	ctx    context.Context
	cancel context.CancelFunc

	mu  sync.RWMutex
	wg  sync.WaitGroup
	err error
}

// Config returns the generated TLS Config
func (t *config) Config() *tls.Config {
	return t.tlsConfig
}

// Stop stops the TLS Config from reloading certificates and shuts down all goroutines
func (t *config) Stop() {
	t.cancel()
	t.wg.Wait()
}

// rotate is a goroutine that reloads the TLS Certificate on a given interval
func (t *config) rotate() {
	defer t.wg.Done()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(t.interval):
			certificate, err := t.loader.Certificate(t.ctx)
			if err != nil {
				t.mu.Lock()
				t.err = fmt.Errorf("failed to load certificate: %w", err)
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
