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
)

// Loader is an interface that allows for loading TLS Certificates as required
//
// A Loader is used to load the TLS Certificate and the Root CA Pool for a given application,
// and can be used for loading both Client and Server TLS Certificates
//
// The Loader cannot be used in situations where different certificates must be served depending
// on the SNIs provided by the client, and is only intended for use in situations where a single
// certificate is served for all requests, but where the certificate must be reloaded on a given
// interval
type Loader interface {
	// RootCA loads the Root CA Pool for the Certificate
	//
	// This will only be called once when creating the TLS Config and not on an interval
	RootCA(ctx context.Context) (*x509.CertPool, error)

	// Certificate loads the TLS Certificate
	//
	// This will be called once when creating the TLS Config and then continuously on an interval
	Certificate(ctx context.Context) (*tls.Certificate, error)
}
