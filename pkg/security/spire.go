// Copyright (c) 2019 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// SpireAgentUnixSocket points to unix socket used by default
	SpireAgentUnixSocket = "/run/spire/sockets/agent.sock"

	// SpireAgentUnixAddr is unix socket address with specified scheme
	SpireAgentUnixAddr = "unix://" + SpireAgentUnixSocket
)

type spireProvider struct {
	address string
	x509Src *workloadapi.X509Source
}

func NewSpireProvider(addr string) (Provider, error) {
	if len(addr) == 0 {
		addr = SpireAgentUnixAddr
	}
	ctx := context.Background()
	x509Src, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(addr),
		),
	)
	if err != nil {
		return nil, err
	}
	logrus.Info("Obtained x509Src:", x509Src)

	go func() {
		// returning the workload SVID
		svid, err := x509Src.GetX509SVID()
		if err != nil {
			logrus.Error("Failed getting the SVID with error:", err)
		}
		if svid != nil {
			logrus.Info("Issued identity:", svid.ID.URL())
		}
	}()

	return &spireProvider{
		address: addr,
		x509Src: x509Src,
	}, nil
}

func (p *spireProvider) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	svid, err := p.x509Src.GetX509SVID()
	if err != nil || svid == nil {
		logrus.Errorf(
			"Error:%v SVID: %v",
			err,
			svid,
		)
		return nil, errors.New("failed getting the SVID")
	}

	trustDomain := svid.ID.TrustDomain()

	bundle, err := p.x509Src.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		logrus.Info("Failed getting the bundle with err:", err)
	}
	logrus.Info("Obtained bundle for trust domain:", trustDomain)

	tlsConfig := tlsconfig.MTLSClientConfig(
		svid,
		bundle,
		tlsconfig.AuthorizeMemberOf(trustDomain),
	)
	return tlsConfig, nil
}

func (p *spireProvider) GetTLSConfigByID(ctx context.Context, id interface{}) (*tls.Config, error) {
	// conversion of the id to a string
	trustDomainStr := fmt.Sprintf("%v", id)

	// creating the spiffeid.TrustDomain struct
	trustDomain, err := spiffeid.TrustDomainFromString(trustDomainStr)
	if err != nil {
		return nil, err
	}
	logrus.Info("TrustDomain:", trustDomain)

	bundleSrc, err := p.x509Src.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		logrus.Info("Could not obtain trust domain bundle", err)
		return nil, err
	}
	logrus.Info("Obtained bundle for trust domain:", trustDomain)

	tlsConfig := tlsconfig.MTLSClientConfig(
		p.x509Src,
		bundleSrc,
		tlsconfig.AuthorizeMemberOf(trustDomain),
	)
	logrus.Info("Obtained tls config:", tlsConfig)
	return tlsConfig, nil

}
