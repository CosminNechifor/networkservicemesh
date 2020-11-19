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
	peer *workloadapi.Client
}

func NewSpireProvider(addr string) (Provider, error) {
	if len(addr) == 0 {
		addr = SpireAgentUnixAddr
	}

	p, err := workloadapi.New(
		context.Background(),
		workloadapi.WithAddr(addr),
	)
	if err != nil {
		return nil, err
	}

	go func() {
		svid, err := p.FetchX509SVID(context.TODO())
		if err != nil {
			logrus.Info("Error:", err)
			return
		}
		logrus.Info("Issued identity:", svid.ID.URL())
	}()

	return &spireProvider{
		peer: p,
		address: addr,
	}, nil
}

func (p *spireProvider) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	svid, err := p.peer.FetchX509SVID(ctx)
	if err != nil {
		logrus.Error("Could not get the x509 source.", err)
		return nil, err
	}
	logrus.Info("svid:", svid)

	bundlesSet, err := p.peer.FetchX509Bundles(ctx)
	if err != nil {
		logrus.Info("Failed to get bundles set.")
		return nil, err
	}
	logrus.Info("bundleSet:", bundlesSet)

	trustDomain := svid.ID.TrustDomain()
	logrus.Info("Trust domain:", trustDomain.String())

	bundle, err := bundlesSet.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		logrus.Info(
			"Failed to get bundle of trustDomain.",
			trustDomain.String(),
		)
		return nil, err
	}
	logrus.Infof("Got bundle %v for trust domain: %v", bundle, bundle.TrustDomain().String())

	tlsConfig := tlsconfig.MTLSClientConfig(
		svid,
		bundle,
		tlsconfig.AuthorizeMemberOf(trustDomain),
	)
	logrus.Info("tlsconfig:", tlsConfig)
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

	bundlesSet, err := p.peer.FetchX509Bundles(ctx)
	if err != nil {
		logrus.Error("Failed to get bundles set.")
		return nil, err
	}
	logrus.Info("bundleset:", bundlesSet)

	bundle, err := bundlesSet.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		logrus.Error(
			"Failed to get bundle of trustDomain",
			trustDomain.String(),
		)
		return nil, err
	}
	logrus.Info("bundle:", bundle)

	svids, err := p.peer.FetchX509SVIDs(ctx)
	if err != nil {
		logrus.Error(
			"Failed fetching SVIDs from spire",
			trustDomain.String(),
		)
		return nil, err
	}

	logrus.Info("Printing svids:")
	for _, svid := range svids {
		logrus.Info("svid:", svid.ID.TrustDomain(), svid)
	}

	x509Src, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr(p.address),
		),
	)
	if err != nil {
		logrus.Error("Could not get the x509 source", err)
		return nil, err
	}
	logrus.Info("Got x509Src:")

	mtlsConfig := tlsconfig.MTLSClientConfig(
		x509Src,
		bundle,
		tlsconfig.AuthorizeMemberOf(trustDomain),
	)
	logrus.Info("mtls:", mtlsConfig)
	return mtlsConfig, nil

}
