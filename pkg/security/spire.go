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
	"os"
	"strings"

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

	// comma separated list of svids used for authorizing mtls
	TrustSvids = "TRUST_SVIDS"
)

type spireProvider struct {
	address string
	x509Src *workloadapi.X509Source
}

func getTrustedSvids() ([]spiffeid.ID, error) {
	var trustedSvids []spiffeid.ID
	commaSvids := os.Getenv(TrustSvids)
	if commaSvids != "" {
		svidSlice := strings.Split(commaSvids, ",")
		for _, s := range svidSlice {
			svid, err := spiffeid.FromString(s)
			if err != nil {
				logrus.Error("Failed to parse:", s)
				return nil, err
			}
			logrus.Info("Trusting: ", svid.URL())
			trustedSvids = append(trustedSvids, svid)
		}
	}
	return trustedSvids, nil
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
		logrus.Error("Failed getting the bundle with err:", err)
	}
	logrus.Info("Obtained bundle for trust domain:", trustDomain)

	trustedSvids, err := getTrustedSvids()
	if err != nil {
		return nil, err
	}

	var authorizer tlsconfig.Authorizer
	if trustedSvids != nil && len(trustedSvids) > 0 {
		authorizer = tlsconfig.AuthorizeOneOf(trustedSvids...)
		logrus.Info("Authorizing only:", trustedSvids)
	} else {
		authorizer = tlsconfig.AuthorizeMemberOf(trustDomain)
		logrus.Info("Authorizing any workload part of the trustdomain:", trustDomain)
	}

	tlsConfig := tlsconfig.MTLSClientConfig(
		svid,
		bundle,
		authorizer,
	)
	return tlsConfig, nil
}

func (p *spireProvider) GetTLSConfigByID(ctx context.Context, id interface{}) (*tls.Config, error) {
	var trustDomain spiffeid.TrustDomain
	var err error

	if w, ok := id.(string); ok {
		trustDomain, err = spiffeid.TrustDomainFromString(w)
		if err != nil {
			return nil, err
		}
	}

	if w, ok := id.(spiffeid.TrustDomain); ok {
		trustDomain = w
	}

	bundleSrc, err := p.x509Src.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		logrus.Error("Could not obtain trust domain bundle", err)
		return nil, err
	}

	trustedSvids, err := getTrustedSvids()
	if err != nil {
		return nil, err
	}

	var authorizer tlsconfig.Authorizer
	if trustedSvids != nil && len(trustedSvids) > 0 {
		authorizer = tlsconfig.AuthorizeOneOf(trustedSvids...)
	} else {
		authorizer = tlsconfig.AuthorizeMemberOf(trustDomain)
	}

	tlsConfig := tlsconfig.MTLSClientConfig(
		p.x509Src,
		bundleSrc,
		authorizer,
	)
	return tlsConfig, nil
}

func (p *spireProvider) GetTLSConfigs(ctx context.Context) ([]*tls.Config, error) {
	var tlsConfigs []*tls.Config

	bundles, err := workloadapi.FetchX509Bundles(
		ctx,
		workloadapi.WithAddr(p.address),
	)
	if err != nil {
		logrus.Error("Failed to fetch bundles", err)
		return nil, err
	}

	for _, bundle := range bundles.Bundles() {
		id := bundle.TrustDomain()
		tlsConfig, err := p.GetTLSConfigByID(ctx, id)
		if err != nil {
			logrus.Errorf("Failed to fetch tlsConfig for Trust Domain: %v", id)
			return nil, err
		}

		tlsConfigs = append(tlsConfigs, tlsConfig)
	}

	return tlsConfigs, nil
}
