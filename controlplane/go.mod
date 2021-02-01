module github.com/cisco-app-networking/networkservicemesh/controlplane

go 1.13

replace (
	github.com/networkservicemesh/networkservicemesh/controlplane => ./
	github.com/networkservicemesh/networkservicemesh/controlplane/api => ./api
	github.com/networkservicemesh/networkservicemesh/forwarder => ../forwarder
	github.com/networkservicemesh/networkservicemesh/forwarder/api => ../forwarder/api
	github.com/networkservicemesh/networkservicemesh/k8s/pkg/apis => ../k8s/pkg/apis
	github.com/networkservicemesh/networkservicemesh/pkg => ../pkg
	github.com/networkservicemesh/networkservicemesh/sdk => ../sdk
	github.com/networkservicemesh/networkservicemesh/side-cars => ../side-cars
	github.com/networkservicemesh/networkservicemesh/utils => ../utils
)

require (
	github.com/golang/protobuf v1.4.2
	github.com/networkservicemesh/networkservicemesh/controlplane v0.0.0-00010101000000-000000000000
	github.com/networkservicemesh/networkservicemesh/controlplane/api v0.3.0
	github.com/networkservicemesh/networkservicemesh/forwarder/api v0.0.0-00010101000000-000000000000
	github.com/networkservicemesh/networkservicemesh/pkg v0.3.0
	github.com/networkservicemesh/networkservicemesh/sdk v0.0.0-00010101000000-000000000000
	github.com/networkservicemesh/networkservicemesh/utils v0.3.0
	github.com/onsi/gomega v1.10.3
	github.com/opentracing/opentracing-go v1.1.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.1.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.2 // indirect
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	golang.org/x/net v0.0.0-20201006153459-a7d1128ccaa0
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20200114203027-fcfc50b29cbb
	google.golang.org/grpc v1.33.2
)
