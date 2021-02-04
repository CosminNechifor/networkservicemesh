module github.com/cisco-app-networking/networkservicemesh/controlplane/api

go 1.13

replace (
	github.com/census-instrumentation/opencensus-proto v0.1.0-0.20181214143942-ba49f56771b8 => github.com/census-instrumentation/opencensus-proto v0.0.3-0.20181214143942-ba49f56771b8
	github.com/networkservicemesh/networkservicemesh/controlplane/api => ./
)

require (
	github.com/golang/protobuf v1.3.2
	github.com/networkservicemesh/networkservicemesh/controlplane/api v0.0.0-00010101000000-000000000000
	github.com/pkg/errors v0.8.1
	google.golang.org/grpc v1.33.3
)

