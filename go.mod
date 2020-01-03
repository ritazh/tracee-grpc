module github.com/ritazh/tracee-grpc

go 1.13

require (
	github.com/golang/protobuf v1.3.2
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20191112030435-1307ba72bce3
	google.golang.org/grpc v1.26.0
	k8s.io/apiextensions-apiserver v0.0.0-20191016113550-5357c4baaf65
	k8s.io/apimachinery v0.0.0-20191030190112-bb31b70367b7
)

replace (
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20191016113439-b64f2075a530
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191004115701-31ade1b30762
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191016111841-d20af8c7efc5
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191016110837-54936ba21026
)
