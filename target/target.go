package target

import (
	"fmt"
	"text/template"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ client.TargetHandler = &SyscallValidationTarget{}

type SyscallValidationTarget struct{}

func (h *SyscallValidationTarget) GetName() string {
	return "syscall.k8s.gatekeeper.sh"
}

var libTempl = template.Must(template.New("library").Parse(templSrc))

func (h *SyscallValidationTarget) Library() *template.Template {
	return libTempl
}

func (h *SyscallValidationTarget) ProcessData(obj interface{}) (bool, string, interface{}, error) {
	return true, "", nil, nil
}

func (h *SyscallValidationTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	return true, obj, nil
}

func (h *SyscallValidationTarget) HandleViolation(result *types.Result) error {
	_, ok := result.Review.(map[string]interface{})
	if !ok {
		return fmt.Errorf("could not cast review as map[string]: %+v", result.Review)
	}
	// fmt.Println("rmap:")
	// fmt.Println(rmap)
	return nil
}

func (h *SyscallValidationTarget) MatchSchema() apiextensions.JSONSchemaProps {
	stringList := &apiextensions.JSONSchemaPropsOrArray{
		Schema: &apiextensions.JSONSchemaProps{Type: "string"}}
	labelSelectorSchema := apiextensions.JSONSchemaProps{
		Properties: map[string]apiextensions.JSONSchemaProps{
			// Map schema validation will only work in kubernetes versions > 1.10. See https://github.com/kubernetes/kubernetes/pull/62333
			//"matchLabels": apiextensions.JSONSchemaProps{
			//	AdditionalProperties: &apiextensions.JSONSchemaPropsOrBool{
			//		Allows: true,
			//		Schema: &apiextensions.JSONSchemaProps{Type: "string"},
			//	},
			//},
			"matchExpressions": apiextensions.JSONSchemaProps{
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Properties: map[string]apiextensions.JSONSchemaProps{
							"key": apiextensions.JSONSchemaProps{Type: "string"},
							"operator": apiextensions.JSONSchemaProps{
								Type: "string",
								Enum: []apiextensions.JSON{
									"In",
									"NotIn",
									"Exists",
									"DoesNotExist",
								},
							},
							"values": apiextensions.JSONSchemaProps{
								Type: "array",
								Items: &apiextensions.JSONSchemaPropsOrArray{
									Schema: &apiextensions.JSONSchemaProps{Type: "string"},
								},
							},
						},
					},
				},
			},
		},
	}
	return apiextensions.JSONSchemaProps{
		Properties: map[string]apiextensions.JSONSchemaProps{
			"kinds": apiextensions.JSONSchemaProps{
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Properties: map[string]apiextensions.JSONSchemaProps{
							"apiGroups": {Items: stringList},
							"kinds":     {Items: stringList},
						},
					},
				},
			},
			"namespaces": apiextensions.JSONSchemaProps{
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{Type: "string"}}},
			"labelSelector":     labelSelectorSchema,
			"namespaceSelector": labelSelectorSchema,
		},
	}
}

func (h *SyscallValidationTarget) ValidateConstraint(u *unstructured.Unstructured) error {
	

	return nil
}
