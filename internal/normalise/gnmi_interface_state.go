// Package normalise converts protocol-specific, sanitised network output into
// the exact schema accepted by a trusted evidence parser.
package normalise

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	"network_broker/internal/artefacts"
	"network_broker/internal/sanitise"
)

const (
	gnmiInterfaceStateSchema = "v1"
	maximumGNMIUpdates       = 256
)

// GNMIInterfaceState converts one bounded OpenConfig oper-status response to
// the broker's interface-state v1 schema. It first runs the complete raw gNMI
// document through hostile-output sanitisation, then strictly decodes and
// allowlists the response shape. The returned manifest binds the original
// captured response directly to the canonical normalised derivative.
type GNMIInterfaceState struct {
	id         string
	version    string
	sanitiser  sanitise.Pipeline
	maxUpdates int
}

func NewGNMIInterfaceState(id, version string, pipeline sanitise.Pipeline,
	maxUpdates int,
) (*GNMIInterfaceState, error) {
	if id == "" || version == "" || pipeline.ID == "" || pipeline.Version == "" ||
		maxUpdates <= 0 || maxUpdates > maximumGNMIUpdates {
		return nil, fmt.Errorf("normaliser, sanitiser and bounded update identities are required")
	}
	rules := pipeline.Rules
	if rules.Version == "" {
		rules = sanitise.DefaultRules()
	}
	if !slices.Contains(rules.FreeTextJSONFields, "name") {
		return nil, fmt.Errorf("gNMI sanitisation rules must classify name fields as device-controlled text")
	}
	pipeline.Rules = rules

	return &GNMIInterfaceState{
		id: id, version: version, sanitiser: pipeline, maxUpdates: maxUpdates,
	}, nil
}

func (n *GNMIInterfaceState) NormaliserVersion() string {
	if n == nil {
		return ""
	}

	return n.version
}

func (n *GNMIInterfaceState) Transform(captured []byte) ([]byte,
	artefacts.TransformationManifest,
	error,
) {
	if n == nil {
		return nil, artefacts.TransformationManifest{}, fmt.Errorf("gNMI interface-state normaliser is required")
	}
	safePayload, sourceManifest, err := n.sanitiser.Transform(captured)
	if err != nil {
		return nil, artefacts.TransformationManifest{}, err
	}
	if sourceManifest.Quarantined {
		return safePayload, sourceManifest, nil
	}
	response := &gpb.GetResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(safePayload, response); err != nil {
		return nil, artefacts.TransformationManifest{}, fmt.Errorf("decode sanitised gNMI response: %w", err)
	}
	observation, err := n.extract(response)
	if err != nil {
		return nil, artefacts.TransformationManifest{}, err
	}
	normalised, err := json.Marshal(observation)
	if err != nil {
		return nil, artefacts.TransformationManifest{}, fmt.Errorf("encode normalised interface state: %w", err)
	}
	if len(sourceManifest.Outcomes) > 510 {
		return nil, artefacts.TransformationManifest{}, fmt.Errorf("gNMI transformation outcome limit exceeded")
	}
	outputDigest := sha256.Sum256(normalised)
	manifest := sourceManifest
	manifest.PipelineID = n.id
	manifest.PipelineVersion = n.version
	manifest.OutputDigest = hex.EncodeToString(outputDigest[:])
	manifest.OverallStatus = "tainted"
	manifest.TaintedFields = []string{"$/interface_name"}
	manifest.OutputByteCount = uint64(len(normalised))
	manifest.Truncated = false
	manifest.Outcomes = append(manifest.Outcomes,
		artefacts.TransformationOutcome{
			Action: sanitise.ActionTainted, ReasonCode: "gnmi_interface_name_mapped",
			JSONPath: "$/interface_name", Count: 1,
		},
		artefacts.TransformationOutcome{
			Action: sanitise.ActionRetained, ReasonCode: "gnmi_interface_state_normalised",
			JSONPath: "$", Count: 1,
		})

	return normalised, manifest, nil
}

type interfaceStateWire struct {
	SchemaVersion    string    `json:"schema_version"`
	InterfaceName    string    `json:"interface_name"`
	OperationalState string    `json:"operational_state"`
	ObservedAt       time.Time `json:"observed_at"`
}

//nolint:cyclop,gocognit // The allowlisted response-shape checks remain linear and auditable in one function.
func (n *GNMIInterfaceState) extract(response *gpb.GetResponse) (interfaceStateWire, error) {
	if response == nil || populatedField(response.ProtoReflect(), "error") || len(response.GetNotification()) != 1 {
		return interfaceStateWire{}, fmt.Errorf("gNMI interface-state response requires exactly one successful notification")
	}
	notification := response.GetNotification()[0]
	if notification == nil || notification.GetTimestamp() <= 0 || len(notification.GetDelete()) != 0 ||
		len(notification.GetUpdate()) == 0 || len(notification.GetUpdate()) > n.maxUpdates {
		return interfaceStateWire{}, fmt.Errorf("gNMI notification timestamp, updates and deletion bounds are invalid")
	}
	observedAt := time.Unix(0, notification.GetTimestamp()).UTC()
	if observedAt.Year() < 1970 || observedAt.Year() > 9999 {
		return interfaceStateWire{}, fmt.Errorf("gNMI notification timestamp is outside the supported range")
	}

	var interfaceName, operationalState string
	for _, update := range notification.GetUpdate() {
		name, leaf, err := interfaceUpdatePath(notification.GetPrefix(), update.GetPath())
		if err != nil {
			return interfaceStateWire{}, err
		}
		if interfaceName == "" {
			interfaceName = name
		} else if interfaceName != name {
			return interfaceStateWire{}, fmt.Errorf("gNMI response contains more than one interface")
		}
		switch leaf {
		case "name":
			value, valueErr := scalarString(update.GetVal())
			if valueErr != nil || value != interfaceName {
				return interfaceStateWire{}, fmt.Errorf("gNMI interface name leaf does not match its path key")
			}
		case "oper-status":
			if operationalState != "" {
				return interfaceStateWire{}, fmt.Errorf("gNMI response contains duplicate operational state")
			}
			value, valueErr := scalarString(update.GetVal())
			if valueErr != nil {
				return interfaceStateWire{}, valueErr
			}
			operationalState, valueErr = mapOperationalState(value)
			if valueErr != nil {
				return interfaceStateWire{}, valueErr
			}
		default:
			return interfaceStateWire{}, fmt.Errorf("gNMI interface-state response contains unsupported leaf %q", leaf)
		}
	}
	if interfaceName == "" || operationalState == "" {
		return interfaceStateWire{}, fmt.Errorf("gNMI response lacks one interface operational state")
	}

	return interfaceStateWire{
		SchemaVersion: gnmiInterfaceStateSchema, InterfaceName: interfaceName,
		OperationalState: operationalState, ObservedAt: observedAt,
	}, nil
}

func interfaceUpdatePath(prefix, path *gpb.Path) (interfaceName, leaf string, err error) {
	if path == nil || populatedPathElement(path) || populatedPathElement(prefix) {
		return "", "", fmt.Errorf("gNMI interface-state path must use structured path elements")
	}
	if err := validatePathAuthority(prefix); err != nil {
		return "", "", err
	}
	if err := validatePathAuthority(path); err != nil {
		return "", "", err
	}
	elements := append([]*gpb.PathElem(nil), prefix.GetElem()...)
	elements = append(elements, path.GetElem()...)
	if len(elements) == 0 || elements[len(elements)-1] == nil {
		return "", "", fmt.Errorf("gNMI interface-state path is empty")
	}
	for _, element := range elements {
		if element == nil {
			return "", "", fmt.Errorf("gNMI interface-state path contains an empty element")
		}
		if element.GetName() == "interface" {
			if interfaceName != "" || len(element.GetKey()) != 1 || element.GetKey()["name"] == "" {
				return "", "", fmt.Errorf("gNMI interface path requires one canonical name key")
			}
			interfaceName = element.GetKey()["name"]
		} else if len(element.GetKey()) != 0 {
			return "", "", fmt.Errorf("gNMI interface-state path contains unsupported keys")
		}
	}
	if interfaceName == "" {
		return "", "", fmt.Errorf("gNMI interface-state path lacks an interface name key")
	}

	return interfaceName, elements[len(elements)-1].GetName(), nil
}

func validatePathAuthority(path *gpb.Path) error {
	if path == nil {
		return nil
	}
	if (path.GetOrigin() != "" && path.GetOrigin() != "openconfig") || path.GetTarget() != "" {
		return fmt.Errorf("gNMI path origin or target is outside the interface-state profile")
	}

	return nil
}

func populatedPathElement(path *gpb.Path) bool {
	return path != nil && populatedField(path.ProtoReflect(), "element")
}

func populatedField(message protoreflect.Message, name protoreflect.Name) bool {
	field := message.Descriptor().Fields().ByName(name)
	return field != nil && message.Has(field)
}

func scalarString(value *gpb.TypedValue) (string, error) {
	if value == nil {
		return "", fmt.Errorf("gNMI interface-state value is required")
	}
	var result string
	switch typed := value.GetValue().(type) {
	case *gpb.TypedValue_StringVal:
		result = typed.StringVal
	case *gpb.TypedValue_AsciiVal:
		result = typed.AsciiVal
	case *gpb.TypedValue_JsonIetfVal:
		if err := decodeJSONString(typed.JsonIetfVal, &result); err != nil {
			return "", err
		}
	case *gpb.TypedValue_JsonVal:
		if err := decodeJSONString(typed.JsonVal, &result); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("gNMI interface-state value must be a scalar string")
	}
	if result == "" || result != strings.TrimSpace(result) {
		return "", fmt.Errorf("gNMI interface-state value must be a canonical non-empty string")
	}

	return result, nil
}

func decodeJSONString(payload []byte, destination *string) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("gNMI JSON value must contain one string: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("gNMI JSON value must contain exactly one string")
	}
	return nil
}

func mapOperationalState(value string) (string, error) {
	switch value {
	case "UP", "up":
		return "up", nil
	case "DOWN", "down", "DORMANT", "NOT_PRESENT", "LOWER_LAYER_DOWN":
		return "down", nil
	case "UNKNOWN", "unknown", "TESTING":
		return "unknown", nil
	default:
		return "", fmt.Errorf("unsupported OpenConfig operational state %q", value)
	}
}
