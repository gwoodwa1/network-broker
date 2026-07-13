package policy

import "fmt"

// Decision captures the outcome of evaluating a candidate or collection-trigger policy.
type Decision struct {
	Allow            bool
	RequiresApproval bool
	DecisionID       string
	Denials          []string
	Obligations      map[string]string
}

// Evaluator performs basic policy decisions.
type Evaluator struct{}

// Evaluate returns a policy decision for a recipe and target class.
func (Evaluator) Evaluate(recipeID, targetClass string) (Decision, error) {
	if recipeID == "" {
		return Decision{}, fmt.Errorf("recipe id is required")
	}

	decision := Decision{DecisionID: fmt.Sprintf("decision-%s", recipeID), Obligations: map[string]string{}}
	decision.Obligations["max_duration_ms"] = "10000"
	decision.Obligations["max_response_bytes"] = "1048576"

	switch recipeID {
	case "cached_openconfig_interfaces":
		decision.Allow = true
	case "gnmi_interface_get":
		if targetClass == "production_core" {
			decision.Allow = false
			decision.Denials = append(decision.Denials, "production_core targets require approval")
			decision.RequiresApproval = true
		} else {
			decision.Allow = true
		}
	case "vendor_cli_show_interface":
		if targetClass == "production_core" {
			decision.Allow = true
			decision.RequiresApproval = true
		} else {
			decision.Allow = false
			decision.Denials = append(decision.Denials, "cli recipe only permitted for production_core targets")
		}
	default:
		return Decision{}, fmt.Errorf("unsupported recipe id %q", recipeID)
	}

	return decision, nil
}
