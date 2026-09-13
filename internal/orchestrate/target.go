package orchestrate

import "github.com/yohnark/tadori/internal/model"

// ParseTarget is retained as the orchestration package's source-compatible
// entry point. All semantics live in model.ParseTarget; this function does
// not maintain a second parser or target representation.
func ParseTarget(raw string) (model.Target, error) {
	return model.ParseTarget(model.TargetIntent{Input: raw})
}
