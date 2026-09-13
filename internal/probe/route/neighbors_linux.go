//go:build linux

package route

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

// SystemNeighborTable reads the Linux ARP cache when it is exposed through
// procfs. Linux does not provide a stable portable NDP-cache file, so IPv6
// lookups remain explicitly unobserved rather than falling back to a shell.
type SystemNeighborTable struct {
	ARPPath string
}

func (t SystemNeighborTable) Neighbors(ctx context.Context, target netip.Addr, interfaceIndex int) (model.NeighborEvidence, error) {
	if err := ctx.Err(); err != nil {
		return model.NeighborEvidence{}, err
	}
	target = model.NormalizeAddr(target)
	if !target.IsValid() {
		return model.NeighborEvidence{Observation: model.NeighborObservationUnknown, Source: "linux-neighbor-cache", Note: "neighbor lookup target is invalid"}, nil
	}
	if target.IsLoopback() {
		return model.NeighborEvidence{Observation: model.NeighborObservationNotApplicable, Source: "linux-neighbor-cache", Note: "loopback does not use ARP/NDP"}, nil
	}
	if !target.Is4() {
		return model.NeighborEvidence{
			Observation: model.NeighborObservationNotObserved,
			Source:      "linux-neighbor-cache",
			Note:        "stable NDP cache evidence is not exposed by the native provider; absence is not unreachable",
		}, nil
	}
	path := t.ARPPath
	if path == "" {
		path = "/proc/net/arp"
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return model.NeighborEvidence{Observation: model.NeighborObservationUnsupported, Source: "procfs:/proc/net/arp", Note: "ARP cache is unavailable; absence is not unreachable"}, ErrUnsupported
		}
		return model.NeighborEvidence{}, err
	}
	defer file.Close()

	result := model.NeighborEvidence{Observation: model.NeighborObservationNotObserved, Source: "procfs:/proc/net/arp", Note: "no matching ARP cache entry observed; this is not proof of unreachable state"}
	wanted := target.String()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] != wanted {
			continue
		}
		entry := model.NeighborEntry{Address: fields[0], LinkAddress: fields[3], State: fields[2]}
		entry.Interface = fields[5]
		entry.InterfaceIndex = interfaceIndex
		result.Observation = model.NeighborObservationObserved
		result.Note = "ARP cache entry observed; this is supporting local evidence only"
		result.Entries = append(result.Entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	return result, nil
}
