//go:build windows

package route

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/yohnark/tadori/internal/model"
)

var getIPNetTable2 = iphlpapiDLL.NewProc("GetIpNetTable2")

const windowsMaxNeighborRows = 1 << 20

type windowsMIBIPNetRow2 struct {
	Address        windowsSockaddrInet
	InterfaceIndex uint32
	// The native row includes the interface LUID between the index and the
	// physical address. Omitting it shifts every field after InterfaceIndex.
	InterfaceLuid         uint64
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32
	Flags                 uint8
	Padding               [3]byte
	ReachabilityTime      uint32
}

type windowsMIBIPNetTable2 struct {
	NumEntries uint32
	// GetIpNetTable2 returns an inline variable-length row array, not a row
	// pointer. Keep the header layout identical to the native structure.
	Table [1]windowsMIBIPNetRow2
}

func windowsNeighborEvidence(ctx context.Context, target netip.Addr, interfaceIndex int) (model.NeighborEvidence, error) {
	if err := ctx.Err(); err != nil {
		return model.NeighborEvidence{}, err
	}
	target = model.NormalizeAddr(target)
	if !target.IsValid() || target.IsLoopback() {
		return model.NeighborEvidence{Observation: model.NeighborObservationNotApplicable, Source: "GetIpNetTable2", Note: "loopback does not use ARP/NDP"}, nil
	}
	var table *windowsMIBIPNetTable2
	ret, _, _ := getIPNetTable2.Call(windowsAFUnspec, uintptr(unsafe.Pointer(&table)))
	if ret != 0 {
		if ret == windowsErrorNotFound || ret == windowsErrorNoData {
			return model.NeighborEvidence{Observation: model.NeighborObservationNotObserved, Source: "GetIpNetTable2", Note: "no neighbor entry observed; this is not proof of unreachable state"}, nil
		}
		return model.NeighborEvidence{Observation: model.NeighborObservationUnsupported, Source: "GetIpNetTable2", Note: "neighbor cache could not be read; absence is not unreachable"}, syscall.Errno(ret)
	}
	if table == nil {
		return model.NeighborEvidence{Observation: model.NeighborObservationNotObserved, Source: "GetIpNetTable2", Note: "no neighbor entry observed; this is not proof of unreachable state"}, nil
	}
	defer freeMibTable.Call(uintptr(unsafe.Pointer(table)))
	if table.NumEntries > windowsMaxNeighborRows {
		return model.NeighborEvidence{}, errors.New("GetIpNetTable2 returned an unreasonable row count")
	}
	result := model.NeighborEvidence{Observation: model.NeighborObservationNotObserved, Source: "GetIpNetTable2", Note: "no matching neighbor entry observed; this is not proof of unreachable state"}
	for _, row := range unsafe.Slice(&table.Table[0], int(table.NumEntries)) {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		address, ok := windowsSockaddrAddr(row.Address)
		if !ok || model.NormalizeAddr(address) != target || (interfaceIndex != 0 && int(row.InterfaceIndex) != interfaceIndex) {
			continue
		}
		length := int(row.PhysicalAddressLength)
		if length < 0 || length > len(row.PhysicalAddress) {
			length = 0
		}
		entry := model.NeighborEntry{Address: target.String(), InterfaceIndex: int(row.InterfaceIndex), State: windowsNeighborState(row.State)}
		if length > 0 {
			entry.LinkAddress = hex.EncodeToString(row.PhysicalAddress[:length])
		}
		result.Observation = model.NeighborObservationObserved
		result.Note = "neighbor-cache entry observed; this is supporting local evidence only"
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

func windowsNeighborState(state uint32) string {
	// NlnsReachable through NlnsPermanent are the documented IP Helper state
	// values. Preserve an unknown numeric value rather than assigning meaning.
	labels := map[uint32]string{0: "unreachable", 1: "incomplete", 2: "probe", 3: "stale", 4: "delay", 5: "reachable", 6: "permanent"}
	if label, ok := labels[state]; ok {
		return label
	}
	return "state_" + strconv.FormatUint(uint64(state), 10)
}
