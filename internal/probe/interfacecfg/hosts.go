package interfacecfg

import (
	"net/netip"
	"strings"

	"github.com/yohnark/tadori/internal/model"
)

// ParseHostsFileEntries parses the stable, comment-delimited hosts-file
// format without treating it as proof of the mechanism selected by the
// system resolver. It is shared by Windows fixtures and the native reader.
func ParseHostsFileEntries(data []byte, source string) []model.NameResolutionHostEntry {
	entries := make([]model.NameResolutionHostEntry, 0)
	indices := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) < 2 {
			continue
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		addressText := model.NormalizeAddr(address).String()
		for _, rawName := range fields[1:] {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawName), "."))
			if name == "" {
				continue
			}
			index, exists := indices[name]
			if !exists {
				indices[name] = len(entries)
				entries = append(entries, model.NameResolutionHostEntry{Name: name, Source: source})
				index = len(entries) - 1
			}
			duplicate := false
			for _, existing := range entries[index].Addresses {
				if existing == addressText {
					duplicate = true
					break
				}
			}
			if !duplicate {
				entries[index].Addresses = append(entries[index].Addresses, addressText)
			}
		}
	}
	return entries
}
