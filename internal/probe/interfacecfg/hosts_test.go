package interfacecfg

import "testing"

func TestParseHostsFileEntriesGroupsAliasesAndFamilies(t *testing.T) {
	data := []byte("# fixture\n10.30.14.22 fileserver fileserver.corp.example\n2001:db8::22 fileserver\n10.30.14.22 fileserver\n")
	entries := ParseHostsFileEntries(data, "fixture:hosts")
	if len(entries) != 2 {
		t.Fatalf("entries = %#v, want two names", entries)
	}
	if entries[0].Name != "fileserver" || len(entries[0].Addresses) != 2 || entries[0].Source != "fixture:hosts" {
		t.Fatalf("primary hosts entry = %#v", entries[0])
	}
	if entries[1].Name != "fileserver.corp.example" || len(entries[1].Addresses) != 1 {
		t.Fatalf("alias hosts entry = %#v", entries[1])
	}
}
