package main

import (
	"testing"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/protobuf/proto"
)

func TestVerifyEntries(t *testing.T) {
	first := lpmEntry(10, 1, []byte{10, 0, 1, 0}, 24, 20,
		actionParam(1, []byte{1}), actionParam(2, []byte{2}))
	second := exactEntry(11, 1, []byte{3}, 21, actionParam(1, []byte{1}))

	t.Run("unordered", func(t *testing.T) {
		gotFirst := proto.Clone(first).(*p4v1.TableEntry)
		gotFirst.GetAction().GetAction().Params[0], gotFirst.GetAction().GetAction().Params[1] =
			gotFirst.GetAction().GetAction().Params[1], gotFirst.GetAction().GetAction().Params[0]
		if err := verifyEntries([]*p4v1.TableEntry{first, second},
			[]*p4v1.TableEntry{second, gotFirst}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing", func(t *testing.T) {
		if err := verifyEntries([]*p4v1.TableEntry{first, second},
			[]*p4v1.TableEntry{first}); err == nil {
			t.Fatal("missing entry was accepted")
		}
	})

	t.Run("extra", func(t *testing.T) {
		if err := verifyEntries([]*p4v1.TableEntry{first},
			[]*p4v1.TableEntry{first, second}); err == nil {
			t.Fatal("extra entry was accepted")
		}
	})

	t.Run("wrong match", func(t *testing.T) {
		wrong := proto.Clone(first).(*p4v1.TableEntry)
		wrong.Match[0].GetLpm().Value = []byte{10, 0, 2, 0}
		if err := verifyEntries([]*p4v1.TableEntry{first},
			[]*p4v1.TableEntry{wrong}); err == nil {
			t.Fatal("wrong match value was accepted")
		}
	})

	t.Run("wrong prefix", func(t *testing.T) {
		wrong := proto.Clone(first).(*p4v1.TableEntry)
		wrong.Match[0].GetLpm().PrefixLen = 32
		if err := verifyEntries([]*p4v1.TableEntry{first},
			[]*p4v1.TableEntry{wrong}); err == nil {
			t.Fatal("wrong prefix length was accepted")
		}
	})

	t.Run("wrong action", func(t *testing.T) {
		wrong := proto.Clone(first).(*p4v1.TableEntry)
		wrong.GetAction().GetAction().ActionId++
		if err := verifyEntries([]*p4v1.TableEntry{first},
			[]*p4v1.TableEntry{wrong}); err == nil {
			t.Fatal("wrong action was accepted")
		}
	})

	t.Run("wrong parameter", func(t *testing.T) {
		wrong := proto.Clone(first).(*p4v1.TableEntry)
		wrong.GetAction().GetAction().Params[0].Value = []byte{9}
		if err := verifyEntries([]*p4v1.TableEntry{first},
			[]*p4v1.TableEntry{wrong}); err == nil {
			t.Fatal("wrong action parameter was accepted")
		}
	})
}

func TestVerifyEntriesRejectsNil(t *testing.T) {
	if err := verifyEntries(nil, []*p4v1.TableEntry{nil}); err == nil {
		t.Fatal("nil readback entry was accepted")
	}
}
