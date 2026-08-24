package main

import (
	"testing"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zhh2001/p4runtime-go-controller/pipeline"
)

func TestStaticNATEntries(t *testing.T) {
	got, err := staticNATEntries(testPipeline(t))
	if err != nil {
		t.Fatalf("staticNATEntries: %v", err)
	}
	want := expectedNATEntries()
	if err := verifyEntries(want, got); err != nil {
		t.Fatal(err)
	}
}

func TestStaticNATEntryVerification(t *testing.T) {
	want := expectedNATEntries()

	t.Run("unordered", func(t *testing.T) {
		got := []*p4v1.TableEntry{want[3], want[1], want[0], want[2]}
		if err := verifyEntries(want, got); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("missing reverse mapping", func(t *testing.T) {
		if err := verifyEntries(want, want[:3]); err == nil {
			t.Fatal("missing reverse mapping was accepted")
		}
	})

	t.Run("extra mapping", func(t *testing.T) {
		extra := exactEntry(testOutboundNATTable, 1, []byte{10, 0, 99, 1},
			testSetPublicAddrAction, actionParam(1, []byte{192, 0, 2, 99}))
		got := append(append([]*p4v1.TableEntry{}, want...), extra)
		if err := verifyEntries(want, got); err == nil {
			t.Fatal("extra NAT mapping was accepted")
		}
	})

	t.Run("mismatched addresses", func(t *testing.T) {
		wrong := cloneEntries(want)
		wrong[0].GetAction().GetAction().Params[0].Value = []byte{192, 0, 2, 2}
		if err := verifyEntries(want, wrong); err == nil {
			t.Fatal("mismatched private-to-public mapping was accepted")
		}
	})

	t.Run("wrong private address", func(t *testing.T) {
		wrong := cloneEntries(want)
		wrong[2].Match[0].GetExact().Value = []byte{10, 0, 9, 1}
		if err := verifyEntries(want, wrong); err == nil {
			t.Fatal("wrong private address was accepted")
		}
	})

	t.Run("wrong public address", func(t *testing.T) {
		wrong := cloneEntries(want)
		wrong[3].Match[0].GetExact().Value = []byte{192, 0, 2, 9}
		if err := verifyEntries(want, wrong); err == nil {
			t.Fatal("wrong public address was accepted")
		}
	})

	t.Run("wrong action", func(t *testing.T) {
		wrong := cloneEntries(want)
		wrong[1].GetAction().GetAction().ActionId = testSetPublicAddrAction
		if err := verifyEntries(want, wrong); err == nil {
			t.Fatal("wrong NAT action was accepted")
		}
	})

	t.Run("wrong action parameter", func(t *testing.T) {
		wrong := cloneEntries(want)
		wrong[2].GetAction().GetAction().Params[0].ParamId = 2
		if err := verifyEntries(want, wrong); err == nil {
			t.Fatal("wrong NAT action parameter was accepted")
		}
	})
}

func TestStaticNATEntriesRejectWrongSchema(t *testing.T) {
	t.Run("match field", func(t *testing.T) {
		pl := testPipeline(t)
		pl.Info().Tables[3].MatchFields[0].Name = "wrong_name"
		pl = rebuildPipeline(t, pl)
		if _, err := staticNATEntries(pl); err == nil {
			t.Fatal("wrong outbound NAT match field was accepted")
		}
	})

	t.Run("action parameter", func(t *testing.T) {
		pl := testPipeline(t)
		pl.Info().Actions[4].Params[0].Name = "wrong_name"
		pl = rebuildPipeline(t, pl)
		if _, err := staticNATEntries(pl); err == nil {
			t.Fatal("wrong inbound NAT action parameter was accepted")
		}
	})
}

func expectedNATEntries() []*p4v1.TableEntry {
	return []*p4v1.TableEntry{
		exactEntry(testOutboundNATTable, 1, []byte{10, 0, 1, 1},
			testSetPublicAddrAction, actionParam(1, []byte{192, 0, 2, 1})),
		exactEntry(testInboundNATTable, 1, []byte{192, 0, 2, 1},
			testSetPrivateAction, actionParam(1, []byte{10, 0, 1, 1})),
		exactEntry(testOutboundNATTable, 1, []byte{10, 0, 2, 1},
			testSetPublicAddrAction, actionParam(1, []byte{192, 0, 2, 2})),
		exactEntry(testInboundNATTable, 1, []byte{192, 0, 2, 2},
			testSetPrivateAction, actionParam(1, []byte{10, 0, 2, 1})),
	}
}

func cloneEntries(entries []*p4v1.TableEntry) []*p4v1.TableEntry {
	clones := make([]*p4v1.TableEntry, 0, len(entries))
	for _, entry := range entries {
		clones = append(clones, proto.Clone(entry).(*p4v1.TableEntry))
	}
	return clones
}

func rebuildPipeline(t *testing.T, pl *pipeline.Pipeline) *pipeline.Pipeline {
	t.Helper()
	rebuilt, err := pipeline.New(pl.Info(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rebuilt
}
