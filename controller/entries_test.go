package main

import (
	"testing"

	p4configv1 "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/protobuf/proto"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
)

const (
	testZoneTable        = 1001
	testDestinationTable = 1002
	testRouteTable       = 1003
	testSetZoneAction    = 2001
	testSetDestAction    = 2002
	testForwardAction    = 2003
)

func TestConfigurationEntries(t *testing.T) {
	pl := testPipeline(t)
	got, err := configurationEntries(pl)
	if err != nil {
		t.Fatalf("configurationEntries: %v", err)
	}

	want := []*p4v1.TableEntry{
		exactEntry(testZoneTable, 1, []byte{1}, testSetZoneAction, actionParam(1, []byte{1})),
		exactEntry(testZoneTable, 1, []byte{2}, testSetZoneAction, actionParam(1, []byte{1})),
		exactEntry(testZoneTable, 1, []byte{3}, testSetZoneAction, actionParam(1, []byte{2})),
		lpmEntry(testDestinationTable, 1, []byte{10, 0, 1, 0}, 24,
			testSetDestAction, actionParam(1, []byte{1})),
		lpmEntry(testDestinationTable, 1, []byte{10, 0, 2, 0}, 24,
			testSetDestAction, actionParam(1, []byte{1})),
		lpmEntry(testDestinationTable, 1, []byte{192, 0, 2, 0}, 24,
			testSetDestAction, actionParam(1, []byte{3})),
		lpmEntry(testRouteTable, 1, []byte{10, 0, 1, 0}, 24, testForwardAction,
			actionParam(1, []byte{1}),
			actionParam(2, []byte{0xaa, 0, 0, 1, 1}),
			actionParam(3, []byte{1, 1})),
		lpmEntry(testRouteTable, 1, []byte{10, 0, 2, 0}, 24, testForwardAction,
			actionParam(1, []byte{2}),
			actionParam(2, []byte{0xaa, 0, 0, 2, 1}),
			actionParam(3, []byte{2, 1})),
		lpmEntry(testRouteTable, 1, []byte{10, 0, 3, 0}, 24, testForwardAction,
			actionParam(1, []byte{3}),
			actionParam(2, []byte{0xaa, 0, 0, 3, 1}),
			actionParam(3, []byte{3, 1})),
	}

	if err := verifyEntries(want, got); err != nil {
		t.Fatal(err)
	}
	updates := makeUpdates(got)
	if len(updates) != len(got) {
		t.Fatalf("got %d updates, want %d", len(updates), len(got))
	}
	for i, update := range updates {
		if update.GetType() != client.UpdateInsert {
			t.Errorf("update %d type = %s, want INSERT", i, update.GetType())
		}
		if !proto.Equal(update.GetEntity().GetTableEntry(), got[i]) {
			t.Errorf("update %d contains the wrong table entry", i)
		}
	}
}

func TestConfigurationEntriesRejectsWrongSchema(t *testing.T) {
	pl := testPipeline(t)
	pl.Info().Tables[0].MatchFields[0].Name = "wrong_name"
	pl, err := pipeline.New(pl.Info(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configurationEntries(pl); err == nil {
		t.Fatal("configurationEntries accepted a P4Info with the wrong match field")
	}
}

func testPipeline(t *testing.T) *pipeline.Pipeline {
	t.Helper()
	info := &p4configv1.P4Info{
		Tables: []*p4configv1.Table{
			testTable(testZoneTable, "IngressImpl.zone_by_port", "zone_by_port",
				"ingress_port", 9, p4configv1.MatchField_EXACT),
			testTable(testDestinationTable, "IngressImpl.destination_zone", "destination_zone",
				"dst_addr", 32, p4configv1.MatchField_LPM),
			testTable(testRouteTable, "IngressImpl.ipv4_lpm", "ipv4_lpm",
				"dst_addr", 32, p4configv1.MatchField_LPM),
		},
		Actions: []*p4configv1.Action{
			testAction(testSetZoneAction, "IngressImpl.set_zone", "set_zone",
				testParam(1, "zone", 2)),
			testAction(testSetDestAction, "IngressImpl.set_destination_zone", "set_destination_zone",
				testParam(1, "zone", 2)),
			testAction(testForwardAction, "IngressImpl.forward", "forward",
				testParam(1, "port", 9),
				testParam(2, "src_mac", 48),
				testParam(3, "dst_mac", 48)),
		},
	}
	pl, err := pipeline.New(info, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

func testTable(id uint32, name, alias, field string, width int32,
	matchType p4configv1.MatchField_MatchType) *p4configv1.Table {
	return &p4configv1.Table{
		Preamble: &p4configv1.Preamble{Id: id, Name: name, Alias: alias},
		MatchFields: []*p4configv1.MatchField{{
			Id:       1,
			Name:     field,
			Bitwidth: width,
			Match: &p4configv1.MatchField_MatchType_{
				MatchType: matchType,
			},
		}},
	}
}

func testAction(id uint32, name, alias string, params ...*p4configv1.Action_Param) *p4configv1.Action {
	return &p4configv1.Action{
		Preamble: &p4configv1.Preamble{Id: id, Name: name, Alias: alias},
		Params:   params,
	}
}

func testParam(id uint32, name string, width int32) *p4configv1.Action_Param {
	return &p4configv1.Action_Param{Id: id, Name: name, Bitwidth: width}
}

func exactEntry(tableID, fieldID uint32, value []byte, actionID uint32,
	params ...*p4v1.Action_Param) *p4v1.TableEntry {
	return tableEntry(tableID, &p4v1.FieldMatch{
		FieldId: fieldID,
		FieldMatchType: &p4v1.FieldMatch_Exact_{
			Exact: &p4v1.FieldMatch_Exact{Value: value},
		},
	}, actionID, params...)
}

func lpmEntry(tableID, fieldID uint32, value []byte, length int32, actionID uint32,
	params ...*p4v1.Action_Param) *p4v1.TableEntry {
	return tableEntry(tableID, &p4v1.FieldMatch{
		FieldId: fieldID,
		FieldMatchType: &p4v1.FieldMatch_Lpm{
			Lpm: &p4v1.FieldMatch_LPM{Value: value, PrefixLen: length},
		},
	}, actionID, params...)
}

func tableEntry(tableID uint32, match *p4v1.FieldMatch, actionID uint32,
	params ...*p4v1.Action_Param) *p4v1.TableEntry {
	return &p4v1.TableEntry{
		TableId: tableID,
		Match:   []*p4v1.FieldMatch{match},
		Action: &p4v1.TableAction{Type: &p4v1.TableAction_Action{Action: &p4v1.Action{
			ActionId: actionID,
			Params:   params,
		}}},
	}
}

func actionParam(id uint32, value []byte) *p4v1.Action_Param {
	return &p4v1.Action_Param{ParamId: id, Value: value}
}
