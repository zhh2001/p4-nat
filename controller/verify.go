package main

import (
	"encoding/hex"
	"fmt"
	"sort"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/protobuf/proto"
)

func verifyEntries(expected, actual []*p4v1.TableEntry) error {
	want, err := entryMultiset(expected)
	if err != nil {
		return fmt.Errorf("invalid expected entry: %w", err)
	}
	got, err := entryMultiset(actual)
	if err != nil {
		return fmt.Errorf("invalid readback entry: %w", err)
	}

	for key, count := range want {
		if got[key] < count {
			return fmt.Errorf("missing entry %s", entrySummary(key))
		}
	}
	for key, count := range got {
		if want[key] < count {
			return fmt.Errorf("unexpected entry %s", entrySummary(key))
		}
	}
	return nil
}

func entryMultiset(entries []*p4v1.TableEntry) (map[string]int, error) {
	set := make(map[string]int, len(entries))
	for i, entry := range entries {
		if entry == nil {
			return nil, fmt.Errorf("entry %d is nil", i)
		}
		normalized := proto.Clone(entry).(*p4v1.TableEntry)
		normalized.TimeSinceLastHit = nil
		sort.Slice(normalized.Match, func(i, j int) bool {
			return normalized.Match[i].GetFieldId() < normalized.Match[j].GetFieldId()
		})
		action := normalized.GetAction().GetAction()
		if action != nil {
			sort.Slice(action.Params, func(i, j int) bool {
				return action.Params[i].GetParamId() < action.Params[j].GetParamId()
			})
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
		if err != nil {
			return nil, fmt.Errorf("marshal entry %d: %w", i, err)
		}
		set[string(encoded)]++
	}
	return set, nil
}

func entrySummary(key string) string {
	entry := &p4v1.TableEntry{}
	if err := proto.Unmarshal([]byte(key), entry); err != nil {
		return hex.EncodeToString([]byte(key))
	}
	actionID := uint32(0)
	if action := entry.GetAction().GetAction(); action != nil {
		actionID = action.GetActionId()
	}
	return fmt.Sprintf("table_id=%d action_id=%d matches=%d", entry.GetTableId(), actionID, len(entry.GetMatch()))
}
