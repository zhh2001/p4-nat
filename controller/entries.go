package main

import (
	"fmt"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
)

const (
	zoneInside  = 1
	zoneOutside = 2
	zonePublic  = 3
)

type portZone struct {
	port uint64
	zone uint64
}

type destinationZone struct {
	prefix string
	length int32
	zone   uint64
}

type route struct {
	prefix string
	length int32
	port   uint64
	srcMAC string
	dstMAC string
}

type staticMapping struct {
	privateAddr string
	publicAddr  string
}

var portZones = []portZone{
	{port: 1, zone: zoneInside},
	{port: 2, zone: zoneInside},
	{port: 3, zone: zoneOutside},
}

var destinationZones = []destinationZone{
	{prefix: "10.0.1.0", length: 24, zone: zoneInside},
	{prefix: "10.0.2.0", length: 24, zone: zoneInside},
	{prefix: "192.0.2.0", length: 24, zone: zonePublic},
}

var routes = []route{
	{
		prefix: "10.0.1.0", length: 24, port: 1,
		srcMAC: "00:aa:00:00:01:01", dstMAC: "00:00:00:00:01:01",
	},
	{
		prefix: "10.0.2.0", length: 24, port: 2,
		srcMAC: "00:aa:00:00:02:01", dstMAC: "00:00:00:00:02:01",
	},
	{
		prefix: "10.0.3.0", length: 24, port: 3,
		srcMAC: "00:aa:00:00:03:01", dstMAC: "00:00:00:00:03:01",
	},
}

var staticMappings = []staticMapping{
	{privateAddr: "10.0.1.1", publicAddr: "192.0.2.1"},
	{privateAddr: "10.0.2.1", publicAddr: "192.0.2.2"},
}

func configurationEntries(pl *pipeline.Pipeline) ([]*p4v1.TableEntry, error) {
	entries := make([]*p4v1.TableEntry, 0,
		len(portZones)+len(destinationZones)+len(routes)+2*len(staticMappings))

	for _, spec := range portZones {
		entry, err := portZoneEntry(pl, spec)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	for _, spec := range destinationZones {
		entry, err := destinationZoneEntry(pl, spec)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	for _, spec := range routes {
		entry, err := routeEntry(pl, spec)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	natEntries, err := staticNATEntries(pl)
	if err != nil {
		return nil, err
	}
	entries = append(entries, natEntries...)
	return entries, nil
}

func staticNATEntries(pl *pipeline.Pipeline) ([]*p4v1.TableEntry, error) {
	entries := make([]*p4v1.TableEntry, 0, 2*len(staticMappings))
	for _, mapping := range staticMappings {
		privateAddr, err := codec.IPv4(mapping.privateAddr)
		if err != nil {
			return nil, fmt.Errorf("encode private address %s: %w", mapping.privateAddr, err)
		}
		publicAddr, err := codec.IPv4(mapping.publicAddr)
		if err != nil {
			return nil, fmt.Errorf("encode public address %s: %w", mapping.publicAddr, err)
		}

		outbound, err := tableentry.NewBuilder(pl, "nat_outbound").
			Match("private_addr", tableentry.Exact(privateAddr)).
			Action("set_public_address", tableentry.Param("public_addr", publicAddr)).
			Build()
		if err != nil {
			return nil, fmt.Errorf("build outbound NAT entry for %s: %w", mapping.privateAddr, err)
		}
		inbound, err := tableentry.NewBuilder(pl, "nat_inbound").
			Match("public_addr", tableentry.Exact(publicAddr)).
			Action("set_private_address", tableentry.Param("private_addr", privateAddr)).
			Build()
		if err != nil {
			return nil, fmt.Errorf("build inbound NAT entry for %s: %w", mapping.publicAddr, err)
		}
		entries = append(entries, outbound, inbound)
	}
	return entries, nil
}

func portZoneEntry(pl *pipeline.Pipeline, spec portZone) (*p4v1.TableEntry, error) {
	port, err := codec.EncodeUint(spec.port, 9)
	if err != nil {
		return nil, fmt.Errorf("encode ingress port %d: %w", spec.port, err)
	}
	zone, err := codec.EncodeUint(spec.zone, 2)
	if err != nil {
		return nil, fmt.Errorf("encode zone %d: %w", spec.zone, err)
	}
	entry, err := tableentry.NewBuilder(pl, "zone_by_port").
		Match("ingress_port", tableentry.Exact(port)).
		Action("set_zone", tableentry.Param("zone", zone)).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build zone entry for port %d: %w", spec.port, err)
	}
	return entry, nil
}

func destinationZoneEntry(pl *pipeline.Pipeline, spec destinationZone) (*p4v1.TableEntry, error) {
	prefix, err := codec.IPv4(spec.prefix)
	if err != nil {
		return nil, fmt.Errorf("encode destination prefix %s: %w", spec.prefix, err)
	}
	zone, err := codec.EncodeUint(spec.zone, 2)
	if err != nil {
		return nil, fmt.Errorf("encode zone %d: %w", spec.zone, err)
	}
	entry, err := tableentry.NewBuilder(pl, "destination_zone").
		Match("dst_addr", tableentry.LPM(prefix, spec.length)).
		Action("set_destination_zone", tableentry.Param("zone", zone)).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build destination zone entry for %s/%d: %w", spec.prefix, spec.length, err)
	}
	return entry, nil
}

func routeEntry(pl *pipeline.Pipeline, spec route) (*p4v1.TableEntry, error) {
	prefix, err := codec.IPv4(spec.prefix)
	if err != nil {
		return nil, fmt.Errorf("encode route prefix %s: %w", spec.prefix, err)
	}
	port, err := codec.EncodeUint(spec.port, 9)
	if err != nil {
		return nil, fmt.Errorf("encode route port %d: %w", spec.port, err)
	}
	srcMAC, err := codec.MAC(spec.srcMAC)
	if err != nil {
		return nil, fmt.Errorf("encode source MAC %s: %w", spec.srcMAC, err)
	}
	dstMAC, err := codec.MAC(spec.dstMAC)
	if err != nil {
		return nil, fmt.Errorf("encode destination MAC %s: %w", spec.dstMAC, err)
	}
	entry, err := tableentry.NewBuilder(pl, "ipv4_lpm").
		Match("dst_addr", tableentry.LPM(prefix, spec.length)).
		Action("forward",
			tableentry.Param("port", port),
			tableentry.Param("src_mac", srcMAC),
			tableentry.Param("dst_mac", dstMAC),
		).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build route entry for %s/%d: %w", spec.prefix, spec.length, err)
	}
	return entry, nil
}

func makeUpdates(entries []*p4v1.TableEntry) []*p4v1.Update {
	updates := make([]*p4v1.Update, 0, len(entries))
	for _, entry := range entries {
		updates = append(updates, client.TableEntryUpdate(client.UpdateInsert, entry))
	}
	return updates
}
