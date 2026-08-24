import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
P4INFO = ROOT / "build" / "nat.p4info.txtpb"
BMV2_JSON = ROOT / "build" / "nat.json"

TOKEN = re.compile(
    r'''\s*(?:
        (?P<punctuation>[{}:])
        |(?P<string>"(?:\\.|[^"\\])*")
        |(?P<number>-?[0-9]+)
        |(?P<identifier>[A-Za-z_][A-Za-z0-9_.]*)
    )''',
    re.VERBOSE,
)


def parse_textproto(text):
    text = re.sub(r"(?m)^\s*#.*$", "", text)
    tokens = []
    position = 0
    while position < len(text):
        match = TOKEN.match(text, position)
        if match is None:
            if text[position:].strip() == "":
                break
            raise ValueError(f"unexpected textproto input at offset {position}")
        kind = match.lastgroup
        value = match.group(kind)
        if kind == "string":
            value = ast.literal_eval(value)
        elif kind == "number":
            value = int(value)
        tokens.append((kind, value))
        position = match.end()

    index = 0

    def parse_message(expect_close=False):
        nonlocal index
        message = {}
        while index < len(tokens):
            kind, value = tokens[index]
            if kind == "punctuation" and value == "}":
                if not expect_close:
                    raise ValueError("unexpected closing brace")
                index += 1
                return message
            if kind != "identifier":
                raise ValueError(f"expected field name, got {value!r}")
            field = value
            index += 1
            if index >= len(tokens):
                raise ValueError(f"missing value for {field}")
            kind, value = tokens[index]
            index += 1
            if kind == "punctuation" and value == "{":
                parsed = parse_message(expect_close=True)
            elif kind == "punctuation" and value == ":":
                if index >= len(tokens):
                    raise ValueError(f"missing scalar value for {field}")
                scalar_kind, parsed = tokens[index]
                index += 1
                if scalar_kind not in {"string", "number", "identifier"}:
                    raise ValueError(f"invalid scalar value for {field}")
            else:
                raise ValueError(f"expected ':' or '{{' after {field}")
            message.setdefault(field, []).append(parsed)
        if expect_close:
            raise ValueError("unterminated message")
        return message

    parsed = parse_message()
    if index != len(tokens):
        raise ValueError("unparsed textproto tokens")
    return parsed


def one(message, field):
    values = message.get(field, [])
    if len(values) != 1:
        raise ValueError(f"{field} occurs {len(values)} times, want one")
    return values[0]


def preamble_alias(entity):
    return one(one(entity, "preamble"), "alias")


def field_references(value):
    references = set()
    if isinstance(value, dict):
        if value.get("type") == "field" and isinstance(value.get("value"), list):
            references.add(tuple(value["value"]))
        for nested in value.values():
            references.update(field_references(nested))
    elif isinstance(value, list):
        for nested in value:
            references.update(field_references(nested))
    return references


def calculation_inputs(calculation):
    fields = {
        tuple(item["value"])
        for item in calculation["input"]
        if item["type"] == "field"
    }
    has_payload = any(item["type"] == "payload" for item in calculation["input"])
    has_zero_byte = any(
        item["type"] == "hexstr"
        and int(item["value"], 16) == 0
        and item.get("bitwidth") == 8
        for item in calculation["input"]
    )
    return fields, has_payload, has_zero_byte


class ArtifactTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p4info = parse_textproto(P4INFO.read_text(encoding="utf-8"))
        cls.bmv2 = json.loads(BMV2_JSON.read_text(encoding="utf-8"))

    def test_p4info_schema(self):
        self.assertEqual(one(one(self.p4info, "pkg_info"), "arch"), "v1model")

        actions = {
            preamble_alias(action): action
            for action in self.p4info.get("actions", [])
        }
        self.assertEqual(len(actions), len(self.p4info.get("actions", [])))
        expected_parameters = {
            "NoAction": {},
            "set_zone": {"zone": 2},
            "set_destination_zone": {"zone": 2},
            "set_public_address": {"public_addr": 32},
            "set_private_address": {"private_addr": 32},
            "forward": {"port": 9, "src_mac": 48, "dst_mac": 48},
        }
        self.assertEqual(set(actions), set(expected_parameters))

        action_by_id = {}
        parameter_names = {}
        for alias, action in actions.items():
            preamble = one(action, "preamble")
            action_id = one(preamble, "id")
            action_by_id[action_id] = alias
            parameters = {
                one(parameter, "name"): one(parameter, "bitwidth")
                for parameter in action.get("params", [])
            }
            self.assertEqual(parameters, expected_parameters[alias], alias)
            parameter_names[action_id] = {
                one(parameter, "id"): one(parameter, "name")
                for parameter in action.get("params", [])
            }

        tables = {
            preamble_alias(table): table
            for table in self.p4info.get("tables", [])
        }
        self.assertEqual(len(tables), len(self.p4info.get("tables", [])))
        expected_tables = {
            "zone_by_port": (
                ("ingress_port", 9, "EXACT"),
                {"set_zone", "NoAction"},
                ("NoAction", {}),
            ),
            "destination_zone": (
                ("dst_addr", 32, "LPM"),
                {"set_destination_zone"},
                ("set_destination_zone", {"zone": b"\x02"}),
            ),
            "ipv4_lpm": (
                ("dst_addr", 32, "LPM"),
                {"forward", "NoAction"},
                ("NoAction", {}),
            ),
            "nat_outbound": (
                ("private_addr", 32, "EXACT"),
                {"set_public_address", "NoAction"},
                ("NoAction", {}),
            ),
            "nat_inbound": (
                ("public_addr", 32, "EXACT"),
                {"set_private_address", "NoAction"},
                ("NoAction", {}),
            ),
        }
        self.assertEqual(set(tables), set(expected_tables))

        for alias, (expected_key, expected_actions, expected_default) in expected_tables.items():
            table = tables[alias]
            match_fields = table.get("match_fields", [])
            self.assertEqual(len(match_fields), 1, alias)
            match = match_fields[0]
            key = (
                one(match, "name"),
                one(match, "bitwidth"),
                one(match, "match_type"),
            )
            self.assertEqual(key, expected_key, alias)

            allowed_actions = {
                action_by_id[one(reference, "id")]
                for reference in table.get("action_refs", [])
            }
            self.assertEqual(allowed_actions, expected_actions, alias)

            default = one(table, "initial_default_action")
            default_id = one(default, "action_id")
            default_alias = action_by_id[default_id]
            default_arguments = {}
            for argument in default.get("arguments", []):
                parameter = parameter_names[default_id][one(argument, "param_id")]
                default_arguments[parameter] = one(argument, "value").encode("latin1")
            self.assertEqual((default_alias, default_arguments), expected_default, alias)

    def action_assignment(self, action_name, target):
        action = next(
            action for action in self.bmv2["actions"] if action["name"] == action_name
        )
        assignments = [
            primitive
            for primitive in action["primitives"]
            if primitive["op"] in {"assign", "modify_field"}
            and primitive["parameters"][0].get("type") == "field"
            and tuple(primitive["parameters"][0]["value"]) == target
        ]
        self.assertEqual(len(assignments), 1, f"{action_name} assignment to {target}")
        return action, assignments[0]["parameters"][1]

    def assert_runtime_source(self, action, source, parameter):
        self.assertEqual(source.get("type"), "runtime_data")
        index = source["value"]
        self.assertEqual(action["runtime_data"][index]["name"], parameter)

    def test_bmv2_rewrite_actions(self):
        action, source = self.action_assignment(
            "IngressImpl.set_public_address", ("ipv4", "src_addr")
        )
        self.assert_runtime_source(action, source, "public_addr")

        action, source = self.action_assignment(
            "IngressImpl.set_private_address", ("ipv4", "dst_addr")
        )
        self.assert_runtime_source(action, source, "private_addr")

        forwarding = "IngressImpl.forward"
        for target, parameter in (
            (("ethernet", "src_addr"), "src_mac"),
            (("ethernet", "dst_addr"), "dst_mac"),
            (("standard_metadata", "egress_spec"), "port"),
        ):
            action, source = self.action_assignment(forwarding, target)
            self.assert_runtime_source(action, source, parameter)

        _, ttl_source = self.action_assignment(forwarding, ("ipv4", "ttl"))
        self.assertIn(("ipv4", "ttl"), field_references(ttl_source))

    def test_bmv2_checksum_calculations(self):
        calculations = {
            calculation["name"]: calculation
            for calculation in self.bmv2["calculations"]
        }

        def matching_checksums(target, update=None, verify=None):
            matches = []
            for checksum in self.bmv2["checksums"]:
                if tuple(checksum["target"]) != target:
                    continue
                if update is not None and checksum["update"] != update:
                    continue
                if verify is not None and checksum["verify"] != verify:
                    continue
                matches.append(checksum)
            return matches

        ipv4_updates = matching_checksums(
            ("ipv4", "hdr_checksum"), update=True, verify=False
        )
        self.assertEqual(len(ipv4_updates), 1)
        ipv4_calculation = calculations[ipv4_updates[0]["calculation"]]
        self.assertEqual(ipv4_calculation["algo"], "csum16")
        ipv4_fields, ipv4_payload, _ = calculation_inputs(ipv4_calculation)
        self.assertFalse(ipv4_payload)
        self.assertTrue(
            {
                ("ipv4", "ttl"),
                ("ipv4", "src_addr"),
                ("ipv4", "dst_addr"),
            }.issubset(ipv4_fields)
        )

        tcp_updates = matching_checksums(("tcp", "checksum"), update=True, verify=False)
        self.assertEqual(len(tcp_updates), 1)
        tcp_calculation = calculations[tcp_updates[0]["calculation"]]
        self.assertEqual(tcp_calculation["algo"], "csum16")
        tcp_fields, tcp_payload, tcp_zero = calculation_inputs(tcp_calculation)
        self.assertTrue(tcp_payload)
        self.assertTrue(tcp_zero)
        self.assertTrue(
            {
                ("ipv4", "src_addr"),
                ("ipv4", "dst_addr"),
                ("ipv4", "protocol"),
                ("scalars", "metadata_t.transport_len"),
                ("tcp", "src_port"),
                ("tcp", "dst_port"),
                ("tcp", "seq_no"),
                ("tcp", "ack_no"),
                ("tcp", "data_offset"),
                ("tcp", "reserved"),
                ("tcp", "ns"),
                ("tcp", "flags"),
                ("tcp", "window"),
                ("tcp", "urgent_ptr"),
            }.issubset(tcp_fields)
        )

        udp_updates = matching_checksums(("udp", "checksum"), update=True, verify=False)
        payload_updates = []
        repair_updates = []
        for checksum in udp_updates:
            calculation = calculations[checksum["calculation"]]
            if any(item["type"] == "payload" for item in calculation["input"]):
                payload_updates.append(checksum)
            else:
                repair_updates.append(checksum)
        self.assertEqual(len(payload_updates), 1)
        self.assertEqual(len(repair_updates), 1)

        udp_calculation = calculations[payload_updates[0]["calculation"]]
        self.assertEqual(udp_calculation["algo"], "csum16")
        udp_fields, udp_payload, udp_zero = calculation_inputs(udp_calculation)
        self.assertTrue(udp_payload)
        self.assertTrue(udp_zero)
        self.assertTrue(
            {
                ("ipv4", "src_addr"),
                ("ipv4", "dst_addr"),
                ("ipv4", "protocol"),
                ("udp", "length"),
                ("udp", "src_port"),
                ("udp", "dst_port"),
            }.issubset(udp_fields)
        )
        self.assertTrue(
            any(
                field[-1] == "metadata_t.udp_checksum_present"
                for field in field_references(payload_updates[0].get("if_cond"))
            )
        )

        repair = repair_updates[0]
        repair_calculation = calculations[repair["calculation"]]
        self.assertEqual(repair_calculation["algo"], "csum16")
        repair_inputs = repair_calculation["input"]
        self.assertTrue(repair_inputs)
        self.assertTrue(
            all(
                item["type"] == "hexstr" and int(item["value"], 16) == 0
                for item in repair_inputs
            )
        )
        repair_fields = field_references(repair.get("if_cond"))
        self.assertIn(("udp", "checksum"), repair_fields)
        self.assertTrue(
            any(
                field[-1] == "metadata_t.udp_checksum_present"
                for field in repair_fields
            )
        )
        self.assertLess(
            self.bmv2["checksums"].index(payload_updates[0]),
            self.bmv2["checksums"].index(repair),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
