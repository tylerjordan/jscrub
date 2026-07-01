#!/usr/bin/env python3

import hashlib
import ipaddress
import json
import re
from pathlib import Path


class DocumentIPAnonymizer:

    IPV6_PREFIXES = [
        ("link-local", ipaddress.IPv6Network("fe80::/10")),
        ("unique-local", ipaddress.IPv6Network("fc00::/7")),
        ("multicast", ipaddress.IPv6Network("ff00::/8")),
        ("docu", ipaddress.IPv6Network("2001:db8::/32")),
        ("docu", ipaddress.IPv6Network("3fff::/20")),
        ("global", ipaddress.IPv6Network("2000::/3")),
    ]

    IPV4_PREFIXES = [
        ("private10", ipaddress.IPv4Network("10.0.0.0/8")),
        ("shared", ipaddress.IPv4Network("100.64.0.0/10")),
        ("loopback", ipaddress.IPv4Network("127.0.0.0/8")),
        ("linklocal", ipaddress.IPv4Network("169.254.0.0/16")),
        ("private172", ipaddress.IPv4Network("172.16.0.0/12")),
        ("private192", ipaddress.IPv4Network("192.168.0.0/16")),
        ("docu", ipaddress.IPv4Network("192.0.2.0/24")),
        ("benchmark", ipaddress.IPv4Network("198.18.0.0/15")),
        ("docu", ipaddress.IPv4Network("198.51.100.0/24")),
        ("docu", ipaddress.IPv4Network("203.0.113.0/24")),
        ("multicast", ipaddress.IPv4Network("224.0.0.0/4")),
        ("reserved", ipaddress.IPv4Network("240.0.0.0/4")),
        ("public", ipaddress.IPv4Network("0.0.0.0/0")),
    ]

    TOKEN_RE = re.compile(
        r"""
        (?:
            (?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?
        )
        |
        (?:
            [0-9A-Fa-f:]+:+[0-9A-Fa-f:]*
            (?:/\d{1,3})?
        )
        """,
        re.VERBOSE,
    )

    def __init__(self, salt="ip-anonymizer"):
        self.salt = salt

        self.network_map_v4 = {}
        self.network_map_v6 = {}

        self.replacement_map = {}

    def deterministic_int(self, text, bits):
        if bits <= 0:
            return 0

        digest = hashlib.sha256(
            f"{self.salt}:{text}".encode()
        ).digest()

        return int.from_bytes(digest, "big") & (
            (1 << bits) - 1
        )

    def classify_prefix(self, network):

        table = (
            self.IPV6_PREFIXES
            if network.version == 6
            else self.IPV4_PREFIXES
        )

        for _, prefix in table:
            if network.network_address in prefix:
                return prefix

        return None

    def anonymize_network(self, network):

        cache = (
            self.network_map_v6
            if network.version == 6
            else self.network_map_v4
        )

        key = str(network)

        if key in cache:
            return cache[key]

        base_prefix = self.classify_prefix(network)

        if base_prefix is None:
            cache[key] = network
            return network

        keep_bits = base_prefix.prefixlen

        if network.prefixlen < keep_bits:
            cache[key] = network
            return network

        variable_bits = network.prefixlen - keep_bits

        random_value = self.deterministic_int(
            key,
            variable_bits
        )

        new_network_int = (
            int(base_prefix.network_address)
            |
            (
                random_value
                << (network.max_prefixlen - network.prefixlen)
            )
        )

        anonymized_network = type(network)(
            (
                new_network_int,
                network.prefixlen
            ),
            strict=False
        )

        cache[key] = anonymized_network

        return anonymized_network

    def discover_networks(self, tokens):

        discovered = []

        for token in tokens:

            if "/" not in token:
                continue

            try:
                net = ipaddress.ip_network(
                    token,
                    strict=True
                )

                discovered.append(net)

            except Exception:
                pass

        discovered.sort(
            key=lambda n: (
                n.version,
                n.prefixlen
            ),
            reverse=True
        )

        for network in discovered:
            self.anonymize_network(network)

    def find_parent_network(self, address):

        cache = (
            self.network_map_v6
            if address.version == 6
            else self.network_map_v4
        )

        best = None

        for net_string in cache:

            net = ipaddress.ip_network(net_string)

            if address in net:
                if (
                    best is None
                    or
                    net.prefixlen > best.prefixlen
                ):
                    best = net

        return best

    def anonymize_host(self, address):

        parent = self.find_parent_network(address)

        if parent is None:
            return str(address)

        cache = (
            self.network_map_v6
            if address.version == 6
            else self.network_map_v4
        )

        anon_network = cache[str(parent)]

        offset = (
            int(address)
            - int(parent.network_address)
        )

        anon_address = type(address)(
            int(anon_network.network_address)
            + offset
        )

        return str(anon_address)

    def anonymize_interface(self, interface):

        parent = self.find_parent_network(interface.ip)

        if parent is None:
            return str(interface)

        cache = (
            self.network_map_v6
            if interface.version == 6
            else self.network_map_v4
        )

        anon_network = cache[str(parent)]

        offset = (
            int(interface.ip)
            - int(parent.network_address)
        )

        anon_ip = type(interface.ip)(
            int(anon_network.network_address)
            + offset
        )

        return (
            f"{anon_ip}/"
            f"{interface.network.prefixlen}"
        )

    def determine_object_type(self, token):

        if "/" not in token:
            return "host"

        try:

            addr_part = token.split("/")[0]

            if ":" in addr_part:

                iface = ipaddress.IPv6Interface(token)

                if addr_part.lower() == str(
                    iface.network.network_address
                ).lower():
                    return "network"

                return "interface"

            iface = ipaddress.IPv4Interface(token)

            if addr_part == str(
                iface.network.network_address
            ):
                return "network"

            return "interface"

        except Exception:
            return None

    def anonymize_token(self, token):

        obj_type = self.determine_object_type(token)

        if obj_type is None:
            return token

        if obj_type == "network":

            network = ipaddress.ip_network(
                token,
                strict=True
            )

            return str(
                self.anonymize_network(network)
            )

        if obj_type == "interface":

            if ":" in token:
                iface = ipaddress.IPv6Interface(token)
            else:
                iface = ipaddress.IPv4Interface(token)

            return self.anonymize_interface(iface)

        address = ipaddress.ip_address(token)

        return self.anonymize_host(address)

    def extract_tokens(self, text):

        found = set()

        for match in self.TOKEN_RE.finditer(text):

            token = match.group(0)

            try:

                if "/" in token:

                    addr = token.split("/")[0]

                    if ":" in addr:
                        ipaddress.IPv6Interface(token)
                    else:
                        ipaddress.IPv4Interface(token)

                else:

                    ipaddress.ip_address(token)

                found.add(token)

            except Exception:
                pass

        return found

    def build_replacement_map(self, text):

        tokens = self.extract_tokens(text)

        self.discover_networks(tokens)

        replacements = {}

        for token in tokens:

            try:
                replacements[token] = (
                    self.anonymize_token(token)
                )

            except Exception:
                pass

        self.replacement_map = replacements

    def rewrite_text(self, text):

        replacements = sorted(
            self.replacement_map.items(),
            key=lambda item: len(item[0]),
            reverse=True
        )

        for original, replacement in replacements:

            text = re.sub(
                rf'(?<![0-9A-Fa-f:.]){re.escape(original)}(?![0-9A-Fa-f:.])',
                replacement,
                text
            )

        return text

    def save_mapping_json(self, filename):

        data = {
            "metadata": {
                "salt": self.salt,
                "version": 1
            },
            "networks": {},
            "reverse_networks": {}
        }

        combined = {}

        combined.update(self.network_map_v4)
        combined.update(self.network_map_v6)

        for original, anonymous in combined.items():

            data["networks"][original] = str(anonymous)

            data["reverse_networks"][
                str(anonymous)
            ] = original

        with open(filename, "w") as f:
            json.dump(
                data,
                f,
                indent=2
            )

    def anonymize_file(
        self,
        input_file,
        output_file,
        mapping_file
    ):

        text = Path(input_file).read_text(
            encoding="utf-8"
        )

        self.build_replacement_map(text)

        anonymized_text = self.rewrite_text(text)

        Path(output_file).write_text(
            anonymized_text,
            encoding="utf-8"
        )

        self.save_mapping_json(mapping_file)

        print(f"Input     : {input_file}")
        print(f"Output    : {output_file}")
        print(f"Mappings  : {mapping_file}")


if __name__ == "__main__":

    anonymizer = DocumentIPAnonymizer(
        salt="my-secret-salt"
    )

    anonymizer.anonymize_file(
        input_file="network_doc.txt",
        output_file="network_doc_anon.txt",
        mapping_file="network_doc_mapping.json"
    )