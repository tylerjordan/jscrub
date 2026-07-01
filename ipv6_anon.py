import ipaddress
import hashlib

# --------------------------------------------
# Prefix classification table
# --------------------------------------------

PREFIX_TYPES = [
    ("link-local", ipaddress.IPv6Network("fe80::/10")),
    ("unique-local", ipaddress.IPv6Network("fc00::/7")),
    ("multicast", ipaddress.IPv6Network("ff00::/8")),
    ("docu-prefix", ipaddress.IPv6Network("2001:db8::/32")),
    ("docu-prefix", ipaddress.IPv6Network("3fff::/20")),
    ("global-unique", ipaddress.IPv6Network("2000::/3")),
]


def classify_ipv6(addr: ipaddress.IPv6Address):
    for name, net in PREFIX_TYPES:
        if addr in net:
            return name, net
    return "unknown", None


# --------------------------------------------
# Deterministic bit generator
# --------------------------------------------

def deterministic_int(text: str, bits: int, salt: str):
    digest = hashlib.sha256(f"{salt}:{text}".encode()).digest()
    value = int.from_bytes(digest, "big")
    return value & ((1 << bits) - 1)


# --------------------------------------------
# IPv6 Anonymizer Class
# --------------------------------------------

class IPv6Anonymizer:
    def __init__(self, salt="ipv6-anon"):
        self.salt = salt
        self.network_map = {}

    # ------------------------
    # Network anonymization
    # ------------------------
    def anonymize_network(self, net: ipaddress.IPv6Network):
        net_str = str(net)

        # Return cached result if already seen
        if net_str in self.network_map:
            return self.network_map[net_str]

        addr_type, base_prefix = classify_ipv6(net.network_address)

        if base_prefix is None:
            raise ValueError(f"Unsupported IPv6 type: {net}")

        keep_bits = base_prefix.prefixlen
        variable_bits = net.prefixlen - keep_bits

        if variable_bits < 0:
            raise ValueError(f"Prefix too small for type boundary: {net}")

        # Deterministic replacement for network portion
        rand_part = deterministic_int(net_str, variable_bits, self.salt)

        base_int = int(base_prefix.network_address)

        new_network_int = (
            base_int |
            (rand_part << (128 - net.prefixlen))
        )

        new_net = ipaddress.IPv6Network(
            (new_network_int, net.prefixlen),
            strict=False
        )

        self.network_map[net_str] = new_net
        return new_net

    # ------------------------
    # Host anonymization
    # ------------------------
    def anonymize_host(self, addr: ipaddress.IPv6Address, prefixlen=64):
        """
        prefixlen determines how we detect the 'network' portion.
        Default is /64 (can be adjusted if needed).
        """

        original_net = ipaddress.IPv6Network(
            (addr, prefixlen),
            strict=False
        )

        anon_net = self.anonymize_network(original_net)

        host_bits_len = 128 - prefixlen
        host_mask = (1 << host_bits_len) - 1

        host_bits = int(addr) & host_mask

        # ✅ preserve host bits exactly
        return ipaddress.IPv6Address(
            int(anon_net.network_address) | host_bits
        )

    # ------------------------
    # Entry point
    # ------------------------
    def anonymize(self, value: str):
        if "/" in value:
            net = ipaddress.IPv6Network(value, strict=False)
            return str(self.anonymize_network(net))
        else:
            addr = ipaddress.IPv6Address(value)
            return str(self.anonymize_host(addr))