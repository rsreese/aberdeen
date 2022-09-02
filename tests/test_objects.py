from ipaddress import IPv4Network

from aberdeen.network import Host, Port, Protocol


# alert tcp $HOME_NET any -> $EXTERNAL_NET [443,3606]


def test_port():
    port = Port("[443,3606]")
    valid = {443, 3606}
    assert valid.issubset(port.valid)

    valid_port = +port
    assert valid_port in valid
    assert valid_port in port.valid
    assert valid_port not in port.invalid

    invalid_port = -port
    assert invalid_port not in valid
    assert invalid_port in port.invalid
    assert invalid_port not in port.valid


def test_negated_port():
    port = Port("![443,3606]")
    invalid = {443, 3606}
    assert invalid.issubset(port.invalid)

    valid_port = +port
    assert valid_port not in invalid
    assert valid_port in port.valid
    assert valid_port not in port.invalid

    invalid_port = -port
    assert invalid_port in invalid
    assert invalid_port in port.invalid
    assert invalid_port not in port.valid


def test_host():
    host = Host("10.0.0.0/24")
    valid = IPv4Network("10.0.0.0/24")

    valid_host = +host
    assert valid_host in valid
    assert int(valid_host) in host.valid
    assert int(valid_host) not in host.invalid

    invalid_host = -host
    assert invalid_host not in valid
    assert int(invalid_host) in host.invalid
    assert int(invalid_host) not in host.valid


def test_host_negated():
    host = Host("!10.0.0.0/24")
    invalid = IPv4Network("10.0.0.0/24")

    valid_host = +host
    assert valid_host not in invalid
    assert int(valid_host) in host.valid
    assert int(valid_host) not in host.invalid

    invalid_host = -host
    assert invalid_host in invalid
    assert int(invalid_host) in host.invalid
    assert int(invalid_host) not in host.valid
