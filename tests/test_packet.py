import os
import tempfile

from scapy.all import AsyncSniffer, rdpcap
from scapy.layers.inet import IP

from aberdeen.packet import Packet


def test_send_hit(rule):
    p = Packet(rule)
    pkt = p.craft_hit()
    sniffer = AsyncSniffer(
        filter=f"dst host {pkt[IP].dst}"
    )
    sniffer.start()

    Packet.send(pkt)

    pkts = sniffer.stop()
    # TODO - better prove that the packet was sent
    assert len(pkts) == 1


def test_send_miss(rule):
    p = Packet(rule)
    pkt = p.craft_hit()
    sniffer = AsyncSniffer(
        filter=f"src host {pkt[IP].dst}"
    )
    sniffer.start()

    Packet.send(pkt)

    pkts = sniffer.stop()
    # TODO - better prove that the packet was sent
    assert len(pkts) == 0


def test_send(rule):
    p = Packet(rule)
    pkts = [p.craft_hit() for _ in range(10)]
    sniffer = AsyncSniffer(
        filter=f"dst host {pkts[0][IP].dst}"
    )
    sniffer.start()

    Packet.send(*pkts)

    recv_pkts = sniffer.stop()
    # TODO - better prove that the packet was sent
    # TODO - this test sometimes fails for what I assume is due to sniffer weirdness
    assert len(pkts) == len(recv_pkts)


def test_pcap(rule):
    p = Packet(rule)
    pkts = [p.craft_hit() for _ in range(10)]
    pcap = tempfile.NamedTemporaryFile(delete=False)

    Packet.pcap(*pkts, pcap=pcap.name)
    pcap_pkts = rdpcap(pcap.name)
    os.remove(pcap.name)

    assert len(pkts) == len(pcap_pkts)
