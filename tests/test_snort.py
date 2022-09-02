import os

from tempfile import NamedTemporaryFile

from scapy.layers.inet import IP, TCP

from aberdeen import Packet, snort


def test_snort(packet: Packet, snort_config):
    pcap = NamedTemporaryFile(delete=False)
    with NamedTemporaryFile('w+') as rules:
        pkt = packet.craft_hit()
        Packet.pcap(pkt, pcap=pcap.name)

        rules.write(packet.rule.rule + '\n')  # write rule to file for snort
        rules.flush()
        pcap = open(pcap.name, 'rb')  # reopen pcap fd because wrpcap closes it
        scapy_cap = snort.run_snort(config=snort_config, rules=rules.name, pcap=pcap.name)
    os.remove(pcap.name)

    seen_pkt = scapy_cap[0]
    assert pkt[IP].src == seen_pkt[IP].src
    assert pkt[IP].dst == seen_pkt[IP].dst
    assert pkt[TCP].sport == seen_pkt[TCP].sport
    assert pkt[TCP].dport == seen_pkt[TCP].dport


def test_snort_count(packet: Packet, snort_config):
    pcap = NamedTemporaryFile(delete=False)
    with NamedTemporaryFile('w+') as rules:
        hits = [packet.craft_hit() for _ in range(10)]
        miss = [packet.craft_miss() for _ in range(10)]

        Packet.pcap(*hits, *miss, pcap=pcap.name)
        rules.write(packet.rule.rule + '\n')
        rules.flush()

        scapy_hits = snort.run_snort(config=snort_config, rules=rules.name, pcap=pcap.name)
    os.remove(pcap.name)

    assert len(scapy_hits) == len(hits)
