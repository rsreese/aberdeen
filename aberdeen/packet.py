import random

from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import BinaryIO, Union

from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.sendrecv import send
from scapy.utils import wrpcap

from .network import RuleElementABC
from .rule import Protocol, Rule


class PacketType(Enum):
    MISS = 0
    HIT = 1


def _hit_miss(_type: PacketType, element: RuleElementABC):
    return +element if _type == PacketType.HIT else -element


def build_contents(service, rule_content):
    layer = ""
    if service == "http":
        # TODO - add logic for request/response
        kwargs, data = {}, b""
        for content_type, contents in rule_content.items():
            if content_type == "http_uri":
                # TODO - is there a better method than random selection?
                kwargs["Path"] = random.choice(contents)
            elif content_type == "http_client_body":
                data = "\r\n".join(contents)
            elif content_type == "http_cookie":
                kwargs["Cookie"] = contents

        layer = HTTP()/HTTPRequest(**kwargs)
        if data:
            layer /= data
    else:  # Service is None
        layer = b""
        for k, contents in rule_content.items():
            layer += b"\r\n".join(contents)

    return layer


@dataclass
class Packet:
    rule: Rule

    def craft_packet(self, _type: PacketType):
        hit_miss = partial(_hit_miss, _type)
        # get stringified ipaddress.IPv4Address
        pkt = IP(src=str(hit_miss(self.rule.src).exploded),
                 dst=str(hit_miss(self.rule.dst).exploded))

        if self.rule.protocol in [Protocol.TCP, Protocol.UDP]:
            transport = TCP if self.rule.protocol == Protocol.TCP else UDP
            pkt = pkt / transport(sport=hit_miss(self.rule.src_port),
                                  dport=hit_miss(self.rule.dst_port))
        elif self.rule.protocol == Protocol.ICMP:
            pkt = pkt / ICMP()

        content = ""
        if self.rule.content.contents:
            content = build_contents(self.rule.content.service, self.rule.content.contents)

        return pkt / content

    def craft_hit(self):
        return self.craft_packet(PacketType.HIT)

    def craft_miss(self):
        return self.craft_packet(PacketType.MISS)

    @staticmethod
    def pcap(*packet: 'Packet', pcap: Union[BinaryIO, str]):
        wrpcap(pcap, list(packet))  # TODO - do we really need to convert the tuple to a list?

    @staticmethod
    def send(*packet: 'Packet'):
        send(list(packet))

    @staticmethod
    def from_rule(*rule: Rule):
        return [Packet(r) for r in rule]
