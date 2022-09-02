import random
import socket

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Set


PORT_MIN = 1
PORT_MAX = 2**16 - 1
ALL_PORTS = set(range(PORT_MIN, PORT_MAX + 1))
APIPA_IPS = set(map(int, IPv4Network('169.254.0.0/16')))


# Snort docs identify only four supported protocols for now
class Protocol(Enum):
    """
    Enumeration of supported protocols
    """
    ip = IP = socket.IPPROTO_IP
    icmp = ICMP = socket.IPPROTO_ICMP
    tcp = TCP = socket.IPPROTO_TCP
    udp = UDP = socket.IPPROTO_UDP


@dataclass
class RuleElementABC(ABC):
    """
    Abstract base class for testable elements of a NIDS rule
    """
    raw: str
    valid: Set[int] = field(default_factory=set)
    invalid: Set[int] = field(default_factory=set)

    @abstractmethod
    def __pos__(self):
        pass

    @abstractmethod
    def __neg__(self):
        pass


@dataclass
class Port(RuleElementABC):
    """
    Network ports identified by a Rule
    """
    def __post_init__(self):
        port_strings = self.raw.strip().lstrip('!').lstrip('[').rstrip(']').split(',')
        for port in port_strings:
            if port == "any":
                ports = ALL_PORTS
            elif ":" not in port:
                ports = [int(port)]
            elif port.startswith(":"):
                p = int(port.lstrip(":"))
                ports = range(PORT_MIN, p + 1)
            elif port.endswith(":"):
                p = int(port.rstrip(":"))
                ports = range(p, PORT_MAX + 1)
            else:
                p1, p2 = port.split(":")
                ports = range(int(p1), int(p2) + 1)

            if self.raw.startswith('!') ^ port.startswith('!'):
                # XOR in case double negation is supported
                self.invalid.update(list(ports))
            else:
                self.valid.update(list(ports))

        if not self.valid:
            self.valid = ALL_PORTS - self.invalid
        if not self.invalid:
            self.invalid = ALL_PORTS - self.valid

    def __pos__(self) -> int:
        if self.valid:
            return random.choice(tuple(self.valid))

    def __neg__(self) -> int:
        if self.invalid:
            return random.choice(tuple(self.invalid))


@dataclass
class Host(RuleElementABC):
    """
    Host addresses identified by a Rule
    """
    def __post_init__(self):
        host_strings = self.raw.strip().lstrip('!').lstrip('[').rstrip(']').split(',')
        for host in host_strings:
            hosts = list(map(int, IPv4Network(host)))

            if self.raw.startswith('!') ^ host.startswith('!'):
                # XOR in case double negation is supported
                self.invalid.update(hosts)
            else:
                self.valid.update(hosts)

            if not self.valid:
                self.valid = APIPA_IPS
            if not self.invalid:
                self.invalid = APIPA_IPS

    def __pos__(self) -> IPv4Address:
        r = random.choice(tuple(self.valid))
        return IPv4Address(r)

    def __neg__(self) -> IPv4Address:
        r = random.choice(tuple(self.invalid))
        return IPv4Address(r)
