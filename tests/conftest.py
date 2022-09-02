import pathlib

import pytest

from aberdeen import Packet, Rule


GENERIC_RULE = """alert tcp 172.16.255.100 any -> 172.16.255.101 [443,3606] (msg:"443 incoming";)"""
ADVANCED_RULE = """alert tcp 172.16.255.100 any -> 172.16.255.101 [443,3606] ( msg:"MALWARE";
content:"|0D 0A 0D 0A|name=|22|",fast_pattern,nocase; content:"|22 3B|filename=|22|",nocase; 
content:"|22 0A|Content-Type:",nocase; )"""

snort3_cfg = pathlib.Path(__file__).parent.parent / 'configs' / 'snort3.lua'


@pytest.fixture
def snort_config():
    return snort3_cfg


@pytest.fixture(params=[GENERIC_RULE, ADVANCED_RULE])
def rule(request):
    return Rule(request.param)


@pytest.fixture
def packet(rule):
    return Packet(rule)
