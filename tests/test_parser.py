# from pathlib import Path
#
#
# example_rule_path = Path().parent / "snort-rules/sunburst-malware-cnc.rules"
# example_rules = example_rule_path.read_text("utf-8").splitlines()

import re

import pytest

from aberdeen.rule import Rule
from aberdeen.network import Protocol

test_rule = """alert tcp 10.0.0.0/24 any -> !10.0.0.0/24 [443,3606] (msg:"MALWARE-CNC Win.Trojan.Agent variant 
outbound connection"; flow:to_server,established; content:"|00 00 00 E2 DA A6 7E FB F2 28 DC C7 E5 BA 6B|"; 
fast_pattern:only; metadata:impact_flag red, policy balanced-ips drop, policy max-detect-ips drop, 
policy security-ips drop; reference:url,
virustotal.com/#/file/ea4e1a46f8b3cb759b77ccca7269371f3cf72d42b76b4cba566678369495efca; classtype:trojan-activity; 
sid:48868; rev:1;) """
test_rule_2 = """alert tcp 10.0.0.0/24 any -> !10.0.0.0/24 [443,3606] ( msg:"MALWARE-CNC Win.Backdoor.Sunburst 
outbound connection attempt"; flow:to_server,established; http_client_body; 
content:"|0D 0A 0D 0A|name=|22|",fast_pattern,nocase; content:"|22 3B|filename=|22|",nocase; 
content:"|22 0A|Content-Type:",nocase; metadata:impact_flag red,policy max-detect-ips drop,policy security-ips drop; 
service:http; 
http_cookie; content:"X-AnonResource-Backend=",nocase; 
pcre:"/X-AnonResource-Backend=[^\x3b]*?([\x5d\x40\x23\x2f]|:444)/i";
reference:url,www.virustotal.com/gui/file/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77; 
classtype:trojan-activity; sid:56668; rev:1; )"""


def test_parser_basic():
    rule = Rule(test_rule)

    assert rule.rule == test_rule
    assert rule.action == "alert"
    assert rule.protocol == Protocol['tcp']

    assert rule.src.raw == "10.0.0.0/24"
    assert rule.src_port.raw == "any"

    assert rule.direction == "->"

    assert rule.dst.raw == "!10.0.0.0/24"
    assert rule.dst_port.raw == "[443,3606]"

    assert rule.options == test_rule[test_rule.index('('):]


def test_parser_advanced():
    rule = Rule(test_rule_2)

    assert rule.rule == test_rule_2
    assert rule.action == "alert"
    assert rule.protocol == Protocol['tcp']

    assert rule.src.raw == "10.0.0.0/24"
    assert rule.src_port.raw == "any"

    assert rule.direction == "->"

    assert rule.dst.raw == "!10.0.0.0/24"
    assert rule.dst_port.raw == "[443,3606]"

    assert b"\x0D\x0A\x0D\x0Aname=\x22" in rule.content.contents["http_client_body"]
    assert b"\x22\x3Bfilename=\x22" in rule.content.contents["http_client_body"]
    assert b"\x22\x0AContent-Type:" in rule.content.contents["http_client_body"]

    pat = re.compile(r"X-AnonResource-Backend=[^\x3b]*?([\x5d\x40\x23\x2f]|:444)")
    matches = list(filter(pat.match, rule.content.contents["http_cookie"]))
    print(rule.content.contents["http_cookie"])
    assert matches
