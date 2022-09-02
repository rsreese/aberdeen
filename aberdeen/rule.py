import re

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TextIO

import rstr

from aberdeen.network import Host, Port, Protocol


# https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/249/original/snort_manual.pdf p182
# alert tcp $HOME_NET any -> $EXTERNAL_NET [443,3606]
snort_regex_str = r'(?P<action>\w+) (?P<protocol>\w+) ' \
                  r'(?P<src>\S+) (?P<src_port>\S+) ' \
                  r'(?P<direction>[-<]>) ' \
                  r'(?P<dst>\S+) (?P<dst_port>\S+) ' \
                  r'(?P<options>.*)'
snort_regex = re.compile(snort_regex_str, re.DOTALL)
services = ["http"]
content_types = ["http_uri", "http_client_body", "http_cookie"]
c_types = '|'.join(content_types)
snort_regex_service = re.compile(rf'service:\s*({"|".join(services)});')
snort_regex_content = re.compile(
    # TODO - add within/before
    rf'(?:(?P<c_type>{c_types});)?\s+content:?"(?P<content>.*?)".*?;(?:\s+(?P<pcre>pcre):?"(?P<p_content>.*?)".*?;)?',
    re.DOTALL)
snort_regex_content_bytes = re.compile(r'(\|[a-fA-F0-9 ]+\|)', re.DOTALL)


# pylint: disable=too-many-instance-attributes
@dataclass
class Content(dict):
    """
    Dataclass containing collection of contents directives
    """
    _rule: str
    raw_contents: list[str] = field(init=False)
    contents: dict[str, list[bytes]] = field(init=False)
    service: str = field(init=False)

    def __post_init__(self):
        self.raw_contents = re.findall(snort_regex_content, self._rule)
        service = re.findall(snort_regex_service, self._rule)
        self.service = service[0] if service else None
        self.contents = self.parse_content(self.raw_contents)

    @staticmethod
    def parse_content(matches):
        ret = defaultdict(list)
        previous_type = 'generic'
        for c_type, content, pcre, p_content in matches:
            if c_type == '':
                c_type = previous_type
            previous_type = c_type

            # Handle content |XX| style bytes
            b_matches = re.findall(snort_regex_content_bytes, content)
            for b_match in b_matches:
                b_match_trimmed = b_match.replace('|', '')
                b = b''.join([bytes.fromhex(x) for x in b_match_trimmed.split(' ')])
                if isinstance(content, bytes):
                    content = content.replace(b_match.encode(), b)
                else:
                    content = content.encode().replace(b_match.encode(), b)

            # If `pcre` is used, replace content with a string that matches the `pcre`
            if pcre:
                # This is a really ugly way to do this but some of the special characters were terminating regex groups
                # and causing other weirdness with regex
                re_str = p_content.lstrip("/").rstrip("i").rstrip("/")
                content = rstr.xeger(re_str)

            ret[c_type].append(content)

        return ret


# pylint: disable=too-many-instance-attributes
@dataclass
class Rule(dict):
    """
    Dataclass containing parts of a Snort rule
    """
    rule: str
    action: str = field(init=False)
    protocol: Protocol = field(init=False)
    src: Host = field(init=False)
    src_port: Port = field(init=False)
    direction: str = field(init=False)
    dst: Host = field(init=False)
    dst_port: Port = field(init=False)
    content: Content = field(init=False)
    options: str = field(init=False)

    def __post_init__(self):
        match = snort_regex.match(self.rule)
        if not match:
            raise ValueError(f"Unable to parse rule from string:\n{self.rule}")

        groups = match.groupdict()

        self.action = groups.get('action')
        self.protocol = Protocol[groups.get('protocol')]

        self.src = Host(groups.get('src'))
        self.src_port = Port(groups.get('src_port'))

        self.direction = groups.get('direction')

        self.dst = Host(groups.get('dst'))
        self.dst_port = Port(groups.get('dst_port'))

        self.options = groups.get('options')

        self.content = Content(self.rule)

    @staticmethod
    def from_file(file: TextIO):
        return [Rule(line) for line in file.readlines() if line.strip()]
