import datetime
import logging
import pathlib
import sys

import click

from aberdeen import Packet, Rule
from aberdeen.snort import run_snort


logger = logging.getLogger(__name__)
snort3_cfg = pathlib.Path(__file__).parent.parent / 'configs' / 'snort3.lua'


def set_verbosity(v):
    if v == 1:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    elif v >= 2:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)


def get_packets(rules_file):
    logger.info("Generating packets from rules file: %s", rules_file.name)
    rules = Rule.from_file(rules_file)
    packets = Packet.from_rule(*rules)
    hits = [p.craft_hit() for p in packets]
    miss = [p.craft_miss() for p in packets]
    pkts = hits + miss
    logger.debug("Generated %d packets", len(pkts))
    # TODO - random.shuffle(pkts)?
    return pkts


@click.command()
@click.argument('rules_file', type=click.File('r', encoding='utf-8'))
@click.option('-v', '--verbose', count=True)
def cli_app(rules_file, verbose):
    set_verbosity(verbose)
    packets = get_packets(rules_file)

    epoch = int(datetime.datetime.now().timestamp())
    input_pcap = f"test_packets.{epoch}.pcap"
    output_pcap = f"alert_packets.{epoch}.pcap"
    logger.info("Writing test packets to %s", input_pcap)
    logger.info("Writing alert packets to %s", output_pcap)

    Packet.pcap(*packets, pcap=input_pcap)
    run_snort(config=str(snort3_cfg.resolve()),
              rules=rules_file.name,
              pcap=input_pcap,
              output_pcap=output_pcap)
