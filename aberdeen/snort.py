import glob
import logging
import os
import shlex

from tempfile import TemporaryDirectory
from typing import Union

from scapy.plist import PacketList
from scapy.utils import rdpcap

from subprocess import PIPE, Popen


logger = logging.getLogger(__name__)

TIMEOUT = 30


def run_snort(*, config: str, rules: str, pcap: str, output_pcap: str = None) -> Union[PacketList, str]:
    logger.info("Analyzing packets with Snort")
    with TemporaryDirectory() as tdir:
        cmd_str = f'snort -c {config} -r {pcap} -R {rules} -l {tdir}'
        cmd = shlex.split(cmd_str)
        logger.debug("Running command: %s", cmd_str)
        p = Popen(cmd, stderr=PIPE, stdout=PIPE)
        try:
            out, err = p.communicate(timeout=TIMEOUT)
        except TimeoutError:
            logger.warn("Subprocess timed out after %d seconds... Cleaning up", TIMEOUT)
            p.kill()
            out, err = p.communicate()

        # TODO - is there a better way to grab the alert file?
        logs = glob.glob(f"{tdir}/log.pcap.*")
        try:
            tmp_pcap = logs[0]
            pcap_log = open(tmp_pcap, 'rb')
        except IndexError:
            raise ValueError(f"Snort didn't generate an output file")

        if p.returncode != 0:
            logger.error("Subprocess exited with status %d", p.returncode)
            raise ValueError(f"Snort exited with status {p.returncode}\n{out.decode('utf-8')}\n{err.decode('utf-8')}")

        if output_pcap:
            logger.debug("Renaming temporary pcap to %s", output_pcap)
            os.rename(tmp_pcap, output_pcap)
            return output_pcap

        logger.debug("Returning Scapy PacketList from pcap")
        return rdpcap(pcap_log)
