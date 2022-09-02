import logging
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy.all  # Import scapy module in order to prevent circular import issues

from .packet import Packet
from .rule import Rule

logger = logging.getLogger(__name__)
