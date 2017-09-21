#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=invalid-name
"""Test module for the nldecap script"""
import unittest
import os.path
import sys
from contextlib import contextmanager
import nldecap

PCAPS_DIR = os.path.join(os.path.dirname(sys.modules[__name__].__file__),
                         "pcaps")


def get_pcap_path(name):
    """Given a pcap's name in the test directory, returns its full path."""
    return os.path.join(PCAPS_DIR, name)


@contextmanager
def open_pcap(name):
    """Given a pcap's name in the test directory, returns a file handle to it.
    """
    fullpath = get_pcap_path(name)
    fd = open(fullpath, "rb")
    yield fd
    fd.close()


class NLPcapTests(unittest.TestCase):
    """Tests the NLPcap class"""
    def test_valid_pcap(self):
        """Valid big and little endian pcaps must be properly parsed"""
        for pcapfile in "two_packets_be.pcap", "two_packets_le.pcap":
            with open_pcap(pcapfile) as fd:
                pcap = nldecap.NLPcap(fd)
                family, packet = next(pcap)
                # The first packet's payoad is 20 bytes long
                self.assertEquals(len(packet), 20)

                family2, packet2 = next(pcap)
                # The second packet's payoad is 256 bytes long
                self.assertEquals(len(packet2), 256)

                with self.assertRaises(StopIteration):
                    next(pcap)

                # The pcap contains two packets
                self.assertEquals(pcap.pkt_count, 2)

    def test_non_netlink_pcap(self):
        """Non-netlink but valid pcaps raise PcapError"""
        for pcapfile in "1pkt_not_netlink_le.pcap", "1pkt_not_netlink_be.pcap":
            with open_pcap(pcapfile) as fd:
                with self.assertRaises(nldecap.PcapError):
                    _ = nldecap.NLPcap(fd)

    def test_empty_file(self):
        """Empty files must raise PcapError"""
        with open_pcap("emptyfile") as fd:
            with self.assertRaises(nldecap.PcapError):
                _ = nldecap.NLPcap(fd)

    def test_random_file(self):
        """Non-pcap files must raise PcapError"""
        with open_pcap("garbage") as fd:
            with self.assertRaises(nldecap.PcapError):
                _ = nldecap.NLPcap(fd)


class ScriptTests(unittest.TestCase):
    """Tests calls to main() (when called as a script)"""
    @staticmethod
    def call_main(*args):
        """shorthand for nldecap.main()
        TODO: redirect std{in,out,err}
        """
        return nldecap.main(args)

    def test_basic_usage(self):
        """main() called with a simple pcap must return 0"""
        ret = self.call_main(get_pcap_path("two_packets_le.pcap"))
        self.assertEqual(ret, 0)

    def test_non_netlink_pcap(self):
        """main() called with a non-netlink pcap must exit unsuccessfully"""
        with self.assertRaises(SystemExit):
            self.call_main(get_pcap_path("1pkt_not_netlink_le.pcap"))

    def test_no_args(self):
        """main() called without arguments must exit unsuccessfully"""
        with self.assertRaises(SystemExit):
            self.call_main()


if __name__ == '__main__':
    unittest.main(verbosity=2)
