#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=locally-disabled,invalid-name

# Copyright © 2017 Étienne Noss
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.

"""Parse pcaps containing rtnetlink messages and display them.

These pcaps are typically obtained by capturing on a nlmon interface.
Assuming your kernel supports it, use 'ip link add nlmon0 type nlmon' to create
such an interface.

You can indifferently use a pcap file or tcpdump's piped output, like this:
    tcpump -i nlmon0 -w - | ./nldecap.py -
"""
from __future__ import print_function
import logging
from struct import Struct, unpack, error as StructError
from pprint import pprint
from argparse import ArgumentParser, FileType
from collections import namedtuple
from sys import stdout
from pyroute2.netlink.rtnl.marshal import MarshalRtnl
from pyroute2.netlink import nla_slot


LOG = logging.getLogger("nldecap")
LOG.addHandler(logging.StreamHandler())
LOG.setLevel(logging.INFO)

LOG_LEVELS = ("debug", "info", "warn", "warning")
MSG_MAP = {k: v.__name__ for k, v in MarshalRtnl.msg_map.items()}
MSG_TYPES = set(MSG_MAP.values())
PRINT_PREFIXES = (
    ('├─', '│ '),
    ('└─', '  ')
)

# instances of this are yielded by prefixes()
PrefixedElement = namedtuple("PrefixedElement", ("index", "prefix",
                                                 "children_prefix", "item"))


def prefixes(iterable, prefix=""):
    """Prefix iterator for tree-like printing, for nl_pprint usage.

    Yields for each item in the given iterable, a namedtuple containing:
    - The item's index, starting at 0
    - The item's prefix and children_prefix for tree-like display of
      respectively the current item and its children
    - the item itself

    Both yielded string prefixes start with the passed prefix.
    """
    last = len(iterable) - 1
    for i, item in enumerate(iterable):
        current, child = [prefix + j for j in PRINT_PREFIXES[i == last]]
        yield PrefixedElement(i, current, child, item)


def nl_pprint(obj, where=stdout, prefix=None):
    """Pretty-prints in a tree-like fashion a parsed netlink packet.

    'obj' is the object to print
    'where' is the stream it must be written to
    'prefix' is the string the object and its children must be prefixed with,
    for recursive internal use. Passing any value other than None disables the
    writing of a newline before the first element.
    """
    newline = "\n"

    # We must print a newline before writing an object, except if it's the
    # first one.
    if prefix is None:
        prefix = ""
        newline = ""

    if obj and isinstance(obj, dict):
        where.write(newline)
        for i in prefixes(obj, prefix):
            where.write("%s%s" % (i.prefix, i.item))
            nl_pprint(obj[i.item], where, i.children_prefix)
    elif obj and isinstance(obj, list):
        where.write(newline)
        for i in prefixes(obj, prefix):
            # list items are printed with their index
            where.write("%s\b[%d] " % (i.prefix, i.index))
            nl_pprint(i.item, where, i.children_prefix)
    elif obj and isinstance(obj, nla_slot):
        where.write(str(obj[0]))
        nl_pprint(obj[1], where, prefix)
    else:
        where.write(" : %s\n" % repr(obj))


class NamedStruct(Struct):
    """Struct with named fields"""
    def __init__(self, fmt, fields):
        self._ntuple = namedtuple(type(self).__name__, fields)
        super(NamedStruct, self).__init__(fmt)
        Struct.__init__(self, fmt)

    def unpack(self, data):
        """Like Struct.unpack, but returns a namedtuple"""
        return self._ntuple(*Struct.unpack(self, data))

    def unpack_from(self, data):
        """Like Struct.unpack_from, but returns a namedtuple"""
        return self._ntuple(*Struct.unpack_from(self, data))


# direction ll_type ? family
NetlinkCookedHeader = NamedStruct("!HH10sH", "dir ll_type dunno family")


class PcapError(Exception):
    """Raised by NLPcap when there are issues with the pcap file"""
    pass


class NLPcap(object):  # pylint: disable=too-few-public-methods
    """Netlink pcaps parser.
    Takes a pcap file descriptor, and allows using the resulting object as an
    iterator that yields each packet's contents.
    """
    # typedef struct pcap_hdr_s {
    #         guint32 magic_number;  /* magic number */
    #         guint16 version_major; /* major version number */
    #         guint16 version_minor; /* minor version number */
    #         gint32  thiszone;      /* GMT to local correction */
    #         guint32 sigfigs;       /* accuracy of timestamps */
    #         guint32 snaplen;       /* max length of packets in octets */
    #         guint32 network;       /* data link type */
    # } pcap_hdr_t;
    PCAP_HEADER_FMT = "IHHiIII"
    PCAP_HEADER_FIELDS = "magic v_maj v_min zone sig snap network"

    # typedef struct pcaprec_hdr_s {
    #         guint32 ts_sec;        /* timestamp seconds */
    #         guint32 ts_usec;       /* timestamp microseconds */
    #         guint32 incl_len;      /* number of octets of packet in file */
    #         guint32 orig_len;      /* actual length of packet */
    # } pcaprec_hdr_t;
    PKT_HEADER_FMT = "IIII"
    PKT_HEADER_FIELDS = "ts_sec ts_usec incl_len orig_len"

    def __init__(self, pcap_fd):
        """Reads the pcap file header to check if it is valid."""
        self.pcap_fd = pcap_fd
        # Incremented for each packet
        self.pkt_count = 0
        # Read the header to check the magic number, which also happens to tell
        # us the pcap file's endianness
        header_data = self.pcap_fd.read(24)  # sizeof(pcap_hdr_t)
        # The first 4 bytes of the file are the magic number
        magic = unpack("I", header_data[:4])[0]
        if magic == 0xa1b2c3d4:  # Little-endian
            endianness = "<"
        elif magic == 0xd4c3b2a1:  # Big-endian
            endianness = ">"
        else:
            raise PcapError("not a pcap or unimplemented type (0x%x)" % magic)

        # Use the right parsers for the pcap's endianness
        pcap_header_cls = NamedStruct(endianness + self.PCAP_HEADER_FMT,
                                      self.PCAP_HEADER_FIELDS)
        self.pkt_header_cls = NamedStruct(endianness + self.PKT_HEADER_FMT,
                                          self.PKT_HEADER_FIELDS)

        # Check the pcap type
        pcap_header = pcap_header_cls.unpack(header_data)
        if pcap_header.network != 253:
            raise PcapError("pcap link type isn't netlink")

    def __iter__(self):
        """Yields the contents valid netlink packets in the pcap file."""
        while True:
            self.pkt_count += 1
            pkt_header_data = self.pcap_fd.read(self.pkt_header_cls.size)
            if len(pkt_header_data) < self.pkt_header_cls.size:
                LOG.info("reached EOF")
                break
            pkt_hdr = self.pkt_header_cls.unpack(pkt_header_data)

            # Check that whole packets were captured
            if pkt_hdr.incl_len < pkt_hdr.orig_len:
                LOG.warn("[packet %d] incomplete (%d/%d bytes), skipping",
                         self.pkt_count, pkt_hdr.incl_len, pkt_hdr.orig_len)
                continue
            if pkt_hdr.incl_len <= NetlinkCookedHeader.size:
                # skip empty or too small packets
                LOG.debug("[packet %d] too small (%d bytes), skipped",
                          self.pkt_count, pkt_hdr.incl_len)
                continue

            # Read data from the packet
            pkt_data = self.pcap_fd.read(pkt_hdr.incl_len)

            # Read a netlink header
            nl_hdr = NetlinkCookedHeader.unpack_from(pkt_data)
            pkt_data = pkt_data[NetlinkCookedHeader.size:]

            # we only want rtnetlink packets
            # TODO: parse other packet types ?
            if nl_hdr.family != 0x0000:
                LOG.debug("[packet %d] unhandled netlink type 0x%04x, skipped",
                          self.pkt_count, nl_hdr.family)
                continue
            # Should not happen because the link type for the capture
            # is already netlink
            if nl_hdr.ll_type != 0x0338:
                LOG.info("[packet %d] not a Netlink packet, skipped",
                         self.pkt_count)
                continue
            yield pkt_data


def main():
    """Parse arguments, read the pcap and parse nl packets with pyroute2"""
    psr = ArgumentParser(description=__doc__.splitlines()[0])
    psr.add_argument("pcap", type=FileType("rb"),
                     help="The pcap file to read, or - for stdin")
    psr.add_argument("-p", "--pprint",
                     help="use pprint() for pretty-printing messages instead "
                          "of the builtin tree-like display",
                     default=False, action="store_true")
    psr.add_argument("-l", "--log-level", choices=LOG_LEVELS, default="info",
                     help="Log level. 'info' (the default) prints a header "
                          "for each packet, 'debug' prints information about "
                          "skipped packets, 'warn' only prints packet or "
                          "message decoding errors.")
    psr.add_argument("filter", nargs="*",
                     help="Only display messages of this type. "
                          "Can be specified multiple times.")
    args = psr.parse_args()
    for i in args.filter:
        if i not in MSG_TYPES:
            psr.error("Invalid filter '%s' (choose from %s)" % (i, MSG_TYPES))

    LOG.setLevel(args.log_level.upper())

    # Open the pcap file (read its header)
    try:
        pcap_file = NLPcap(args.pcap)
    except PcapError as pce:
        psr.error("%r: %s" % (args.pcap.name, pce))

    # Use the built in marshal for decoding
    marshal = MarshalRtnl()

    # The function that will be used for printing
    print_func = pprint if args.pprint else nl_pprint

    # Loop over the pcap file
    for packet in pcap_file:
        # Parse the packet content and display all contained messages
        try:
            messages = marshal.parse(packet)
        except StructError:
            LOG.warn("[packet %d] could not parse %r",
                     pcap_file.pkt_count, packet)
            continue

        for msg_num, msg in enumerate(messages, start=1):
            msg_type = MSG_MAP.get(msg["header"]["type"], "unknown type")
            if args.filter and msg_type not in args.filter:
                continue

            LOG.info("[packet %d] message %d (%s)",
                     pcap_file.pkt_count, msg_num, msg_type)
            print_func(msg)


if __name__ == "__main__":
    main()
