#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=locally-disabled,invalid-name
# FIXME endianness issues (probably)

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
from struct import Struct, error as StructError
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


# typedef struct pcap_hdr_s {
#         guint32 magic_number;  /* magic number */
#         guint16 version_major; /* major version number */
#         guint16 version_minor; /* minor version number */
#         gint32  thiszone;      /* GMT to local correction */
#         guint32 sigfigs;       /* accuracy of timestamps */
#         guint32 snaplen;       /* max length of captured packets in octets */
#         guint32 network;       /* data link type */
# } pcap_hdr_t;
PcapHeader = NamedStruct("IHHiIII", "magic v_maj v_min zone sig snap network")

# typedef struct pcaprec_hdr_s {
#         guint32 ts_sec;        /* timestamp seconds */
#         guint32 ts_usec;       /* timestamp microseconds */
#         guint32 incl_len;      /* number of octets of packet saved in file */
#         guint32 orig_len;      /* actual length of packet */
# } pcaprec_hdr_t;
PcapPacketHeader = NamedStruct("IIII", "ts_sec ts_usec incl_len orig_len")


# direction ll_type ? family
NetlinkCookedHeader = NamedStruct("!HH10sH", "dir ll_type dunno family")


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

    # Is this a valid pcap
    pcap_header = PcapHeader.unpack(args.pcap.read(PcapHeader.size))
    if pcap_header.magic != 0xa1b2c3d4:
        psr.error("'%s': not a pcap or unimplemented type" % args.pcap.name)
    if pcap_header.network != 253:
        psr.error("'%s': pcap link type isn't netlink" % args.pcap.name)

    # Use the built in marshal for decoding
    marshal = MarshalRtnl()

    # The function that will be used for printing
    print_func = pprint if args.pprint else nl_pprint

    # Loop as long as we don't hit EOF
    pkt_count = 0
    while True:
        pkt_count += 1
        # Read a pcap packet header
        raw_header = args.pcap.read(PcapPacketHeader.size)
        if len(raw_header) < PcapPacketHeader.size:
            LOG.info("reached EOF")
            break

        pkt_hdr = PcapPacketHeader.unpack(raw_header)
        # Check that whole packets were captured
        if pkt_hdr.incl_len < pkt_hdr.orig_len:
            LOG.warn("[packet %d] incomplete (%d/%d bytes), skipping",
                     pkt_count, pkt_hdr.incl_len, pkt_hdr.orig_len)
            continue
        if pkt_hdr.incl_len <= NetlinkCookedHeader.size:
            # skip empty or too small packets
            LOG.debug("[packet %d] too small (%d bytes), skipped",
                      pkt_hdr.pkt_count, pkt_hdr.incl_len)
            continue

        # Read data from the packet
        pkt_data = args.pcap.read(pkt_hdr.incl_len)

        # Read a netlink header
        nl_hdr = NetlinkCookedHeader.unpack_from(pkt_data)
        pkt_data = pkt_data[NetlinkCookedHeader.size:]

        # we only want rtnetlink packets
        # TODO: parse other packet types ?
        if nl_hdr.family != 0x0000:
            LOG.debug("[packet %d] unhandled netlink type 0x%04x, skipped",
                      pkt_count, nl_hdr.family)
            continue
        # Should not happen as the link type for the capture is already netlink
        if nl_hdr.ll_type != 0x0338:
            LOG.info("[packet %d] not a Netlink packet, skipped", pkt_count)
            continue

        # Parse the packet content and display all contained messages
        try:
            messages = marshal.parse(pkt_data)
        except StructError:
            LOG.warn("[packet %d] could not parse %r", pkt_count, pkt_data)
            continue

        for msg_num, msg in enumerate(messages, start=1):
            msg_type = MSG_MAP.get(msg["header"]["type"], "unknown type")
            if args.filter and msg_type not in args.filter:
                continue

            LOG.info("[packet %d] message %d (%s)",
                     pkt_count, msg_num, msg_type)
            print_func(msg)


if __name__ == "__main__":
    main()
