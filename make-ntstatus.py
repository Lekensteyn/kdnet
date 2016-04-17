#!/usr/bin/env python
# Generate a mapping from NTSTATUS codes to their names
# Usage: ./make-ntstatus.py --out ntstatus.lua
from __future__ import print_function
import argparse, os.path, sys

import requests
from lxml import html

def get_statuses(html_text):
    root = html.fromstring(html_text)
    for td in root.findall(".//td[@data-th][p]"):
        if "Return value/code" not in td.attrib["data-th"]:
            continue
        code = td.find("./p[1]").text
        status = td.find("./p[2]").text
        yield int(code, 16), status

def write_to_file(statuses, out, source):
    print("-- Generated from %s" % source, file=out)
    print("return {", file=out)
    seen = {}
    for code, status in get_statuses(html_text):
        if code not in seen:
            print("    [0x%08x] = \"%s\"," % (code, status), file=out)
            seen[code] = 1
    print("}", file=out)

parser = argparse.ArgumentParser()
parser.add_argument("--cache", metavar="FILE", help="Cache remote file")
parser.add_argument("--url",
        default="https://msdn.microsoft.com/en-us/library/cc704588.aspx")
parser.add_argument("--out", metavar="file.lua",
        help="Output file (default stdout)")

args = parser.parse_args()
if args.cache and os.path.exists(args.cache):
    html_text = open(args.cache).read()
else:
    html_text = requests.get(args.url).text
    if args.cache:
        open(args.cache, "w").write(html_text)

write_to_file(
    get_statuses(html_text),
    sys.stdout if args.out in (None, "-") else open(args.out, "w"),
    args.url
)
