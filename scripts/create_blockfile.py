#!/usr/bin/env python

import json
import sys
import urllib2

from disconnect_mapping import disconnect_mapping

def write_header_file(output_file, output):
    """Writes the header file containing the block rules in c++
       This function is awful but works for now. Maybe move to another file.
    """
    entry_count = len(output)
    output_file.write(r"""#ifndef NET_URL_REQUEST_TPFILTER_ENTRIES_H_
#define NET_URL_REQUEST_TPFILTER_ENTRIES_H_

namespace net {

#define TPFILTER_FLAG_EXCEPTION 1
#define TPFILTER_FLAG_MATCH_DOMAIN 2
#define TPFILTER_FLAG_MATCH_BEGIN 4
#define TPFILTER_FLAG_MATCH_END 8
#define TPFILTER_FLAG_HAS_WILDCARD 16
#define TPFILTER_FLAG_HAS_SEPARATOR 32
#define TPFILTER_FLAG_MATCH_CASE 64
#define TPFILTER_FLAG_THIRD_PARTY 128
#define TPFILTER_FLAG_FIRST_PARTY 256

struct tpfilter_entry {
  const char **matches;
  int flags;
  const char **domains, **domains_skip;
};

""")
    output_file.write("#define TPFILTER_ENTRY_COUNT %s\n\n" % entry_count)


    for i, o in enumerate(output):
        output_file.write('const char *m%s[] = { "%s^", NULL };\n' % (i, o))

    output_file.write(
            "\nstruct tpfilter_entry TPFILTER_ENTRIES[TPFILTER_ENTRY_COUNT] = {")

    for i in range(entry_count):
        output_file.write("\n    {m%s, " % (i))
        output_file.write("TPFILTER_FLAG_MATCH_DOMAIN | TPFILTER_FLAG_HAS_SEPARATOR | TPFILTER_FLAG_THIRD_PARTY, NULL, NULL }")
        if not i == (entry_count - 1):
            output_file.write(",")
    output_file.write("\n};\n\n}\n\n#endif")

def load_json_from_url(url):
    try:
        loaded_json = json.loads(urllib2.urlopen(url).read())
    except:
        sys.stderr.write("Error loading %s\n" % url)
        sys.exit(-1)
    return loaded_json

def find_hosts(blocklist_json, allow_list, output_file, log_file,
               list_categories):
    """Finds hosts that we should block from the Disconnect json.
    Args:
      blocklist_json: A JSON blob containing Disconnect's list.
      allow_list: Hosts that we can't put on the blocklist.
      output_file: A file-handle to the output file.
      log_file: A filehandle to the log file.
    """
    # Number of items published
    publishing = 0

    # Remember previously-processed domains so we don't print them more than once
    domain_dict = {};

    # Array holding hash bytes to be written to f_out. We need the total bytes
    # before writing anything.
    output = [];

    categories = blocklist_json["categories"]

    for c in categories:
        add_category_to_list = False
        for lc in list_categories.split(","):
            if c.find(lc) != -1:
                add_category_to_list = True
        if not add_category_to_list:
            continue
        if add_category_to_list:
            # Is this list a single-category list?
            if len(list_categories) == 1:
                # Reset output to only include this category's content
                output = []
        if log_file:
            log_file.write("Processing %s\n" % c)

        # Objects of type
        # { Automattic: { http://automattic.com: [polldaddy.com] }}
        # Domain lists may or may not contain the address of the top-level site.
        for org in categories[c]:
            for orgname in org:
                org_json = org[orgname]
                dnt_value = org_json.pop('dnt', '')
                # Exclude sites that obey Do Not Track standards
                assert dnt_value in ["w3c", "eff", ""]
                if dnt_value != "":
                    continue
                for top in org_json:
                    domains = org_json[top]
                    for d in domains:
                        d = d.encode('utf-8');
                        if c == "Disconnect":
                            try:
                                if not disconnect_mapping[d] in list_categories:
                                    continue
                            except KeyError:
                                sys.stderr.write(
                                    "[ERROR] %s not found in disconnect_mapping" % d
                                )
                        if not d in allow_list:
                            if log_file:
                                log_file.write("[m] %s\n" % (d));
                            publishing += 1
                            domain_dict[d] = 1;
                            output.append(d);
    # for o in output:
    #     if output_file:
    #         output_file.write("%s\n" % (o))
    write_header_file(output_file, output)

def main():
    disconnect_url = "https://raw.githubusercontent.com/mozilla-services/shavar-prod-lists/master/disconnect-blacklist.json"
    allowlist_url = "https://raw.githubusercontent.com/mozilla-services/shavar-list-exceptions/master/allow_list"

    # Use local files for testing
    #disconnect_filename = "disconnect-blacklist.json"
    #allowlist_filename = "allow_list"

    #list_categories = "Advertising,Analytics,Social,Disconnect,Content"
    list_categories = "Advertising,Analytics,Social,Disconnect"
    output_filename = "tpfilter_entries.h"
    log_filename = "create_blockfile.log"

    # open output and log files
    try:
        output_file = open(output_filename, "wb")
        log_file = open(log_filename, "w")
    except:
        sys.stderr.write("Error opening %s\n" % url)
        sys.exit(-1)

    # process disconnect
    blocklist_json = load_json_from_url(disconnect_url)
    # read local file for testing
    #with open(disconnect_filename) as f:
    #    blocklist_json = json.load(f)

    # load our allowlist
    allowed = set()
    # read local files for testing
    #for line in open(allowlist_filename).readlines():
    for line in urllib2.urlopen(allowlist_url).readlines():
        line = line.strip()
        # don't add blank lines or comments
        if not line or line.startswith('#'):
          continue
        allowed.add(line)

    find_hosts(blocklist_json, allowed, output_file, log_file,
                 list_categories)

    if output_file:
        output_file.close()
    if log_file:
        log_file.close()

if __name__ == "__main__":
    main()
