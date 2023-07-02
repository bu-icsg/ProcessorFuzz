#!/usr/bin/python

import sys
import os
import re
from collections import defaultdict
#from split_firrtl import split_firrtl

# Takes firrtl text, returns a dict from module name to module definition
def split_firrtl(firrtl_lines):
    modules = defaultdict(list)
    current_mod = ""

    pattern = re.compile('\s*(?:ext)?module\s+(\S+)\s*:\s*')
    for line in firrtl_lines:
        m = pattern.match(line)
        if m:
            current_mod = m.group(1)
        if current_mod:
            modules[current_mod].append(line)
    return modules

def get_submods(modules):
    submods = defaultdict(list)
    pattern = re.compile('\s*inst\s+\S+\s+of\s+(\S+)\s+.*')

    for mod, lines in modules.iteritems():
        for line in lines:
            m = pattern.match(line)
            if m:
                submods[mod].append(m.group(1))
    return submods

def submods_of(submodules, top):
    mods = [top]

    to_visit = submodules[top]
    while len(to_visit) > 0:
        head = to_visit.pop(0)
        if not head in mods:
            mods.append(head)
            to_visit.extend(submodules[head])
    return mods

if __name__ == "__main__":
    def error_out():
        usage = "Usage: {} newtop infile outfile".format(os.path.basename(sys.argv[0]))
        print(usage)
        sys.exit(-1)
    # Check number of arguments
    if len(sys.argv) != 4:
        error_out()
    newtop = sys.argv[1]
    infile = sys.argv[2]
    outfile = sys.argv[3]
    if not(os.path.isfile(infile)) :
        print("infile must be a valid file!")
        error_out()

    with open(infile, "r") as f:
        modules = split_firrtl(f.readlines())

    if not(newtop in modules):
        print("newtop must actually be a module!")
        error_out()

    submods = get_submods(modules)
    new_mods = submods_of(submods, newtop)

    with open(outfile, "w") as f:
        f.write('circuit {} :\n'.format(newtop))
        for mod in new_mods:
            for line in modules[mod]:
                f.write(line)
