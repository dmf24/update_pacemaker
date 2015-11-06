#!/usr/bin/env python
import sys
import os
import argparse
import time

scriptdir=os.path.dirname(os.path.abspath(sys.argv[0]))
sys.path.insert(0, os.path.join(scriptdir, '../lib/python'))

import crmwrap

configdir='/etc/ha.d'

helptext = '''This tool modifies a pacemaker CIB database on a running system.  It must be run as root.
'''

parser = argparse.ArgumentParser(description=helptext, epilog='See also /usr/share/doc/pacemaker/crm_cli.txt.gz')

parser.add_argument('-a', '--apply', action='store_true', help='Actually apply updates to the running config.  The default is to show diffs and do a dry-run.')

parser.add_argument('-q', '--quiet', action='store_true', help='Suppress information output')

parser.add_argument('-u', '--updates-only', action='store_true', help='''Print only output suitable for piping to crm configure load update -.  NOTE BENE: if modifications to the configuration require any deletions, this command will not include them.''')

parser.add_argument('-d', '--diffs-only', action='store_true', help='Print only human-readable adds, deletions, and diffs to standard out')

parser.add_argument('-c', '--commands-only', action='store_true', help='Print only shell commands to standard out')

parser.add_argument('--updates-and-commands', action='store_true', help='Print only shell commands to standard out')

parser.add_argument('--dir', action='store_true', help='Specify configuation directory')

parser.add_argument('pacemaker_resources', type=str, nargs='?', action='store', help='HMS Pacemaker resources file (pacemaker_resources.conf)')

args=parser.parse_args()

if isinstance(args.dir, str):
    configdir=args.dir

if args.pacemaker_resources is None:
    pacemaker_resources_file=os.path.join(configdir, 'pacemaker_resources.conf')
else:    
    pacemaker_resources_file=args.pacemaker_resources

updater=crmwrap.Updater(pacemaker_resources_file)

def smallcomment(comment, n=10):
    return "\n%s %s %s" % ("#" * n, comment, "#" * n)

def bigcomment(comment, n=10):
    line = "%s %s %s" % ("#" * n, comment, "#" * n)
    hashline = "#" * len(line)
    return "\n%s\n%s\n%s" % (hashline, line, hashline)

def repr_line(item):
    keys=['name', 'type', 'ips', 'loadbalancers']
    if set(keys).issubset(set(item.keys())):
        return "%s (%s) %s [%s]" % (item['name'], item['type'], ','.join(item['ips']), ','.join(item['loadbalancers']))
    else:
        result=[]
        for k in keys:
            if k in item.keys():
                if k in ['name', 'type']:
                    result.append(item[k])
                else:
                    result.append(','.join(item[k]))
        return ' '.join(result)

if (args.quiet is not True and
    args.updates_only is not True and
    args.updates_and_commands is not True and
    args.commands_only is not True or
    args.diffs_only is True):
    print smallcomment("Services to add")
    print
    for x in updater.services_to_add:
        print "Add service: %s" % repr_line(x)
    
    print smallcomment("Services to delete")
    print
    for x in updater.services_to_delete:
        print "Delete service: %s" % repr_line(x)
    
    print smallcomment("Diffs to existing services")
    print
    for x in updater.service_diffs:
        print x

if (args.quiet is not True and
    args.commands_only is not True and
    args.diffs_only is not True or
    args.updates_only is True or
    args.updates_and_commands is True):
    print bigcomment("Updates to be piped to 'crm configure load update -'")
    print
    print updater.to_add_and_update

if (args.quiet is not True and
    args.updates_only is not True and
    args.diffs_only is not True or
    args.commands_only is True or
    args.updates_and_commands is True):
    print bigcomment("crm configure commands to execute")
    print
    for itm in updater.ips_to_delete + updater.lds_to_delete:
        print crmwrap.stop_tag(itm)
    for cmd in updater.delete_ips:
        print cmd
    for cmd in updater.delete_ld:
        print cmd
    for item in updater.services_to_delete:
        for cmd in crmwrap.stop_service(item['name']):
            print cmd
        for cmd in crmwrap.delete_service(item['name']):
            print cmd

if args.apply:
    process=crmwrap.process
    # Actually update the running CRM configuration
    crmwrap.update_live_crm_config(updater.to_add_and_update)
    for itm in updater.ips_to_delete + updater.lds_to_delete:
        print process(crmwrap.stop_tag(itm))
    for cmd in updater.delete_ips + updater.delete_ld:
        #print "process('%s')" % cmd
        print process(cmd)
    for item in updater.services_to_delete:
        for cmd in crmwrap.stop_service(item['name']):
            print process(cmd)

        check=False
        for cc in range(5):
            if check:
                continue
            if False in crmwrap.is_service_stopped(item['name']):
                print "%s not yet stopped, sleeping 1 second..." % item['name']
                time.sleep(1)
            else:
                check=True
        
        for cmd in crmwrap.delete_service(item['name']):
            #print "process('%s')" % cmd
            print process(cmd)
