# update_pacemaker
Helper scripts for configuring pacemaker resources.  Written for use with pacemaker version: 1.0.9.  (On debian squeeze using the heartbeat stack, though that should not be relevant)

These scripts implement only a subset of pacemaker functionality and are not intended to be a drop-in replacement for the existing command-line interface.

This tool allows you to define pacemaker resources in a file with stanzas that look like this:

```
myservice.mydomain.com:
     ldirectord
     [loadbalancer1 loadbalancer2]
     127.0.0.1/8/lo
     10.0.0.5/24/eth1
```

The idea being that this sacrifices the flexibility of the raw pacemaker configuration directives and gains readability, usability, and safety.  The above configuration would look like this as crm configure directives:

```
primitive myservice.mydomain.com-ip127.0.0.1 ocf:heartbeat:IPaddr2 params ip="127.0.0.1" cidr_netmask="8" nic="lo"
primitive myservice.mydomain.com-ip10.0.0.5 ocf:heartbeat:IPaddr2 params ip="10.0.0.5" cidr_netmask="24" nic="eth1"
primitive myservice.mydomain.com-ld lsb:ldirectord-myservice.mydomain.com
group myservice.mydomain.com myservice.mydomain.com-ip127.0.0.1 myservice.mydomain.com-ip10.0.0.5 myservice.mydomain.com-ld
location myservice.mydomain.com-ha0 myservice.mydomain.com 15000: loadbalancer1
location myservice.mydomain.com-ha1 myservice.mydomain.com 14900: loadbalancer2
```

The tool's help:

```
usage: update_pacemaker [-h] [-a] [-q] [-u] [-d] [-c]
                        [--updates-and-commands] [--dir]
                        [pacemaker_resources]

This tool modifies a pacemaker CIB database on a running system. It must be
run as root.

positional arguments:
  pacemaker_resources   HMS Pacemaker resources file
                        (pacemaker_resources.conf)

optional arguments:
  -h, --help            show this help message and exit
  -a, --apply           Actually apply updates to the running config. The
                        default is to show diffs and do a dry-run.
  -q, --quiet           Suppress information output
  -u, --updates-only    Print only output suitable for piping to crm configure
                        load update -. NOTE BENE: if modifications to the
                        configuration require any deletions, this command will
                        not include them.
  -d, --diffs-only      Print only human-readable adds, deletions, and diffs
                        to standard out
  -c, --commands-only   Print only shell commands to standard out
  --updates-and-commands
                        Print only shell commands to standard out
  --dir                 Specify configuation directory
```
