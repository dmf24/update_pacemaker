# update_pacemaker
Helper scripts for configuring pacemaker resources.

These scripts implement only a subset of pacemaker functionality and are not intended to be a drop-in replacement for the existing command-line interface.

This tool allows you to define pacemaker resources in a file with stanzas that look like this:

```
myservice.mydomain.com:
     ldirectord
     [loadbalancer1 loadbalancer2]
     120.0.0.1/8/lo
```


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
