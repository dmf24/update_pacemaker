#!/usr/bin/env python
"""
Pacemaker CRM wrapper library
"""

import sys
import os

import subprocess
import shlex
from tempfile import SpooledTemporaryFile
import string
import re
import json
import yaml
from operator import itemgetter
import copy

import haresources2

def template(s):
    return string.Template(s).substitute

def iptag(service_name, ip):
    return "%s-ip%s" % (service_name, ip)

crm_commands = {
    'configure-load-update' : 'crm configure load update -',
    'configure-show' : 'crm configure show',
    'status' : 'crm status inactive failcounts',
    'resource-status'  : template('crm resource status ${obj}'),
    'delete' : template('crm configure delete ${obj}'),
    'stop' : template('crm resource stop ${obj}')
    }

crm_configure_strings = dict(
    #ldirectord='primitive ${service_name}-ld lsb:ldirectord-${service_name} op monitor interval="${interval}s"',
    ldirectord='primitive ${service_name}-ld lsb:ldirectord-${service_name}',
    ldirectord_nomon='primitive ${service_name}-ld lsb:ldirectord-${service_name}',
    group = 'group $service_name $service_list',
    location = 'location ${service_name}-ha${index} ${service_name} ${value}: $server',
    ipaddr = 'primitive ${service_name}-ip${ip} ocf:heartbeat:IPaddr2 params ip="${ip}" cidr_netmask="${cidr_netmask}"${nicstring}'
    )
    
crm_configure_templates = dict([(k, template(crm_configure_strings[k])) for k in crm_configure_strings.keys()])

def crm_configure(command, **kwargs):
    return crm_configure_templates[command](kwargs)

#print crm_configure('ldirectord', service_name='test.orchestraweb.med.harvard.edu', interval=15)
#print crm_configure('group', service_name='test.orchestraweb.med.harvard.edu', service_list='1 2')
#print crm_configure('location', service_name='test.orchestraweb.med.harvard.edu', index=1, value=14900, server='cobo')
#print crm_configure('ipaddr', service_name='test.orchestraweb.med.harvard.edu', ip='5.6.7.8', cidr_netmask='24',
#                    nicstring='')

def process_run(cmd_string, stdin=None):
    """Given a string representing a single command, open a process, and return
    the Popen process object.
    http://docs.python.org/2/library/subprocess.html#popen-objects
    """
    process_object=subprocess.Popen(shlex.split(cmd_string),
                                    stdin=stdin,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
    return process_object

def process_results(process_object):
    """Given a process object, wait for it to complete then return a tuple with stdout and stderr"""
    (stdout, stderr)=process_object.communicate()
    return (process_object.returncode, stdout, stderr)

def process(cmd_string, stdin=None):
    """Given a string representing a single command, open a process, wait for it to terminate and then
    return standard out and standard in as a tuple"""
    return process_results(process_run(cmd_string, stdin=stdin))

def pipestring_process(cmd_string, stdin_string=''):
    """Pipe a python string to standard input for cmd_string

    >>> pipestring_process('grep 2', '1\n2\n3\n')[1]
    '2\n'
    """
    f=SpooledTemporaryFile()
    f.write(stdin_string)
    f.seek(0)
    results=process(cmd_string, stdin=f)
    f.close()
    return results

def evaluate_line_continuations(txt):
    """
    Given text using backlashes to indicate line continuations,
    return the equivalent text with backslashes removed
    """
    return ' '.join([x.strip() for x in txt.split('\\\n')])

def configure_show():
    results=process('crm configure show')
    if results[0] == 0:
        return evaluate_line_continuations(results[1])
    else:
        return results

def key2(lst):
    """Given a list, return a tuple: ('first second', [third...]) """
    if len(lst) > 1:
        return (' '.join(lst[0:2]), lst[2:])
    elif len(lst) == 1:
        if lst[0] != '':
            return (lst[0], None)
        else:
            return None
    else:
        return None

def configure_parse(crm_configure_output=None):
    if crm_configure_output is None:
        crmlines=configure_show()
    else:
        crmlines=evaluate_line_continuations(crm_configure_output)
    return [key2(x.split()) for x in crmlines.split('\n')]

def splitip(cidr):
    device=None
    if '/' in cidr:
        splitcidr=cidr.split('/')
        if len(splitcidr) == 2:
            ip, cidr_netmask = splitcidr
        elif len(splitcidr) == 3:
            ip, cidr_netmask, device = splitcidr
    else:
        ip=cidr
        cidr_netmask='24'
    return (ip, cidr_netmask, device)

def nicst(nic):
    if nic == '' or nic == None:
        return ''
    else:
        return ' nic="%s"' % nic

def matcher(crm_configure_dict=None):
    if crm_configure_dict is None:
        crm_configure_dict=dict(configure_parse())
    def matchfn2(service_spec):
        key, lst = key2(service_spec.split())
        values=' '.join(lst)
        crmvalues=' '.join(crm_configure_dict[key])
        if key in crm_configure_dict.keys():
            if values == crmvalues:
                return (True, key + values)
            else:
                return (key + crmvalues, key + values)
        else:
            return (None, key + values)
    return matchfn2

def ip_primitives(service_name, cidrlist):
    return [crm_configure('ipaddr', **{'service_name':service_name,
                                       'ip':ip,
                                       'cidr_netmask':cidr_netmask,
                                       'nicstring':nicst(nic)})
            for ip, cidr_netmask, nic in [splitip(ipstr) for ipstr in cidrlist]]

def ld_primitives(service_name, interval=15):
    return [crm_configure('ldirectord',
                          service_name=service_name,
                          interval=interval)]

def primitives(service_name, service_type, cidrlist, interval=15):
    lst=[]
    lst += ip_primitives(service_name, cidrlist)
    if service_type=='ldirectord':
        lst += ld_primitives(service_name)
    return lst

def group(service_name, service_type, cidrlist):
    service_list = [iptag(service_name, splitip(cidr)[0]) for cidr in cidrlist]
    if service_type == 'ldirectord':
        service_list += ['%s-ld' % service_name]
    return [crm_configure('group', service_name=service_name,
                                   service_list=' '.join(service_list))]

def group2(item):
    return group(item['name'], item['type'], item['ips'])

def lborder(service_name, lblist):
    lst=[]
    n=len(lblist)
    for index, value, server in zip(range(n), [15000-(100*s) for s in range(n)], lblist):
        lst.append(crm_configure('location',
                                   service_name=service_name,
                                   index=index,
                                   value=value,
                                   server=server))
    return lst

def parse_tag(tag):
    #Currently the first item in the suffix tuples are not used
    suffixes = [('location', r'(.*)-(ha[0-9])$'),
                ('primitive', r'(.*)-(ip\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'),
                ('primitive', r'(.*)-(ld)$')]
    suffix_regexes = [re.compile(expr) for (conf_type, expr) in suffixes]
    for mo in [sr.match(tag) for sr in suffix_regexes]:
        if mo is not None:
            return mo.groups()
    return (tag, None)

def get_service_ids(service_name, conf_list=None):
    if conf_list is None:
        conf_list=configure_parse()
    results=[]
    for key, lst in conf_list:
        config_type, tag = key.split()
        if config_type in ['primitive', 'group', 'location']:
            configure_service_name, extra = parse_tag(tag)
            if service_name == configure_service_name.strip():
                results.append(tag)
    return results

def delete(tag):
    return crm_commands['delete'](dict(obj=tag))

def delete_service(service_name):
    return [delete(object_tag) for object_tag in
            get_service_ids(service_name)]

def stop_tag(tag):
    return crm_commands['stop'](dict(obj=tag))

def stop_service(service_name):
    return [stop_tag(object_tag) for object_tag in
            get_service_ids(service_name)]

def is_stopped(tag):
    results=process(crm_commands['resource-status'](dict(obj=tag)))
    if results[0] != 0:
        sys.stderr.write(results[2])
    else:
        if 'is running' in results[1]:
            return False
        elif results[2].strip().endswith('NOT running'):
            return True
        else:
            sys.stderr.write("Error checking status\n")
            sys.stdout.write("%s" % results[1])
            sys.stderr.write("%s" % results[2])
            return None

def is_service_stopped(service_name):
    return [is_stopped(object_tag) for object_tag in
            get_service_ids(service_name)]

def getkeys(conf_dict, keytype):
    return [key for key in conf_dict.keys() if key.split()[0] == keytype]

def haipstr(parsed_params):
    if 'nic' not in parsed_params:
        return '/'.join([parsed_params[x] for x in ['ip', 'cidr_netmask']] + ['eth2'])
    else:
        return '/'.join([parsed_params[x] for x in ['ip', 'cidr_netmask', 'nic']])

                                                   

def crm2dict(conf_list=None):
    """Convert a simple list of configuration directives generated by 'configure_parse()'
    into a dictionary with the format:
    { <service_name>: { 'loadbalancers' : <balancer list>,
                        'ips' : <cidr list>,
                        'members' : <group members list>,
                        'type' : <ip or ldirectord> },
      <service_name2> : ...
      }

    This function is intended to be a lower level representation of the configuration as read
    from a running instance of pacemaker.  For a higher level, pass this dictionary to
    'crmdict2haresources' to get a high-level object compatible with the haresources2 library.
    """
    if conf_list is None:
        conf_list=configure_parse()
    conf_dict=dict(conf_list)
    results={}
    groupkeys = getkeys(conf_dict, 'group')
    primitivekeys = getkeys(conf_dict, 'primitive')
    for gk in groupkeys:
        results.setdefault(gk.split()[1], {})
    locationkeys = getkeys(conf_dict, 'location')
    for key in conf_dict.keys():
        conf_type, tag = key.split()
        if conf_type == 'group':
            members=[x for x in conf_dict[key] if not (x.startswith('target-role') or x == 'meta')]
            results[tag].update({'members' : members })
        elif conf_type == 'location':
            service_name, loc=parse_tag(tag)
            balancer = conf_dict[key][2]
            if service_name not in results.keys():
                results.setdefault(service_name, {'loadbalancers' : {loc:balancer}})
            elif 'loadbalancers' not in results[service_name].keys():
                results[service_name].update({'loadbalancers' : {loc:balancer}})
            else:
                results[service_name]['loadbalancers'].update({loc:balancer})
        elif conf_type == 'primitive':
            service_name, service_type = parse_tag(tag)
            if service_type == 'ld':
                results[service_name].update({'type' : 'ldirectord'})
            elif service_type[:2] == 'ip':
                params = conf_dict[key]
                parsed_params={}
                for param in params:
                    if param[:3] == 'ip=':
                        parsed_params.setdefault('ip', param[4:-1])
                    elif param[:13] == 'cidr_netmask=':
                        parsed_params.setdefault('cidr_netmask', param[14:-1])
                    elif param[:4] == 'nic=':
                        parsed_params.setdefault('nic', param[5:-1])
                if 'ips' not in results[service_name].keys():
                    results[service_name].update({'ips' : [haipstr(parsed_params)]})
                else:
                    results[service_name]['ips'].append(haipstr(parsed_params))
    return results

def crmdict2haresources(anydict):
    """Convert a dictionary generated by crm2dict into a format compatible with
    the haresources2 library.
    There are a few key format differences.  Instead of a key map, there is a list with
    'name' fields.  The "members" field is dropped, as this information is implied from
    the other fields.  Finally, the loadbalancers are placed in an ordered list rather than
    in a dictionary indexed by 'ha#' keys.
    """
    lst=[]
    for k in anydict.keys():
        d={}
        for subkey in anydict[k].keys() + ['name']:
            if subkey == 'name':
                d.setdefault(subkey, k)
            elif subkey == 'loadbalancers':
                numbalancers=len(anydict[k][subkey].keys())
                d.setdefault(subkey, [anydict[k][subkey]['ha%s' % lb] for lb in range(numbalancers)])
            elif subkey != 'members':
                d.setdefault(subkey, anydict[k][subkey])
        if 'type' not in d.keys():
            d.setdefault('type', 'ip')
        lst.append(d)
    return lst

def names(config_list):
    return [item['name'] for item in config_list]

#for x in delete_service('auxweb.hms.harvard.edu'):
#    print x

class Updater(object):
    def __init__(self, candidate_filename):
        self.candidate_config=sortby('name')(haresources2.load(candidate_filename))
        self.live_config=sortby('name')(crmdict2haresources(crm2dict(configure_parse())))
        self.services_to_delete=self._services_to_delete()
        self.services_to_add=self._services_to_add()
        self.ips_to_delete=self._ips_to_delete()
        self.lds_to_delete=self._lds_to_delete()
        self.delete_ld=self._delete_ld()
        self.delete_ips=self._delete_ips()
        self.service_diffs=self._service_diffs()
        self.to_add_and_update=self._to_add_and_update()

    def _services_to_delete(self):
        return [item for item in self.live_config if
                item['name'] not in names(self.candidate_config)]

    def _services_to_add(self):
        return [item for item in self.candidate_config if
                item['name'] not in names(self.live_config)]

    def _delete_ld(self):
        return [delete(tag) for tag in self.lds_to_delete]

    def _ips_to_delete(self):
        deleted_ips=[]
        for item in self.candidate_config:
            if item['name'] in names(self.live_config):
                live_item=[x for x in self.live_config if x['name']==item['name']][0]
                live_ips=[splitip(x)[0] for x in live_item['ips']]
                item_ips=[splitip(x)[0] for x in item['ips']]
                deleted_ips += [iptag(item['name'], ip) for ip in live_ips if ip not in item_ips]
        return deleted_ips

    def _lds_to_delete(self):
        deleted_lds=[]
        for item in self.candidate_config:
            if item['name'] in names(self.live_config):
                live_item=[x for x in self.live_config if x['name']==item['name']][0]
                if item['type'] == 'ip' and live_item['type'] == 'ldirectord':
                    deleted_lds.append("%s-ld" % item['name'])
        return deleted_lds


    def _delete_ips(self):
        return [delete(ip) for ip in self.ips_to_delete]

    def _service_diffs(self):
        services_to_update=[]
        for item in self.candidate_config:
            if item in self.services_to_add:
                continue
            live_item=[x for x in self.live_config if x['name']==item['name']][0]
            for k in item.keys():
                if k not in live_item.keys():
                    services_to_update.append("+%s: %s> %s" % (item['name'], k, item[k]))
                elif k == 'ips':
                    deleted_ips=[x for x in live_item['ips'] if x not in item['ips']]
                    added_ips=[x for x in item['ips'] if x not in live_item['ips']]
                    for x in deleted_ips:
                        services_to_update.append("-%s: %s: %s" % (item['name'], k, x))
                    for x in added_ips:
                        services_to_update.append("+%s: %s: %s" % (item['name'], k, x))
                else:
                    if item[k] != live_item[k]:
                        services_to_update.append("-%s: %s: %s" % (item['name'], k, live_item[k]))
                        services_to_update.append("+%s: %s: %s" % (item['name'], k, item[k]))
        return services_to_update
    
    def _to_add_and_update(self):
        """Returns a string of directives in crm syntax.
        They can be passed as an argument to update_live_crm_config in this script,
        or sent to standard out for the user to pipe manually to
        'crm configure load update -'
        """
        primitive_list=[]
        group_list=[]
        location_list = []
        #primitives
        for item in self.candidate_config:
            item_groupdef=group(item['name'], item['type'], item['ips'])
            if item['name'] in names(self.live_config):
                live_item=[x for x in self.live_config if x['name']==item['name']][0]
                added_ips=[x for x in item['ips'] if x not in live_item['ips']]
                primitive_list += ip_primitives(item['name'], added_ips)
                if item['type'] != live_item['type']:
                    if item['type'] == 'ldirectord':
                        primitive_list += ld_primitives(item['name'], item['loadbalancers'])
                if set(item_groupdef[0].split()) != set(group2(live_item)[0].split()):
                    group_list += item_groupdef
                if item['loadbalancers'] != live_item['loadbalancers']:
                    location_list += lborder(item['name'], item['loadbalancers'])
            else:
                primitive_list += primitives(item['name'], item['type'], item['ips'])
                group_list += item_groupdef
                location_list += lborder(item['name'], item['loadbalancers'])
        return '\n'.join(primitive_list + group_list + location_list)
    
def service_diffs(candidate_config, services_to_add):
    services_to_update=[]
    for item in candidate_config:
        if item in services_to_add:
            continue
        live_item=[x for x in live_config if x['name']==item['name']][0]
        for k in item.keys():
            if k not in live_item.keys():
                services_to_update.append("+%s: %s> %s" % (item['name'], k, item[k]))
            elif k == 'ips':
                deleted_ips=[x for x in live_item['ips'] if x not in item['ips']]
                added_ips=[x for x in item['ips'] if x not in live_item['ips']]
                for x in deleted_ips:
                    services_to_update.append("-%s: %s: %s" % (item['name'], k, x))
                for x in added_ips:
                    services_to_update.append("+%s: %s: %s" % (item['name'], k, x))
            else:
                if item[k] != live_item[k]:
                    services_to_update.append("-%s: %s: %s" % (item['name'], k, live_item[k]))
                    services_to_update.append("+%s: %s: %s" % (item['name'], k, item[k]))
    return services_to_update

def to_add_and_update(candidate_config, live_config):
    """Returns a string of directives in crm syntax.
    They can be passed as an argument to update_crm_config in this script,
    or sent to standard out for the user to pipe manually to
    'crm configure load update -'
    """
    primitive_list=[]
    group_list=[]
    location_list = []
    #primitives
    for item in candidate_config:
        item_groupdef=group(item['name'], item['type'], item['ips'])
        if item['name'] in names(live_config):
            live_item=[x for x in live_config if x['name']==item['name']][0]
            added_ips=[x for x in item['ips'] if x not in live_item['ips']]
            primitive_list += ip_primitives(item['name'], added_ips)
            if item['type'] != live_item['type']:
                if item['type'] == 'ldirectord':
                    primitive_list += ld_primitives(item['name'], item['loadbalancers'])
            if set(item_groupdef[0].split()) != set(group2(live_item)[0].split()):
                group_list += item_groupdef
            if item['loadbalancers'] != live_item['loadbalancers']:
                location_list += lborder(item['name'], item['loadbalancers'])
        else:
            primitive_list += primitives(item['name'], item['type'], item['ips'])
            group_list += item_groupdef
            location_list += lborder(item['name'], item['loadbalancers'])
    return '\n'.join(primitive_list + group_list + location_list)

def delete_ips(candidate_config, live_config):
    crm_commands_list=[]
    for item in candidate_config:
        if item['name'] in names(live_config):
            live_item=[x for x in live_config if x['name']==item['name']][0]
            # only delete the resource if the IP itself is gone.
            # netmask and nic changes are handled by load update
            live_ips=[splitip(x)[0] for x in live_item['ips']]
            item_ips=[splitip(x)[0] for x in item['ips']]
            deleted_ips=[ip for ip in live_ips if ip not in item_ips]
            crm_commands_list += [delete(iptag(item['name'], ip)) for ip in deleted_ips]
    return crm_commands_list

def delete_ld(candidate_config, live_config):
    crm_commands_list=[]
    for item in candidate_config:
        if item['name'] in names(live_config):
            live_item=[x for x in live_config if x['name']==item['name']][0]
            if item['type'] == 'ip' and live_item['type'] == 'ldirectord':
                crm_commands_list.append(delete("%s-ld" % item['name']))
    return crm_commands_list

def update_live_crm_config(stdin_string):
    return pipestring_process(crm_commands['configure-load-update'], stdin_string=stdin_string)

def sortby(key):
    def sort_list(lst):
        return sorted(lst, key=itemgetter(key))
    return sort_list

def get_configs(candidate_filename):
    """Given a candidate filename, returns (candidate_config, live_config)"""
    return (sortby('name')(haresources2.load(haresources2_file)),
            sortby('name')(crmdict2haresources(crm2dict(configure_parse()))))

def services_to_delete(candidate_config, live_config):
    return [item for item in live_config if item['name'] not in names(candidate_config)]

def services_to_add(candidate_config, live_config):
    return [item for item in candidate_config if item['name'] not in names(live_config)]

def repr_line(item):
    return "%s (%s) %s [%s]" % (item['name'], item['type'], ','.join(item['ips']), ','.join(item['loadbalancers']))

if __name__=='__main__':
    
    def smallcomment(comment, n=10):
        return "\n%s %s %s" % ("#" * n, comment, "#" * n)
    
    def bigcomment(comment, n=10):
        line = "%s %s %s" % ("#" * n, comment, "#" * n)
        hashline = "#" * len(line)
        return "\n%s\n%s\n%s" % (hashline, line, hashline)
    
    live_config=sorted(crmdict2haresources(crm2dict()), key=itemgetter('name'))
    if len(sys.argv) > 1:
        haresources2_file=sys.argv[1]
    else:
        haresources2_file="/etc/ha.d/pacemaker_resources.conf"

    crmwrap=Updater(haresources2_file)
    
    #candidate_config=sortby('name')(haresources2.parse(file(haresources2_file).read()))

    #candidate_config=sortby('name')(haresources2.load(haresources2_file))
    
    #candidate_service_names = names(candidate_config)
    #live_service_names = names(live_config)
    
    #services_to_delete=[item for item in live_config if item['name'] not in candidate_service_names]
    #services_to_add=[item for item in candidate_config if item['name'] not in live_service_names]
    
    print smallcomment("Services to add")
    print
    for x in crmwrap.services_to_add:
        print "Add service: %s" % repr_line(x)
    
    print smallcomment("Services to delete")
    print
    for x in crmwrap.services_to_delete:
        print "Delete service: %s" % repr_line(x)
    
    print smallcomment("Diffs to existing services")
    print
    for x in crmwrap.service_diffs: #candidate_config, services_to_add):
        print x
    
    
    print bigcomment("Updates to be piped to 'crm configure load update -'")
    print
    print crmwrap.to_add_and_update #candidate_config, live_config)
    
    print bigcomment("crm configure commands to execute")
    print
    for cmd in crmwrap.delete_ips: #(candidate_config, live_config):
        print cmd
    for cmd in crmwrap.delete_ld: #(candidate_config, live_config):
        print cmd
    for item in crmwrap.services_to_delete:
        for cmd in delete_service(item['name']):
            print cmd
    
    sys.exit(0)

