# This file is not currently used
import string

def template(s):
    return string.Template(s).substitute

crm_configure_strings = dict(
    ldirectord="primitive ${service_name}-ld lsb:ldirectord-${service_name} op monitor interval=${interval}s",
    group = 'group $service_name $service_list',
    location = 'location ${service_name}-ha${index} ${service_name} ${value}: $server',
    ipaddr = 'primitive ${service_name}-ip${ip} ocf:heartbeat:IPaddr2 params ip=${ip} cidr_netmask="${cidr_netmask}"${nicstring}'
    )
    
crm_configure_templates = dict([(k, template(crm_configure_strings[k])) for k in crm_configure_strings.keys()])

def crm_configure(command, **kwargs):
    return crm_configure_templates[command](kwargs)

if __name__=='__main__':
    print crm_configure('ldirectord', service_name='myservice.mydomain.com', interval=15)
    print crm_configure('group', service_name='myservice.mydomain.com', service_list='1 2')
    print crm_configure('location', service_name='myservice.mydomain.com', index=1, value=14900, server='cobo')
    print crm_configure('ipaddr', service_name='myservice.mydomain.com', ip='5.6.7.8', cidr_netmask='24',
                    nicstring='')
