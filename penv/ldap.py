#!/usr/local/bin/python3

import click
import ldap
import json
import requests
import yaml
from requests.exceptions import ConnectionError

class Ldap(object):

    def __init__(self):

        # Default Values
        self.hosts = {
            'infi1': 'dhcp-prod01',
            'telad': 'dhcp-telad-01',
            'gdc': 'dhcp-prod01',
            'nw': 'dhcp-nw-01',
            'wt': 'dhcp-wt-01'
            }

        self.basedns = {
            'infi1': 'dc=infinidat,dc=com',
            'telad': 'dc=telad,dc=infinidat,dc=com',
            'gdc': 'dc=infinidat,dc=com',
            'nw': 'dc=nw,dc=infinidat,dc=com',
            'wt': 'dc=wt,dc=us,dc=infinidat,dc=com'
            }
        self.labs = {
            'telad': [self.hosts['telad'],self.basedns['telad']],
            'infi1': [self.hosts['infi1'],self.basedns['infi1']],
            'gdc': [self.hosts['gdc'],self.basedns['gdc']],
            'nw': [self.hosts['nw'],self.basedns['nw']],
            'wt': [self.hosts['wt'],self.basedns['wt']]

            }

        self.ldap = None
        self.lab = None
        self.basedn = None
        self.host = None
        self.username = None
        self.password = None

    def connect(self, lab):
        if lab.lower() not in self.labs:
            click.secho("Lab %s is not a valid option" % lab, fg='red')
            raise click.UsageError("Please only use next option for --lab: %s" % list(self.labs.keys()))
        else:
            self.lab = lab
            self.host =  self.labs[self.lab.lower()][0]
            self.basedn = self.labs[self.lab.lower()][1]

        click.secho('Connecting LDAP in lab %s' % lab, fg='blue')

        ldapi = "ldap://" + self.host + ":389"
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        self.ldap = ldap.initialize(ldapi)
        self.ldap.set_option(ldap.OPT_REFERRALS, 0)
        self.ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        self.ldap.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
        self.ldap.set_option(ldap.OPT_X_TLS_DEMAND, False)
        self.ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)

        binddn = "cn=" + self.username + "," + self.basedns[self.lab.lower()]
        try:
            self.ldap.simple_bind_s(binddn, self.password)
        except ldap.INVALID_CREDENTIALS:
            click.secho("Your username or password is incorrect.", fg='red')
            click.Abort()
        except ldap.LDAPError as e:
            if type(e.message) == dict and e.message.has_key('desc'):
                click.secho(e.message['desc'], fg='red')
            else:
                click.echo(e)
                click.exit


    def pull_dhcp_data(self):

        if not self.lab:
            click.secho("No lab was provided", fg='red')
            raise click.Abort()

        return self.ldap.search_s(self.basedn, ldap.SCOPE_SUBTREE, '(objectClass=*)')

    def process_raw(self, data, quick=False, sample=False, sanity=False):
        """
        method for taking raw data from ldap and
        disect to smaller pieces.
        """
        counter = 0
        hosts_str = ''
        if quick:
            cmd_str = "- url: /api/multiple_register/\n"+" "*2 +"data: " + \
                      " " +"{\n" + " "*8 + "\"deploy\": \"False\",\n" + " "*8 + \
                      "\"quick\": \"True\",\n"
        else:
            cmd_str = "- url: /api/multiple_register/\n"+" "*2 +"data: " + " " +"{\n"

        mac_dict = dict()
        ip_dict = dict()
        for e in data:
            if 'dhcpHost' in [el.decode('utf-8') for el in e[1]['objectClass']]:
                cn = e[0].split(',')
                hostname = e[1]['cn'][0].decode('utf-8')
                group_name = e[0].split(',')[1].split('=')[1]
                if 'dhcpHWAddress' in e[1]:
                    mac = e[1]['dhcpHWAddress'][0].split()[1].decode('utf-8')
                    if not mac in mac_dict:
                        mac_dict[mac] = []
                        if 'dhcpStatements' in e[1]:
                            ip = e[1]['dhcpStatements'][0].split()[1].decode('utf-8')
                            if not ip in ip_dict:
                                ip_dict[ip] = []
                            data = json.dumps({'ip':ip })
                            try:
                                subnet = requests.get('http://127.0.0.1:5000/api/subnets/query_subnet_from_ip/', data=data).text
                            except ConnectionError as e:
                                click.secho('Please check cob testserver is running on localhost port 5000', fg='red')
                                raise click.Abort()

                            if 'Bad Request' in subnet:
                                continue
                        else:
                            ip = None

                        if ip:
                            hosts_str += "h"+str(counter) + ": " + \
                                         "{hostname: \"%s\", mac: \"%s\", group: \"%s\", subnet: %s, ip: \"%s\", deployed: False },\n" \
                                         % (hostname, mac, group_name, subnet.strip(), ip) + " "*9

                            ip_dict[ip].append(hostname)
                            mac_dict[mac].append(hostname)
                        else:
                            hosts_str += "h" + str(counter) + ": " + \
                                         "{hostname: \"%s\", mac: \"%s\", group: \"%s\", deployed: False },\n" \
                                         % (hostname, mac, group_name) + " " * 9
                            mac_dict[mac].append(hostname)

                        counter += 1
                        if sample and counter > 10:
                            break

        cmd_str += " "*8 +"%s\n" % hosts_str + " "*8 +"}"
        if sanity:
            return ip_dict, mac_dict
        else:
            return cmd_str

    def sanity_report(self, data):

        report_str = ''
        ip_dict, mac_dict = self.process_raw(data, True, False, True)
        report_str += "IP DUPS\n"
        # print("IP DUPS")
        for i in ip_dict:
            if len(ip_dict[i]) > 1:
                report_str += '%s, %s \n' % (i, ip_dict[i])
                # print(i, ip_dict[i])
        report_str += 'MAC DUPS\n'
        # print("MAC DUPS")
        for m in mac_dict:
            if len(mac_dict[m]) > 1:
                report_str += '%s, %s \n' % (m, mac_dict[m])
                # print(m, mac_dict[m])
        return report_str



@click.group()
@click.option('-u', '--username', help='username for LDAP access', required=True)
@click.option('-p', '--password', help='password for LDAP access', required=True)
@click.pass_context
def dhcpldap(ctx, username, password):

    ctx.obj = Ldap()
    ctx.obj.username = username
    ctx.obj.password = password
    # ctx.obj.connect(lab)


@click.group()
@click.option('-y','--yaml', help='path to YAML file')
@click.pass_context
def yml(ctx, yaml):
    ctx.obj = yaml


@dhcpldap.command()
@click.option('--elem', default='raw', help='host/system/ip/mac')
@click.option('--lab', default='infi1', help='Infi1 / telad / gdc /')
@click.option('--raw/--no-raw', default=False, help='Process data for dhcpawn')
@click.option('--quick/--no-quick', default=False, help='if used ,a quick copy from ldap to dhcpawn DB is done')
@click.option('--sample/--no-sample', default=False, help='meant for testing ,will only return 10 records from ldap to see the output is right')
@click.option('--ofile', help='output file to which ldap data is written')
@click.pass_obj
def ldap_to_yml(ldaph, lab, elem, raw, quick, ofile, sample):
    if raw and not ofile:
        click.secho("Please also provide an output file ", fg='red')
        raise click.Abort()
    ldaph.connect(lab)
    click.secho('Retrieving LDAP raw data', fg='green')
    ldap_raw_data = ldaph.pull_dhcp_data()
    with open(ofile, 'w') as f:
        f.write(ldaph.process_raw(ldap_raw_data, quick, sample))
        click.secho("Data is ready in %s" % ofile, fg='blue')



######## YAML SPLITTING
def write_small_yml(fname, info):
    with open(fname, 'w') as fh:
                click.secho("Creating %s" % fname, fg='blue')
                fh.write(yaml.dump(info))

@yml.command()
@click.option('-n', '--number', default=500, help='number of max ldap records in each of the yaml files to be created')
@click.pass_obj
def split_yml(ymlctx, number):
    """
    split a yaml file into smaller yaml files so that i can
    populate all ldap records to dockerized dhcpawn
    number - how many ldap records i would like to have in each yaml file (default = 500 )
    ymlctx - this is the context of the yml click group
    """
    with open(ymlctx, 'r') as y:
        click.secho("Loading YAML", fg='green')
        loaded = yaml.load(y)

    url = loaded[0]['url']
    record_count = 0
    file_count = 0
    name = "ymlcmd"
    small_yml = [dict()]
    small_yml[0].setdefault('url', url)
    small_yml[0].setdefault('data',{})
    for rec in loaded[0]['data']:
        record_count += 1
        small_yml[0]['data'].update({rec: loaded[0]['data'][rec]})
        if record_count > 500:
            # we get 500 records ,create a file and move to the next one
            write_small_yml("%s%s.yml" % (name, str(file_count)), small_yml)
            small_yml[0]['data'] = {} # clear data part
            file_count += 1
            record_count = 0 # start counting all over again

    if small_yml[0]['data']:
        # incase we have less then 500 records but we reached the end of the main yml
        write_small_yml("%s%s.yml" % (name, str(file_count)), small_yml)

@dhcpldap.command()
@click.option('--ofile', default=None, help='output file to which ldap data is written')
@click.option('--lab', default='infi1', help='Infi1 / telad / gdc /')
@click.pass_obj
def sanity_report(ldaph, lab, ofile):

    ldaph.connect(lab)
    click.secho('Retrieving LDAP raw data', fg='green')
    ldap_raw_data = ldaph.pull_dhcp_data()

    click.secho('Creating Sanity Report', fg='blue')
    report_str = ldaph.sanity_report(ldap_raw_data)

    if ofile:
        with open(ofile, 'w') as f:
            f.write(report_str)
        click.secho('Sanity report availble in %s' % ofile, fg='green')
    else:
        print(report_str)


##### LDAP SEARCH

def search_in_lab(ldaph, lab, st):

    ldaph.connect(lab)
    click.secho('Retrieving LDAP raw data from %s' % lab, fg='green')
    data = ldaph.pull_dhcp_data()

    dhcp_dict = dict()

    for e in data:
        if st in str(e):
            if 'dhcpHWAddress' in e[1]:
                mac = e[1]['dhcpHWAddress'][0].split()[1]
            else:
                mac = "NA"

            if 'dhcpStatements' in e[1]:
                ip = e[1]['dhcpStatements'][0].split()[1]
            else:
                ip = "NA"

            dhcp_dict[e[1]['cn'][0]] = [mac, ip]

    return dhcp_dict

@dhcpldap.command()
@click.option('-l', '--lab', default=None, help='which ldap to search')
@click.argument('st')
@click.pass_obj
def ldap_search(ldaph, st, lab):

    dhcp_dict = dict()

    if lab:
        # click.secho('Searching for %s in %s' % (str, lab), fg='green' )
        dhcp_dict[lab] = search_in_lab(ldaph, lab, st )
    else:
        for l in ldaph.labs.keys():
            # click.secho('Searching for %s in %s' % (str, l), fg='green' )
            dhcp_dict[l] = search_in_lab(ldaph,l, st)
            if not dhcp_dict[l]:
                click.secho('nothing found in %s' % l, fg='yellow' )

    for l in dhcp_dict:
        # since infi1 and gdc will give the same data
        # filter gdc when infi1 is incleded
        if l=='gdc' and 'infi1' in dhcp_dict and 'gdc' in dhcp_dict:
            break
        for component in dhcp_dict[l]:
            print("(%s) %s -> %s" % (l, component, dhcp_dict[l][component]))
