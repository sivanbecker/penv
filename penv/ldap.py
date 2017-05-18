#!/usr/local/bin/python3

import click
import ldap
import json
import requests


class Ldap(object):




    def __init__(self):

        # Default Values
        self.hosts = {
            'INFI1': 'dhcp-prod01',
            'TELAD': 'dhcp-telad-01',
            'GDC': 'dhcp-prod01',
            'NW': 'dhcp-nw-01',
            'WT': 'dhcp-wt-01'
            }

        self.basedns = {
            'INFI1': 'dc=infinidat,dc=com',
            'TELAD': 'dc=telad',
            'GDC': 'dc=infinidat,dc=com',
            'NW': 'dc=nw,dc=infinidat,dc=com',
            'WT': 'dc=wt,dc=infinidat,dc=com'
            }
        self.labs = {
            'telad': [self.hosts['TELAD'],self.basedns['TELAD']],
            'infi1': [self.hosts['INFI1'],self.basedns['INFI1']],
            'gdc': [self.hosts['GDC'],self.basedns['GDC']],
            'needham': [self.hosts['NW'],self.basedns['NW']],
            'wt': [self.hosts['WT'],self.basedns['WT']]

            }
        # HOST_INFI1 = ''
        # HOST_TELAD = 'dhcp-telad-01'
        # HOST_GDC = HOST_INFI1
        # HOST_NW = 'dhcp-nw-01'
        # HOST_WT = 'dhcp-wt-01'

        # BASEDN_INFI1 = 'dc=infinidat,dc=com'
        # BASEDN_GDC = BASEDN_INFI1
        # BASEDN_TELAD = ','.join(['dc=telad', BASEDN_INFI1])
        # BASEDN_NW = ','.join(['dc=nw', BASEDN_INFI1])
        # BASEDN_WT = ','.join(['dc=wt', BASEDN_INFI1])

        # LABS = {
        #     'telad': [self.hosts['TELAD'],self.basedns['TELAD']],
        #     'infi1': [HOST_INFI1, BASEDN_INFI1],
        #     'gdc': [HOST_GDC, BASEDN_GDC],
        #     'needham': [HOST_NW, BASEDN_NW],
        #     'wt':[HOST_WT, BASEDN_WT]
        # }

        self.ldap = None
        self.lab = None
        self.basedn = None
        self.host = None

    def connect(self, lab, username, password):
        if lab.lower() not in self.labs:
            click.secho("Lab %s is not a valid option" % lab, fg='red')
            raise click.UsageError("Please only use next option for --lab: %s" % list(self.labs.keys()))
        else:
            self.lab = lab
            self.host =  self.labs[self.lab.lower()][0]
            self.basedn = self.labs[self.lab.lower()][1]

        ldapi = "ldap://" + self.host + ":389"
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        self.ldap = ldap.initialize(ldapi)
        self.ldap.set_option(ldap.OPT_REFERRALS, 0)
        self.ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        self.ldap.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
        self.ldap.set_option(ldap.OPT_X_TLS_DEMAND, False)
        self.ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)

        binddn = "cn=" + username + "," + self.basedn

        try:
            self.ldap.simple_bind_s(binddn, password)
        except ldap.INVALID_CREDENTIALS:
            print("Your username or password is incorrect.")
            sys.exit()
        except ldap.LDAPError as e:
            if type(e.message) == dict and e.message.has_key('desc'):
                print(e.message['desc'])
            else:
                print(e)
                sys.exit()


    def pull_dhcp_data(self):

        if not self.lab:
            click.secho("No lab was provided", fg='red')
            raise click.Abort()

        return self.ldap.search_s(self.basedn, ldap.SCOPE_SUBTREE, '(objectClass=*)')

    def process_raw(self, data, sanity=False, quick=False, sample=False):
        """
        method for taking raw data from ldap and
        disect to smaller pieces.
        """
        counter = 0
        hosts_str = ''
        if quick:
            cmd_str = "- url: /api/multiple_register/\n"+" "*2 +"data: " + " " +"{\n" + " "*8 + "\"deploy\": \"False\",\n" + " "*8 + "\"quick\": \"True\",\n"
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
                            subnet = requests.get('http://127.0.0.1:5000/api/subnets/query_subnet_from_ip/', data=data).text
                            if 'Bad Request' in subnet:
                                continue
                        else:
                            ip = None

                        if ip:
                            hosts_str += "h"+str(counter) + ": " + "{hostname: \"%s\", mac: \"%s\", group: \"%s\", subnet: %s, ip: \"%s\", deployed: False },\n" \
                                         % (hostname, mac, group_name, subnet.strip(), ip) + " "*9

                            ip_dict[ip].append(hostname)
                            mac_dict[mac].append(hostname)
                        else:
                            hosts_str += "h" + str(
                                counter) + ": " + "{hostname: \"%s\", mac: \"%s\", group: \"%s\", deployed: False },\n" \
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
        ip_dict, mac_dict = self.process_raw(data, True, False)
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
@click.option('--username', help='username for LDAP access', required=True)
@click.option('--password', help='password for LDAP access', required=True)
@click.option('--lab', default='infi1', help='Infi1 / telad / gdc /')
@click.pass_context
def dhcpldap(ctx, username, password, lab):
    click.secho('Connecting LDAP for lab %s' % lab, fg='blue')
    ctx.obj = Ldap()
    ctx.obj.connect(lab, username, password)

@dhcpldap.command()
@click.option('--elem', default='raw', help='host/system/ip/mac')
@click.option('--raw/--no-raw', default=False, help='Process data for dhcpawn')
@click.option('--quick/--no-quick', default=True, help='if used ,a quick copy from ldap to dhcpawn DB is done')
@click.option('--sample/--no-sample', default=False, help='meant for testing ,will only return 10 records from ldap to see the output is right')
@click.option('--ofile', help='output file to which ldap data is written')
@click.pass_obj
def ldap_to_yml(ldaph, elem, raw, sanity, quick, ofile, sample):
    if raw and not ofile:
        click.secho("Please also provide an output file ", fg='red')
        raise click.Abort()

    click.secho('Retrieving LDAP raw data', fg='green')
    ldap_raw_data = ldaph.pull_dhcp_data()
    with open(ofile, 'w') as f:
        f.write(ldaph.process_raw(ldap_raw_data, sanity, quick, sample))
        click.secho("Data is ready in %s" % ofile, fg='blue')

@dhcpldap.command()
@click.option('--ofile', default=None, help='output file to which ldap data is written')
@click.pass_obj
def sanity_report(ldaph, ofile):

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
