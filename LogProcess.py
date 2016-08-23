import csv
import re
import boto
import time

#  These ports are usually ports we want to allow, so don't filter these out
DEFAULT_PORTS = ['']


#   Writes security group analysis output to a csv file.
def write_output_csv(ports_dict):
    with open('./groups.csv', 'w+') as csv_file:
        csv_writer = csv.writer(csv_file)
        for grp in ports_dict:
            if ports_dict[grp]:
                csv_writer.writerow([grp.name, grp.id, '', ''])
                for port in ports_dict[grp]:
                    port_list = ['', '', port]
                    if len(ports_dict[grp][port].keys()) > 5:
                        port_list.append('0.0.0.0/0')
                    else:
                        ip_list = []
                        for x in ports_dict[grp][port].keys():
                            if x is not 'total':
                                ip_list.append(x)
                        port_list.append(' '.join(ip_list))
                    csv_writer.writerow(port_list)
            else:
                csv_writer.writerow([grp.name, grp.id, 'None', ''])


#   Replaces private IP addresses with their associated security groups, if applicable.
def replace_ip(ip_dict, conn):
    new_dict = {}
    for ip in ip_dict:
        if ip != 'total':
            while True:
                try:
                    all_resev = conn.get_all_instances(filters={'private-ip-address': ip})
                    if not all_resev:
                        new_dict[ip] = ip_dict[ip]
                    else:
                        for res in all_resev:
                            for ins in res.instances:
                                for x in ins.groups:
                                    grp_id = x.id
                                    if grp_id not in new_dict:
                                        new_dict[grp_id] = ip_dict[ip]
                                    else:
                                        new_dict[grp_id] += ip_dict[ip]
                except boto.exception.BotoServerError:
                    print 'Rate limit exceeded.'
                    time.sleep(1)
                    continue
                break
        else:
            new_dict[ip] = ip_dict[ip]
    new_dict['total'] = ip_dict['total']
    return new_dict


#   Helper method to process log files
def process_logs(grp, eni_dict, counter):
    insts = grp.instances()
    eni_list = []
    private_ips = []
    out_dict = {}

    ports = {}
    total = 0

    #   For each instance associated with the security group, gets its private IP and ENI.
    if insts:
        for x in insts:
            private_ips.append(x.private_ip_address)
            inters = x.interfaces
            for y in inters:
                eni_list.append(y.id)
        eni_dict[grp] = eni_list

    for eni in eni_list:
        #   Builds the file path to the particular .CSV file associated with the ENI.
        file_name = './' + eni + '.csv'
        try:
            with open(file_name, 'rb') as csv_file:
                log_reader = csv.reader(csv_file, delimiter=',')
                for row in log_reader:
                    #   Filters out only flow log events with a source IP of one of the instances in the security group.
                    if row[3] in private_ips:
                        #   A basic filter to remove response traffic, rejected traffic, and pings.
                        if int(row[6]) < 10000 and row[12] == 'ACCEPT' and row[7] != '1':
                            port = row[6]
                            dst_ip = row[4]
                            #   Builds the dictionary.  Each port has a dictionary with dst IPs and counts.
                            if port not in ports:
                                ports[port] = {dst_ip: 1}
                            else:
                                if dst_ip in ports[port]:
                                    ports[port][dst_ip] += 1
                                else:
                                    ports[port][dst_ip] = 1
                            total += 1
        except IOError:
            print 'No logs associated with ENI.'
    # Adds a value 'total' which represents the total proportion of traffic on this port compared to total traffic.
    for x in ports:
        total_hits = 0
        for y in ports[x]:
            total_hits += ports[x][y]
        ports[x]['total'] = (float(total_hits) / total) * 100
    # A more advanced filter to remove ephemeral responses.
    for z in ports.keys():
        #   This hits filter is to get rid of ports that have a high % of total traffic, but a low number of hits.
        hits = 0
        for y in ports[z]:
            if y != 'total':
                hits += ports[z][y]
        is_match = False
        for x in ports[z].keys():
            #   For now, only filter responses to inside the VPC.  Most responses seem to be within the VPC.
            if re.match('172', x):
                is_match = True
        # Only filter ports with a low enough proportion, not a port we care about, and traffic to within the VPC:
        if ports[z]['total'] < 0.1 and z not in DEFAULT_PORTS and is_match:
            del ports[z]
    # Wraps the dictionary into another dictionary in order to correlate it with the security group.
    out_dict[grp] = ports
    counter[0] += 1  # Increments the number of security groups processed
    print 'Security group complete: ' + grp.id + '\nNumber of security groups complete: ' \
          + str(counter[0]) + ' of ' + str(counter[1]) + '\n'
    return out_dict


def print_sec_group(index, lock, group_dict, conn):
    if group_dict[index]:
        for y in group_dict[index]:
            group_dict[index][y] = replace_ip(group_dict[index][y], conn)
            # print group_dict[index][y]
        lock.acquire()
        print index, "\tID: ", index.id
        print "Outbound ports:"
        for j in group_dict[index]:
            print 'Port: ' + str(j)
            print '% of total: ' + format(group_dict[index][j]['total'], '.3f') + '%'
            if len(group_dict[index][j].keys()) <= 7:
                print 'Destination IP addresses/security groups: ' + ', '.join(
                    z + ': ' + str(group_dict[index][j][z]) for z in group_dict[index][j] if z != 'total')
            else:
                print 'Many dest. IP addresses/security groups'

                # for z in group_dict[index][j]:
                #     if z != 'total':
                #         print z + '\t' + str(group_dict[index][j][z])
        print "-----------------------------------------------------------------------------------------"
        lock.release()


def modify_sec_groups(groups, conn):
    for grp in groups:
        print 'Authorizing rules for security group ', grp.id
        new_rules = []  # The list of new egress rules
        curr_egress_rules = grp.rules_egress
        for port in groups[grp]:
            # Begin building the dict to represent the new rule
            rule_dict = {'group_id': grp.id, 'from_port': port, 'to_port': port, 'ip_protocol': 'tcp'}
            dest_grps = []
            dest_cidr = []
            dst = groups[grp][port].keys()  # The destination IPs/security groups associated with the port

            # Build the lists of destination IPs and security groups
            for x in dst:
                if re.match('sg', x):
                    dest_grps.append(x)
                elif not re.match('total', x):
                    dest_cidr.append(x + '/32')

            if str(port) == '123':
                rule_dict['ip_protocol'] = 'udp'  # Set protocol to UDP, but only for NTP

            # If there's a lot of destinations, set it to allow outbound to all
            if len(groups[grp][port].keys()) > 4:
                rule_dict['cidr_ip'] = '0.0.0.0/0'
            elif dest_grps:
                rule_dict['src_group_id'] = dest_grps
            elif dest_cidr:
                rule_dict['cidr_ip'] = dest_cidr
            new_rules.append(rule_dict)  # Add rule to the security group's list of rules

        for rule in new_rules:
            for x in rule:
                if x != 'from_port' and x != 'group_id':
                    print x, ': ', rule[x]  # Print the rules we want to authorize
            print '---'
        if new_rules:
            result = raw_input('Authorize security group egress rule modification? [y/n]: ')
            if result == 'y' or result == 'Y':
                #   Revoke the rules to allow all outbound traffic
                for rule in curr_egress_rules:
                    grant_list = rule.grants
                    for grant in grant_list:
                        if str(grant) == '0.0.0.0/0' and grant.cidr_ip == '0.0.0.0/0':
                            print 'Revoking all outbound access.'
                            conn.revoke_security_group_egress(group_id=grp.id, ip_protocol=rule.ip_protocol,
                                                              from_port=rule.from_port, to_port=rule.to_port,
                                                              cidr_ip=grant.cidr_ip)
                for rule in new_rules:
                    ip_list = rule['cidr_ip']
                    if ip_list:
                        if ip_list == '0.0.0.0/0':  # If allowing all outbound, don't iterate
                            conn.authorize_security_group_egress(group_id=grp.id, ip_protocol=rule['ip_protocol'],
                                                                 from_port=rule['from_port'], to_port=rule['to_port'],
                                                                 cidr_ip=ip_list)
                        else:
                            for ip in ip_list:  # Authorize a different rule for each dest. IP
                                conn.authorize_security_group_egress(group_id=grp.id, ip_protocol=rule['ip_protocol'],
                                                                     from_port=rule['from_port'],
                                                                     to_port=rule['to_port'],
                                                                     cidr_ip=ip)
                    grp_list = rule['src_group_id']
                    if grp_list:  # Authorize a different rule for each group in our list of dest. security groups
                        for group in grp_list:
                            conn.authorize_security_group_egress(group_id=grp.id, ip_protocol=rule['ip_protocol'],
                                                                 from_port=rule['from_port'], to_port=rule['to_port'],
                                                                 src_group_id=group)
                print 'Egress rules added.'
