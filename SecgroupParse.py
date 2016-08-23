import boto.ec2 as ec2_conn
from multiprocessing.pool import ThreadPool as Pool
from multiprocessing import Lock
from functools import partial
import CloudwatchDump as fileLogs
import LogProcess as Process
import argparse


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('region', help='The AWS region to connect to.')
    parser.add_argument('name', help='The name of the AWS CloudWatch flow logs')

    return_args = parser.parse_args()
    return return_args


def edit_groups(args):

    ec2 = ec2_conn.connect_to_region(args.region)

    sec_ports = {}
    sec_eni = {}
    num_grps = [0,0]  # Tracks the number of security groups processed

    sec_groups = ec2.get_all_security_groups()
    for x in sec_groups:
        print x.name
    fileLogs.save_logs(args)  # Ensures we have .csv files saved for every ENI we care about.
    num_grps[1] = len(sec_groups)

    # Does all of the processing using a thread pool, and maps it to our member dictionary.
    processor = partial(Process.process_logs, eni_dict=sec_eni, counter=num_grps)
    p = Pool(20)
    pool_dict = p.map(processor, sec_groups)
    for p in pool_dict:
        for y in p:
            sec_ports[y] = p[y]

    lock = Lock()
    new_pool = Pool(5)
    print_grp = partial(Process.print_sec_group, lock=lock, group_dict=sec_ports, conn=ec2)
    #   Prints the output.
    new_pool.map(print_grp, sec_ports.keys())
    Process.write_output_csv(sec_ports)
    #   Automatically modify egress rules for security groups
    Process.modify_sec_groups(sec_ports, ec2)


if __name__ == '__main__':
    input_args = parse_args()
    edit_groups(input_args)
