import boto.logs as cloud
import boto.configservice
import os.path
from functools import partial
from multiprocessing.pool import ThreadPool as Pool


def write_log_file(grp, region, name):
    logs = cloud.connect_to_region(region)

    if grp.instances():
        for grp_instance in grp.instances():
            for inst_interface in grp_instance.interfaces:
                interface = inst_interface.id
                stream_name = interface + '-accept'
                file_path = './' + interface + '.csv'
                if not os.path.isfile(file_path):
                    try:
                        with open(file_path, 'w+') as out_file:
                            stream = logs.get_log_events(log_group_name=name, log_stream_name=stream_name)
                            token = stream['nextBackwardToken']
                            for x in range(0, 12):
                                print token
                                for event in stream['events']:
                                    csv_string = event['message'].replace(' ', ',')
                                    out_file.write(csv_string)
                                    out_file.write('\n')
                                stream = logs.get_log_events(log_group_name=name,
                                                             log_stream_name=stream_name, next_token=token)
                                prev_token = token
                                token = stream['nextBackwardToken']
                                if token == prev_token:
                                    print 'end of logs.'
                                    break
                    except boto.logs.exceptions.ResourceNotFoundException:
                        print 'No logs associated with ENI.'


def save_logs(groups, args):

    write_log = partial(write_log_file, region=args.region, name=args.name)
    Pool(10).map(write_log, groups)
    print 'Done saving logs.'


