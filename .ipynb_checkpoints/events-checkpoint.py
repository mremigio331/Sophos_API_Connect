import sophos_functions as sf
import json
from os.path import exists
import time
import sys

global log_from
log_from = 'Events'

def start():
    log_file_name = 'events_log.json'

    txt_file_exists = exists('Sophos_Logs.log')
    if txt_file_exists is True:
        pass
    if txt_file_exists is False:
        note = 'New Log File Created'
        sf.log_add(note,log_from)
    json_file_exists = exists(log_file_name)
    events = sf.events()
    note = 'Pulling Sophos Events'
    message = sf.log_add(note,log_from)
    print(message)
    events = events['items']

    if json_file_exists is True:
        sf.add_data(events,log_file_name)

    if json_file_exists is False:
        with open(log_file_name, 'w') as outfile:
            json.dump(events, outfile)
            note = 'No events json file exited, created a new events json file'
            sf.log_add(note,log_from)
            print('File does not exist')

        new_alert_id_count = 0

        for x in events:
            e = x['id']
            t = x['created_at']

            current_alert_data.append(x)
            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + e + ' created at ' + t + ' added'
            message = log_add(note, log_from)
            print(message)

        note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
        message = sf.log_add(note,log_from)
        print(message)



def run():
    status = True
    while status is True:
        start()
        with open('sophos.conf') as f:
            lines = [line.strip() for line in f]

        for x in lines:
            if 'pull_time' in x:
                pull_time = x.split(' = ')[1]
                pull_time = int(pull_time)

        while pull_time >= 0:
            if pull_time == 0:
                time_left = (str(pull_time) + ' seconds till next event pull')
                sys.stdout.write('%s\r' % time_left)
                print('\n')
                print('Next Events Pull Initiated')
                pull_time = pull_time - 1
            if pull_time > 0:
                time_left = (str(pull_time) + ' seconds till next event pull')
                sys.stdout.write('%s\r' % time_left)
                sys.stdout.flush()
                pull_time = pull_time - 1

            time.sleep(1)