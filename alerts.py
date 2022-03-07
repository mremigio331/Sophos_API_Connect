import sophos_functions as sf
import json
from os.path import exists
import time
import sys

global log_from
log_from = 'Alerts'

def start():
    log_file_name = 'alerts_log.json'

    txt_file_exists = exists('Sophos_Logs.log')
    if txt_file_exists is True:
        pass
    if txt_file_exists is False:
        note = 'New Log File Created'
        sf.log_add(note,log_from,True)
    json_file_exists = exists(log_file_name)
    alerts = sf.alerts()
    note = 'Pulling Sophos Alerts'
    message = sf.log_add(note,log_from,False)
    print(message)
    alerts = alerts['items']

    if json_file_exists is True:
        sf.add_data(alerts,log_file_name)

    if json_file_exists is False:
        with open(log_file_name, 'w') as outfile:
            json.dump(alerts, outfile)
            note = 'No alerts json file exited, created a new alerts json file'
            sf.log_add(note,log_from,True)
            print('File does not exist')

        new_alert_id_count = 0
        current_alert_data = []

        for x in alerts:
            e = x['id']
            t = x['raisedAt']
            d = x['description']

            current_alert_data.append(x)
            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + e + ' created at ' + t + ' added. Description: ' + d
            message = sf.log_add(note, log_from,True)
            print(message)

        note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
        message = sf.log_add(note,log_from,False)
        print(message)



def run():
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    for x in lines:
        if 'run' in x:
            status = x.split(' = ')[1]
            status = bool(run)

    while status is True:

        with open('sophos.conf') as f:
            lines = [line.strip() for line in f]

        for x in lines:
            if 'pull_time' in x:
                pull_time = x.split(' = ')[1]
                pull_time = int(pull_time)

        start()
        while pull_time >= 0:
            if pull_time == 0:
                time_left = (str(pull_time) + ' seconds till next alerts pull')
                sys.stdout.write('%s\r' % time_left)
                print('\n')
                print('Next Alerts Pull Initiated')
                pull_time = pull_time - 1
            if pull_time > 0:
                time_left = (str(pull_time) + ' seconds till next alerts pull')
                sys.stdout.write('%s\r' % time_left)
                sys.stdout.flush()
                pull_time = pull_time - 1

            time.sleep(1)