import sophos_functions as sf
import json
from datetime import datetime
from os.path import exists
import time
import sys

def start():
    txt_file_exists = exists('alerts_logs.txt')
    if txt_file_exists is True:
        pass
    if txt_file_exists is False:
        note = 'New alerts log created'
        log_add(note)
    json_file_exists = exists('alerts_log.json')
    alerts = sf.alerts()
    note = 'Grabbed new Sophos events'
    log_add(note)
    alerts = alerts['items']
    if json_file_exists is True:
        with open('alerts_log.json', 'r') as j:
            old_data = json.load(j)
            print('File exists')
            add_data(alerts)
    if json_file_exists is False:
        with open('alerts_log.json', 'w') as outfile:
            json.dump(alerts, outfile)
            note = 'No json file exited, created a new json file'
            log_add(note)
            print('File does not exist')


def add_data(events):

    dtg = []
    for x in events:
        d = x['raisedAt']
        year = d.split('-')[0]
        month = d.split('-')[1].split('-')[0]
        day = d.split('-')[2].split('T')[0]
        hour = d.split('T')[1].split(':')[0]
        minute = d.split(':')[1].split(':')[0]
        second = d.split(':')[2].split('.')[0]
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
        fmt = "%Y/%m/%d %H:%M:%S"
        date_time = dt.strftime(fmt)
        dtg.append(date_time)

    dtg = sorted(dtg)
    last_pull_time = dtg[-1]
    print(last_pull_time)

    new_items_count = []
    for x in events:
        d = x['raisedAt']
        year = d.split('-')[0]
        month = d.split('-')[1].split('-')[0]
        day = d.split('-')[2].split('T')[0]
        hour = d.split('T')[1].split(':')[0]
        minute = d.split(':')[1].split(':')[0]
        second = d.split(':')[2].split('.')[0]
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
        fmt = "%Y/%m/%d %H:%M:%S"
        date_time = dt.strftime(fmt)
        if date_time > last_pull_time:
            new_items_count.append(date_time)
            events.append(x)
        else:
            pass

    with open('alert_log.json', 'w') as outfile:
        json.dump(events, outfile)

    note = str(len(new_items_count)) + ' new logs added'
    full_note = log_add(note)
    print(full_note)

def log_add(note):
    with open('alerts_logs.txt', 'a') as f:
        now = datetime.now()
        now = now.strftime('%d/%m/%Y %H:%M:%S')
        full_note = note + ' at ' + now + '\n'
        f.write(full_note)
        f.close()
        return full_note

def run():
    status = True
    while status is True:
        start()
        with open('sophos.conf') as f:
            lines = [line.strip() for line in f]

        sleep_time = lines[2]
        sleep_time = int(sleep_time.split(' = ')[1])

        while sleep_time >= 0:
            if sleep_time == 0:
                time_left = (str(sleep_time) + ' seconds till next alert pull')
                sys.stdout.write('%s\r' % time_left)
                print('\n')
                print('Next pull initiated')
                sleep_time = sleep_time - 1
            if sleep_time > 0:
                time_left = (str(sleep_time) + ' seconds till next alert pull')
                sys.stdout.write('%s\r' % time_left)
                sys.stdout.flush()
                sleep_time = sleep_time - 1

            time.sleep(1)