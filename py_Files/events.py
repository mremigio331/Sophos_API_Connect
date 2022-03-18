import sophos_functions as sf
import json
from os.path import exists
import time
import sys

global log_from
log_from = 'Events'

def json_start():
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    for x in lines:
        if 'events_json_file_name' in x:
            file_name = x.split('=')[1].strip()
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name

    json_file_exists = exists(log_file_name)
    events = sf.events(False)
    note = 'Pulling Sophos Events'
    message = sf.log_add(note,log_from,False)
    print(message)
    events = events['items']

    if json_file_exists is True:
        sf.add_data_json(events,log_file_name)

    if json_file_exists is False:
        with open(log_file_name, 'w') as outfile:
            json.dump(events, outfile)
            note = 'No events json file exited, created a new events json file'
            sf.log_add(note,log_from,True)
            print('File does not exist')

        new_alert_id_count = 0
        current_alert_data = []

        for x in events:
            e = x['id']
            t = x['created_at']
            d = x['name']

            current_alert_data.append(x)
            new_alert_id_count = new_alert_id_count + 1
            note = 'Event ID: ' + e + ' created at ' + t + ' added. Description: ' + d
            message = sf.log_add(note, log_from,True)
            print(message)

        note = 'Added ' + str(new_alert_id_count) + ' new Event IDs'
        message = sf.log_add(note,log_from,False)
        print(message)

def txt_start():
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    for x in lines:
        if 'events_txt_file_name' in x:
            file_name = x.split('=')[1].strip()
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name

    export_file = exists(log_file_name)
    events = sf.events(False)
    note = 'Pulling Sophos Events'
    message = sf.log_add(note, log_from, False)
    print(message)
    events = events['items']

    if export_file is True:
        sf.events_add_data(events,log_file_name,False)

    if export_file is False:
        sf.events_add_data(events, log_file_name, True)

def run():
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    for x in lines:
        if 'run' in x:
            status = x.split(' = ')[1]
            status = sf.bool_return(status)
        if 'txt_file_creation' in x:
            txt_file = x.split(' = ')[1]
            txt_file = sf.bool_return(txt_file)
        if 'json_file_creation' in x:
            json_file = x.split(' = ')[1]
            json_file = sf.bool_return(json_file)

    while status is True:

        with open('sophos.conf') as f:
            lines = [line.strip() for line in f]

        for x in lines:
            if 'pull_time' in x:
                pull_time = x.split(' = ')[1]
                pull_time = int(pull_time)
            if 'run' in x:
                status = x.split(' = ')[1]
                status = sf.bool_return(status)
            if 'txt_file_creation' in x:
                txt_file = x.split(' = ')[1]
                txt_file = sf.bool_return(txt_file)
            if 'json_file_creation' in x:
                json_file = x.split(' = ')[1]
                json_file = sf.bool_return(json_file)

        if txt_file is True:
            try:
                txt_start()
            except Exception as err:
                error = err
                note = 'ERROR: ' + error
                sf.log_add(note, log_from, True)

        if json_file is True:
            try:
                json_start()
            except Exception as err:
                error = err
                note = 'ERROR: ' + error
                sf.log_add(note, log_from, True)

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