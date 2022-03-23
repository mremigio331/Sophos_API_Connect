import sys
from os.path import exists
import json
import requests
from datetime import datetime, timedelta
import time

import s_authenticate as cate
import s_common as common


global log_from
log_from = 'Events'

def json_start():
    lines = common.config_load()
    for x in lines:
        if 'events_json_file_name' in x:
            file_name = x.split('=')[1].strip()
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name

    json_file_exists = exists(log_file_name)
    events = events_pull(False)
    note = 'Pulling Sophos Events'
    message = common.log_add(note,log_from,3)
    print(message)
    events = events['items']

    if json_file_exists is True:
        common.add_data_json(events,log_file_name)

    if json_file_exists is False:
        with open(log_file_name, 'w') as outfile:
            json.dump(events, outfile)
            note = 'No events json file exited, created a new events json file'
            common.log_add(note,log_from,2)
            print('File does not exist')

        new_event_id_count = 0
        current_event_data = []

        for x in events:
            e = x['id']
            t = x['created_at']
            d = x['name']

            current_event_data.append(x)
            new_event_id_count = new_event_id_count + 1
            note = 'Event ID: ' + e + ' created at ' + t + ' added. Description: ' + d
            common.log_add(note, log_from,4)

        note = 'Added ' + str(new_event_id_count) + ' new Event IDs'
        common.log_add(note,log_from,3)

def txt_start():
    lines = common.config_load()

    for x in lines:
        if 'events_txt_file_name' in x:
            file_name = x.split('=')[1].strip()
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name

    export_file = exists(log_file_name)
    events = events_pull(False)
    note = 'Pulling Sophos Events'
    common.log_add(note, log_from, False)
    events = events['items']

    if export_file is True:
        add_log_data(events, log_file_name, False)

    if export_file is False:
        add_log_data(events, log_file_name, True)

def add_log_data(events,logfile,newfile):

    if newfile is True:
        today = datetime.now()
        today = today.strftime('%Y-%m-%d')

        new_event_id_count = 0
        events_list = []

        for x in events:
            createdAt = x['created_at']
            yearMonthDate = createdAt.split('T')[0]
            if yearMonthDate >= today:
                sourceInfo = x['source_info']
                sourceInfo = str(sourceInfo)
                customerID = x['customer_id']
                severity = x['severity']
                name = x['name']
                location = x['location']
                eventID = x['id']
                eventType = x['type']
                group = x['group']

                event_line = '[Timestamp: ' + createdAt + '] ' + '[EventID: ' + eventID + '] ' + '[Severity: ' + severity + '] ' + '[Name: ' + name + '] ' + '[IP: ]' + '[EventType: ' + eventType + '] ' + '[SourceInfo: ' + str(sourceInfo) + '] ' + '[Location: ' + location + '] ' + '[Group: ' + group + '] ' + '[CustomerID: ' + customerID + ']'
                events_list.append(event_line)

                new_event_id_count = new_event_id_count + 1
                note = 'Event ID: ' + eventID + ' created at ' + createdAt + ' added. Name: ' + name
                common.log_add(note, log_from, 4)

        with open(logfile, 'w') as f:
            for x in events_list:
                f.write(x + '\n')
            f.close()

        note = 'Added ' + str(new_event_id_count) + ' new Event IDs'
        common.log_add(note, log_from, 3)

    if newfile is False:
        today = datetime.now()
        today = today.strftime('%Y-%m-%d')

        with open(logfile, 'r') as f:
            current_events = [line.strip() for line in f]

        event_id_list = []
        for x in current_events:
            event_id = x.split('EventID: ')[1].split(']')[0]
            event_id_list.append(event_id)

        new_event_id_count = 0
        events_list = []

        for x in events:
            eventID = x['id']
            if eventID in event_id_list:
                pass
            else:
                createdAt = x['created_at']
                yearMonthDate = createdAt.split('T')[0]
                if yearMonthDate >= today:
                    sourceInfo = x['source_info']
                    sourceInfo = str(sourceInfo)
                    customerID = x['customer_id']
                    severity = x['severity']
                    name = x['name']
                    location = x['location']
                    eventID = x['id']
                    eventType = x['type']
                    group = x['group']
                    ip = ' '

                    event_line = '[Timestamp: ' + createdAt + '] ' + '[EventID: ' + eventID + '] ' + '[Severity: ' + severity + '] ' + '[Name: ' + name + '] ' + '[IP: ]' + '[EventType: ' + eventType + '] ' + '[SourceInfo: ' + str(sourceInfo) + '] ' + '[Location: ' + location + '] ' + '[Group: ' + group + '] ' + '[CustomerID: ' + customerID + ']'
                    events_list.append(event_line)

                    new_event_id_count = new_event_id_count + 1
                    note = 'Event ID: ' + eventID + ' created at ' + createdAt + ' added. Name: ' + name
                    common.log_add(note, log_from, 4)


        with open(logfile, 'a') as f:
            for x in events_list:
                f.write(x + '\n')
            f.close()

        note = 'Added ' + str(new_event_id_count) + ' new Event IDs'
        common.log_add(note, log_from, 3)

def events_pull(timespan):
    """
    events will grab the events from sophos
    timespan(bool) will identify how much data will be puulled
        True will pull from the last 1000 entries
        False will pull from the last 24 hours
    """
    if timespan is True:
        auth = cate.auth_header_grab()
        info = cate.whoami()
        tenant_id = info['id']
        region = (info['apiHosts']['dataRegion'])
        requestUrl = region + '/siem/v1/events?limit=1000'
        requestHeaders = {
            'X-Tenant-ID': tenant_id,
            'Authorization': auth,
            'Accept': 'application/json'
        }
        request = requests.get(requestUrl, headers=requestHeaders)

        return request.json()

    if timespan is False:
        d = datetime.today() - timedelta(days=1)  # creates a datetime variable for yesterday at this time
        unix_time = time.mktime(d.timetuple())  # creates a unix timestamp
        auth = cate.auth_header_grab()
        info = cate.whoami()
        tenant_id = info['id']
        region = (info['apiHosts']['dataRegion'])
        requestUrl = region + '/siem/v1/events?from_date' + str(unix_time)
        requestHeaders = {
            'X-Tenant-ID': tenant_id,
            'Authorization': auth,
            'Accept': 'application/json'
        }
        request = requests.get(requestUrl, headers=requestHeaders)

        return request.json()

def run():
    lines = common.config_load()

    for x in lines:
        if 'run' in x:
            status = x.split(' = ')[1]
            status = common.bool_return(status)
        if 'txt_file_creation' in x:
            txt_file = x.split(' = ')[1]
            txt_file = common.bool_return(txt_file)
        if 'json_file_creation' in x:
            json_file = x.split(' = ')[1]
            json_file = common.bool_return(json_file)

    while status is True:

        lines = common.config_load()

        for x in lines:
            if 'pull_time' in x:
                pull_time = x.split(' = ')[1]
                pull_time = int(pull_time)
            if 'run' in x:
                status = x.split(' = ')[1]
                status = common.bool_return(status)
            if 'txt_file_creation' in x:
                txt_file = x.split(' = ')[1]
                txt_file = common.bool_return(txt_file)
            if 'json_file_creation' in x:
                json_file = x.split(' = ')[1]
                json_file = common.bool_return(json_file)

        if txt_file is True:
            try:
                txt_start()
            except Exception as err:
                error = err
                note = 'ERROR: ' + error
                common.log_add(note, log_from, 1)

        if json_file is True:
            try:
                json_start()
            except Exception as err:
                error = err
                note = 'ERROR: ' + error
                common.log_add(note, log_from, 1)

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