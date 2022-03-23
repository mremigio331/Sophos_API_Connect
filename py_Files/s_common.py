import sys
import os
from os.path import exists
import json

from datetime import datetime


def add_data_json(events,filename):

    log_from = filename.split('_')[0]
    log_from = log_from.capitalize()

    with open(filename, 'r') as j:
        current_alert_data = json.load(j)

    current_alert_ids = []
    for x in current_alert_data:
        e = x['id']
        current_alert_ids.append(e)

    new_alert_id_count = 0
    for x in events:
        e = x['id']

        try:
            t = x['created_at']
            d = x['name']
        except:
            t = x['created_at']
            d = x['description']

        if e in current_alert_ids:
            pass
        else:
            current_alert_data.append(x)
            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + e + ' created at ' + t + ' added. Description: ' + d
            log_add(note,log_from,3)

    with open(filename, 'w') as outfile:
        json.dump(current_alert_data, outfile)

    new_alert_id_count = str(new_alert_id_count)
    note = new_alert_id_count + ' new logs added'
    log_add(note,log_from,2)

def log_add(note,log_from,level):

    logging_level = log_level()

    lines = config_load()

    for x in lines:
        if 'log_file_name' in x:
            log_file = x.split('=')[1].strip()

    log_file_exists = exists(log_file)

    if log_file_exists is False:
        with open(log_file, 'w') as f:
            now = datetime.now()
            now = now.strftime('%d/%m/%Y %H:%M:%S')
            full_note = '[' + log_from + ' Log ' + now + '] ' + 'New Log File Created'
            full_note = str(full_note)
            f.write(full_note + '\n')
            f.close()

        print(full_note)

    if int(level) <= int(logging_level):
        with open(log_file, 'a') as f:
            now = datetime.now()
            now = now.strftime('%d/%m/%Y %H:%M:%S')
            full_note = '[' + log_from + ' Log ' + now + '] ' + note
            full_note = str(full_note)
            f.write(full_note + '\n')
            f.close()
            print(full_note)

def bool_return(string):
    if string == 'True':
        return True
    if string == 'False':
        return False

def config_load():
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    return lines

def config_check():

    lines = config_load()
    total_errors = []
    full_config = []
    log_levels = ['VERBOSE', 'INFO+', 'INFO', 'ERROR', 'OFF']
    bool_options = ['True','False']

    for x in lines:

        if 'client_id' in x:
            try:
                client_id = x.split(' = ')[1]
            except:
                error = 'Invalid Client ID'
                total_errors.append(error)

        if 'client_secret' in x:
            try:
                client_secret = x.split(' = ')[1]
            except:
                error = 'Invalid Client Secret ID'
                total_errors.append(error)

        if 'pull_time' in x:
            try:
                pull_time = x.split(' = ')[1]
                pull_time = int(pull_time)
                full_config.append(x)
            except:
                error = 'Invalid Pull Time'
                total_errors.append(error)

        if 'run' in x:
            try:
                run = x.split(' = ')[1]
                if run in bool_options:
                    full_config.append(x)
                else:
                    error = 'Invalid Run'
                    total_errors.append(error)
            except:
                error = 'Invalid Run'
                total_errors.append(error)

        if 'txt_file_creation' in x:
            try:
                txt_file_creation = x.split(' = ')[1]
                if txt_file_creation in bool_options:
                    full_config.append(x)
                else:
                    error = 'Invalid Run'
                    total_errors.append(error)
            except:
                error = 'Invalid TXT File Creation'
                total_errors.append(error)

        if 'json_file_creation' in x:
            try:
                json_file_creation = x.split(' = ')[1]
                if json_file_creation in bool_options:
                    full_config.append(x)
                else:
                    error = 'Invalid Run'
                    total_errors.append(error)
            except:
                error = 'Invalid JSON File Creation'
                total_errors.append(error)

        if 'alerts_txt_file_name' in x:
            try:
                alerts_txt_file_name = x.split('=')[1].strip()
                full_config.append(x)
            except:
                error = 'Invalid Alerts TXT File Name'
                total_errors.append(error)

        if 'events_txt_file_name' in x:
            try:
                events_txt_file_name = x.split('=')[1].strip()
                full_config.append(x)
            except:
                error = 'Invalid Events TXT File Name'
                total_errors.append(error)

        if 'alerts_json_file_name' in x:
            try:
                alerts_json_file_name = x.split('=')[1].strip()
                full_config.append(x)
            except:
                error = 'Invalid Alerts JSON File Name'
                total_errors.append(error)

        if 'events_json_file_name' in x:
            try:
                events_json_file_name = x.split('=')[1].strip()
                full_config.append(x)
            except:
                error = 'Invalid Events JSON File Name'
                total_errors.append(error)

        if 'log_level' in x:
            try:
                log_level = x.split('=')[1].strip()

                if log_level in log_levels:
                    full_config.append(x)
                else:
                    error = 'Invalid Log Level File Name'
                    total_errors.append(error)
            except:
                error = 'Invalid Events JSON File Name'
                total_errors.append(error)

        if 'log_file_name' in x:
            try:
                log_file_name = x.split('=')[1].strip()
                full_config.append(x)
            except:
                error = 'Invalid Events JSON File Name'
                total_errors.append(error)

    if len(total_errors) > 0:
        note = 'ERROR: Config file contains the following errors: ' + str(total_errors)
        log_add(note,'System',1)
        return False

    else:
        note = 'Configurations: ' + str(full_config)
        log_add(note,'System',3)
        return True

def log_level():
    lines = config_load()
    log_levels = ['VERBOSE', 'INFO+', 'INFO', 'ERROR', 'OFF']

    for x in lines:
        if 'log_level' in x:
            log_level = x.split(' = ')[1]

    if log_level in log_levels:

        if log_level == 'VERBOSE':
            return 4
        elif log_level == 'INFO+':
            return 3
        elif log_level == 'INFO':
            return 2
        elif log_level == 'ERROR':
            return 1
        elif log_level == 'OFF':
            return 0
    else:
        return 0