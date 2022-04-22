"""
S_Common holds functions that didn't fit in its own python file
"""
import sys
from os.path import exists
import json

from datetime import datetime


def add_data_json(add_data, filename):
    """
    add_data_json takes events or alerts generated by Sophos and places them into JSON file

        events(dict) are a dict of either events or alerts that will be analyzed
        filename(str) is the name of the final output
    """

    log_from = filename.split('_')[0]
    log_from = log_from.capitalize()

    with open(filename, 'r') as j:
        current_data = json.load(j)

    current_ids = []
    for x in current_data:
        e = x['id']
        current_ids.append(e)

    new_id_count = 0
    for x in add_data:
        e = x['id']

        try:
            t = x['created_at']
            d = x['name']
            log_type = 'Event ID: '
        except:
            t = x['created_at']
            d = x['description']
            log_type = 'Alert ID: '

        if e in current_ids:
            pass
        else:
            current_data.append(x)
            new_id_count = new_id_count + 1
            note = log_type + e + ' created at ' + t + ' added. Description: ' + d
            log_add(note, log_from, 3)

    with open(filename, 'w') as outfile:
        json.dump(current_data, outfile)

    if new_id_count > 0:
        new_id_count = str(new_id_count)
        note = new_id_count + ' new logs added'
        log_add(note, log_from, 2)


def log_add(note, log_from, level):
    """
    log_add controls the logging of information as the code runs

        note(str) is the specific thing being logged
        log_from(str) is where the log is coming from
        level(int) identifies what priority level the log is to determine if the log will be added to the log file
    """

    logging_level = log_level()  # identifies what the log level is in the config file

    lines = config_load()  #

    for x in lines:
        if 'log_file_name' in x:
            log_file = x.split('=')[1].strip()

    log_file_exists = exists(log_file)

    if log_file_exists is False:  # if a log file does not exist a new file will be created
        with open(log_file, 'w') as f:
            now = datetime.now()
            now = now.strftime('%d/%m/%Y %H:%M:%S')
            full_note = '[' + log_from + ' Log ' + now + '] ' + 'New Log File Created'
            full_note = str(full_note)
            f.write(full_note + '\n')
            f.close()

        print(full_note)

    if int(level) <= int(logging_level):  # will log information if level is smaller or equal to the config log level
        with open(log_file, 'a') as f:
            now = datetime.now()
            now = now.strftime('%d/%m/%Y %H:%M:%S')
            full_note = '[' + log_from + ' Log ' + now + '] ' + note
            full_note = str(full_note)
            f.write(full_note + '\n')
            f.close()
            print(full_note)


def bool_return(string):
    """
    bool_return will take a str in the form of either True or False and return a bool

        string(str)

        return either True(bool) or False(bool)
    """

    if string == 'True':
        return True
    if string == 'False':
        return False


def config_load():
    """
    config_load will open the config file and return all config options in the form of a list

        return lines(list)
    """

    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    return lines


def config_check():
    """
    config_check looks confirms the config file is correctly filled
    if any errors are identified it will return a False(bool)

        return True(bool) or False(bool)
    """

    lines = config_load()
    total_errors = []
    full_config = []
    log_levels = ['VERBOSE', 'LOG', 'INFO', 'ERROR', 'OFF']
    bool_options = ['True', 'False']

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
        log_add(note, 'System', 1)
        return False

    else:
        note = 'Configurations: ' + str(full_config)
        log_add(note, 'System', 2)
        return True


def auto_acknowledge_level():
    """ 
    reads the config file and returns a dict for auto_acknowledge
        
        retun acknowledge_levls(dict)
    """

    lines = config_load()

    alerts_auto_acknowledge = False
    alerts_auto_acknowledge_level = []
    events_auto_acknowledge = False
    events_auto_acknowledge_level = []

    for x in lines:
        if 'alerts_auto_acknowledge' in x:
            alerts_auto_acknowledge = x.split(' = ')[1]
            print(alerts_auto_acknowledge)
        if 'alerts_auto_acknowledge_level' in x:
            alerts_auto_acknowledge_level = x.split(' = ')[1].strip()
            print(alerts_auto_acknowledge_level)
        if 'events_auto_acknowledge' in x:
            events_auto_acknowledge = x.split(' = ')[1]
            print(events_auto_acknowledge)
        if 'events_auto_acknowledge_level' in x:
            events_auto_acknowledge_level = x.split(' = ')[1].strip()
            print(events_auto_acknowledge_level)

        if alerts_auto_acknowledge_level in ['Low', 'low', 'LOW']:
            alerts_levels = ['low']

        if alerts_auto_acknowledge_level in ['Medium', 'medium', 'MEDIUM']:
            alerts_levels = ['low', 'medium']

        if alerts_auto_acknowledge_level in ['High', 'high', 'HIGH']:
            alerts_levels = ['low', 'medium', 'high']

        if events_auto_acknowledge_level in ['None', 'none', 'NONE']:
            events_levels = ['none']

        if events_auto_acknowledge_level in ['Low', 'low', 'LOW']:
            events_levels = ['none', 'low']

        if events_auto_acknowledge_level in ['Medium', 'medium', 'MEDIUM']:
            events_levels = ['none', 'low', 'medium']

        if events_auto_acknowledge_level in ['High', 'high', 'HIGH']:
            events_levels = ['none', 'low', 'medium', 'high']

        if events_auto_acknowledge_level in ['Critical', 'critical', 'CRITICAL']:
            events_levels = ['none', 'low', 'medium', 'high', 'critical']

        acknowledge_levels = {'alerts':
                                  {'auto_acknowledge': alerts_auto_acknowledge,
                                   'level': alerts_levels},
                              'events':
                                  {'auto_acknowledge': events_auto_acknowledge,
                                   'level': events_levels}}

        print('acknowledge_levels loaded')
        return acknowledge_levels


def log_level():
    """
    log_level reads the config file and returns an int variable
    if the log_level is incorrect an error will be printed and the code will exit

        return int
    """
    lines = config_load()
    log_levels = ['VERBOSE', 'LOG+', 'INFO', 'ERROR', 'OFF']

    for x in lines:
        if 'log_level' in x:
            log_level = x.split(' = ')[1]
        if 'log_file_name' in x:
            log_file = x.split('=')[1].strip()

    if log_level in log_levels:

        if log_level == 'VERBOSE':
            return 4
        elif log_level == 'LOG':
            return 3
        elif log_level == 'INFO':
            return 2
        elif log_level == 'ERROR':
            return 1
        elif log_level == 'OFF':
            return 0
    else:
        with open(log_file, 'a') as f:
            now = datetime.now()
            now = now.strftime('%d/%m/%Y %H:%M:%S')
            full_note = ('[System Log ' +
                         now +
                         "] Config file contains the following errors: ['Invalid Log Level Input']")

            full_note = str(full_note)
            f.write(full_note + '\n')
            f.close()
            print(full_note)
            sys.exit()
