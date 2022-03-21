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
            message = log_add(note,log_from,True)
            print(message)


    with open(filename, 'w') as outfile:
        json.dump(current_alert_data, outfile)

    new_alert_id_count = str(new_alert_id_count)
    note = new_alert_id_count + ' new logs added'
    full_note = log_add(note,log_from,False)
    print(full_note)

def log_add(note,log_from,log):
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

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

    if log is True:
        with open(log_file, 'a') as f:
            now = datetime.now()
            now = now.strftime('%d/%m/%Y %H:%M:%S')
            full_note = '[' + log_from + ' Log ' + now + '] ' + note
            full_note = str(full_note)
            f.write(full_note + '\n')
            f.close()
            return full_note

    if log is False:
        now = datetime.now()
        now = now.strftime('%d/%m/%Y %H:%M:%S')
        full_note = '[' + log_from + ' Log ' + now + '] ' + note
        return full_note

def bool_return(string):
    if string == 'True':
        return True
    if string == 'False':
        return False

def config_load():
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    return lines