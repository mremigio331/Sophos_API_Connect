import sys
from os.path import exists
import json
import requests
from datetime import datetime, timedelta
import time

import s_authenticate as cate
import s_common as common


global log_from
log_from = 'Alerts'

def json_start():
    lines = common.config_load()

    for x in lines:
        if 'alerts_json_file_name' in x:
            file_name = x.split('=')[1].strip()
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name

    json_file_exists = exists(log_file_name)
    alerts = alerts_grab(False)
    note = 'Pulling Sophos Alerts'
    message = common.log_add(note,log_from,False)
    print(message)
    alerts = alerts['items']

    if json_file_exists is True:
        common.add_data_json(alerts,log_file_name)

    if json_file_exists is False:
        with open(log_file_name, 'w') as outfile:
            json.dump(alerts, outfile)
            note = 'No alerts json file exited, created a new alerts json file'
            common.log_add(note,log_from,2)
            print('File does not exist')

        new_alert_id_count = 0
        current_alert_data = []

        for x in alerts:
            e = x['id']
            t = x['created_at']
            d = x['description']

            current_alert_data.append(x)
            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + e + ' created at ' + t + ' added. Description: ' + d
            message = common.log_add(note, log_from,4)
            print(message)

        note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
        message = common.log_add(note,log_from,3)
        print(message)

def txt_start():
    lines = common.config_load()

    for x in lines:
        if 'alerts_txt_file_name' in x:
            file_name = x.split(' = ')[1]
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name

    export_file = exists(log_file_name)
    alerts = alerts_grab(False)
    note = 'Pulling Sophos Alerts'
    message = common.log_add(note, log_from, 2)
    print(message)
    alerts = alerts['items']

    if export_file is True:
        add_log_data(alerts,log_file_name, True)

    if export_file is False:
        add_log_data(alerts, log_file_name, False)

def alerts_grab(timespan):
    """
    Pulls all alerts that have not been acknowledged yet.
    timespan(bool) will identify how much data will be puulled
        True will pull from the last 1000 entries
        False will pull from the last 24 hours
    """
    if timespan is True:
        auth = cate.auth_header_grab()  # grabs the proper Authorization header
        info = cate.whoami()  # grabs the x-tenant-id and data region
        tenant_id = info['id']
        region = (info['apiHosts']['dataRegion'])
        requestUrl = region + '/siem/v1/alerts?limit=1000'  # pulls last 1000 alerts

        requestHeaders = {
            "X-Tenant-ID": tenant_id,
            "Authorization": auth,
            "Accept": "application/json"
        }
        request = requests.get(requestUrl, headers=requestHeaders)

        return (
            request.json())  # returns a dic with every alert. Each alert will have the following keys: (['id', 'allowedActions', 'category', 'description', 'groupKey', 'managedAgent', 'product', 'raisedAt', 'severity', 'tenant', 'type'])

    if timespan is False:
        d = datetime.today() - timedelta(days=1)  # creates a datetime variable for yesterday at this time
        unix_time = time.mktime(d.timetuple())  # creates a unix timestamp
        auth = cate.auth_header_grab()  # grabs the proper Authorization header
        info = cate.whoami()  # grabs the x-tenant-id and data region
        tenant_id = info['id']
        region = (info['apiHosts']['dataRegion'])
        requestUrl = region + '/siem/v1/alerts?limit=1000&from_date' + str(unix_time)

        requestHeaders = {
            "X-Tenant-ID": tenant_id,
            "Authorization": auth,
            "Accept": "application/json"
        }
        request = requests.get(requestUrl, headers=requestHeaders)

        return request.json()  # returns a dic with every alert. Each alert will have the following keys: (['id', 'allowedActions', 'category', 'description', 'groupKey', 'managedAgent', 'product', 'raisedAt', 'severity', 'tenant', 'type'])

def alert_actions(alert_id):
    auth = cate.auth_header_grab()  # grabs the proper Authorization header
    info = cate.whoami()  # grabs the x-tenant-id and data region
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/common/v1/alerts?ids=' + alert_id  # pulls the alert_id info

    requestHeaders = {
        "X-Tenant-ID": tenant_id,
        "Authorization": auth,
        "Accept": "application/json"
    }
    request = requests.get(requestUrl, headers=requestHeaders)

    alert_info = request.json()
    actions = alert_info['items'][0]['allowedActions']
    return actions

def update_alert(action,alert_id):
    """
    update_alert will update an alert based on the alert_id(str) and an action(str)
    each alert has an allowedAction which will give you the allowable action
    """
    alert_action = action
    auth = cate.auth_header_grab()
    info = cate.whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/common/v1/alerts/' + alert_id + '/actions'
    requestBody = {
    "action": alert_action
    }
    requestHeaders = {
        "X-Tenant-ID": tenant_id,
        "Authorization": auth,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    request = requests.post(requestUrl, headers=requestHeaders, json=requestBody)

    return request.json() # will a dict stating the id, the action chosen, the result of the action, the time requested, and the time completed.

def add_log_data(alerts,logfile,exist):

    if exist is False:
        new_alert_id_count = 0
        alert_list = []
        for x in alerts:
            createdAt = x['created_at']
            severity = x['severity']
            alertID = x['id']
            alertType = x['type']
            description = x['description']
            data = x['data']
            data = str(data)
            location = x['location']

            alert_line = '[Timestamp: ' + createdAt + '] ' + '[AlertID: ' + alertID + '] ' + '[Severity: ' + severity + '] ' + '[IP: ]' + '[Description: ' + description + '] ' + '[AlertType: ' + alertType + '] ' + '[Data: ' + data + '}] ' + '[Location: ' + location + ']'
            alert_list.append(alert_line)

            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + alertID + ' created at ' + createdAt + ' added. Description: ' + description
            message = common.log_add(note, log_from, 4)
            print(message)

        with open(logfile, 'w') as f:
            for x in alert_list:
                f.write(x + '\n')
            f.close()

        note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
        message = common.log_add(note, log_from, 3)
        print(message)

    if exist is True:
        today = datetime.now()
        today = today.strftime('%Y-%m-%d')

        with open(logfile, 'r') as f:
            current_alerts = [line.strip() for line in f]

        alert_id_list = []
        for x in current_alerts:
            alert_id = x.split('AlertID: ')[1].split(']')[0]
            alert_id_list.append(alert_id)

        new_alert_id_count = 0
        alert_list = []
        for x in alerts:
            alert_id = x['id']
            if alert_id in alert_id_list:
                pass
            else:
                createdAt = x['created_at']
                yearMonthDate = createdAt.split('T')[0]
                if yearMonthDate >= today:
                    createdAt = x['created_at']
                    severity = x['severity']
                    alertID = x['id']
                    alertType = x['type']
                    description = x['description']
                    data = x['data']
                    data = str(data)
                    location = x['location']

                    alert_line = '[Timestamp: ' + createdAt + '] ' + '[AlertID: ' + alertID + '] ' + '[Severity: ' + severity + '] ' + '[IP: ]' + '[Description: ' + description + '] ' + '[AlertType: ' + alertType + '] ' + '[Data: ' + data + '}] ' + '[Location: ' + location + ']'
                    alert_list.append(alert_line)

                    new_alert_id_count = new_alert_id_count + 1
                    note = 'Alert ID: ' + alertID + ' created at ' + createdAt + ' added. Description: ' + description
                    message = common.log_add(note, log_from, 4)
                    print(message)

        with open(logfile, 'a') as f:
            for x in alert_list:
                f.write(x + '\n')
            f.close()

        note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
        message = common.log_add(note, log_from, 3)
        print(message)

def run()
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