"""
S_Alerts holds all functions that specifically deal with Alerts
"""
import sys
from os.path import exists
import json
import requests
from datetime import datetime, timedelta
import time

import s_authenticate as cate
import s_common as common


global log_from
log_from = 'Alerts'  # defines for all logs where the log is connected to


def json_start():
    """
    json_start will pull and analyze alerts from Sophos Central then create a file or append a file with the data pulled
    This function will only run if enabled in the config file
    """
    lines = common.config_load()

    for x in lines:
        if 'alerts_json_file_name' in x:
            file_name = x.split('=')[1].strip()
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name

    json_file_exists = exists(log_file_name)
    alerts = alerts_grab(False)  # False indicates pull only from the last 24 hours
    note = 'Pulling Sophos Alerts'
    common.log_add(note, log_from, 3)
    alerts = alerts['items']

    if json_file_exists is True:
        common.add_data_json(alerts, log_file_name)

    if json_file_exists is False:
        with open(log_file_name, 'w') as outfile:
            json.dump(alerts, outfile)
            note = 'No alerts json file exited, created a new alerts json file'
            common.log_add(note, log_from, 2)

        new_alert_id_count = 0
        current_alert_data = []

        for x in alerts:
            e = x['id']
            t = x['created_at']
            d = x['description']

            current_alert_data.append(x)
            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + e + ' created at ' + t + ' added. Description: ' + d
            common.log_add(note, log_from, 3)

        if new_alert_id_count > 0:
            note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
            common.log_add(note, log_from, 3)


def txt_start():
    """
    txt_start will pull and analyze alerts from Sophos Central then create a file or append a file with the data pulled
    This function will only run if enabled in the config file
    """
    lines = common.config_load()

    for x in lines:
        if 'alerts_txt_file_name' in x:
            file_name = x.split(' = ')[1]
        if 'save_file_location' in x:
            save_file_location = x.split('=')[1].strip()

    log_file_name = save_file_location + file_name  # combines the location and file name to save the file

    export_file = exists(log_file_name)  # checks to see if the txt alerts file has been created
    alerts = alerts_grab(False)
    note = 'Pulling Sophos Alerts'
    common.log_add(note, log_from, 3)
    alerts = alerts['items']  # creates a list for all the alerts

    if export_file is True:
        add_log_data(alerts, log_file_name, True)

    if export_file is False:
        add_log_data(alerts, log_file_name, False)


def alerts_grab(timespan):
    """
    Pulls all alerts that have not been acknowledged yet.
    timespan(bool) will identify how much data will be pulled
        True will pull from the last 1000 entries
        False will pull from the last 1000 entries for the last 24 hours
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

        return request.json()  # returns a dict with all alerts

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

        return request.json()  # returns a dict with all alerts


def alert_actions(alert_id):
    """
    alert_actions will identify and return all available alert actions of a specified alert
    alert_id(str) is the id of the specific alert
    """
    auth = cate.auth_header_grab()  # grabs the proper Authorization header
    info = cate.whoami()  # grabs the x-tenant-id and data region
    tenant_id = info['id']  # grabs the tenant id
    region = (info['apiHosts']['dataRegion'])  # identifies the region for the URL
    requestUrl = region + '/common/v1/alerts?ids=' + alert_id

    requestHeaders = {
        "X-Tenant-ID": tenant_id,
        "Authorization": auth,
        "Accept": "application/json"
    }
    request = requests.get(requestUrl, headers=requestHeaders)

    alert_info = request.json()
    actions = alert_info['items'][0]['allowedActions']
    return actions


def update_alert(action, alert_id):
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

    return request.json()  # returns dict stating action chosen, result of the action, time requested, time completed


def add_log_data(alerts, logfile, exist):
    """
    add_log_data analyzes alerts and adds them to a log file.
    alerts(list) are a list of dict alerts created by Sophos
    logfile(str) the name of the file the logs will be saved in
    exist(bool) determines if a log file has already been created
        if a logfile does not exist a new file will be created
    """

    acknowledge = common.auto_acknowledge_level()
    acknowledge_level = acknowledge['alerts']['auto_acknowledge']
    acknowledge_level = common.bool_return(acknowledge_level)
    auto_acknowledge_levels = acknowledge['alerts']['level']
    print(auto_acknowledge_levels)

    if exist is False:  # if a log file does not exist
        new_alert_id_count = 0  # creates a variable(int) starting at 0 to identify how many alert ids are added
        alert_list = []  # creates a list to hold each new line to be added
        for x in alerts:
            createdAt = x['created_at']
            severity = x['severity']
            alertID = x['id']
            alertType = x['type']
            description = x['description']
            data = x['data']
            data = str(data)
            location = x['location']

            alert_line = ('[Reporter: Sophos Central] ' +
                          '[Timestamp: ' + createdAt + '] ' +
                          '[AlertID: ' + alertID + '] ' +
                          '[Severity: ' + severity + '] ' +
                          '[IP: ]' +
                          '[Description: ' + alertType + ' ' + description + '] ' +
                          '[AlertType: ' + alertType + '] ' +
                          '[Data: ' + data + '] ' +
                          '[Location: ' + location + ']')

            alert_list.append(alert_line)

            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + alertID + ' created at ' + createdAt + ' added. Description: ' + description
            message = common.log_add(note, log_from, 4)
            print(message)

            if acknowledge_level is True:
                if severity in auto_acknowledge_levels:
                    update = update_alert('acknowledge', alertID)
                    note = 'Auto Acknowledged Alert ID: ' + alertID + ' ' + str(update)
                    common.log_add(note, log_from, 4)


        with open(logfile, 'w') as f:
            for x in alert_list:
                f.write(x + '\n')
            f.close()

        if new_alert_id_count > 0:
            note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
            common.log_add(note, log_from, 3)

    if exist is True:  # if a log file does exist
        today = datetime.now()
        today = today.strftime('%Y-%m-%d')  # creates a variable for the current day to ensure adding new data

        with open(logfile, 'r') as f:
            current_alerts = [line.strip() for line in f]  # adds all alerts from the log file to a list

        alert_id_list = []
        for x in current_alerts:
            alert_id = x.split('AlertID: ')[1].split(']')[0]
            alert_id_list.append(alert_id)  # creates a list of all alert_ids

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

                    alert_line = ('[Reporter: Sophos Central] ' +
                                  '[Timestamp: ' + createdAt + '] ' +
                                  '[AlertID: ' + alertID + '] ' +
                                  '[Severity: ' + severity + '] ' +
                                  '[IP: ]' +
                                  '[Description: ' + alertType + ' ' + description + '] ' +
                                  '[AlertType: ' + alertType + '] ' +
                                  '[Data: ' + data + '] ' +
                                  '[Location: ' + location + ']')
                    alert_list.append(alert_line)

                    new_alert_id_count = new_alert_id_count + 1
                    note = 'Alert ID: ' + alertID + ' created at ' + createdAt + ' added. Description: ' + description
                    common.log_add(note, log_from, 4)

            if acknowledge_level is True:
                if severity in auto_acknowledge_levels:
                    update = update_alert('acknowledge', alertID)
                    note = 'Auto Acknowledged Alert ID: ' + alertID + ' ' + str(update)
                    common.log_add(note, log_from, 4)

        with open(logfile, 'a') as f:
            for x in alert_list:
                f.write(x + '\n')
            f.close()

        if new_alert_id_count > 0:
            note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
            common.log_add(note, log_from, 3)


def run():
    """
    run will continuously run either txt_start or json_start depending on the config file
    The config file will determine the time between each pull
    """
    lines = common.config_load()

    for x in lines:
        if 'run' in x:
            status = x.split(' = ')[1]
            status = common.bool_return(status)
        if 'txt_file_creation' in x:
            txt_file = x.split(' = ')[1]
            txt_file = common.bool_return(txt_file)  # returns a bool response for txt file creation
        if 'json_file_creation' in x:
            json_file = x.split(' = ')[1]
            json_file = common.bool_return(json_file)  # returns a bool response for json file creation

    while status is True:

        lines = common.config_load()  # will update the config settings after each pull

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
            #try:
            txt_start()
"""            except Exception as err:
                error = err
                note = 'ERROR: ' + str(error)
                common.log_add(note, log_from, 1) """

        if json_file is True:
            try:
                json_start()
            except Exception as err:
                error = err
                note = 'ERROR: ' + error
                common.log_add(note, log_from, 1)

        while pull_time >= 0:  # creates a delay to identify next pull and prints the time left in the terminal
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
