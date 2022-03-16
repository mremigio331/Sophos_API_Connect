import sys
import os
import json
import urllib
import urllib.parse
import urllib.request
import requests
from datetime import datetime

global pwd
pwd = os.getcwd()

def api_request(url, method='GET', params={}, headers={}, body=None, is_json=True):
    full_url = url
    if params:
        full_url = url + '?' + urllib.parse.urlencode(params)

    data = None
    if body is not None:
        if is_json:
            data = bytes(json.dumps(body), 'utf-8')
            headers.update({
                'Content-Type': 'application/json; charset=utf-8',
            })
        else:
            data = bytes(urllib.parse.urlencode(body), 'utf-8')
            headers.update({
                'Content-Type': 'application/x-www-form-urlencoded'
            })
        headers.update({
            'Content-Length': len(data)
        })

    req = urllib.request.Request(url=full_url, method=method,
                                 data=data, headers=headers)

    response_body = None
    try:
        with urllib.request.urlopen(req) as response:
            response_body = response.read()
    except urllib.error.URLError as e:
        #print(e)
        if hasattr(e, 'reason'):
            print('Failed to reach the server', e.reason)
        elif hasattr(e, 'code'):
            print('Server failed to fulfill the request', e.code)
        return None
    return json.loads(response_body)

def authenticate(client_id, client_secret):
    body = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'token'
    }

    auth = api_request('https://id.sophos.com/api/v2/oauth2/token',
                   method='POST', body=body, is_json=False)

    if auth is None:
        raise SystemExit('Failed to authenticate', auth)

    return [auth[k] for k in ('access_token', 'refresh_token', 'token_type')]

def auth_header_grab():
    """
    This function returns the proper authentication header by taking the API token (client_id(str) and client_secret(str)) and creating the proper header.
    The client_id and client_secret are in a config file which is imported
    """
    with open('sophos.conf') as f:
        lines = [line.strip() for line in f]

    for x in lines:
        if 'client_id' in x:
            client_id = x.split(' = ')[1]
        if 'client_secret' in x:
            client_secret = x.split(' = ')[1]


    access_token, refresh_token, token_type = authenticate(client_id,
                                                           client_secret)

    auth_header = token_type.title() + ' ' + access_token

    return (auth_header)

def whoami():
    """
    whoami returns the unique ID assigned to the specific entity.
    whoami takes no parameters but is needed for all api requests to get a X-Tenant-ID and a data region
    """
    success = 5
    while success >= 0:
        try:
            auth = auth_header_grab() # grabs the proper Authorization header
            requestUrl = "https://api.central.sophos.com/whoami/v1"
            requestHeaders = {
                "Authorization": auth,
                "Accept": "application/json"
            }

            request = requests.get(requestUrl, headers=requestHeaders)

            note = 'WhoAmI Authentication Sucessfull'
            full_note = log_add(note, 'System', False)
            print(full_note)

            return (request.json()) # will return in a dict the X-Tenant-ID and the data region

        except:

            if success == 0:
                note = 'WhoAmI Authentication TimedOut'
                message = log_add(note, 'System', True)
                print(message)
                success = success - 1


            else:
                note = 'WhoAmI Authentication unsuccessful, attempting ' + str(success) + ' more attempts.'
                message = log_add(note, 'System', True)
                print(message)
                success = success - 1

def alerts():
    """
    Pulls all alerts that have not been acknowledged yet.
    """
    auth = auth_header_grab() # grabs the proper Authorization header
    info = whoami() # grabs the x-tenant-id and data region
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/common/v1/alerts'

    requestHeaders = {
        "X-Tenant-ID": tenant_id,
        "Authorization": auth,
        "Accept": "application/json"
    }
    request = requests.get(requestUrl, headers=requestHeaders)

    return (request.json()) # returns a dic with every alert. Each alert will have the following keys: (['id', 'allowedActions', 'category', 'description', 'groupKey', 'managedAgent', 'product', 'raisedAt', 'severity', 'tenant', 'type'])

def update_alert(action,alert_id):
    """
    update_alert will update an alert based on the alert_id(str) and an action(str)
    each alert has an allowedAction which will give you the allowable action
    """
    alert_action = action
    auth = auth_header_grab()
    info = whoami()
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

def events():
    """
    events will grab the events from sophos
    """
    auth = auth_header_grab()
    info = whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/siem/v1/events'
    requestHeaders = {
        'X-Tenant-ID': tenant_id,
        'Authorization': auth,
        'Accept': 'application/json'
    }
    request = requests.get(requestUrl, headers=requestHeaders)

    return(request.json())

def health_status(query):
    """
    Will grab the health status from Sophos
    It takes a dict for the specific parameters you are looking to get
    If you want all the data, pass an empty dict
    If you want to specify things, use the following syntax for your keys:
        ipAddresses - each separated by a comma
        ids - each separated by a comma
        healthStatus - options are bad, good, suspicious, unknown
        isolationStatus - options are isolated, notIsolated
        type - options are computer, server, securityVm
        lockdownStatus - options are creatingWhitelist, installing, locked, notInstalled, registering, starting, stopping, unavailable, uninstalled, unlocked
    """
    auth = auth_header_grab()
    info = whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    full_string = region + '/endpoint/v1/endpoints?'

    for x in query:
        q_type = x
        q_input = query[x]
        full_string = full_string + q_type + '=' + q_input + '&'
    requestUrl = (full_string[:-1])
    requestHeaders = {
        'X-Tenant-ID': tenant_id,
        'Authorization': auth,
        'Accept': 'application/json'
    }

    request = requests.get(requestUrl, headers=requestHeaders)
    return request.json()

def isolation(xid, change, comment):
    """
    Will enable or disable isolation for a specific device. Will first confirm the device's status and depending on the output will execute the isolation_run function if applicable.
    xid(str) is the X-Tenant-ID
    The change(bool) will indicate what you want the device change to be
        True will isolate the device
        False will take device out of isolation
    A comment(str) will be passed for recording purposes
    """

    # Checking current status of device
    inputs = {'ids': xid, 'view': 'full'} # creates a dict to run with the health_status function
    c_status = health_status(inputs) # runs the health_status function
    c_status_status = c_status['items'][0]['isolation']['status'] # creates a variable for the current isolation status of the device
    c_status_name = c_status['items'][0]['hostname'] # creates a variable for the name of the device
    if change is True: # True indicates the device will enter isolation mode
        if c_status_status == 'isolated':
            print(c_status_name, 'is already isolated')  # if the device is already in isolation mode the code will print the following
        if c_status_status == 'notIsolated':
            print('The current status of', c_status_name, 'is',c_status_status + '.')  # if the device is not in isolation mode it will run the isolation_run function
            isolation_run(xid,change,comment)

    if change is False: # False indicates the device will exit isolation mode
        if c_status_status == 'isolated':
            print('The current status of', c_status_name, 'is', c_status_status + '.')  # if the device is in isolation mode the code will execute the isolation_run function
            isolation_run(xid, change, comment)
        if c_status_status == 'notIsolated':
            print(c_status_name, 'is already out of isolation mode.')  # if the device is already in isolation mode it will not execute the isolation_run function

def isolation_run(xid,change,comment):
    """
    Will take the information from isolation and run an API call.
    """
    auth = auth_header_grab() # grabs the proper Authorization header
    info = whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/endpoint/v1/endpoints/isolation'
    requestBody = {
        'enabled': change,
        'ids': [xid],
        'comment': comment,
    }
    requestHeaders = {
        'X-Tenant-ID': tenant_id,
        'Authorization': auth,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    request = requests.post(requestUrl, headers=requestHeaders, json=requestBody)
    #print(request.json())

def tamper_protection(eid,change):
    """
    Will enable or disable Tamper Protection for the selected device. Will confirm with tamper_status to see if the right change is indicated then run tamper_protection_change if applicable.
    eid(str) is the endpoint id for the device you want to change.
    change(bool) indicates what change you want to make
        True will turn Tamper Protection on
        False will turn Tamper Protection off
    """
    status = tamper_status(eid)
    current_status = status['enabled']
    print(type(current_status))
    if change is True: # True indicates turning on Tamper Protection
        if current_status is True:
            print('Tamper Protection already enabled')
        if current_status is False:
            print('Tamper Protection is currently disabled')
            tamper_protection_change(eid, change)

    if change is False: # False indicates turning off Tamper Protection
        if current_status is True:
            print('Tamper Protection is currently enabled')
            tamper_protection_change(eid, change)
        if current_status is False:
            print('Tamper Protection is already disabled')

def tamper_status(eid):
    """
    Will get the current Tamper Protection status of the device
    eid(str) is the endpoint id for the devices
    """

    auth = auth_header_grab()
    info = whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/endpoint/v1/endpoints/' + eid + '/tamper-protection'
    requestHeaders = {
        'X-Tenant-ID': tenant_id,
        'Authorization': auth,
        'Accept': 'application/json'
    }
    request = requests.get(requestUrl, headers=requestHeaders)

    return request.json()

def tamper_protection_change(eid, change):
    """
    Will take the info from tamper_protection to run the API call
    """

    auth = auth_header_grab()
    info = whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/endpoint/v1/endpoints/' + eid + '/tamper-protection'
    requestBody = {
        'enabled': change
    }
    requestHeaders = {
        'X-Tenant-ID': tenant_id,
        'Authorization': auth,
        'Accept': 'application/json'
    }
    request = requests.post(requestUrl, headers=requestHeaders, json=requestBody)
    #print(request.content)

def scan(eid):
    """
    Will initiate a scan on the specified device
    eid(str) is the endpoint id of the device
    """

    auth = auth_header_grab()
    info = whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/endpoint/v1/endpoints/' + eid + '/scans'
    requestBody = {}
    requestHeaders = {
        'X-Tenant-ID': tenant_id,
        'Authorization': auth,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    request = requests.post(requestUrl, headers=requestHeaders, json=requestBody)

    return request.json()

def update(eid):
    """
    Will initiate an update on specified device
    eid(str) is the endpoint id of the device
    """

    auth = auth_header_grab()
    info = whoami()
    tenant_id = info['id']
    region = (info['apiHosts']['dataRegion'])
    requestUrl = region + '/endpoint/v1/endpoints/' + eid + '/update-checks'
    requestBody = {}
    requestHeaders = {
        'X-Tenant-ID': tenant_id,
        'Authorization': auth,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    request = requests.post(requestUrl, headers=requestHeaders, json=requestBody)
    return request.json()

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
            t = x['raisedAt']
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

def alert_add_data(alerts,logfile,newfile):

    if newfile is True:
        new_alert_id_count = []
        events_list = []
        for x in alerts:
            alert_id = x['id']
            allowedActions = x['allowedActions']
            allowedActions = ",".join(allowedActions)
            description = x['description']
            groupKey = x['groupKey']
            product = x['product']
            raisedAt = x['raisedAt']
            severity = x['severity']
            eventType = x['type']

            event_line = '[Timestamp: ' + raisedAt + '] ' + '[AlertID: ' + alert_id + '] ' + '[Severity: ' + severity + '] ' + '[Description: ' + description + '] ' + '[EventType: ' + eventType + '] ' + '[AllowedActions: {' + allowedActions + '}] ' + '[Product: ' + product + '] ' + '[GroupKey: ' + groupKey + ']'
            events_list.append(event_line)

            new_alert_id_count = new_alert_id_count + 1
            note = 'Alert ID: ' + alert_id + ' raised at ' + raisedAt + ' added. Description: ' + description
            message = sf.log_add(note, log_from, True)
            print(message)

        with open(logfile, 'w') as f:
            for x in events_list:
                f.write(x + '\n')
            f.close()

        note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
        message = sf.log_add(note, log_from, False)
        print(message)

    if newfile is False:
        today = datetime.now()
        today = now.strftime('%Y-%m-%d')

        with open(logfile, 'r') as f:
            current_alerts = [line.strip() for line in f]

        alert_id_list = []
        for x in current_alerts:
            alert_id = x.split('AlertID: ')[1].split(']')[0]
            alert_id_list.append(alert_id)

        new_alert_id_count = []
        for x in alerts:
            alert_id = x['id']
            if alert_id in alert_id_list:
                pass
            else:
                raisedAt = x['raisedAt']
                yearMonthDate = raisedAt.split('T')[0]
                if yearMonthDate >= today:
                    alert_id = x['id']
                    allowedActions = x['allowedActions']
                    allowedActions = ",".join(allowedActions)
                    description = x['description']
                    groupKey = x['groupKey']
                    product = x['product']
                    raisedAt = x['raisedAt']
                    severity = x['severity']
                    eventType = x['type']

                    event_line = '[Timestamp: ' + raisedAt + '] ' + '[AlertID: ' + alert_id + '] ' + '[Severity: ' + severity + '] ' + '[Description: ' + description + '] ' + '[EventType: ' + eventType + '] ' + '[AllowedActions: {' + allowedActions + '}] ' + '[Product: ' + product + '] ' + '[GroupKey: ' + groupKey + ']'
                    events_list.append(event_line)

                    new_alert_id_count = new_alert_id_count + 1
                    note = 'Alert ID: ' + alert_id + ' raised at ' + raisedAt + ' added. Description: ' + description
                    message = sf.log_add(note, log_from, True)
                    print(message)

        with open(logfile, 'a') as f:
            for x in events_list:
                f.write(x + '\n')
            f.close()

        note = 'Added ' + str(new_alert_id_count) + ' new Alert IDs'
        message = sf.log_add(note, log_from, False)
        print(message)




def log_add(note,log_from,log):
    if log is True:
        with open('../Sophos_Logs.log', 'a') as f:
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