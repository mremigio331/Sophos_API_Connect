import requests

import authenticate as cate
import common



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
    auth = cate.auth_header_grab()
    info = cate.whoami()
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
    auth = cate.auth_header_grab() # grabs the proper Authorization header
    info = cate.whoami()
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
    return (request.json())

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

    auth = cate.auth_header_grab()
    info = cate.whoami()
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

    auth = cate.auth_header_grab()
    info = cate.whoami()
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
    return request.content()

def scan(eid):
    """
    Will initiate a scan on the specified device
    eid(str) is the endpoint id of the device
    """

    auth = cate.auth_header_grab()
    info = cate.whoami()
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

    auth = cate.auth_header_grab()
    info = cate.whoami()
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
