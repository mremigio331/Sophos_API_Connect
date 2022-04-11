"""
S_endpoints holds all functions that specifically deal with Endpoints
"""
import sys
import requests

import s_authenticate as cate
import s_common as common

configuration_check = common.config_check()  # confirms the config file is correctly filled

if configuration_check is False:  # exits code if config file is incorrectly filled
    sys.exit()

global log_from
log_from = 'System'  # defines for all logs where the log is connected to


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
        lockdownStatus - options are creatingWhitelist, installing, locked, notInstalled, registering, starting,
            stopping, unavailable, uninstalled, unlocked

        query(dict)
        return result(dict)
    """

    note = 'Initiating Health Status Query ' + str(query) + '.'
    common.log_add(note, log_from, 4)

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
    result = request.json()
    return result


def isolation(xid, change, comment):
    """
    Will enable or disable isolation for a specific device. Will first confirm the device's status and depending on the
        output will execute the isolation_run function if applicable.
    xid(str) is the X-Tenant-ID
    The change(bool) will indicate what you want the device change to be
        True will isolate the device
        False will take device out of isolation
    A comment(str) will be passed for recording purposes

        xid(str)
        change(bool)
        comment(str)
    """

    # Checking current status of device
    inputs = {'ids': xid, 'view': 'full'}  # creates a dict to run with the health_status function
    c_status = health_status(inputs)  # runs the health_status function
    c_status_status = c_status['items'][0]['isolation']['status']  # variable for the current isolation status
    c_status_name = c_status['items'][0]['hostname']  # variable for the name of the device

    if change is True:  # True indicates the device will enter isolation mode

        if c_status_status == 'isolated':  # if device is already in isolation mode the code will print the following
            note = c_status_name + ' is already isolated'
            common.log_add(note, log_from, 2)

        if c_status_status == 'notIsolated':  # if the device not in isolation mode will run the isolation_run function
            note = 'The current status of ' + c_status_name + ' is ' + c_status_status + '.'
            common.log_add(note, log_from, 2)
            isolation_run(xid, change, comment)

    if change is False:  # False indicates the device will exit isolation mode
        if c_status_status == 'isolated':
            note = 'The current status of ' + c_status_name + ' is ' + c_status_status + '.'
            common.log_add(note, log_from, 2)
            isolation_run(xid, change, comment)

        if c_status_status == 'notIsolated':
            note = c_status_name + ' is already out of isolation mode.'
            common.log_add(note, log_from, 2)


def isolation_run(xid, change, comment):
    """
    Will take the information from isolation and run an API call.

        xid(str)
        change(bool)
        comment(str)

        return result(dict)
    """

    auth = cate.auth_header_grab()  # grabs the proper Authorization header
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

    result = request.json()

    note = str(result)
    common.log_add(note, log_from, 2)

    return result


def tamper_protection(eid, change):
    """
    Will enable or disable Tamper Protection for the selected device. Will confirm with tamper_status to see if the
        right change is indicated then run tamper_protection_change if applicable.
    eid(str) is the endpoint id for the device you want to change.
    change(bool) indicates what change you want to make
        True will turn Tamper Protection on
        False will turn Tamper Protection off

        eid(str)
        change(bool)
    """
    status = tamper_status(eid)
    current_status = status['enabled']
    if change is True:  # True indicates turning on Tamper Protection
        if current_status is True:
            note = 'Tamper Protection already enabled for ' + eid + '.'
            common.log_add(note, log_from, 2)
        if current_status is False:
            note = 'Tamper Protection is currently disabled for ' + eid + '.'
            common.log_add(note, log_from, 2)
            tamper_protection_change(eid, change)

    if change is False:  # False indicates turning off Tamper Protection
        if current_status is True:
            note = 'Tamper Protection is currently enabled for ' + eid + '.'
            common.log_add(note, log_from, 2)
            tamper_protection_change(eid, change)

        if current_status is False:
            note = 'Tamper Protection is already disabled for ' + eid + '.'
            common.log_add(note, log_from, 2)


def tamper_status(eid):
    """
    Will get the current Tamper Protection status of the device
    eid(str) is the endpoint id for the devices

        eid(str)
        return result(dict)
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

    result = request.json()

    note = str(result)
    common.log_add(note, log_from, 2)

    return result


def tamper_protection_change(eid, change):
    """
    Will take the info from tamper_protection to run the API call

        eid(str)
        change(str)
        return result(dict)
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

    result = request.json()

    note = str(result)
    common.log_add(note, log_from, 2)

    return result


def scan(eid):
    """
    Will initiate a scan on the specified device
    eid(str) is the endpoint id of the device

        eid(str)
        return result(dict)
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

    result = request.json()

    note = str(result)
    common.log_add(note, log_from, 2)

    return result


def update(eid):
    """
    Will initiate an update on specified device
    eid(str) is the endpoint id of the device

        eid(str)
        return result(dict)
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

    result = request.json()

    note = str(result)
    common.log_add(note, log_from, 2)

    return result
