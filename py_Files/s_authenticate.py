import json
import urllib
import urllib.parse
import urllib.request
import requests
import s_common as common

global log_from
log_from = 'System'

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
        if hasattr(e, 'reason'):
            reason = e.reason
            note = str('ERROR: Failed to reach the server ' + str(reason))
            common.log_add(note, log_from, 1)
        elif hasattr(e, 'code'):
            code = e.code
            note = str('ERROR: Server failed to fulfill the request ' + str(code))
            common.log_add(note, log_from, 1)
        else:
            note = 'ERROR: ' + str(e)
            common.log_add(note, log_from, 1)

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

    return auth_header

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
            common.log_add(note, log_from, 4)

            return (request.json()) # will return in a dict the X-Tenant-ID and the data region

        except:

            if success == 0:
                note = 'ERROR: WhoAmI Authentication TimedOut'
                common.log_add(note, log_from, 1)
                success = success - 1


            else:
                note = 'ERROR: WhoAmI Authentication unsuccessful, attempting ' + str(success) + ' more attempts.'
                common.log_add(note, log_from, 1)
                success = success - 1

