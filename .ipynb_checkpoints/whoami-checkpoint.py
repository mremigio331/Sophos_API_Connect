#!/usr/bin/env python3

import sys
import os
import json
import urllib
import urllib.parse
import urllib.request


def request(url, method='GET', params={}, headers={}, body=None, is_json=True):
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
        print(e)
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

    auth = request('https://id.sophos.com/api/v2/oauth2/token',
                   method='POST', body=body, is_json=False)

    if auth is None:
        raise SystemExit('Failed to authenticate', auth)

    print('Authenticated! JWT is:\n')
    print(json.dumps(auth, indent=2), '\n')

    return [auth[k] for k in ('access_token', 'refresh_token', 'token_type')]


def whoami(auth_header):
    headers = {
        'Authorization': auth_header
    }

    account = request('https://api.central.sophos.com/whoami/v1',
                      headers=headers)

    if account is None:
        raise SystemExit('Failed to call /whoami')

    return account


def main():
    client_id = '06320e16-d588-4337-890e-5dfb935d9e78'
    client_secret = 'c8a96f1bd7abe316c25c954275f5502f059fef8d9ed8e47d618d608e1eacd92da7a9661375aac2e9ea6b4fc2e8ce8531f38b'

    access_token, refresh_token, token_type = authenticate(client_id,
                                                           client_secret)

    auth_header = token_type.title() + ' ' + access_token

    account = whoami(auth_header)

    print('Credentials belong to account:\n')
    print(json.dumps(account, indent=2))

main()
#if __name__ == '__main__':
#    if not sys.argv[2:]:
#        raise SystemExit('usage: python %s {} {c8a96f1bd7abe316c25c954275f5502f059fef8d9ed8e47d618d608e1eacd92da7a9661375aac2e9ea6b4fc2e8ce8531f38b}' %
#                         os.path.basename(__file__))
#    main(*sys.argv[1:])
