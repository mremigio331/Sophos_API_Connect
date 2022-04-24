"""
Sophos_Auto is the command line code for pulling alerts and events. It can also be used to do a quick authentication
request to confirm connectivity to Sophos Central.
The user will need to utilize a flag to run the code
"""
import sys
import os

cwd = sys.argv[0]


if '/' in cwd:
    mvwd = cwd.split('sophos_auto.py')[0]
    os.chdir(mvwd)
# if the user runs the code in a different directory, the code move into the sophos_api_connect directory

import multiprocessing
from multiprocessing import freeze_support

sys.path.append('py_Files/')

import s_alerts as alerts
import s_authenticate as cate
import s_events as events
import s_common as common

configuration_check = common.config_check()  # see config_check() in s_common.py

if configuration_check is False:
    sys.exit()
# if the config_check returns False the cod will not run and exit with an error message.

global log_from
log_from = 'System'  # defines for all logs where the log is connected to


def alerts_grab():
    """
    Alert_grab starts the run function in the alerts.py
    If any error occurs the error is documented depending on the error type
    """
    try:
        alerts.run()

    except Exception as e:
        note = 'ERROR: ' + str(e)
        common.log_add(note, 'Alerts', 1)
    except KeyboardInterrupt:  # will throw alert code if a user manually stops the code
        note = 'User Ended Alert_Pull'
        common.log_add(note, 'Alerts', 2)


def events_grab():
    """
    Events_grab starts the run function in the events.py
    If any error occurs the error is documented depending on the error type
    """
    try:
        events.run()

    except Exception as e:
        note = 'ERROR: ' + str(e)
        common.log_add(note, 'Events', 1)
    except KeyboardInterrupt:  # will throw alert code if a user manually stops the code
        note = 'User Ended Event_Pull'
        common.log_add(note, 'Events', 2)


if ('-a' in sys.argv) or ('-alerts' in sys.argv):
    """
    The -a or -alerts flag will run the alert_grab function
    """
    print('*** Pulling Just Alerts ***')
    note = 'Initiating Sophos Alerts Pull'
    common.log_add(note, log_from, 2)
    alerts_grab()

if ('-e' in sys.argv) or ('-events' in sys.argv):
    """
    The -e or -events flag will run the events_grab function
    """
    print('*** Pulling Just Events ***')
    note = 'Initiating Sophos Events Pull'
    common.log_add(note, log_from, 2)
    events_grab()

if ('-h' in sys.argv) or ('-help' in sys.argv):
    """
    The -h or -help flag will print in the terminal all available flags
    """
    print('*** Commands ***')
    print('-a  -alerts       will run just the alerts Sophos pull')
    print('-e  -events       will run just the events Sophos pull')
    print('-h  -help         brings up help screen')
    print('-r  -run          will run both the alerts and events Sophos pulls')
    print('-w  -whoami       will attempt a whoami authentication')

if ('-r' in sys.argv) or ('-run' in sys.argv):
    """
    The -r or -run flag will run both the alert_grab and even_flag functions
    """
    print('*** Pulling Both Alerts and Events ***')
    note = 'Initiating Sophos Alerts and Events Pull'
    common.log_add(note, log_from, 2)
    if __name__ == '__main__':
        freeze_support()
        p1 = multiprocessing.Process(target=alerts_grab)
        p2 = multiprocessing.Process(target=events_grab)
        p1.start()
        p2.start()
        p1.join()
        p2.join()

if ('-w' in sys.argv) or ('-whoami' in sys.argv):
    """
    The -w or -whoami flag will attempt a whoami authentication via the authenticate.py file
    """
    print('*** Attempting a WhoAmI Authentication Request ***')
    print(cate.whoami())
