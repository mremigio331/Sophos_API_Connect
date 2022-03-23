import sys
import os
cwd = sys.argv[0]

if '/' in cwd:
    mvwd = cwd.split('sophos_auto.py')[0]
    os.chdir(mvwd)

import multiprocessing
from multiprocessing import freeze_support

sys.path.append('py_Files/')

import s_alerts as alerts
import s_authenticate as cate
import s_events as events
import s_common as common


global log_from
log_from = 'System'

def alert_grab():
    try:
        alerts.run()

    except Exception as e:
        note = 'ERROR: ' + str(e)
        message = common.log_add(note, 'Alerts', 1)
        print(message)
    except KeyboardInterrupt as e:
        note = 'ERROR: ' + str(e)
        message = common.log_add(note, 'Alerts', 1)
        print(message)
    except SystemExit:
        note = 'Alert_Grab Stopped'
        message = common.log_add(note, 'Alerts', 1)
        print(message)

def events_grab():
    try:
        events.run()

    except Exception as e:
        note = 'ERROR: ' + str(e)
        message = common.log_add(note, 'Events', 1)
        print(message)
    except KeyboardInterrupt as e:
        note = 'ERROR: ' + str(e)
        message = common.log_add(note, 'Events', 1)
        print(message)
    except SystemExit:
        note = 'Events_Grab Stopped'
        message = common.log_add(note, 'Events', 1)
        print(message)

if ('-a' in  sys.argv) or ('-alerts' in sys.argv):
    print('*** Pulling Just Alerts ***')
    note = 'Initiating Sophos Alerts Pull'
    message = common.log_add(note, log_from,2)
    print(message)
    alert_grab()

if ('-e' in  sys.argv) or ('-events' in sys.argv):
    print('*** Pulling Just Events ***')
    note = 'Initiating Sophos Events Pull'
    common.log_add(note, log_from,2)
    events_grab()

if ('-h' in sys.argv) or ('-help' in sys.argv):
    print('*** Commands ***')
    print('-a  -alerts       will run just the alerts Sophos pull')
    print('-e  -events       will run just the events Sophos pull')
    print('-h  -help         brings up help screen')
    print('-r  -run          will run both the alerts and events Sophos pulls')
    print('-w  -whoami       will attempt a whoami authentication')

if ('-r' in sys.argv) or ('-run' in sys.argv):
    print('*** Pulling Both Alerts and Events ***')
    note = 'Initiating Sophos Alerts and Events Pull'
    common.log_add(note,log_from,True)
    if __name__ == '__main__':
        freeze_support()
        p1 = multiprocessing.Process(target=alert_grab)
        p2 = multiprocessing.Process(target=events_grab)
        p1.start()
        p2.start()
        p1.join()
        p2.join()

if ('-w' in sys.argv) or ('-whoami' in sys.argv):
    print('*** Attempting a WhoAmI Authentication Request ***')
    cate.whoami()


