import sys
import multiprocessing
from multiprocessing import Process, Pool, Manager, freeze_support
sys.path.append('py_Files/')
import alerts
import events
import sophos_functions as sf


def alert_grab():
    alerts.run()

def events_grab():
    events.run()

if ('-a' in  sys.argv) or ('-alerts' in sys.argv):
    print('*** Pulling Just Alerts ***')
    note = 'Initiating Sophos Alerts Pull'
    sf.log_add(note, 'System',True)
    events_grab()

if ('-e' in  sys.argv) or ('-events' in sys.argv):
    print('*** Pulling Just Events ***')
    note = 'Initiating Sophos Events Pull'
    sf.log_add(note, 'System',True)
    events_grab()

if ('-h' in sys.argv) or ('-help' in sys.argv):
    print('*** Commands ***')
    print('-a  -alerts       will run just the alerts Sophos pull')
    print('-e  -events       will run just the events Sophos pull')
    print('-h  -help         brings up help screen')
    print('-r  -run          will run both the alerts and events Sophos pulls')

if ('-r' in  sys.argv) or ('-run' in sys.argv):
    print('*** Pulling Both Alerts and Events ***')
    note = 'Initiating Sophos Alerts and Events Pull'
    sf.log_add(note,'System',True)
    if __name__ == '__main__':
        freeze_support()
        p1 = multiprocessing.Process(target=alert_grab)
        p2 = multiprocessing.Process(target=events_grab)
        p1.start()
        p2.start()
        p1.join()
        p2.join()

