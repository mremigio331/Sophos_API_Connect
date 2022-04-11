# Sophos API Connect

Sophos API Connect contains multiple codes which enables users to connect to Sophos' API and run standard queries

# To install all dependencies needed:

$ pip install -r requirements.txt

# Setting Up Config File

sophos.config contains all configuration settings. 

  * client_id and client secret will be generated via Sophos Central
    * No codes will run if the two are blank


  * pull_time identifies the time in seconds between each pull if running codes from sophos_auto
    * By default is 10    


  * run tells the code to run or stop. This can be helpful for users having the code run via cron
    * Needs to be a bool value (True or False)
    * By default is True


  * save_file_location is the directory that all txt or json will save to
    * This location can be left blank
    * By default is blank
    

  * txt_file_creation and json_file_creation tells the code to create either or both
    * Needs to be a bool value (True or False)
    * By default txt is True and json is False
    

  * alerts_txt_file_name and events_txt_file_name declares a name to save txt files to
    * By default is sophos_alerts and sophos_events


  * alerts_json_file_name and events_json_file_name declares a name to save json files to
    * By default is sophos_alerts.json and sophos_events.json
    

  * log_level declares the level of logging
    * Options available are VERBOSE, LOG+, INFO, ERROR, and OFF
    * More info regarding log_levels to follow
    * By default is INFO


  * log_file_name declares a name to save the logs to
    * By default is Sophos_log.log

# Log Levels

* OFF
  * Nothing
  * Noted as 0 throughout


* ERROR
  * Errors
  * Noted as 1 throughout

* Log
  * Creating new log files, Endpoint tasks, starting of continuous alerts and events pulls, and user ending continuous alerts and event pull
  * Noted as 2 throughout


* LOG+
  * Each time a pull is initiated and total number of new alerts/events pulled during a run
  * Noted as 3 throughout
  

* VERBOSE
  * Each new alert/event entry, each whoami search and each health status check
  * Noted as 4 throughout

# Files
 * requirements.txt
   * Python libraries needed to run code


 * sophos.conf
   * Config file


 * sophos_auto.py
   * Sophos_Auto is the command line code for pulling alerts and events. It can also be used to do a quick authentication request to confirm connectivity to Sophos Central. 
   * The user will need to utilize a flag to run the code
   * Flags
     * (-a  -alerts) will run just the alerts Sophos pull 
     * (-e  -events) will run just the events Sophos pull 
     * (-h  -help) brings up help screen
     * (-r  -run) will run both the alerts and events Sophos pulls
     * (-w  -whoami) will attempt a whoami authentication


 * py_files
   * s_alerts
     * All functions that specifically deal with Alerts
   * s_authenticate
     * All functions that specifically deal with authentication with Sophos Central
   * s_common
     * All functions that didn't fit in its own python file
   * s_endpoint
     * All functions that specifically deal with Endpoints
   * s_events



