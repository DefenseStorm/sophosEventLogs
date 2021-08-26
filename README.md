NOTE:  DefenseStorm is now internally maintaining an AWS Lambda based integration for this deployment.  Customers and public are free to continue to use this integration, but DefenseStorm will no longer be providing updates/development on the integration housed here.  Pleas contact DefenseStorm Support if you have any questions.


Salesforce Integration for DefenseStorm

to pull this repository and submodules:

git clone --recurse-submodules https://github.com/DefenseStorm/sophosEventLogs.git

1. If this is the first integration on this DVM, Do the following:

  cp ds-integration/ds_events.conf to /etc/syslog-ng/conf.d

 Edit /etc/syslog-ng/syslog-ng.conf and add local7 to the excluded list for filter f_syslog3 and filter f_messages. The lines should look like the following:

 filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };

 filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news,local7); };


  Restart syslog-ng
    service syslog-ng restart

2. Copy the template config file and update the settings

  cp sophosEventLogs.conf.template sophosEventLogs.conf

  change the following items in the config file based on your configuration


3. Add the following entry to the root crontab so the script will run every
   5 minutes

   */5 * * * * cd /usr/local/sophosEventLogs; ./sophosEventLogs.py
