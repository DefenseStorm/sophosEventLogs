#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import urllib.request as urlrequest
import urllib.error as urlerror
import calendar
import datetime
import json
import re
import time
from random import randint

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):

    EVENTS_V1 = '/siem/v1/events'
    ALERTS_V1 = '/siem/v1/alerts'

    ENDPOINT_MAP = {'event': [EVENTS_V1],
                'alert': [ALERTS_V1],
                'all': [EVENTS_V1, ALERTS_V1]}

    JSON_field_mappings = {
        'source' : 'username',
        'source_info_ip' : 'ip_src',
        'created_at' : 'timestamp',
        'name' : 'message',
        'endpoint_type' : 'host_type'
    }

    
    def sophos_main(self):
    
        tuple_endpoint = self.ENDPOINT_MAP['all']
    
        self.state_dir = os.path.join(self.ds.config_get('sophos', 'app_path'), 'state')
    
        handler = urlrequest.HTTPSHandler()
        opener = urlrequest.build_opener(handler)
    
        endpoint_config = {'format': 'json',
                           'filename': 'stdout',
                           'state_dir': self.state_dir,
                           'since': False}
    
        for endpoint in tuple_endpoint:
            self.process_endpoint(endpoint, opener, endpoint_config)
    
    
    def process_endpoint(self, endpoint, opener, endpoint_config):
        state_file_name = "siem_lastrun_" + endpoint.rsplit('/', 1)[-1] + ".obj"
        state_file_path = os.path.join(endpoint_config['state_dir'], state_file_name)
    
        self.ds.log('DEBUG', "Config endpoint=%s, filename='%s' and format='%s'" %
            (endpoint, endpoint_config['filename'], endpoint_config['format']))
        self.ds.log('DEBUG', "Config state_file='%s' and cwd='%s'" % (state_file_path, os.getcwd()))
        cursor = False
        since = False
        cursor = self.ds.get_state(self.state_dir)
        if cursor == None:
            since = int(calendar.timegm(((datetime.datetime.utcnow() - datetime.timedelta(hours=12)).timetuple())))
            self.ds.log('INFO', "No datetime found, defaulting to last 12 hours for results")
    
        if since is not False:
            self.ds.log('DEBUG', '%s - Retrieving results since: %s' %(endpoint, since))
        else:
            self.ds.log('DEBUG', '%s - Retrieving results starting cursor: %s' %(endpoint, cursor))
    
        event_list = self.call_endpoint(opener, endpoint, since, cursor, state_file_path)
        for line in event_list:
            self.ds.writeJSONEvent(line, JSON_field_mappings = self.JSON_field_mappings)
    
    def call_endpoint(self, opener, endpoint, since, cursor, state_file_path):
        default_headers = {'Content-Type': 'application/json; charset=utf-8',
                           'Accept': 'application/json',
                           'X-Locale': 'en',
                           'Authorization': self.ds.config_get('sophos', 'authorization'),
                           'x-api-key': self.ds.config_get('sophos', 'api-key')}
    
        params = {
            'limit': 1000
        }
        if not cursor:
            params['from_date'] = since
        else:
            params['cursor'] = cursor
            self.jitter()

        event_list = []

        while True:
            args = '&'.join(['%s=%s' % (k, v) for k, v in params.items()])
            events_request_url = '%s%s?%s' % (self.ds.config_get('sophos', 'url'), endpoint, args)
            self.ds.log('DEBUG', "URL: %s" % events_request_url)
            events_request = urlrequest.Request(events_request_url, None, default_headers)
    
            for k, v in default_headers.items():
                events_request.add_header(k, v)
    
            events_response = self.request_url(opener, events_request)
            self.ds.log('DEBUG', "RESPONSE: %s" % events_response)
            if events_response != None:
                events = json.loads(events_response)
            else:
                return []
    
            # events looks like this
            # {
            # u'chart_detail': {u'2014-10-01T00:00:00.000Z': 3638},
            # u'event_counts': {u'Event::Endpoint::Compliant': 679,
            # u'events': {}
            # }
            event_list +=  events['items']
            for e in events['items']:
                event_list.append(e)
            self.ds.set_state(self.state_dir, events['next_cursor']) 
            if not events['has_more']:
                break
            else:
                params['cursor'] = events['next_cursor']
                params.pop('from_date', None)
        return event_list 
    
    def jitter(self):
        time.sleep(randint(0, 10))
    
    
    def request_url(self, opener, request):
        for i in [1, 2, 3]:  # Some ops we simply retry
            try:
                response = opener.open(request)
            except urlerror.HTTPError as e:
                if e.code in (503, 504, 403, 429):
                    self.ds.log('Error "%s" (code %s) on attempt #%s of 3, retrying' % (e, e.code, i))
                    if i < 3:
                        continue
                    else:
                        return None
                else:
                    self.ds.log('Error during request. Error code: %s, Error message: %s' % (e.code, e.read()))
                    raise
            return response.read()
    
    
    def remove_null_values(self, data):
        return {k: v for k, v in data.items() if v is not None}

    def run(self):
        self.sophos_main()
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print( '  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('sophosEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
