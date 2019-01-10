#!/usr/bin/env python

import sys,os,getopt
import traceback
import os
import urllib2 as urlrequest
import calendar
import datetime
import json
import name_mapping
import re
import pickle
import time
from random import randint

sys.path.insert(0, '/usr/local/sophosEventLogs/ds-integration')
from DefenseStorm import DefenseStorm

class integration(object):

    EVENTS_V1 = '/siem/v1/events'
    ALERTS_V1 = '/siem/v1/alerts'

    ENDPOINT_MAP = {'event': [EVENTS_V1],
                'alert': [ALERTS_V1],
                'all': [EVENTS_V1, ALERTS_V1]}

    CEF_MAPPING = {
        # This is used for mapping CEF header prefix and extension to json returned by server
        # CEF header prefix to json mapping
        # Format
        # CEF_header_prefix: JSON_key
        "device_event_class_id": "type",
        "name": "name",
        "severity" :"severity",

        # json to CEF extension mapping
        # Format
        # JSON_key: CEF_extension
        "source": "suser",
        "when": "end",
        "user_id": "duid",
        "created_at": "rt",
        "full_file_path": "filePath",
        "location": "dhost",
    }

    CEF_FORMAT = ('CEF:%(version)s|%(device_vendor)s|%(device_product)s|'
              '%(device_version)s|%(device_event_class_id)s|%(name)s|%(severity)s|')

    
    MISSING_VALUE = 'NA'
    PREFIX_PATTERN = re.compile(r'([|\\])')
    EXTENSION_PATTERN = re.compile(r'([=\\])')

    SEVERITY_MAP = {'none': 0,
                'low': 1,
                'medium': 5,
                'high': 8,
                'very_high': 10}



    def sophos_main(self):
    
        # Read config file
        
        self.ds.log('DEBUG', "Config loaded, retrieving results for '%s'" % self.ds.config_get('sophos', 'api-key'))
        self.ds.log('DEBUG', "Config retrieving results for '%s'" % self.ds.config_get('sophos', 'authorization'))
    
        tuple_endpoint = self.ENDPOINT_MAP['all']
    
        state_dir = os.path.join(self.ds.config_get('sophos', 'app_path'), 'state')
    
        self.create_state_dir(state_dir)
    
        handler = urlrequest.HTTPSHandler()
        opener = urlrequest.build_opener(handler)
    
        endpoint_config = {'format': 'cef',
                           'filename': 'stdout',
                           'state_dir': state_dir,
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
        if endpoint_config['since']:  # Run since supplied datetime
            since = endpoint_config['since']
        else:
            try:  # Run since last run (retrieve from state_file)
                with open(state_file_path, 'rb') as f:
                    cursor = pickle.load(f)
            except IOError:  # Default to current time
                since = int(calendar.timegm(((datetime.datetime.utcnow() - datetime.timedelta(hours=12)).timetuple())))
                self.ds.log('INFO', "No datetime found, defaulting to last 12 hours for results")
    
        if since is not False:
            self.ds.log('DEBUG', '%s - Retrieving results since: %s' %(endpoint, since))
        else:
            self.ds.log('DEBUG', '%s - Retrieving results starting cursor: %s' %(endpoint, cursor))
    
        results = self.call_endpoint(opener, endpoint, since, cursor, state_file_path)
    
        #write_json_format(results, siem_logger)
        self.write_cef_format(results)
    
    
    def write_json_format(self, results, siem_logger):
        for i in results:
            i = remove_null_values(i)
            update_cef_keys(i)
            name_mapping.update_fields(log, i)
            line = ds_stdout(i)
            siem_logger.info(json.dumps(line, ensure_ascii=False))
    
    def write_cef_format(self, results):
        for i in results:
            i = self.remove_null_values(i)
            name_mapping.update_fields(self.ds.logger, i)
            self.ds.writeEvent(self.format_cef(self.flatten_json(i)).encode('ascii', 'ignore'))
    
    def create_state_dir(self, state_dir):
        if not os.path.exists(state_dir):
            try:
                os.makedirs(state_dir)
            except OSError as e:
                log("Failed to create %s, %s" % (state_dir, str(e)))
                sys.exit(1)
    
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
    
        while True:
            args = '&'.join(['%s=%s' % (k, v) for k, v in params.items()])
            events_request_url = '%s%s?%s' % (self.ds.config_get('sophos', 'url'), endpoint, args)
            self.ds.log('DEBUG', "URL: %s" % events_request_url)
            events_request = urlrequest.Request(events_request_url, None, default_headers)
    
            for k, v in default_headers.items():
                events_request.add_header(k, v)
    
            events_response = self.request_url(opener, events_request)
            self.ds.log('DEBUG', "RESPONSE: %s" % events_response)
            events = json.loads(events_response)
            
    
            # events looks like this
            # {
            # u'chart_detail': {u'2014-10-01T00:00:00.000Z': 3638},
            # u'event_counts': {u'Event::Endpoint::Compliant': 679,
            # u'events': {}
            # }
            for e in events['items']:
                yield e
    
            self.store_state(events['next_cursor'], state_file_path)
            if not events['has_more']:
                break
            else:
                params['cursor'] = events['next_cursor']
                params.pop('from_date', None)
    
    
    def store_state(self, next_cursor, state_file_path):
        # Store cursor
        #log("Next run will retrieve results using cursor %s\n" % next_cursor)
        with open(state_file_path, 'wb') as f:
            pickle.dump(next_cursor, f, protocol=2)
    
    
    # Flattening JSON objects in Python
    # https://medium.com/@amirziai/flattening-json-objects-in-python-f5343c794b10#.37u7axqta
    def flatten_json(self, y):
        out = {}
    
        def flatten(x, name=''):
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + '_')
            else:
                out[name[:-1]] = x
    
        flatten(y)
        return out
    
    
    def log(self, s):
        if not QUIET:
            sys.stderr.write('%s\n' % s)
    
    
    def jitter(self):
        time.sleep(randint(0, 10))
    
    
    def request_url(self, opener, request):
        for i in [1, 2, 3]:  # Some ops we simply retry
            try:
                response = opener.open(request)
            except urlerror.HTTPError as e:
                if e.code in (503, 504, 403, 429):
                    log('Error "%s" (code %s) on attempt #%s of 3, retrying' % (e, e.code, i))
                    if i < 3:
                        continue
                log('Error during request. Error code: %s, Error message: %s' % (e.code, e.read()))
                raise
            return response.read()
    
    def format_prefix(self, data):
        # pipe and backslash in header must be escaped
        # escape group with backslash
        return self.PREFIX_PATTERN.sub(r'\\\1', data)
    
    def format_extension(self, data):
        # equal sign and backslash in extension value must be escaped
        # escape group with backslash
        if type(data) is str:
            return self.EXTENSION_PATTERN.sub(r'\\\1', data)
        else:
            return data
    
    def map_severity(self, severity):
        if severity in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[severity]
        else:
            msg = 'The "%s" severity can not be mapped, defaulting to 0' % severity
            log(msg)
            return self.SEVERITY_MAP['none']
    
    def extract_prefix_fields(self, data):
        # extract prefix fields and remove those from data dictionary
        name_field = self.CEF_MAPPING['name']
        device_event_class_id_field = self.CEF_MAPPING['device_event_class_id']
        severity_field = self.CEF_MAPPING['severity']
    
        name = data.get(name_field, self.MISSING_VALUE)
        name = self.format_prefix(name)
        data.pop(name_field, None)
    
        device_event_class_id = data.get(device_event_class_id_field, self.MISSING_VALUE)
        device_event_class_id = self.format_prefix(device_event_class_id).replace('::', '-')
        data.pop(device_event_class_id_field, None)
    
        severity = data.get(severity_field, self.MISSING_VALUE)
        severity = self.map_severity(severity)
        data.pop(severity_field, None)
    
        fields = {'name': name,
                  'device_event_class_id': device_event_class_id,
                  'severity': severity,
                  'version': self.ds.config_get('cef', 'VERSION'),
                  'device_vendor': self.ds.config_get('cef', 'VENDOR'),
                  'device_version': self.ds.config_get('cef', 'VERSION'),
                  'device_product': self.ds.config_get('cef', 'PRODUCT')}
        return fields

    
    def update_cef_keys(self, data):
        # Replace if there is a mapped CEF key
        for key, value in list(data.items()):
            new_key = self.CEF_MAPPING.get(key, key)
            if new_key == key:
                continue
            data[new_key] = value
            del data[key]
    
    
    def format_cef(self, data):
        fields = self.extract_prefix_fields(data)
        msg = self.CEF_FORMAT % fields

        self.update_cef_keys(data)

        msg += "rt=%s" %data['rt']
        data.pop('rt', None)

        #msg += " duid=%s" %data['duid']
        #data.pop('duid', None)

        #msg += " suser=%s" %data['suser'].replace('\\', '\\\\')
        msg += " suser=%s" %data['suser']
        data.pop('suser', None)

        msg += " dhost=%s" %data['dhost']
        data.pop('dhost', None)

        msg += " msg="
    
        for index, (key, value) in enumerate(data.items()):
            value = self.format_extension(value)
            if index > 0:
                msg += ' %s\=%s' % (key, value)
            else:
                msg += '%s\=%s' % (key, value)
        return msg
    
    
    def remove_null_values(self, data):
        return {k: v for k, v in data.items() if v is not None}

    def run(self):
        self.sophos_main()
    
    def usage(self):
        print
        print os.path.basename(__file__)
        print
        print '  No Options: Run a normal cycle'
        print
        print '  -t    Testing mode.  Do all the work but do not send events to GRID via '
        print '        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\''
        print '        in the current directory'
        print
        print '  -l    Log to stdout instead of syslog Local6'
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
        except Exception ,e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
