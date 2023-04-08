from http.server import BaseHTTPRequestHandler, HTTPServer

import time
import datetime
import ipaddress
import signal
import threading
import sys
import os
import re
import hashlib
import urllib.parse
import yaml       # pip: pyyaml
import pyotp      # pip: pyotp
import requests   # pip: requests

# TODO: 
# - environment variable pour TOTP-Secret
# - gérer les secrets multiples
# - faire un docker image sur github

# Debugging bash aliases: 
# alias knock='myknock() { curl -i http://caddy-knocker:8000/knock -H "X-Forwarded-For: $1" -H "Nonce: $2" ; }; myknock'
# alias check='mycheck() { curl -i http://caddy-knocker:8000/check -H "X-Forwarded-For: $1" ; }; mycheck'
# alias updateconf='myupdate() { curl -i http://caddy-knocker:8000/updateconfig ; }; myupdate'
# alias checkconf='mycheckconf() { curl -i http://caddy-knocker:8000/checkconfig ; }; mycheckconf'
# alias maint='curl -i http://caddy-knocker:8000/maintenance'
# alias termsrv='kill -TERM `pidof python3`'

# BUILDING AND RUNNING
# docker build -t caddy-knocker .
# docker run -it --network caddy --name=caddy-knocker --rm caddy-knocker

configuration_file = 'configuration.yaml' if os.environ.get('CONFIG') is None else os.environ.get('CONFIG')
app_name = 'CaddyKnocker'

# Dict containing the default configuration - will be overridden later by the JSON config
configuration = {}
configuration['ServerPort'] = 8000
configuration['ServerName'] = 'Microsoft-IIS/10.0'
configuration['Server-Response-Header'] = 'X-Whitelist'
configuration['Server-Fowarded-IP-Header'] = 'X-Forwarded-For'
configuration['Server-Security-Header'] =  'Nonce' 
configuration['Server-Content-Type'] =  'text/html'
configuration['Server-Reuses-TOTP'] =  False
configuration['Server-Knock-Flood-Protection'] =  False
configuration['Server-Knock-Flood-Protection-Duration'] =  60
configuration['Server-Knock-Flood-Times'] =  3
configuration['Server-Redirect-Failures-To'] = 'https://www.zombo.com'
configuration['API-Check-Path'] = '/check'
configuration['API-Knock-Path'] = '/knock'
configuration['Allowed-IPs'] = [{'ip': "192.168.31.10", 'expiration': 0}]

configuration['Allowed-Subnets'] = ["192.168.31.0"]
configuration['Allowed-Expiration'] = 24
configuration['TOTP-Secret'] = ''
configuration['TOTP-Last-Used-Code'] = ''
configuration['Configuration-Sync'] = 3600

configuration['Notify'] = {}
configuration['Notify']['Notify-On-Knock-Successful'] = True
configuration['Notify']['Notify-On-Knock-Failure'] = True
configuration['Notify']['Notify-On-Knock-Close'] = True
configuration['Notify']['Notify-HTTP-Method'] = 'POST'
configuration['Notify']['Notify-URL'] = 'http://my.gotify.host/message?token=YOUR_GOTIFY_API_TOKEN'
configuration['Notify']['Notify-HTTP-Form-Payload'] = {}
configuration['Notify']['Notify-HTTP-Form-Payload']['message'] = '{ip} {knock_status}.'
configuration['Notify']['Notify-HTTP-Form-Payload']['priority'] = 3
configuration['Notify']['Notify-HTTP-Form-Payload']['title'] = 'Notification from '+app_name

# Keeps a log of the last time access to the knock endpoint has been reached. 
# This is used to calculate if anti-flood protection is needed.
last_knocks = []

# OTP object used to access the pyotp library.
totp = pyotp.TOTP(configuration['TOTP-Secret'])

def log(msg=''):
    ''' Logger function - writes to STDOUT. '''
    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg) 

def err(msg=''):
    ''' Logger function - writes to STDERR. '''
    print('{0} ** ERROR ** {1}'.format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg), file=sys.stderr) 

def valid_ip(ip): 
    """ Checks if the specified IP is valid """
    try:
        ipaddress.ip_address(ip)
    except ValueError(): 
        return False
    finally: 
        return True

def valid_network(subnet): 
    """ Checks if the specified subnet is valid and in the IP/CIDR notation """
    try:
        ipaddress.ip_network(subnet)
        cidr_regex = re.compile(r'^\d{1,3}(\.\d{1,3}){3}/(?:[12][0-9]|3[012])$')
        #log('ip {0} match? {1}'.format(subnet, cidr_regex.match(subnet)))
        return cidr_regex.match(subnet)
    except ValueError as e: 
        return False

def valid_path(path): 
    ''' Checks if the path part of an URL (the part that comes after the domain) is valid. Requires a leading slash. '''
    url_regex = re.compile(r'^/[-a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=%]*$')
    return url_regex.match(path)

def valid_url(url): 
    ''' Checks if the provided URL is valid. '''
    url_regex = re.compile(r'^(?:http|https):\/\/[\w\-]+(?:\.[\w\-]+)*(?:\:[0-9]+)?(?:\/[^?]+)?(?:\?.*)?$')
    return url_regex.match(url)

def valid_base32(secret): 
    ''' Checks if secret is a valid base32 secret for use by the pytotp module. '''
    # secret length MAY vary, and may be optionnally padded with '=' at the end.
    totp_secret_regex = re.compile(r'^[A-Z2-7]+=*$')
    return bool(totp_secret_regex.match(secret))

def ip_whitelisted(ip): 
    ''' Checks if IP has been whitelisted, and checks for whitelist expiration (remove old entries) at the same time. '''   

    for item in configuration['Allowed-IPs']: 
        if item['expiration'] > 0 and item['expiration'] < time.time(): 
            # Time expired, removing
            log('time expired for whitelisted entry: {0}'.format(item['ip']))
        
            configuration['Allowed-IPs'].remove({'ip': item['ip'], 'expiration': item['expiration']})
            continue
        if item['ip'] == ip: 
            return True
    return False

def ip_whitelisted_by_network(ip): 
    ''' Checks if IP has already been whitelisted by one subnet in the configuration '''
    for subnet in configuration['Allowed-Subnets']: 
        if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet): 
                return True
    return False

def server_thread():
    global httpd
    server_address = ('', configuration['ServerPort'])
    httpd = HTTPServer(server_address, KnockerHandler)
    httpd.serve_forever()


def do_maintenance():
    ''' Executes the maintenance tasks. Cleans up the expired whitelisted adresses and saves the configuration to file. ''' 
    # Cleanup - before saving the config on file, remove expired whitelisted entries
    t = int(time.time())
    cleanedupWhitelist = []
    for i, item in enumerate(configuration['Allowed-IPs']): 
        if item['expiration'] < t and item['expiration'] > 0: 
            # these are the elements we want to get rid.
            notify_close(item['ip'], 'expired')
            continue
        cleanedupWhitelist.append(item)
    configuration['Allowed-IPs'] = cleanedupWhitelist

    # Saves the resulting YAML file to disk
    save_yaml()

def maintenance_thread(): 
    while True: 
        time.sleep(configuration['Configuration-Sync'])
        do_maintenance()
        
        
def handle_signals(sig, frame):
    log('Received signal {0}, shutting down.'.format(sig))
    save_yaml()
    httpd.shutdown() 
    sys.exit(0)

def open_yaml(): 
    ''' Opens, parse and apply the values from configuration file. Will warn about errors in the config file and fallback to sane defaults. '''
    global configuration
    global totp

    # Configuration checking. Values are checked for sane values here.
    # Not exactly idiot-proof, but a decent first protection.
    try: 
        with open(configuration_file, 'rb') as f: 
            yaml_file_data = f.read()
            yaml_data_new = yaml.load(yaml_file_data, Loader=yaml.FullLoader)
            for k in yaml_data_new: 
                
                # Paths should be a string that contains a valid path
                if k == 'API-Check-Path' or k == 'API-Knock-Path':
                    if type(yaml_data_new[k]) is not str:
                        err('Configuration error for {0}: should be a string, not a {1}.'.format(k, type(yaml_data_new[k])))
                    if valid_path(yaml_data_new[k]): 
                        configuration[k] = yaml_data_new[k]
                    else: 
                        err('Configuration error for {0}: {1} is an invalid path. Using defaults'.format(k, yaml_data_new[k]))
                
                # Generic integers
                if k == 'Allowed-Expiration' or k == 'Configuration-Sync' or k == 'ServerPort' \
                    or k == 'Server-Knock-Flood-Protection-Duration' or k == 'Server-Knock-Flood-Protection-Times':
                    if type(yaml_data_new[k]) is not int:
                        err('Configuration error for {0}: should be an int, not a {1}.'.format(k, type(yaml_data_new[k])))
                    else: 
                        configuration[k] = yaml_data_new[k]

                # Allowed-IPs should be a list of {'expiration': time.time(), 'ip': (an IP in string)}
                if k == 'Allowed-IPs':
                    if type(yaml_data_new[k]) is not list:
                        err('Configuration error for {0}: should be a list, not a {1}.'.format(k, type(yaml_data_new[k])))
                    else: 
                        ips = []
                        for l in yaml_data_new[k]:
                            badformat = False
                            if type(l['expiration']) is not int: 
                                err('Configuration error for {0}: expiration {1} is not an int. Must be in an unix timestamp format.'.format(l, l['expiration']))
                                badformat = True
                            if not valid_ip(l['ip']): 
                                err('Configuration error for {0}: ip {1} is not a valid IP.'.format(l, l['ip']))
                                badformat = True
                            if badformat == False: 
                                ips.append(l.copy())
                        configuration[k] = ips.copy()

                # Allowed-Subnets should be a list of IP/CIDR strings
                if k == 'Allowed-Subnets':
                    subnets = []
                    if type(yaml_data_new[k]) is not list:
                        err('Configuration error for {0}: should be a list, not a {1}.'.format(k, type(yaml_data_new[k])))
                    else:     
                        for l in yaml_data_new[k]:
                            if valid_network(l):
                                subnets.append(l)
                            else: 
                                err('{0} is not a valid subnet. Valid format is IP/CIDR (ex: 192.168.31.0/24)'.format(l))

                    configuration[k] = subnets.copy()

                # Notify should be a dict
                if k == 'Notify':
                    if type(yaml_data_new[k]) is not dict:
                        err('Configuration error for {0}: should be a dict, not a {1}.'.format(k, type(yaml_data_new[k])))
                    else: 
                        for l in yaml_data_new[k]:
                            if l == 'Notify-On-Knock-Close' or l == 'Notify-On-Knock-Failure'\
                               or l == 'Notify-On-Knock-Successful': 
                                if type(yaml_data_new[k][l]) is not bool: 
                                    err('Configuration error for {0}: not true or false.'.format(l))
                                    yaml_data_new[k][l] = False
                            if l == 'Notify-URL': 
                                if not valid_url(yaml_data_new[k][l]) and yaml_data_new[k][l] != '': 
                                    err('Configuration error for {0}: invalid URL.'.format(l))
                                    yaml_data_new[k][l] = ''
                            if l == 'Notify-HTTP-Method': 
                                if yaml_data_new[k][l] != 'GET' and yaml_data_new[k][l] != 'POST': 
                                    err('Configuration error for {0}: invalid method (accepted values are GET or POST).'.format(l))
                                    yaml_data_new[k][l] = 'POST'
                            if l == 'Notify-HTTP-Form-Payload': 
                                if type(yaml_data_new[k][l]) is not dict: 
                                    err('Configuration error for {0}: value is not a list.'.format(l))

                        configuration[k] = yaml_data_new[k].copy()

                # Generic strings
                if k == 'Server-Forwarded-IP-Header' or k == 'Server-Redirect-Failures-To' \
                    or k == 'Server-Response-Header' or k == 'Server-Security-Header' or k == 'TOTP-Last-Used-Code': 
                    if type(yaml_data_new[k]) is not str:
                        err('Configuration error for {0}: should be a str, not a {1}.'.format(k, type(yaml_data_new[k])))
                    else: 
                        configuration[k] = yaml_data_new[k]

                # Generic booleans
                if k == 'Server-Reuses-TOTP' or k == 'Server-Knock-Flood-Protection': 
                    if type(yaml_data_new[k]) is not bool:
                        err('Configuration error for {0}: should be a bool, not a {1}.'.format(k, type(yaml_data_new[k])))
                    else: 
                        configuration[k] = yaml_data_new[k]

                # TOTP-Secret should be a valid base32 value.
                if k == 'TOTP-Secret':
                    if not valid_base32(yaml_data_new[k]): 
                        err('Configuration error for {0}: {1} is not a valid TOTP Secret.'.format(k, yaml_data_new[k]))
                    else: 
                        configuration[k] = yaml_data_new[k]

            log('Configuration loaded from disk.')

        totp = pyotp.TOTP(configuration['TOTP-Secret'])
    except FileNotFoundError: 
        log('File not found : {0} . Using defaults.'.format(file))
    except Exception as e: 
        #print(f'Unhandled Exception while trying to read the YAML configuration file (will use defaults instead): {e}')
        log('Unhandled Exception while trying to read the YAML configuration file (will use defaults instead): {0}'.format(e))


def save_yaml(): 
    ''' Saves the configuration, only if the underlying file on disk really differs . ''' 

    yaml_data = yaml.dump(configuration, sort_keys=True, default_flow_style=False)
    
    # This is the comments that will be scattered over the configuration file as user documentation.
    comments = {'ServerPort': 'Port on which the HTTP server listens on.', 
                'ServerName': "'Server' HTTP Header in the server response. Obviously we send a fake server signature to trick hackers ;)", 
                'Server-Response-Header': 'HTTP Header used by the server to specify if the IP has been, or is, whitelisted. Returns True or False, depending if the IP is in the whitelist or not.', 
                'Server-Fowarded-IP-Header': 'HTTP Header used by the server AND Caddy to pass along the external IP of the client trying to connect.', 
                'Server-Security-Header': "HTTP Header used by the client to send it's TOTP code", 
                'Server-Content-Type': 'HTTP Content-type being used by the server as response',
                'Server-Redirect-Failures-To': 'When unauthorized IPs are trying to connect to your endpoints, redirects the connection to this website.',
                'Server-Reuses-TOTP': 'Permits the use of the same TOTP code more than once. This may be a security issue. Set to true or false.',
                'Server-Knock-Flood-Protection': 'Delays successive queries to the "API-Knock-Path" endpoint',
                'Server-Knock-Flood-Protection-Duration': 'Checks for queries made in those last seconds (default: 60). This is used to detect if the server is going under a flood attack.',
                'Server-Knock-Flood-Protection-Times': 'If this number is reached in the last (Server-Knock-Flood-Protection-Duration) seconds, the requests made to the "API-Knock-Path" endpoint is increasingly delayed',
                'API-Check-Path': "HTTP Server will listen for this path to check if the IP is whitelisted, along with 'Server-Reponse-Header'. Can be anything you like, but Caddy MUST know about this path as well.", 
                'API-Knock-Path': 'HTTP Server will listen for this path to let new clients in. Can be anything you like, but Caddy MUST know about this path as well.', 
                'Allowed-IPs': 'List of allowed IPs. This is a list of tuple, which contains the IP address, as well as an expiration date (0 = permanent). This list will change over time, as the program saves the new IPs there.', 
                'Allowed-Subnets': 'List of permanently allowed subnets. Could be used to whitelist your ISP, although this is insecure.', 
                'Allowed-Expiration': 'Expiration of whitelisted IPs, in hours', 
                'TOTP-Secret': "TOTP Secret, used by the client with configuration['Security-Header'], to authenticate. You DEFINITELY want to change this. You can get a TOTP Secret, as well as test it, directly on https://totp.danhersam.com ",
                'TOTP-Last-Used-Code': 'Last used TOTP Code, used by Server-Reuses-TOTP to check for double authentication',
                'Configuration-Sync': 'Delay between each configuration update on disk, in seconds.', 
                'Notify:': 'Section for notifications configuration. You can send a notification whenever an event happens', 
                'Notify-Enabled': 'Toggle on or off this feature globally. Values: True or False', 
                'Notify-URL': 'Sets the HTTP Endpoint where to send the notifications to', 
                'Notify-HTTP-Method': 'HTTP Method, either POST or GET', 
                'Notify-HTTP-Form-Payload': 'The contents of the HTTP Form being sent in the notification. This may be any keys and values', 
                'Notify-On-Knock-Successful': 'Sends a notification for new IP knocking in successfully. true/false', 
                'Notify-On-Knock-Failure': 'Sends a notification for new IP trying to knock-in but fails to do so. true/false', 
                'Notify-On-Knock-Close': 'Sends a notification when removing a known IP from the whitelist. true/false', 
        }
    
    # Tentatively place user docs in the generated YAML file
    lines = yaml_data.split('\n')
    for k in comments: 
        for i, line in enumerate(lines):
            if line.count(k) > 0: 
                lines[i] = lines[i] + ' # ' + comments[k]

    yaml_output = '\n'.join(lines)

    yaml_hash = hashlib.md5(yaml_output.encode()).hexdigest()
    try: 
        with open(configuration_file, 'rb') as f: 
            yaml_file_data = f.read()
            existing_hash = hashlib.md5(yaml_file_data).hexdigest()
    except FileNotFoundError: 
        existing_hash = None
        

    if yaml_hash == existing_hash:
        log('Saving configuration: hash is the same - skipping writing')
        return

    with open(configuration_file, 'w') as f: 
        log('Writing configuration on disk')
        f.write(yaml_output)


def check_filesystem():
    ''' Safeguards against improper filesystem rights for a present configuration file, or create a new one with the defaults. '''

    try: 
        status = os.stat(configuration_file)
    except FileNotFoundError: 
        log('Configuration file {0} does not exist, creating one with the defaults'.format(configuration_file))
        save_yaml()
        os.chmod(configuration_file, 0o600) # no group or world attributes on purpose
        return

    # Checking if we have sane configuration permission rights
    # This ensures we don't expose a TOTP Token up for grabs...
    group_perms = (status.st_mode & 0o70) >> 3
    other_perms = status.st_mode & 0o7

    if group_perms & 0o4: 
        err("I'm a coward, and i'm bailing out:")
        err("Your {0} file is readable to all the UNIX groups you are a member of,".format(configuration_file))
        err("and this potentially exposes your TOTP Secret to others!")
        err()
        err("To fix this, secure your file by running `chmod go-rwx {0}` and try again.".format(configuration_file))
        sys.exit(1)

    if other_perms & 0o4: 
        err("I'm a coward, and i'm bailing out:")
        err("Your {0} file is readable to ALL the users of this server,".format(configuration_file))
        err("and this potentially exposes your TOTP Secret to others!")
        err()
        err("To fix this, run `chmod go-rwx {0}` and try again.".format(configuration_file))
        sys.exit(1)

    if group_perms & 0o2: 
        err("I'm a coward, and i'm bailing out:")
        err("Your {0} file is writable to all the UNIX groups you are a member of,".format(configuration_file))
        err("and this potentially exposes this server for others to exploit!")
        err()
        err("To fix this, secure your file by running `chmod go-rwx {0}` and try again.".format(configuration_file))
        sys.exit(1)

    if other_perms & 0o2: 
        err("I'm a coward, and i'm bailing out:")
        err("Your {0} file is writable to ALL the users of this server,".format(configuration_file))
        err("and this potentially exposes this server for others to exploit!")
        err()
        err("To fix this, run `chmod go-rwx {0}` and try again.".format(configuration_file))
        sys.exit(1)

def notify_format_payload(ip, message): 
    ''' Prepares the HTTP Form object by replacing macros for relevant information. '''
    payload = configuration['Notify']['Notify-HTTP-Form-Payload'].copy()
    for i, k in enumerate(payload): 
        #log('key {0}, val {1}'.format(k, payload[k]))
        if type(payload[k]) == str: 
            data = payload[k]
            data = data.replace('{ip}', ip)
            data = data.replace('{knock_status}', message)
            data = data.replace('{date}', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            payload[k] = data
    return payload

def notify_call(payload):
    ''' Sends the notification to the HTTP server. Returns the requests.post() object. ''' 
    if configuration['Notify']['Notify-URL'] == '': 
        # Do not even bother if the URL was not set. Consider it deactivated.
        return 
    if configuration['Notify']['Notify-HTTP-Method'] == 'POST': 
        return requests.post(configuration['Notify']['Notify-URL'] , data=payload)
    elif configuration['Notify']['Notify-HTTP-Method'] == 'GET': 
        fullurl = configuration['Notify']['Notify-URL']
        params = urllib.parse.urlencode(configuration['Notify']['Notify-HTTP-Form-Payload'])

        if '?' in fullurl: 
            fullurl += '&'+params
        else: 
            fullurl += '?'+params

        if len(fullurl) > 2048:
            log('WARNING: generated HTTP GET URL is longer that 2048; depending on the web server this may be longer than supported.')
            log('You may want to switch to HTTP POST if possible.')

        return requests.get(fullurl)

def notify_success(ip, message): 
    ''' Notify when a new connexion has been authentified successfully.  ''' 
    if configuration['Notify']['Notify-On-Knock-Successful'] == True:
        payload = notify_format_payload(ip, message)
        response = notify_call(payload)
    log(payload['message'])

def notify_failure(ip, message): 
    ''' Notify when a new connexion has NOT been authentified successfully.  ''' 
    if configuration['Notify']['Notify-On-Knock-Failure'] == True:
        payload = notify_format_payload(ip, message)
        response = notify_call(payload)
    log(payload['message'])

def notify_close(ip, message): 
    ''' Notify when a previously whitelisted IP needs to be removed from the whitelist.  ''' 
    if configuration['Notify']['Notify-On-Knock-Close'] == True:
        payload = notify_format_payload(ip, message)
        response = notify_call(payload)
    log(payload['message'])

class KnockerHandler(BaseHTTPRequestHandler):
    ''' Overrides BaseHTTPRequestHandler and serves as the class that deals with incoming HTTP requests. ''' 

    def log_message(self, format, *args): 
        # here lies incoming connection logging from HTTPRequestHandler - we silent that for now.
        pass

    def version_string(self):
        ''' Overrides the default HTTP Server 'Server' header when replying to an HTTP request '''
        return configuration['ServerName']

    def refuse(self, ip): 
        ''' Refuses a connexion, sending the client away according to the value of Server-Redirect-Failures-To in the configuration.  '''
        self.send_response(301)
        self.send_header(configuration['Server-Response-Header'], 'False')
        self.send_header('Location', configuration['Server-Redirect-Failures-To'])
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('X-IP', ip)
        self.end_headers()
        self.wfile.write("FAIL".encode())     
        self.close_connection = True
    
    def accept(self, ip): 
        ''' Accepts the incoming connexion and tentatively adds the IP to the allowed list. If the ip=='subnet', the connection is accepted via a whitelisted subnet.'''

        # Adds the IP if not already present AND not accepted via a subnet
        if not ip_whitelisted(ip) and ip != 'subnet': 
            t = time.time()
            dt = datetime.datetime.fromtimestamp(t)
            offset = dt + datetime.timedelta(hours=configuration['Allowed-Expiration'])
            configuration['Allowed-IPs'].append({'ip': ip, 'expiration': int(offset.timestamp())})

        self.send_response(202)
        self.send_header(configuration['Server-Response-Header'], 'True')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('X-IP', ip)
        self.end_headers()
        self.wfile.write("OK".encode())
        self.close_connection = True  

    def do_GET(self):
        ''' Main entrypoint for incoming HTTP requests '''

        global configuration
        global last_knocks

        requestedIP = self.headers[configuration['Server-Fowarded-IP-Header']]

        ### KNOCK entrypoint
        if self.path == configuration['API-Knock-Path']: 

            if configuration['Server-Knock-Flood-Protection'] == True and not totp.verify(self.headers[configuration['Server-Security-Header']]): 
                # rudimentary flood protection where replies with the bad TOTP code are 
                # increasingly delayed if there are more than 5 hits on /knock in the 
                # last 60 seconds

                duration = configuration['Server-Knock-Flood-Protection-Duration']
                maximum_hits = configuration['Server-Knock-Flood-Protection-Times']

                last_knocks.append(time.time())

                # Keeps the last 5 minutes of data
                last_knocks = [t for t in last_knocks if time.time() - t <= 300]

                # Amount of hit on /knock in the last 60 seconds
                recent_knocks = len([t for t in last_knocks if time.time() - t <= duration])

                if recent_knocks > maximum_hits: 
                    reply_delay = (recent_knocks - 3) * 2
                    log('Delaying reply by {0} secs, server has too many successive {1} requests, and flood protection is enabled'.format(reply_delay, configuration['API-Knock-Path']))
                    time.sleep(reply_delay)

            if requestedIP is None or requestedIP == '' or not valid_ip(requestedIP): 
                # This may happen when the reverse proxy server does NOT pass the X-Fowarded-IP
                # header to this server, or that you provided a custom header that's not set 
                # up in the reverse proxy to pass to this server.
                #log('Refusing: invalid IP: {0}'.format(requestedIP))
                notify_failure(requestedIP, 'IP invalid.')
                self.refuse(requestedIP)
                return
            
            if ip_whitelisted_by_network(requestedIP): 
                # accept the connection if it comes from a whitelisted subnet
                #log('Accepting {0}: part of a whitelisted subnet.'.format(requestedIP))
                notify_success(requestedIP, 'is part of a whitelisted subnet.')
                self.accept('subnet')

            elif ip_whitelisted(requestedIP):
                # this accepts a previously whitelisted IP
                #log('Accepting {0}: previously whitelisted IP.'.format(requestedIP))
                notify_success(requestedIP, 'was previously accepted.')
                self.accept(requestedIP)
            else: 
                # New unknown IP knocking in, verifying with 'Server-Security-Header'
                
                log('last used: {0}, header: {1}'.format(configuration['TOTP-Last-Used-Code'], self.headers[configuration['Server-Security-Header']]))
                if configuration['TOTP-Last-Used-Code'] == self.headers[configuration['Server-Security-Header']] and configuration['Server-Reuses-TOTP'] == False:
                    # this TOTP was alreday used, and the app is configured to NOT let through successive requests
                    # with the same TOTP code.
                    notify_failure(requestedIP, 'has a valid TOTP code, however TOTP reuse with Server-Reuses-TOTP is configured to False')
                    self.refuse(requestedIP)
                    return

                if totp.verify(self.headers[configuration['Server-Security-Header']]): 
                    notify_success(requestedIP, 'is a new IP with correct TOTP token.')
                    configuration['TOTP-Last-Used-Code'] = self.headers[configuration['Server-Security-Header']]
                    self.accept(requestedIP)
                else: 
                    notify_failure(requestedIP, 'used an invalid TOTP token.')
                    self.refuse(requestedIP)

        ### CHECK entrypoint
        elif self.path.index(configuration['API-Check-Path']) == 0: 
            # caddy will still pass the ?var=val&var2=val2 part in the URI.
            # so we need only to match on the start of the string.

            #log('CHECK is hit')
            if requestedIP is not None and requestedIP != '' and ip_whitelisted(requestedIP): 
                #log('CHECK: {0} is whitelisted.'.format(requestedIP))
                self.accept(requestedIP)

            elif ip_whitelisted_by_network(requestedIP): 
                # accept the connection if it comes from a whitelisted subnet

                #log('CHECK: {0} is part of a subnet'.format(requestedIP))
                self.accept("subnet") 
            else: 
                log('CHECK: {0} is NOT whitelisted.'.format(requestedIP))
                self.refuse(requestedIP)

        # Diagnostics and development - should NOT be part of prod EVER.
        #elif self.path == '/updateconfig':
        #    save_yaml()
        #elif self.path == '/maintenance':
        #    do_maintenance()
        #elif self.path == '/checkconfig':
        #    log('config is: {0}'.format(configuration))
        #elif self.path == '/gotify':
        #    notify_success(self.client_address[0], "gets whitelisted: valid TOTP token provided.")
        #    return
        else:
            #print('refusing: invalid path: ',  self.path)
            log('Refusing {0}: invalid path {1}'.format(requestedIP, self.path))
            self.refuse(requestedIP)

if __name__ == '__main__':
    if os.environ.get('CONFIG') is not None: 
        log('Using environment variable CONFIG={0}'.format(configuration_file))
    check_filesystem()
    open_yaml()

    if configuration['TOTP-Secret'] == '': 
        log("You probably forgot to configure the app, or configuration read has failed. Configure at least the 'TOTP-Secret' line in the configuration file {0} with a secret TOTP Token, and restart the app.".format(configuration_file))
        time.sleep(5)
        sys.exit(1)

    # Launches a thread for the web server
    server_t = threading.Thread(target=server_thread)
    server_t.start()

    # Launches another thread for maintenance
    maintenance_thread = threading.Thread(target=maintenance_thread)
    maintenance_thread.daemon = True
    maintenance_thread.start()

    # Signals
    signal.signal(signal.SIGTERM, handle_signals)
    signal.signal(signal.SIGINT, handle_signals)

    # Wait until server_t ended
    server_t.join()
