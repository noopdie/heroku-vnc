#!/bin/bash
set -ex
mkdir -p ~/.vnc ~/.config/xfce4
tar -xvf /app/panel.tar -C ~/.config/xfce4
rm -rf /usr/share/icons/Adwaita
cp -r /usr/share/icons/Humanity-Dark /usr/share/icons/Adwaita

mkdir -p /Desktop
cat << EOF >  /Desktop/Chromium.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=Chromium
Comment=Access the Internet
Exec=/usr/bin/chromium-browser --no-sandbox --disable-dev-shm-usage
Icon=chromium-browser
Path=
Terminal=false
StartupNotify=true
EOF

#cat << EOF >  /Desktop/AnyDesk.desktop
#[Desktop Entry]
#Version=1.0
#Type=Application
#Name=AnyDesk
#Comment=
#Exec=/usr/bin/anydesk
#Icon=anydesk
#Path=
#Terminal=false
#StartupNotify=true
#EOF

cat << EOF >  /Desktop/Swicth_to_Chinese_input.sh
#!/bin/bash
im-config -s ibus
ibus-setup
EOF

cat << EOF >  /Desktop/Readme.txt
Step 1: Excute Swicth_to_Chinese_input.sh on Deskop to switch input method.
Step 2: Select 'Input Method', then click add button, choose Chinese and Pinyin icon to add.
Step 3: Now it can support Chinese, Enjoy!
EOF

cat << EOF >  /Desktop/sshkey
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx4tNBsFIRQq8sh/e6A/5G42wJ5H9Pt2E4830SWMtVybf15Or
4QMeMaBbOMK173Lb/Au6O7HX1rPLGDSE39hXt8ZKco0qAYwLfQWMVs5An1xDb5pC
fLzuDGNdtv0bdXfMMHRrw25jPxbkx7WwXe2QLMAmfQ9IKFrChCxPA0cbRLrfflzO
yQAjCSlzXyCRBWMOrB3U7p/LmL5H6ThHWwTMzR7rO7H/IC92wjiu00AQVe6szcXu
7sVUXZfpj3OqXZqCmu4/7x+0TmyAVirT9MsDmGupLefLgJGgh35vVDhsnqwDmlEM
YH8Ms5QsCAkSBciEn5+qHK9VJfCO0hTIrmlisQIDAQABAoIBAH7Wox2aGpAYZR1s
eMpV7OiAxepBOBKPyHrtXUyQyC9PvJVRfr3Gt5if75xC2FbeUcsCwVxUjXgiTQST
zapj4E4mswfhh0P4ewz7S9uZuyYRBaSZD44uoboqJ1W7yYp/ncFnH2DYeCmQKdhw
Oy1ZZn2rnkt8PUe5eU9+wrK4rjKe3qv+mzA26ug11SiG78T/iu0kbhDclSl8A6Ar
UCAR9lXWvG5YQ7j6eFsKd88Ac1NfE+kmE4lSSURK2BOEFDmwn40TU0vmQfbC+xFe
fiC0yu0c28TiJjWCcunLHVJV5x3sraDIZme8fax+dLUpW00awNoIFj6XVIxR+8c0
b7dnq0kCgYEA8M5iDNjIM1dUdkW78xTERGQ6FN62YwDSD0d+pqb1QQ/9Gsr/xSVJ
R3S9oKoqarxxWkmBCt/8K/fn6z4vpEZ8euhgbueuqTq8CSRgnzReIYeFfxovPmZN
QUjBOqQ0zckvWiHZZJbAB9k9yrniSaOQGyumH9wTi64sU5JrVXCQd9MCgYEA1CJv
AbWBgCzt/dWcKx83ztxppf+MjaMDjd2ZU4wKyXNua2rg5LAyK0liA6Sdh30h+7tO
aW0hEYum/pXreM/Qh83FrMCKQ6stSh90fqwHlij9aaU3jhmpKg/2B85KYWtJF/Ql
qGbZ0OUHh18ZiwB2AAtdM9VTrv8CMAH/tkAsjOsCgYEA26Y1M6itfH9FEJjtJn4j
xIpznEPFs6q08LDzKooSHaW65iySfr5TCDXJHnr5M+DtuEBhz4ydlXGMfzx68mpE
80txYtg7ritgByrCY5W94vGd6GD3BQEFqO33K0lKzQadBaboh+MmCEK1JWzGpwrl
0JLQ9jClN3zI+/YLp6SEcncCgYEArYw+JLfJaoNXcQMA8IZpseLAy/11j6p9jeJt
PdykNospGtglhPJhGOjANxrFhcLpunhSfg25sBEAXedo7T2W7IN75QjgFNxGAQ4a
0EcNLdv69iMkgCyeKLtGHLy4PVr4QZCL/mmmaS/2KNm0m/OUlhS1+2HbRJ97uqrn
+MInsGECgYAo9CipO1kdNxLLaXeQUmYhNNFPwTGheM75VHa6ZFAqNXc1EOnc/0i3
Sg19TNm5oqoHk3UNp3QM6a5nmi2ccVzBYOMdgg1GQRfRIlLzwVhQxMOuYMBvke1z
1ev9RGOlqY22xAGPfEiquGico1VGeSYiGFS6YKKuH0ziLmzm9oUZUQ==
-----END RSA PRIVATE KEY-----
EOF

cat << EOF >  /Desktop/vncport.py
#!/usr/bin/env python

# USAGE: download this script together with your private key to your server and start it there.
# When this script is active you will be able to start and stop a tunnel from your server to our access point
# through the web interface.
#
# Ensure that this script is automatically started upon reboot!
#
# Warning: on unix/linux based systems this script opens ssh tunnels with StrictHostKeyChecking=no option.
# It means they will automatically accept forwarding server signature and put it in known_hosts file. If you want
# to turn this option off read below how to do it. Please take note that if you turn this option off,
# the first time ssh tunnel is opening you will have to manually authorize to add the signature
# to known_hosts file
# On windows systems this option is disabled because plink.exe does not support it.
#
# There are 4 command line arguments
# * private_key_file - a full path of private key file (if not specified it is assumed
#       to be 'id_rsa' in local directory)
# * debug - if set it will write debugging information to logger
# * console - if set logging will also be sent to console
# * stricthostkeychecking - turn on StrictHostKeyChecking for ssh tunnel
#
# Examples:
# python sshreachme.py '/root/.ssh/my_private_key' debug console
#   this will use private key in '/root/.ssh/my_private_key' file and will write all debug messages
#   to console as well as to the log file
#
# python sshreachme.py console stricthostkeychecking
#   this will use private key in 'id_rsa' file in local directory, will write only error messages to
#   console and log file and will start ssh tunnel with StrictHostKeyChecking=yes switch
#
# python sshreachme.py
#   this will use private key in 'id_rsa' file in local directory, will write only error messages to
#   log file and will start ssh tunnel with StrictHostKeyChecking=yes switch
#

import subprocess
import time
import os
import json
import signal
import sys
import logging
import platform
from logging.handlers import TimedRotatingFileHandler
from stat import *
from datetime import datetime
from distutils import spawn

try:
    from urllib2 import urlopen, URLError
except Exception as e:
    from urllib.request import urlopen, URLError


# these values are generated by sshreach.me and should not be changed
URL = 'https://p.sshreach.me/029GCWpxx8KYDPv2N87XDHQtlhGzJQJG'
PORTS_ID = '11033'
UNIX_USERNAME = 'HcCUJoNBj3LZDeGW3vOO8XD0KRHmFx'
HOST_UUID = '43c36d96-e199-463b-8990-415f98e3b368'
USER_ID = '16753'
DB_SERVER_KEY = 'QstSt8zU1we85sbIUag4'
FORWARD_PORT = '5900'
UPGRADE_URL = 'https://sshreach.me/init/api/upgrade_client_script'

# this is the address to which your forwarded port should be forwarded to. This address should be changed only if
# the ssh connection and the server you want to connect to are not on the same machine.
ADDRESS = 'localhost'

# for windows users: change these two values to match your settings
PLINK_PATH = 'c:\\sshreachme'   #   folder where your plink.exe is located
PLINK_EXECUTABLE = 'plink.exe'  #   name of plink executable

debug = False
console = False
StrictHostKeyChecking = False
private_key = "id_rsa"

SCRIPT_VERSION = '370'

# check command line switches
for arg in sys.argv:
    if arg == "debug":
        debug = True
    elif arg == "console":
        console = True
    elif arg == "stricthostkeychecking":
        StrictHostKeyChecking = True
    elif arg != sys.argv[0]:
        private_key = arg

logger = logging.getLogger(__name__)

if debug:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.WARNING)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logfile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "sshreachme.log")
fileHandler = TimedRotatingFileHandler(logfile, when="D", interval=1, backupCount=5)
fileHandler.setFormatter(formatter)
if debug:
    fileHandler.setLevel(logging.DEBUG)
else:
    fileHandler.setLevel(logging.WARNING)
logger.addHandler(fileHandler)

if console:
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(formatter)
    if debug:
        consoleHandler.setLevel(logging.DEBUG)
    else:
        consoleHandler.setLevel(logging.WARNING)
    logger.addHandler(consoleHandler)

WAITTIME = 5
SLEEPTIME = WAITTIME + 40

# check OS
logger.debug('Script version:{0}'.format(SCRIPT_VERSION))

if os.name == 'nt':
    logger.debug("running on windows, importing psutil")
    import psutil
elif os.name == 'posix':
    if platform.system() == 'Darwin':
        logger.debug("running on mac")
    else:
        logger.debug("running on linux")

logger.debug("python {0}".format(sys.version))

pidof_path = "pidof"

if os.name == 'posix':
    try:
        proc = subprocess.Popen(["whereis","pidof"], stdout=subprocess.PIPE)
        pidof_path = [s for s in proc.communicate()[0].split() if s[-6:] == "/pidof"][0]
        logger.debug("pidof_path:{0}".format(pidof_path))
    except Exception as e:
        pidof_path = "pidof"

# We have to check if python executable exists. On rhel8 and centos8 "python" doesn't exist and self-restart is not possible
python_exists = True
if os.name == 'posix':
    if spawn.find_executable("python") == None:
        python_exists = False
        logger.debug("Python executable doesn't exist, script auto-restart is not possible.")

def startSSH(data, private_key):
    try:
        if os.name == 'posix':       # if os is linux or mac
            # first check if there is already started ssh
            pid = get_pid(data['iport'], data['forwarding_server'], private_key)
            if pid:
                logger.debug("ssh already active, pid:{0}".format(pid))
                return pid
            else:
                if StrictHostKeyChecking:
                    # The line below should not be changed. If the ssh command is changed then the corresponding line in get_pid() must
                    # also be changed otherwise the script might not recognize that ssh connection is active and will try to open it
                    # again and again resulting in hundreds of inactive ssh processes.
                    process = 'ssh -N -i {0} -R {1}:{5}:{3} {4}@{2} &'.format(private_key,
                        data['iport'], data['forwarding_server'], FORWARD_PORT, UNIX_USERNAME, ADDRESS)
                else:
                    # The line below should not be changed. If the ssh command is changed then the corresponding line in get_pid() must
                    # also be changed otherwise the script might not recognize that ssh connection is active and will try to open it
                    # again and again resulting in hundreds of inactive ssh processes.
                    process = 'ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -N -i {0} -R {1}:{5}:{3} {4}@{2} &'.format(private_key,
                        data['iport'], data['forwarding_server'], FORWARD_PORT, UNIX_USERNAME, ADDRESS)

                logger.debug("Starting ssh:{0}".format(process))

                proc = subprocess.Popen(process, shell=True)
                time.sleep(3)
                return get_pid(data['iport'], data['forwarding_server'], private_key)
        elif os.name == 'nt':   # os is windows
            process = '{6} -N -i {0} -R {1}:{5}:{3} {4}@{2} &'.format(private_key,
                data['iport'], data['forwarding_server'], FORWARD_PORT, UNIX_USERNAME, ADDRESS,
                os.path.join(PLINK_PATH, PLINK_EXECUTABLE))

            logger.debug("Starting plink:{0}".format(process))
            proc = subprocess.Popen(process, shell=True)
            time.sleep(3)
            return get_pid(data['iport'], data['forwarding_server'], private_key)
    except:
        return 0

def get_pid(iport, forwarding_server, private_key):
    # get pids of all ssh processes
    if os.name == 'posix':
        try:
            # get pids of all ssh processes
            proc = subprocess.Popen([pidof_path,"ssh"], stdout=subprocess.PIPE)
            pids = map(int, (proc.communicate()[0]).split())

            for pid in pids:
                cmdline = open(os.path.join('/proc', str(pid), 'cmdline'), 'rb').read().strip()

                if '-N' in str(cmdline) and '-R' in str(cmdline) and "{0}:{2}:{1}".format(iport, FORWARD_PORT, ADDRESS) in str(cmdline) and "{1}@{0}".format(forwarding_server, UNIX_USERNAME) in str(cmdline):
                    return pid

            return 0
        except Exception as e:
            # we don't have pidof or /proc, try ps-ing
            if StrictHostKeyChecking:
                # The line below should not be changed. If the ssh command is changed then the corresponding line in startSSH() must
                # also be changed otherwise the script might not recognize that ssh connection is active and will try to open it
                # again and again resulting in hundreds of inactive ssh processes.
                checkline = 'ssh -N -i {0} -R {1}:{5}:{3} {4}@{2}'.format(private_key, iport, forwarding_server, FORWARD_PORT, UNIX_USERNAME, ADDRESS)
            else:
                # The line below should not be changed. If the ssh command is changed then the corresponding line in startSSH() must
                # also be changed otherwise the script might not recognize that ssh connection is active and will try to open it
                # again and again resulting in hundreds of inactive ssh processes.
                checkline = 'ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -N -i {0} -R {1}:{5}:{3} {4}@{2}'.format(private_key, iport, forwarding_server, FORWARD_PORT, UNIX_USERNAME, ADDRESS)

            proc = subprocess.Popen(["ps", "-ax"], stdout=subprocess.PIPE)

            pss = proc.communicate()[0].split("\n")
            for ps in pss:
                if checkline in ps:
                    ids = ps.split()
                    return int(ids[0])
            return 0
    elif os.name == 'nt':
        for p in psutil.process_iter():
            if p.name() == PLINK_EXECUTABLE:
                if '{0}:{1}:{2}'.format(iport, ADDRESS, FORWARD_PORT) in p.cmdline() and '{0}@{1}'.format(UNIX_USERNAME, forwarding_server) in p.cmdline():
                    return int(p.pid)
        return 0

def is_process_active(pid, iport, forwarding_server):
    if os.name == 'posix':
        try:
            os.kill(pid, 0)
            return True
        except:
            return False
    elif os.name == 'nt':
        for p in psutil.process_iter():
            if p.name() == PLINK_EXECUTABLE:
                if '{0}:{1}:{2}'.format(iport, ADDRESS, FORWARD_PORT) in p.cmdline() and '{0}@{1}'.format(UNIX_USERNAME, forwarding_server) in p.cmdline():
                    return True
        return False

def looper(private_key):
    pid = 0
    retries = 5
    timeouterrors = 0
    last_good_ping_time = datetime.now()
    disconnect_ssl_when_server_unreachable = False
    lasttime = time.time()
    upgradable = python_exists

    while True:
        try:
            # check if connection needs to be made
            response = urlopen(URL + '/get_port4.php?ports_id={0}&key={1}&uid={2}&dbid={3}&ver={4}&upgradable={5}'.format(PORTS_ID, HOST_UUID, 
                USER_ID, DB_SERVER_KEY, SCRIPT_VERSION, upgradable), None, 4)
            data = json.loads(response.read().strip())

            if len(data) > 0:
                if 'error' in data:
                    raise Exception(data['error'])
                else:
                    last_good_ping_time = datetime.now()
                    disconnect_ssl_when_server_unreachable = data['disconnect_ssl_when_server_unreachable'] == 'T'
                    if 'command' in data:
                        logger.debug('Command:{0}'.format(data['command']))

                        #   activate the tunnel
                        if data['command'] == "1":
                            if pid == 0 or (pid != 0 and is_process_active(pid, data['iport'], data['forwarding_server']) == False):
                                logger.debug('ssh is inactive, starting ssh')
                                #   we have received 'connect' signal, starting ssh tunnel
                                pid = startSSH(data, private_key)
                                logger.debug("Pid:{0}".format(pid))

                                if pid != 0 and is_process_active(pid, data['iport'], data['forwarding_server']) == False:
                                    # ssh is not active, try again
                                    pid = startSSH(data, private_key)
                                    logger.debug("Pid2:{0}".format(pid))
                                elif pid == 0:
                                    logger.debug("ssh not started, pid:{0}".format(pid))
                                    if retries == 0:
                                        logger.debug("can not start ssh, sending error message")
                                        retries = 5
                                        response = urlopen(URL + '/set_error.php?ports_id={0}&key={1}&uid={2}&dbid={3}'.format(PORTS_ID, HOST_UUID, USER_ID, DB_SERVER_KEY), None, 4)
                                    else:
                                        retries = retries - 1
                                        logger.debug("retries:{0}".format(retries))
                                else:
                                    logger.debug("ssh started, pid:{0}".format(pid))
                        elif data['command'] == "0":
                            retries = 5
                            if pid == 0:
                                pid = get_pid(data['iport'], data['forwarding_server'], private_key)
                                logger.debug("Found pid:{0}".format(pid))
                            if pid:
                                try:
                                    logger.debug("Killing ssh, pid:{0}".format(pid))
                                    os.kill(pid, signal.SIGTERM)
                                    pid = 0
                                except Exception as e:
                                    logger.warning(e)
                                    pid = 0                        
                    elif 'error' in data:
                        logger.error(data['error'])
                    if 'upgrade' in data and data['upgrade'] == 'T':
                        new_script = urlopen(UPGRADE_URL + "?ports_id={0}&host_uuid={1}&dbid={2}&user_id={3}".format(PORTS_ID, 
                            HOST_UUID, DB_SERVER_KEY,USER_ID ), None, 4)
                        new_file = new_script.read()
                        with open(__file__, "w") as text_file:
                            text_file.write(new_file)
                        logger.info("Script succesfully upgraded")
                        if python_exists == True:
                            # restart this script only if execute bit is set
                            if os.access(__file__, os.X_OK):
                                logger.info("Restarting script")
                                os.execv(__file__, sys.argv)
                                sys.exit()

            else:
                logger.error("bad response from server")

            time.sleep(WAITTIME)  # do not change this value

            # this is a very primitive way of testing for wakeup event but it works on every system
            # without installing additional modules
            now = time.time()
            # check if computer was suspended
            if (now - lasttime) > SLEEPTIME:
                logger.debug("wake up detected")
                #   we just woke up, check if tunnel is active
                if pid != 0:
                    logger.debug("tunnel was active during sleep - closing it")
                    #   tunnel is active but it is broken, close the tunnel and 
                    #   the new one will be opened if necessary 
                    os.kill(pid, signal.SIGTERM)
                    pid = 0
                
            lasttime = now

        except Exception as e:
            # oops, for some reason we can't open url            
            logger.error("{0}: {1}".format(type(e).__name__, e))

            if isinstance(e, URLError):
                if python_exists == True:
                    if timeouterrors == 3:
                        timeouterrors = 0
                        # restart this script only if execute bit is set
                        if os.access(__file__, os.X_OK):
                            logger.error("Too many URLErrors. Client will now self restart.")
                            os.execv(__file__, sys.argv)
                            sys.exit()
                    else:
                        timeouterrors += 1

            if python_exists == True:
                if (datetime.now() - last_good_ping_time).seconds / 3600 >= 3: 
                   # last ping time was more than 3 hours ago

                    # restart this script only if execute bit is set
                    if os.access(__file__, os.X_OK):
                        logger.error("Last ping was more than 3 hours ago. Client will now self restart.")                    
                        os.execv(__file__, sys.argv)
                        sys.exit()

            logger.error(e)
            if disconnect_ssl_when_server_unreachable and pid != 0:
                logger.debug("Killing ssh, pid:{0}".format(pid))
                os.kill(pid, signal.SIGTERM)
                pid = 0

            time.sleep(WAITTIME)

if __name__ == "__main__":
    # check if private_key exists

    if os.path.isfile(private_key):
        if os.name == 'posix':
            #   check private_key's stat
            if oct(os.stat(private_key)[ST_MODE])[-3:] != '600':
                os.chmod(private_key, 0o600)
            #   Set the execute bit for this script if it is not set
            if not os.access(__file__, os.X_OK):
                os.chmod(__file__, 0o700)            

        looper(private_key)
    else:
        logger.error("private key file not found: {0}".format(private_key))
EOF


chmod +x /Desktop/Chromium.desktop
chmod +x /Desktop/Swicth_to_Chinese_input.sh
exec supervisord -c /app/supervisord.conf
