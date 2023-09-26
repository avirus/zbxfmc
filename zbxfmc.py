import base64
import sys
import json
import requests
from pyzabbix import ZabbixAPI, ZabbixAPIException
import configparser
from os.path import exists
import requests
import urllib3
import hashlib
from zappix.sender import Sender
from time import sleep


# access required: 	Access Admin + 	Security Analyst (Read Only)
def my_preprocess(instring, repldictionary):
    outstring = instring
    for replitem in repldictionary:
        outstring = outstring.replace(replitem['in'], replitem['out'])
    return outstring


ZBX_TRIGGER_LEVEL_NOT_CLASSIFIED = 0
ZBX_TRIGGER_LEVEL_INFO = 1
ZBX_TRIGGER_LEVEL_WARNING = 2
ZBX_TRIGGER_LEVEL_AVERAGE = 3
ZBX_TRIGGER_LEVEL_HIGH = 4
ZBX_TRIGGER_LEVEL_DISASTER = 5
ZBX_ITEM_FLOAT = 0
ZBX_ITEM_CHAR = 1
ZBX_ITEM_LOG = 2
ZBX_ITEM_UNSIGNED = 3
ZBX_ITEM_TEXT = 4
ZBX_ITEM_TYPE_ZBXTRAPPER = 2
ZBX_ITEM_ENABLED = 0
ZBX_ITEM_DISABLED = 1


def create_trigger(replacement_dictionary):
    global key, host_id, zapi, dev_name, item, host_name
    # 0 - (default) not classified; 1 - information; 2 - warning;  3 - average; 4 - high; 5 - disaster.
    # #hostname#/#key#
    # (last(/aa-iscsi/vfs.file.contents[/sys/module/zfs/version],#1)<>last(/aa-iscsi/vfs.file.contents[/sys/module/zfs/version],#2))>0
    #    recovery_mode=item['tg_recovery_mode'],
    expression = my_preprocess(item['expression'], replacement_dictionary)
    eventname = my_preprocess(item['eventname'], replacement_dictionary)
    comment = my_preprocess(item['tg_comment'], replacement_dictionary)
    description = my_preprocess(item['tg_description'], replacement_dictionary)
    try:
        return zapi.trigger.create(description=description, priority=item['tg_priority'],
                                   expression=expression,
                                   event_name=eventname,
                                   comments=comment)
    except ZabbixAPIException as e3:
        print(e3)
        sys.exit()


def create_item(replacement_dictionary):
    global key, host_id, zapi, dev_name, item
    # type: 2-Zabbix trapper
    # val type:  0-numeric float; 1-character; 2-log; 3-numeric unsigned; 4-text
    # status: 0-enabled item; 1-disabled item.
    item_name = my_preprocess(item['name'], replacement_dictionary)
    try:
        return zapi.item.create(hostid=host_id, name=item_name, key_=key, type=ZBX_ITEM_TYPE_ZBXTRAPPER, delay=0,
                                status=ZBX_ITEM_ENABLED,
                                value_type=item['value_type'])
    except ZabbixAPIException as e2:
        print(e2)
        sys.exit()


def test_and_create_item_and_trigger():
    global key, host_id, dev_name, item, host_name
    replacement_dictionary = [{"in": "#hostname#", "out": host_name}, {"in": "#key#", "out": key},
                              {"in": "#item#", "out": item['name']}, {"in": "#devname#", "out": dev_name},
                              {"in": "#FTDNAME#", "out": dev_name}]
    testitem = zapi.item.get(search={"key_": key}, hostids=host_id, output="extend")
    if len(testitem) != 0: return False
    create_item(replacement_dictionary)
    create_trigger(replacement_dictionary)


def ask_fmc(api_endpoint):
    global fmc_prefix, access_token
    try:
        ask_fmc_response = requests.get(fmc_prefix + api_endpoint,
                                        headers={'X-auth-access-token': access_token, 'accept': 'application/json'},
                                        verify=False)
        if ask_fmc_response.status_code != 200: ask_fmc_response = None
    except:
        ask_fmc_response = None
    return ask_fmc_response


def fmc_refresh_tokens():
    # Firepower Management Center REST API authentication tokens are valid for 30 minutes, and can be refreshed up to three times.
    global fmc_prefix, access_token, refresh_token
    try:
        resp_refresh = requests.post(fmc_prefix + "/api/fmc_platform/v1/auth/refreshtoken",
                                     headers={'X-auth-access-token': access_token,
                                              'X-auth-refresh-token': refresh_token},
                                     verify=False)
        if resp_refresh.status_code != 204:
            print(
                f"Fatal: FMC refresh error. Status Code: {resp_refresh.status_code} in response. headers: {resp_refresh.headers} text: {resp_refresh.text}")
            sys.exit()
        access_token = resp_refresh.headers['X-auth-access-token']
        refresh_token = resp_refresh.headers['X-auth-refresh-token']
        return True
    except:
        return False


def fmc_authenticate(user, passwd):
    global fmc_prefix, access_token, refresh_token
    # authenticate on FMC
    login_path = fmc_prefix + "/api/fmc_platform/v1/auth/generatetoken"
    str1 = '%s:%s' % (user, passwd)
    str2 = str1.encode("ascii")
    b64string = base64.b64encode(str2)
    base64string = b64string.decode().replace('\n', '')
    authstring = ("Basic %s" % base64string)
    headers = {'Authorization': authstring}
    try:
        resp_auth = requests.post(login_path, headers=headers, verify=False)
        # print(resp)
        if resp_auth.status_code != 204:
            print(
                f"Fatal: FMC login error. Status Code: {resp_auth.status_code} in response. headers: {resp_auth.headers} text: {resp_auth.text}")
            sys.exit()
        access_token = resp_auth.headers['X-auth-access-token']
        refresh_token = resp_auth.headers['X-auth-refresh-token']
        return True
    except:
        return False


def fmc_uptime_to_sec(uptime_str):
    uptime_days = 0
    uptime_hours = 0
    uptime_mins = 0
    if "day" in uptime_str:
        uptime1 = uptime_str.split()
        uptime_days = int(uptime1[0])
        if ":" in uptime1[2]:
            # 16 days  5:24
            uptime2 = uptime1[2].split(":")
            uptime_hours = int(uptime2[0])
            uptime_mins = int(uptime2[1])
        else:
            # 16 days  24 min
            uptime_mins = int(uptime1[2])
    else:
        if ":" in uptime_str:
            #  5:24
            uptime2 = uptime_str.split(":")
            uptime_hours = int(uptime2[0])
            uptime_mins = int(uptime2[1])
        else:
            # 24 min
            uptime1 = uptime_str.split(" ")
            uptime_mins = int(uptime1[0])
    uptime_total = (uptime_days * 24 * 60 * 60) + (uptime_hours * 60 * 60) + (uptime_mins * 60)
    return uptime_total


requests.packages.urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
config = configparser.ConfigParser()
config_file = "zbxfmc.ini"
if not (exists(config_file)):
    config['zbx'] = {'ip': "1.2.3.4", 'username': "Admin", 'password': "zabbixpassword",
                     "host": "fmc-host-name", "fmctext": "FMC Server"}
    config['fmc'] = {'ip': "1.2.3.4", 'username': "fmcdedicatedapiuser", 'password': "ciscopassword", "cfgdir": "/tmp/",
                     "refresh_rate": 10}
    with open(config_file, 'w') as configfile:
        config.write(configfile)
    print("please configure ini file")
    exit(0)

config.read(config_file)
zbx_ip = config['zbx']['ip']
zbx_url = "https://" + zbx_ip
zbx_user = config['zbx']['username']
zbx_pass = config['zbx']['password']
host_name = config['zbx']['host']
fmc_url = config['fmc']['ip']
fmc_user = config['fmc']['username']
fmc_pass = config['fmc']['password']
fmc_cfgdir = config['fmc']['cfgdir']
fmc_info_refresh_rate = int(config['fmc']['refresh_rate'])
dev_name = config['zbx']['fmctext']
fmc_prefix = "https://" + fmc_url
# 0-numeric float; 1-character; 2-log; 3-numeric unsigned; 4-text.
# recovery_mode OK event  generation mode. 0 - (default) Expression; 1 - Recovery expression; 2 - None (should be closed manually by hands ).
# manual_close		Allow manual close. 0 - (default) No; 1 - Yes.
# recovery_expression - Reduced trigger recovery expression.
fmc_items = [{'name': "FMC #devname# software version", "key": "fmc.serverVersion", "value_type": ZBX_ITEM_TEXT,
              "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
              "tg_description": "#devname# #hostname# changed software version",
              "tg_comment": "FMC #devname# software version changed on #hostname# {ITEM.VALUE} on {HOST.NAME}",
              "eventname": "FMC #devname# software version changed #hostname#"
              },
             {'name': "FMC #devname# geo version", "key": "fmc.geoVersion", "value_type": ZBX_ITEM_TEXT,
              "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
              "tg_description": "#devname# changed geolocation package version on #hostname#",
              "tg_comment": "FMC #devname# geolocation version changed on #hostname# {ITEM.VALUE} on {HOST.NAME}",
              "eventname": "FMC #devname# geolocation version changed #hostname# {ITEM.VALUE}"
              },
             {'name': "FMC #devname# vdb version", "key": "fmc.vdbVersion", "value_type": ZBX_ITEM_TEXT,
              "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
              "tg_description": "changed vdb package version on #hostname#",
              "tg_comment": "FMC #devname# vdb version changed on #hostname# {ITEM.VALUE} on {HOST.NAME}",
              "eventname": "FMC #devname# vdb version changed #hostname# {ITEM.VALUE}"
              },
             {'name': "FMC #devname# sru version", "key": "fmc.sruVersion", "value_type": ZBX_ITEM_TEXT,
              "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
              "tg_description": "#devname# changed sru package version on #hostname#",
              "tg_comment": "FMC #devname# sru version changed on #hostname# {ITEM.VALUE} on {HOST.NAME}",
              "eventname": "FMC #devname# sru version changed #hostname# {ITEM.VALUE}"
              },
             {'name': "FMC #devname# lsp version", "key": "fmc.lspVersion", "value_type": ZBX_ITEM_TEXT,
              "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
              "tg_description": "#devname# changed lsp package version on #hostname#",
              "tg_comment": "FMC #devname# lsp version changed on #hostname# {ITEM.VALUE}",
              "eventname": "FMC #devname# lsp version changed #hostname# {ITEM.VALUE}"
              },
             {'name': "FMC #devname# hostname", "key": "fmc.hostname", "value_type": ZBX_ITEM_TEXT,
              "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
              "tg_description": "#devname# hostname changed on #hostname#",
              "tg_comment": "FMC #devname# hostname changed on #hostname# {ITEM.VALUE}",
              "eventname": "FMC hostname changed #hostname# {ITEM.VALUE}"
              },
             {'name': "FMC #devname# uptime on {HOST.NAME}", "key": "fmc.uptime", "value_type": ZBX_ITEM_UNSIGNED,
              "expression": "change(/#hostname#/#key#)<0", "tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
              "tg_description": "FMC #devname# uptime changed backwards on #hostname#",
              "tg_comment": "FMC #devname# uptime #hostname# {ITEM.VALUE}",
              "eventname": "FMC rebooted #hostname#"
              }
             ]

dev_items = [
    {'name': "FTD #devname# sw version", "key": "sw_version", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
     "tg_description": "software version changed on #devname# controlled by #hostname#",
     "tg_comment": "software upgraded or downgraded on #devname# to {ITEM.VALUE}",
     "eventname": "FTD #devname# software version changed to {ITEM.VALUE}"
     },
    {'name': "FTD #devname# deployment status", "key": "deploymentStatus", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
     "tg_description": "deployment status changed on #devname# controlled by #hostname#",
     "tg_comment": "#devname# deployment status is {ITEM.VALUE}",
     "eventname": "FTD #devname# deployment changed to {ITEM.VALUE}"
     },
    {'name': "FTD #devname# name", "key": "name", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0","tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
     "tg_description": "device name changed on #devname# controlled by #hostname#",
     "tg_comment": "device name different on #devname# to {ITEM.VALUE}",
     "eventname": "FTD #devname# software version changed to {ITEM.VALUE}"
     },
    {'name': "FTD #devname# ips mode", "key": "prohibitPacketTransfer", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
     "tg_description": "ips mode changed on #devname# controlled by #hostname#",
     "tg_comment": "ips mode modified on #devname# to {ITEM.VALUE}",
     "eventname": "FTD #devname# ips {ITEM.VALUE}"
     },
    {'name': "FTD #devname# Serial Number", "key": "deviceSerialNumber", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
     "tg_description": "serial number  changed on #devname# controlled by #hostname#",
     "tg_comment": "device replaced #devname# to {ITEM.VALUE}",
     "eventname": "FTD #devname# probable was replaced by another with serial {ITEM.VALUE}"
     },
    {'name': "FTD #devname# snort", "key": "snortVersion", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
     "tg_description": "snort version changed on #FTDNAME# controlled by #hostname#",
     "tg_comment": "snort upgraded or downgraded on #FTDNAME# to {ITEM.VALUE}",
     "eventname": "FTD #devname# snort version changed to {ITEM.VALUE}"
     },
    {'name': "FTD #devname# vdb", "key": "vdbVersion", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0",
     "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
     "tg_description": "vdb version changed on #devname# controlled by #hostname#",
     "tg_comment": "vdb upgraded or downgraded on #devname# to {ITEM.VALUE}",
     "eventname": "FTD #devname# software version changed to {ITEM.VALUE}"
     },
    {'name': "FTD #devname# lsp", "key": "lspVersion", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0",
     "tg_priority": ZBX_TRIGGER_LEVEL_INFO,
     "tg_description": "lsp version changed on #devname# controlled by #hostname#",
     "tg_comment": "lsp upgraded or downgraded on #devname# to {ITEM.VALUE}",
     "eventname": "FTD #devname# lsp version changed to {ITEM.VALUE}"
     },
    {'name': "FTD #devname# health", "key": "healthStatus", "value_type": ZBX_ITEM_TEXT,
     "expression": "not((last(/#hostname#/#key#)=\"recovered\") or (last(/#hostname#/#key#)=\"green\") )",
     "tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
     "tg_description": "health on #devname#",
     "tg_comment": "health status on #devname# controlled by #hostname# is {ITEM.VALUE}",
     "eventname": "FTD #devname# health alert"
     }
]

dev_logic_items = [
    {'name': "FTD #devname# config hash", "key": "cfghash", "value_type": ZBX_ITEM_TEXT,
     "expression": "change(/#hostname#/#key#)<>0", "tg_priority": ZBX_TRIGGER_LEVEL_HIGH,
     "tg_description": "access control policy changed on #devname# controlled by #hostname#",
     "tg_comment": "access control policy  modified on #devname# to {ITEM.VALUE}",
     "eventname": "FTD #devname# access control policy changed"}
]

device_list = []

zapi = ZabbixAPI(zbx_url)
zapi.session.verify = False
zapi.login(zbx_user, zbx_pass)
host_id = 0
hosts = zapi.host.get(filter={"host": host_name}, selectInterfaces=["interfaceid"])
if len(hosts) == 0:
    try:
        host = zapi.host.create(host=host_name, name=dev_name,
                                description=dev_name + " managed by zbxfmc.py github.com/avirus/zbxfmc",
                                groups=[{"groupid": 2}], inventory_mode=0)
        # ID=2 - Usually 'Linux Servers'
        host_id = host["hostids"][0]
    except ZabbixAPIException as e:
        print(e)
        sys.exit()
else:
    # print(hosts)
    host_id = hosts[0]["hostid"]
print(host_id)

for item in fmc_items:
    key = item['key']
    test_and_create_item_and_trigger()
while not (fmc_authenticate(fmc_user, fmc_pass)):
    print("trying to authenticate on FMC...")
    sleep(10)
resp = ask_fmc("/api/fmc_platform/v1/info/domain?offset=0&limit=25&expanded=true")
res = json.loads(resp.text)
domain_uuid = res['items'][0]['uuid']  # this script supports only one domain.
resp = ask_fmc(f"/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords?expanded=true&offset=0&limit=9999")
res = json.loads(resp.text)
for device in res['items']:
    dev_name = device['name']
    print(dev_name)
    dev_id = device['id']
    device_list.append(dev_id)
    for item in dev_items:
        key = dev_id + "." + item['key']
        test_and_create_item_and_trigger()
    for item in dev_logic_items:
        key = dev_id + "." + item['key']
        test_and_create_item_and_trigger()
sender = Sender(zbx_ip)
sleep_time = 60 * fmc_info_refresh_rate
# FMC allow 30 min for token and 3 reauth
reauth_counter = 0
fmc_request_counter = 0
counter_till_reauth = ((30 * 60) / sleep_time) * 3 / 4
# main cycle - get values from FMC and upload to ZBX
while True:
    print("cycle begin")
    resp = ask_fmc("/api/fmc_platform/v1/info/serverversion?expanded=true")
    if resp is None:
        print("API request error. Wait and try to reconnect")
        sleep(sleep_time * 1)
        if fmc_authenticate(fmc_user, fmc_pass):
            reauth_counter = 0
            fmc_request_counter = 0
        continue
    res = json.loads(resp.text)
    uptime = fmc_uptime_to_sec(res['items'][0]['uptime'])
    try:
        resp = sender.send_value(host_name, "fmc.uptime", uptime)
        resp = sender.send_value(host_name, "fmc.serverVersion", res['items'][0]['serverVersion'])
        resp = sender.send_value(host_name, "fmc.geoVersion", res['items'][0]['geoVersion'])
        resp = sender.send_value(host_name, "fmc.vdbVersion", res['items'][0]['vdbVersion'])
        resp = sender.send_value(host_name, "fmc.sruVersion", res['items'][0]['sruVersion'])
        resp = sender.send_value(host_name, "fmc.lspVersion", res['items'][0]['lspVersion'])
        resp = sender.send_value(host_name, "fmc.hostname", res['items'][0]['hostname'])
    except:
        print("error communicating with zabbix")
        sleep(sleep_time)
        continue
    resp = ask_fmc(f"/api/fmc_config/v1/domain/{domain_uuid}/devices/devicerecords?expanded=true&offset=0&limit=9999")
    if resp is None: continue
    res = json.loads(resp.text)
    for device in res['items']:
        dev_name = device['name']
        print(dev_name)
        dev_id = device['id']
        for item in dev_items:
            key = item['key']
            value = False
            if key in device:
                value = device[key]
            else:
                if key in device['metadata']:
                    value = device['metadata'][key]
                else:
                    pass
                    # print("no value: " + key)
            key = dev_id + "." + item['key']
            if value:
                resp = sender.send_value(host_name, key, value)
        access_policy_id = device['accessPolicy']['id']
        res_rules1 = ask_fmc(
            f"/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{access_policy_id}/accessrules?expanded=true&offset=0&limit=9999")
        if res_rules1 is None: continue
        fd = open(fmc_cfgdir + dev_id + ".cfg", 'w')
        access_policy_rules = json.loads(res_rules1.text)
        cfgtext = json.dumps(access_policy_rules, indent=4, sort_keys=True)
        fd.write(cfgtext)
        fd.close()
        resp = sender.send_value(host_name, f"{dev_id}.cfghash", hashlib.sha1(cfgtext.encode("utf-8")).hexdigest())
    print(f"cycle {fmc_request_counter} done. reauth {reauth_counter}  max {counter_till_reauth}")
    # authentication workarounds
    # looks like there are no limits for refreshing tokens
    fmc_request_counter += 1
    if counter_till_reauth < fmc_request_counter:
        if 3 == reauth_counter:
            fmc_authenticate(fmc_user, fmc_pass)
            reauth_counter = 0
        else:
            fmc_refresh_tokens()
            reauth_counter += 1
        fmc_request_counter = 0
    sleep(sleep_time)
