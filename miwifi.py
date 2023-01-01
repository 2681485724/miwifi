import requests
import re
from Crypto.Hash import SHA
import random
import time
import json
import sys
import re
import os

#CMCC-NHDz    NHDznFk3
#CU_3CTa      hae6xyky
#CMCC-JcGG    fk545g7j
wifiinfodict = {'CMCC-NHDz': 'NHDznFk3', 'CU_3CTa': 'hae6xyky', 'CMCC-JcGG': 'fk545g7j'}

host = '192.168.1.16'

def get_token(host):
    url1 = 'http://' + host + '/cgi-bin/luci/api/xqsystem/login'#登陆请求地址

    Headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh,zh-CN;q=0.9',
        'Connection': 'keep-alive',
        'Content-Length': '126',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': host,
        'Origin': 'http://' + host,
        'Referer': 'http://' + host + '/cgi-bin/luci/web',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
        'dnt': '1',
        'sec-gpc': '1'
    }
    #     'Cookie': '__guid=248908231.4210423834934977500.1671586157030.0227; psp=admin|||2|||0; monitor_count=1',


    import time
    now_timestamp = str(time.time()).split('.',1)
    now_timestamp = now_timestamp[0]

    response2 = requests.get('http://' + host + '/cgi-bin/luci/web')
    pattern_key =re.compile('key: \'(.*?)\'')
    xmkey=re.findall(pattern_key,response2.text)[0]

    mac = re.findall(r'deviceId = \'(.*)\';', response2.text)[0]
    nonce = "0_" + mac + "_" + str(int(time.time())) + "_" + str(random.randint(1000, 10000))

    import hashlib
    xmpwd = '2681485724'
    sha1 = hashlib.sha1()
    sha1.update(str(xmpwd + xmkey).encode(encoding='UTF-8'))
    sha1 = sha1.hexdigest()
    xmsha2 = hashlib.sha1()
    xmsha2.update(str(nonce+sha1).encode(encoding='UTF-8'))
    sha1 = xmsha2.hexdigest()

    data1 = {
        "logtype": 2,
        "nonce": nonce,
        "password": sha1,
        "username": "admin"
    }
    response1 = requests.post(url1, data1, timeout=5, headers=Headers)

    result_json = json.loads(response1.content)

    return result_json['token']

def get_info(host, token, mode):
    base_url = 'http://' + host + '/cgi-bin/luci/;stok=' + token + '/api/misystem/status'
    ap_ssid = 'http://' + host + '/cgi-bin/luci/;stok=' + token + '/api/xqnetwork/wifiap_signal'
    wifi_info = 'http://' + host + '/cgi-bin/luci/;stok=' + token + '/api/xqnetwork/wifi_detail_all'
    wifi_list = 'http://' + host + '/cgi-bin/luci/;stok=' + token + '/api/xqnetwork/wifi_list'
    move_ap = 'http://' + host + '/cgi-bin/luci/;stok=' + token + '/api/xqnetwork/set_wifi_ap'

    response2 = requests.get(base_url)
    result_json = json.loads(response2.content)
    print('当前在线设备总数：' + str(len(result_json['dev'])))
    if mode == 1:
        #print(result_json['count'])
        print('系统状态：MAC地址：{0}，系统版本：{1}，SN码：{2}'.format(result_json['hardware']['mac'], result_json['hardware']['version'], result_json['hardware']['sn']))
        print('CPU状态：当前CPU负载{2}，CPU核心数{0}，核心频率：{1}'.format(result_json['cpu']['core'], result_json['cpu']['hz'], result_json['cpu']['load'] * 100))
        print('内存状态：当前内存占用{0}，内存容量：{1}，内存类型：{2}，内存频率：{3}'.format(result_json['mem']['usage'], result_json['mem']['total'], result_json['mem']['type'], result_json['mem']['hz']))
        #print(result_json['wan'])
    if mode == 2:
        print('系统状态：CPU负载{0}，内存占用{1}%'.format(result_json['cpu']['core'], result_json['mem']['usage'] * 100))
    
    response3 = requests.get(ap_ssid)
    result_json = json.loads(response3.content)
    print('当前中继状态：中继WIFI：{0}，中继信号：{1}'.format(result_json['ssid'], result_json['signal']))
    
    response4 = requests.get(wifi_info)
    result_json = json.loads(response4.content)
    if result_json['info'][0]['encryption'] == 'psk2':
        psk = '强加密(WPA2个人版)'
    if result_json['info'][0]['encryption'] == 'mixed-psk':
        psk = '混合加密(WPA/WPA2个人版)'
    if result_json['info'][0]['encryption'] == 'none':
        psk = '无加密(允许所有人连接)'
    if mode == 1:
        print('当前WIFI信息：设备：{0}，接口名：{2}，WIFI名称：{3}，加密方式：{1}，WIFI密码：{4}，发射功率：{5}，信号：{6}，WIFI名称：{3}，'.format(result_json['info'][0]['device'], psk, result_json['info'][0]['ifname'], result_json['info'][0]['ssid'], result_json['info'][0]['password'], result_json['info'][0]['txpwr'], result_json['info'][0]['signal']))
    if mode == 2:
        print('当前WIFI信息：WIFI名称：{0}，加密方式：{1}，WIFI密码：{2}，信号：{3}'.format(result_json['info'][0]['ssid'], psk, result_json['info'][0]['password'], result_json['info'][0]['signal']))
    
    response5 = requests.get(wifi_list)
    result_json = json.loads(response5.content)
    print('附近WIFI：扫描到{0}个WIFI'.format(len(result_json['list'])))
    for wifi in result_json['list']:
        if wifi['signal'] >= 10 and wifi['signal'] < 100:
            if mode == 1:
                print('WIFI名称：{0}，信号：{1}，加密方式：{2} ({3})，信道：{4}，bssid：{5}'.format(wifi['ssid'], wifi['signal'], wifi['encryption'], wifi['enctype'], wifi['channel'], wifi['bssid']))
            if mode == 2:
                print('WIFI名称：{0}，信号：{1}，加密方式：{2} ({3})，信道：{4}'.format(wifi['ssid'], wifi['signal'], wifi['encryption'], wifi['enctype'], wifi['channel']))

def set_wifi_ap(host, ssid, password, encryption, enctype, channel):
    move_ap = 'http://' + host + '/cgi-bin/luci/;stok=' + get_token(host) + '/api/xqnetwork/set_wifi_ap'
    
    data = {
        'ssid': ssid,
        'encryption': encryption,
        'enctype': enctype,
        'password': password,
        'channel': channel,
        'band': '2g',
        'nssid': '',
        'nencryption': 'mixed-psk',
        'npassword': '' 
    }
    
    response1 = requests.post(move_ap, data=data)
    result_json = json.loads(response1.content)
    if result_json['code'] == 0:
        print('当前WIFI名称：{0}，当前路由器IP：{1}'.format(result_json['ssid'], result_json['ip']))
        conf = open(r'C:\Users\Administrator\Desktop\重要文件夹\编程\VS Code\Python\小米路由器\miwifi.conf', mode='r')
        conf.write('host=')
        conf.write(result_json['ip'])
        conf.write('\n')
        conf.close()
    if result_json['code'] != 0:
        print(result_json['msg'])
    

def autosetwifiap():
    wifi_list = 'http://' + host + '/cgi-bin/luci/;stok=' + token + '/api/xqnetwork/wifi_list'

    response5 = requests.get(wifi_list)
    result_json = json.loads(response5.content)
    print('附近WIFI：扫描到{0}个WIFI'.format(len(result_json['list'])))
    for wifi in result_json['list']:
        if wifi['signal'] >= 10 and wifi['signal'] < 90:
            print('WIFI名称：{0}，信号：{1}，加密方式：{2} ({3})，信道：{4}，bssid：{5}'.format(wifi['ssid'], wifi['signal'], wifi['encryption'], wifi['enctype'], wifi['channel'], wifi['bssid']))
    print('正在连接WIFI：{0}'.format(wifi['ssid']))
    try:
        set_wifi_ap(host, wifi['ssid'], wifiinfodict[wifi['ssid']], wifi['encryption'], wifi['enctype'], wifi['channel'])
    except KeyError:
        print('当前要连接的WIFI无预先存入密码')

def reboot(host, token):
    reboot_url = 'http://' + host + '/cgi-bin/luci/;stok=' + token + '/api/xqnetwork/reboot?client=web'

    response = requests.get(reboot_url)
    print(response.text)


'''
from subprocess import PIPE, Popen
proc = Popen(
    'ping 8.8.8.89',  # cmd特定的查询空间的命令
    stdin=None,  # 标准输入 键盘
    stdout=PIPE,  # -1 标准输出（演示器、终端) 保存到管道中以便进行操作
    stderr=PIPE,  # 标准错误，保存到管道
    shell=True)
#print(proc.communicate()) # 标准输出的字符串+标准错误的字符串
outinfo, errinfo = proc.communicate()
print(outinfo.decode('gbk'))  # 外部程序(windows系统)决定编码格式
print(errinfo.decode('gbk'))
'''

conf = open(r'C:\Users\Administrator\Desktop\重要文件夹\编程\VS Code\Python\小米路由器\miwifi.conf', mode='r')
host = str(conf.readline())[5:]
host = host.rstrip('\n')
print(host)
conf.close()

token = get_token(host)
get_info(host, token, 1)
os.system('cls')
try:
    while True:
        for a in range(1,300):
            get_info(host, token, 2)
            time.sleep(2)
            os.system('cls')
        ping = os.popen('ping sogou.com')
        if '请求找不到主机'in ping.read():
            reboot()
            time.sleep(180)
            ping = os.popen('ping sogou.com')
            if '请求找不到主机'in ping.read():
                autosetwifiap()
                time.sleep(180)

except KeyboardInterrupt:
    print('已手动退出')
except (ConnectionError, TimeoutError, MaxRetryError):
    print('网络错误')



