weixin_demo
=======

文件说明
-----

* [config.py](https://github.com/ZTCooper/weixin_demo/blob/master/config.py)   
```python
# 配置必须参数 

APPID = ""      # 小程序ID
SECRET = ""
MCHID = ""      # 商户号
KEY = ""
NOTIFY_URL = ""     # 统一下单后微信回调地址，api demo见notify_view_demo.py
# 证书路径
'''
发起企业付款时需携带的证书
登录微信商户平台(pay.weixin.qq.com)-->账户设置-->API安全-->证书下载
下载apiclient_cert.p12
python无法使用双向证书，使用openssl导出：
    openssl pkcs12 -clcerts -nokeys -in apiclient_cert.p12 -out apiclient_cert.pem
    openssl pkcs12 -nocerts -in apiclient_cert.p12 -out apiclient_key.pem
导出apiclient_key.pem时需输入PEM phrase, 此后每次发起请求均要输入，可使用openssl解除：
    openssl rsa -in apiclient_key.pem -out apiclient_key.pem.unsecure
'''
WX_CERT_PATH = "path/to/apiclient_cert.pem"
WX_KEY_PATH = "path/to/apiclient_key.pem.unsecure"
```


* [obtain_openid_demo.py](https://github.com/ZTCooper/weixin_demo/blob/master/obtain_openid_demo.py)  
```python
# 获取openid, 支付提现均需要

import requests

from config import APPID, SECRET


class OpenidUtils(object):

    def __init__(self, jscode):
        self.url = "https://api.weixin.qq.com/sns/jscode2session"
        self.appid = APPID
        self.secret = SECRET
        self.jscode = jscode    # 前端传回的动态jscode

    def get_openid(self):
        # url一定要拼接，不可用传参方式
        url = self.url + "?appid=" + self.appid + "&secret=" + self.secret + "&js_code=" + self.jscode + "&grant_type=authorization_code"
        r = requests.get(url)
        print(r.json())
        openid = r.json()['openid']

        return openid
```

* [pay_demo.py](https://github.com/ZTCooper/weixin_demo/blob/master/pay_demo.py)  
支付，即统一下单（官方文档此处不够清晰，可参考注释  
```python
# 统一下单

import requests
import hashlib
import xmltodict
import time
import random
import string

from config import APPID, MCHID, KEY, NOTIFY_URL


# 生成nonce_str
def generate_randomStr():
    return ''.join(random.sample(string.ascii_letters + string.digits, 32))

# 生成签名
def generate_sign(param):
    stringA = ''

    ks = sorted(param.keys())
    # 参数排序
    for k in ks:
        stringA += (k + '=' + param[k] + '&')
    # 拼接商户KEY
    stringSignTemp = stringA + "key=" + KEY

    # md5加密
    hash_md5 = hashlib.md5(stringSignTemp.encode('utf8'))
    sign = hash_md5.hexdigest().upper()

    return sign

# 发送xml请求
def send_xml_request(url, param):
    # dict 2 xml
    param = {'root': param}
    xml = xmltodict.unparse(param)

    response = requests.post(url, data=xml.encode('utf-8'), headers={'Content-Type': 'text/xml'})
    # xml 2 dict
    msg = response.text
    xmlmsg = xmltodict.parse(msg)

    return xmlmsg

# 统一下单
def generate_bill(out_trade_no, fee, openid):
    url = "https://api.mch.weixin.qq.com/pay/unifiedorder"
    nonce_str = generate_randomStr()
    # 1. 参数
    param = {
        "appid": APPID,
        "mch_id": MCHID,    # 商户号
        "nonce_str": nonce_str,     # 随机字符串
        "body": 'TEST_pay',     # 支付说明
        "out_trade_no": out_trade_no,   # 自己生成的订单号
        "total_fee": fee,
        "spbill_create_ip": '127.0.0.1',    # 发起统一下单的ip
        "notify_url": NOTIFY_URL,
        "trade_type": 'JSAPI',      # 小程序写JSAPI
        "openid": openid,
    }
    # 2. 统一下单签名
    sign = generate_sign(param)
    param["sign"] = sign  # 加入签名
    # 3. 调用接口
    xmlmsg = send_xml_request(url, param)
    # 4. 获取prepay_id
    if xmlmsg['xml']['return_code'] == 'SUCCESS':
        if xmlmsg['xml']['result_code'] == 'SUCCESS':
            prepay_id = xmlmsg['xml']['prepay_id']
            # 时间戳
            timeStamp = str(int(time.time()))
            # 5. 五个参数
            data = {
                "appId": APPID,
                "nonceStr": nonce_str,
                "package": "prepay_id=" + prepay_id,
                "signType": 'MD5',
                "timeStamp": timeStamp,
            }
            # 6. paySign签名
            paySign = generate_sign(data)
            data["paySign"] = paySign  # 加入签名
            # 7. 传给前端的签名后的参数
            return data
```

* [notify_view_demo.py](https://github.com/ZTCooper/weixin_demo/blob/master/notify_view_demo.py)  
支付回调接口方法  
```python
# 统一下单回调处理

import xmltodict

from django.http import HttpResponse

def payback(request):
    msg = request.body.decode('utf-8')
    xmlmsg = xmltodict.parse(msg)

    return_code = xmlmsg['xml']['return_code']

    if return_code == 'FAIL':
        # 官方发出错误
        return HttpResponse("""<xml><return_code><![CDATA[FAIL]]></return_code>
                            <return_msg><![CDATA[Signature_Error]]></return_msg></xml>""",
                            content_type='text/xml', status=200)
    elif return_code == 'SUCCESS':
        # 拿到这次支付的订单号
        out_trade_no = xmlmsg['xml']['out_trade_no']

        # 根据需要处理业务逻辑

        return HttpResponse("""<xml><return_code><![CDATA[SUCCESS]]></return_code>
                            <return_msg><![CDATA[OK]]></return_msg></xml>""",
                            content_type='text/xml', status=200)
```

* [withdraw_demo.py](https://github.com/ZTCooper/weixin_demo/blob/master/withdraw_demo.py)  
提现，即企业付款（无回调，需使用双向证书  
登录微信商户平台(pay.weixin.qq.com)-->账户设置-->API安全-->证书下载  
下载apiclient_cert.p12  
python无法使用双向证书，使用openssl导出：  
`openssl pkcs12 -clcerts -nokeys -in apiclient_cert.p12 -out apiclient_cert.pem`  
`openssl pkcs12 -nocerts -in apiclient_cert.p12 -out apiclient_key.pem`  
	导出apiclient_key.pem时需输入PEM phrase, 此后每次发起请求均要输入，可使用openssl解除：
`openssl rsa -in apiclient_key.pem -out apiclient_key.pem.unsecure`  

```python
# 提现（企业付款

import xmltodict
import requests
import hashlib
import random
import string

from config import KEY, APPID, MCHID, WX_CERT_PATH, WX_KEY_PATH

# 生成nonce_str
def generate_randomStr():
    return ''.join(random.sample(string.ascii_letters + string.digits, 32))

# 生成签名
def generate_sign(param):
    stringA = ''

    ks = sorted(param.keys())
    # 参数排序
    for k in ks:
        stringA += (k + '=' + param[k] + '&')
    # 拼接商户KEY
    stringSignTemp = stringA + "key=" + KEY

    # md5加密
    hash_md5 = hashlib.md5(stringSignTemp.encode('utf8'))
    sign = hash_md5.hexdigest().upper()

    return sign

# 发送携带证书的xml请求
def send_cert_request(url, param):
    # dict 2 xml
    param = {'root': param}
    xml = xmltodict.unparse(param)
    
    response = requests.post(url, data=xml.encode('utf-8'),
                             headers={'Content-Type': 'text/xml'},
                             cert=(WX_CERT_PATH, WX_KEY_PATH))
    # xml 2 dict
    msg = response.text
    xmlmsg = xmltodict.parse(msg)

    return xmlmsg


def withdraw(self, openid, withdraw_value, withdraw_trade_no):
    url = "https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers"

    param = {
        "mch_appid": APPID,
        "mchid": MCHID,     # 商户号
        "nonce_str": generate_randomStr(),      # 随机字符串
        "partner_trade_no": withdraw_trade_no,
        "openid": openid,       # 获取openid见obtain_openid_demo.py
        "check_name": "NO_CHECK",
        "amount": withdraw_value,       # 提现金额，单位为分
        "desc": "TEST_withdraw",        # 提现说明
        "spbill_create_ip": "127.0.0.1",    # 发起提现的ip
    }

    sign = generate_sign(param)
    param["sign"] = sign
    # 携带证书
    xmlmsg = send_cert_request(url, param)

    print(xmlmsg)

    if xmlmsg['xml']['return_code'] == 'SUCCESS' and xmlmsg['xml']['result_code'] == 'SUCCESS':
        return xmlmsg
```

