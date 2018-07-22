#coding=UTF-8
'''
微信提现（企业付款）
'''
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
    '''
    登录微信商户平台(pay.weixin.qq.com)-->账户设置-->API安全-->证书下载
    下载apiclient_cert.p12
    python无法使用双向证书，使用openssl导出：
        openssl pkcs12 -clcerts -nokeys -in apiclient_cert.p12 -out apiclient_cert.pem
        openssl pkcs12 -nocerts -in apiclient_cert.p12 -out apiclient_key.pem
    导出apiclient_key.pem时需输入PEM phrase, 此后每次发起请求均要输入，可使用openssl解除：
        openssl rsa -in apiclient_key.pem -out apiclient_key.pem.unsecure
    '''
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
