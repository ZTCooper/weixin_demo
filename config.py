# coding=UTF-8

APPID = ""      # 小程序ID
SECRET = ""
MCHID = ""      # 商户号
KEY = ""
NOTIFY_URL = ""     # 统一下单后微信回调地址，api demo见notify_view_demo.py

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

