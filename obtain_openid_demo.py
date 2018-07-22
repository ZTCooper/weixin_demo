#coding=UTF-8
'''
微信获取openid
参数：appid, secret, 前端生成js_code, grant_type=authorization_code
'''
import requests

from config import APPID, SECRET

# 获取openid
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
