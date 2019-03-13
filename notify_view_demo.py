#coding=UTF-8
'''
统一下单回调处理
'''

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
        # order = Order.objects.get(out_trade_no=out_trade_no)
        if xmlmsg['xml']['nonce_str'] != order.nonce_str:
            # 随机字符串不一致
            return HttpResponse("""<xml><return_code><![CDATA[FAIL]]></return_code>
                                        <return_msg><![CDATA[Signature_Error]]></return_msg></xml>""",
                                content_type='text/xml', status=200)

        # 根据需要处理业务逻辑

        return HttpResponse("""<xml><return_code><![CDATA[SUCCESS]]></return_code>
                            <return_msg><![CDATA[OK]]></return_msg></xml>""",
                            content_type='text/xml', status=200)
