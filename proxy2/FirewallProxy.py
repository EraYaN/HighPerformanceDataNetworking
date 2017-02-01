# -*- coding: utf-8 -*-
from proxy2 import *
from collections import deque

class FirewallProxyRequestHandler(ProxyRequestHandler):
    replaced_urls = deque(maxlen=1024)

    def request_handler(self, req, req_body):        
        req.headers['User-Agent'] = 'Totally not the Govt v1.0'
        if req.path in self.replaced_urls:
            req.path = req.path.replace('http://', 'https://')

    def response_handler(self, req, req_body, res, res_body):
        def httpsreplacefunc(m):
            http_url = "http://" + m.group(1)
            self.replaced_urls.append(http_url)
            return http_url

        def govtreplacefunc(m):
            tagstart = m.group(1)
            content = m.group(2)
            tagend = m.group(3)
            # Don't let those suckers know about that baby eating habit we have. WE'll give them some "alternative fact".
            if "eat" in content.lower() and "babies" in content.lower():
                print("Those pesky citizens tried to look at forbidden content! I'm \"fixing\"  it. Original Content below.")
                print(content)
                content = 'Our government loves you, they are the best!'
                
            tags = tagstart + content + tagend
            
            return tags

        

        re_https_url = r"https://([-_.!~*'()a-zA-Z0-9;/?:@&=+$,%]+)"

        if 'Location' in res.headers:
            res.headers['Location'] = re.sub(re_https_url, httpsreplacefunc, res.headers['Location'])
        httpsless_body = re.sub(re_https_url, httpsreplacefunc, res_body)

        re_govt = r"(<.*?>)(.*?)(</.*?>)"

        good_body = re.sub(re_govt, govtreplacefunc, httpsless_body)

        return good_body



if __name__ == '__main__':
    print("Started Firewall proxy.")
    test(HandlerClass=FirewallProxyRequestHandler)
