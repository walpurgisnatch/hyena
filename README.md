# hyena
Privilege escalation tool 

## Usage

```
usage: hyena.py [-h] [-u TARGET] [-f TARGETS] [-t TIMEOUT] [-r REQTYPE] [-c COOKIE]
                [-d DATA]

optional arguments:
  -h, --help                    show this help message and exit
  -u TARGET                     Target url
  -f TARGETS                    File with target urls
  -t TIMEOUT                    Timeout
  -r REQTYPE                    Request type
  -c COOKIE,  --cookie COOKIE   Cookie
  -d DATA,    --data DATA       Request body
```

### Simple
In simplest case hyena will try to bypass 403 error and get access to directory or file.  
Single target is set with `-u` flag.
```
$ python3 hyena.py -u https://example.com/admin
```

Run through file with multiple URLs using `-f` flag.
```
$ python3 hyena.py -f uris.list
```

### More stuff
- To specify request type, use `-r` flag. GET by default.
- To set data for POST, PUT and PATCH requests use `-d` flag
- For cookie usage, there's `-c` flag
- Also there's `-t` for timeout. 10 sec by default
```
$ python3 hyena.py -u https://example.com/admin -c "session=commonuser" -r post -d "delete=carlos" -t 5
```

## License

Licensed under the MIT License.
