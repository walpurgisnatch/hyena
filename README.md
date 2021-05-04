# hyena
Privilege escalation tool 

## Simple usage
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
Cookie setted with `-c` flag  
Post data with `-d` flag

```
$ python3 hyena.py -u https://example.com/admin -c "session=commonuser" -d "delete=carlos"
```
