# nfcollct

Collect NetFlow, decode it, serialize to json, and emit it.

## Usage
```
go run nfcollect.go -m fluentd -i 0.0.0.0:2056 -o 127.0.0.1:5160 -b 8000000
```

`-m` means output mode and `stdout`, `udp` and `fluentd` are supported.
