Usage
------

```sh
# client 1
quicproxy -qh server:3389 -id 1 localhost:5001,2,localhost:5900

# client 2
quicproxy -qh server:3389 -id 2 

# server
quicproxy -ql :3389 -id 3
```

forward client 1 tcp localhost:5001 to client 2 localhost:5900
