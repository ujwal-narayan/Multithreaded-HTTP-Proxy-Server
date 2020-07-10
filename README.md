# Multi Threaded HTTP Proxy Server

## Ujwal Narayan, 20171170

## Deepti Mahesh, 20171212

A HTTP multithreading proxy server implemented via python socket programming with caching, blacklisting and authentication. 



## Features

- Receives the request from client and pass it to the server after necessary parsing
- Threaded proxy server thus able to handle many requests at the same time
- If one file is requested above the threshold number of times in certain time period, then proxy server caches that request. The threshold number and time limit can be set by changing global constants in ![proxy.py](/proxy.py) file
- To maintain integrity, cached files are accessed by securing mutex locks
- Cache has limited size, so if the cache is full and proxy wants to store another response then it removes the least recently asked cached response. Cache limit can be set by setting up the constant in ![proxy.py](/proxy.py) file
- Certain servers (their ports) are blacklisted so that normal users can't access it. Blacklisted servers are stored in CIDR format in ![blacklist.txt](/blacklist.txt) file.
- Special users can access blacklisted servers. Usernames and passwords of priviledged users are stored in ![username_password.txt](/username_password.txt) file.

## **How to run**

### Proxy

- Specify proxy port while running proxy  
`python proxy.py 20100`  
It will run proxy on port 20100

### Server

- `python server.py 20102` to run server on port 20102  

### Client

- curl request can be sent as client request and get the response.  
`curl --request GET --proxy 127.0.0.1:20000 --local-port 20001-20010 127.0.0.1:19999/filename`  
this request will ask 1.data file from server 127.0.0.1/19999 by GET request via proxy 127.0.0.1/20000 using one of the ports in range 20001-20010 on localhost.
- valid username and password should be provided to access blacklisted servers.  
`curl --request GET -u username:password --proxy 127.0.0.1:20000 --local-port 20001-20010 127.0.0.1:19998/filename`  


