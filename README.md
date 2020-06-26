## What is st-proxy?  
st-proxy is a smart local transport proxy which support to config multi socks5/direct stream tunnel chain. every stream tunnel support limit to proxy a specific area IP, so as you config proper, it can smart choose the best stream tunnel you want.  

### Dependencies
- [CMake](https://cmake.org/) >= 3.7.2
- [Boost](http://www.boost.org/) >= 1.66.0 (system,filesystem,thread)
- [OpenSSL](https://www.openssl.org/) >= 1.1.0

### How to install?  
1. download the source code
2. execute ```install.sh```
3. the st-proxy will install to /usr/local/bin, the default configs will install to /usr/local/etc/st/dns

### How to run?  
#### 1. Run Direct  
*  `st-proxy`search config in /etc/st/dns or /usr/local/etc/st/dns
*  `st-proxy  -c /xxx/xxx`  specific the config folder
#### 2. Run As Service(Recommend)
*  `sudo st-proxy -d start`  
*  `sudo st-proxy -d stop`  

### How to config?  
```
{
  "ip": "127.0.0.1", #the local ip
  "port": "40000",   #the local port
  "tunnels": [       #the stream tunnel chain
    {
      "type": "DIRECT", #the stream tunnel type DIRECT/SOCKS
      "area": "CN",     #the stream tunnel area
      "only_area_ip": true #limit the stream tunnel only to proxy the area ip
    },
    {
      "type": "SOCKS",
      "ip": "127.0.0.1",
      "port": 1080,
      "area": "!CN",
      "only_area_ip": true,
      "real_server_host": "os2-2.sstr-api.xyz" #if socks service is in local, need config the real stream server
    }
  ]
}
```

     

