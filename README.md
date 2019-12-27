# firewall

A simple firewall implementation.

## Usage  

Set initial rules and default action before building the project in **user.c**.

Example  

```
/***
* format:
*      "sip/smaskoff sport dip/dmaskoff dport protocol action log#"
*      "A.B.C.D/x [0->65535] A.B.C.D/x [0->65535] [tcp/udp/icmp] [accept/drop] [yes/no]#"
* example:
*      "192.168.57.0/24 0 192.168.57.0/24 0 icmp accept yes#"
***/
char default_rules[1024] = 
                "192.168.57.0/24 0 192.168.57.0/24 0 icmp drpp yes#" // test in internal network 
                "192.168.57.0/24 0 182.254.53.0/12 0 tcp drop yes#" // wget www.zhihu.com
                "192.168.57.0/24 0 154.8.131.0/24 0 tcp drop yes#" // wget www.douban.com
                "192.168.57.0/24 0 182.61.200.7/24 0 icmp drop yes#" // ping www.baidu.com
                "192.168.57.9/24 0 220.181.38.148/24 0 tcp drop yes#"; //wget www.baidu.com
char *default_action = "accpet";  // "drop" or "accept"
```

1. `./build.sh`  
2. `sudo insmod firewall.ko`  
3. `./user`  
