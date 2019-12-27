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
char data[] = 
                "192.168.57.0/24 0 192.168.57.0/24 0 icmp accept yes#" // test in internal network 
                "192.168.57.0/24 0 182.61.200.7/24 80 tcp accept yes#"
                "222.10.23.0/24 48 222.10.52.0/24 58 tcp drop yes#"
                "202.114.0.245 0 192.168.57.0/24 0 icmp drop yes#" // ping www.hust.edu.cn
                "182.61.200.6/31 0 192.168.57.0/24 0 icmp drop yes#"; //ping www.baidu.com
char *default_action = "drop";  // "drop" or "accept"
```

1. `./build.sh`  
2. `sudo insmod firewall.ko`  
3. `./user`  
