#ifndef _MY_MODULE_H
#define _MY_MODULE_H

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/socket.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/net_namespace.h>

#define unsigned int uint;
#define unsinged long int ulong;

struct keywords{
	ulong src_ip;
	ulong dst_ip;
	uint protocol;
    uint src_port;
	uint dst_port;
};

struct rule
{
	ulong src_ip;  //源IP
	ulong dest_ip;  //目的IP
	ulong maskoff;  //目的地址IP
	 int src_port;  //源端口
	int dest_port;  //目的端口
	int protocol;  //协议
	int log;  //是否记录日志
};
#endif

