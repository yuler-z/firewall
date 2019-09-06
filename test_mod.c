#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/socket.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <arpa/inet.h>

#include <net/net_namespace.h>

#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/list.h>

#define unsigned int uint;

struct keyword {
	unsigned long int src_ip;
	unsigned long int dst_ip;
	uint protocol;
    uint src_port;
	uint dst_port;
};

struct rule {
	unsigned long int src_ip;  
    unsigned long int src_mask;
	unsigned long int dest_ip; 
	unsigned long int maskoff;
	uint src_port; 
	uint dest_port;
	uint protocol; 
    int action;
	int log; 
};

struct state_node {
    struct keyword kw;
    unsigned long int key;
    int action; // 0 = not find, 1 = allow, 2 = deny
    struct hlist_node next;
};

struct rule_node {
  struct rule;
  struct list_node next;  
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("U201614817");

static struct nf_hook_ops nfho;
DEFINE_HASHTABLE(state_table, 10); //状态哈希表
LIST_HEAD(rule_table) // 规则链表

int add_hashtable(){

}



unsigned int hook_input_func(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
    // 先提取keywords
    struct keyword kw; = extract_keyword(kw, skb);
    int state_action, rule_action;
    
    kw = extract_keyword(kw, skb);
    state_action = check_state_table(kw);
    rule_action = cheack_rule_table(kw);
    if(state_action == 1){
        return NF_ACCEPT;
    }else if(state_action == 2){
        return NF_DROP;
    }
    
    check_rule_table(kw);
	return NF_DROP;
}


int extract_keyword(struct keyword &kw, const struct sk_buff *skb){
    /**
     * 0 extract error
     * 1 ok 
     */

    // The Network Layer Header
    struct iphdr *ip_header;
    // The Transport Layer Header
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    if(!skb) return 0; 

    // ip
    ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header) return 0;

    kw.src_ip = (unsigned long int)(ntohl(ip_header->saddr));
	kw.dst_ip = (unsigned long int)(ntohl(ip_header->daddr));
    kw.protocol = ip_header->protocol;

    switch(ip_header->protocol){
        // ICMP
        case 0x01:
            kw.src_port = (uint)0;
		    kw.dst_port = (uint)0; 
            break;
        // TCP
        case 0x06:
		    tcp_header = tcp_hdr(skb);
		    kw.src_port = ntohs(tcp_header->source);
		    kw.dst_port = ntohs(tcp_header->dest);
            break;
        
        case 0x11:
            udp_header = udp_hdr(skb);
            kw.src_port = ntohs(udp_header->source);
            kw.dst_port = ntohs(udp_header->dest);
            break;
        default:
            return 0;
    }
    return 1;
}

unsigned long int hash_function(const struct keyword kw){
    unsigned long int hash = 0;
    return hash;
}

int check_state_table(struct keyword kw){
    unsigned long int hash = hash_function(kw);
    struct state_node* current;
    hash_for_each_possible(state_table, current, hash, next) {
        if(current->hash == hash) {
            if(compare_keywords(current->kw, kw)){
                return current->action;
            }
        }
    }
    return 0; //not find in state table
}

int check_rule_table(const struct keyword kw){
    struct list_node cur;
    for
}

static int init_driver(void)
{
	printk("test module loaded.\n");

	// hook
	nfho.hook = hook_input_func;
	//	nfho.owner = NULL;
	nfho.dev = dev_get_by_name(&init_net, "ens33");
	nfho.pf = PF_INET;
	nfho.hooknum = NF_INET_LOCAL_OUT;
	nfho.priority = NF_IP_PRI_FIRST; //new version, maybe changed to NF_INET_PRI_FIRST
	nf_register_net_hook(&init_net, &nfho);
	return 0;
}

static void exit_driver(void)
{
	printk("test module exit ...\n");
	nf_unregister_net_hook(&init_net, &nfho); //取消钩子注册
}



module_init(init_driver);
module_exit(exit_driver);
