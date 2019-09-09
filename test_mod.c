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

#include <net/net_namespace.h>

#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/list.h>

#define NETLINK_TEST 25 // value > 16

#define uint uint
#define ulong ulong

struct keyword {
	ulong src_ip;
	ulong dst_ip;
	uint protocol;
    uint src_port;
	uint dst_port;
};

struct rule {
	ulong src_ip;  
    ulong src_mask;
	ulong dest_ip; 
	ulong maskoff;
	uint src_port; 
	uint dest_port;
	uint protocol; 
    int action; // deny or allow
	int log; 
};

struct state_node {
    struct keyword kw;
    ulong hash;
    int action; // 0 = not find, 1 = allow, 2 = deny
    struct hlist_node next;
};

struct rule_node {
  struct rule rule;
  struct list_head list;  
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("U201614817");

static struct nf_hook_ops input_hook;
static struct nf_hook_ops output_hook;
static struct sock *nlfd = NULL; //netlink
DEFINE_HASHTABLE(state_table, 10); //状态哈希表
LIST_HEAD(rule_table); // 规则链表

// declaration of function
uint hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int add_hashtable(void);
int extract_keyword(struct keyword *kw, const struct sk_buff *skb);
ulong hash_function(const struct keyword kw);
int check_state_table(struct keyword kw);
int check_rule_table(const struct keyword kw);
int handle_rule_config(char* input);
int send_to_user(char* data);
void rcv_from_user(struct sk_buff *_skb);
int compare_keywords(const struct keyword k1, const struct keyword k2);


int add_hashtable(){}



uint hook_input_func(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
    // 先提取keywords
    struct keyword kw;
    int state_action, rule_action;
    
    extract_keyword(&kw, skb);
    state_action = check_state_table(kw);
    rule_action = check_rule_table(kw);
    if(state_action == 1){
        return NF_ACCEPT;
    }else if(state_action == 2){
        return NF_DROP;
    }
    
    check_rule_table(kw);
	return NF_DROP;
}

uint hook_output_func(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
    // 先提取keywords
    return NF_ACCEPT;
}
int extract_keyword(struct keyword *kw, const struct sk_buff *skb){
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

    kw->src_ip = (ulong)(ntohl(ip_header->saddr));
	kw->dst_ip = (ulong)(ntohl(ip_header->daddr));
    kw->protocol = ip_header->protocol;

    switch(ip_header->protocol){
        // ICMP
        case 0x01:
            kw->src_port = (uint)0;
		    kw->dst_port = (uint)0; 
            break;
        // TCP
        case 0x06:
		    tcp_header = tcp_hdr(skb);
		    kw->src_port = ntohs(tcp_header->source);
		    kw->dst_port = ntohs(tcp_header->dest);
            break;
        
        case 0x11:
            udp_header = udp_hdr(skb);
            kw->src_port = ntohs(udp_header->source);
            kw->dst_port = ntohs(udp_header->dest);
            break;
        default:
            return 0;
    }
    return 1;
}

ulong hash_function(const struct keyword kw){
    ulong hash = 0;
    return hash;
}
int compare_keywords(const struct keyword k1, const struct keyword k2){
    return (k1.src_ip == k2.src_ip) && (k1.dst_ip == k2.dst_ip) && (k1.protocol == k2.protocol) \
            && (k1.src_port == k2.src_port) && (k1.dst_port == k2.src_port);
}
int check_state_table(struct keyword kw){
    ulong hash = hash_function(kw);
    struct state_node *obj;
    hash_for_each_possible(state_table, obj, next, hash) {
        if(obj->hash == hash) {
            if(compare_keywords(obj->kw, kw)){
                return obj->action;
            }
        }
    }
    return 0; //not find in state table
}
int check_rule_table(const struct keyword kw){
    return 0;
}

int handle_rule_config(char* input){
    //int size = strlen(input);
    printk("handle_rule_config");

}

int send_to_user(char* data){
    //1)declare a struct sk_buff*  
    //2)declare a struct nlmsghdr *  
    //3)call alloc_skb() to alloc the struct skb_buff   
    //4)appenxid the struct nlmsg to the tail of the struct skb_buff  
    //5)get the nlmsghdt ponit to the field of the struct skb_buff  
    //6)init the fiels of the nlmsg  
    //7)insrt the meg into the mlmsg  
    //8)call the netlink_unicast() to transmit the struct skb_buff 
  	int size;
	int retval;
    char input[1000];
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    unsigned char *old_tail;
    
    memset(input, '\0', 1000*sizeof(char));
    memcpy(input, data, strlen(data));
    
    size = NLMSG_SPACE(strlen(input));
    skb = alloc_skb(size, GFP_ATOMIC);
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(input))-sizeof(struct nlmsghdr), 0);  //put 
    old_tail = skb->tail;
    memcpy(NLMSG_DATA(nlh), input, strlen(input));
    nlh->nlmsg_len = skb->tail - old_tail;
    NETLINK_CB(skb).pid = 0;
    NETLINK_CB(skb).dst_group = 0;
    //printk(KERN_DEBUG "[kernel space] skb->data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));
    retval = netlink_unicast(nlfd, skb, user_process.pid, MSG_DONTWAIT);
    printk(KERN_DEBUG "[kernel space] netlink_unicast return: %d\n", retval);
    return 0;  
}
void rcv_from_user(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlhdr = NULL;

    skb = skb_get(__skb);

	if(skb->len >= NLMSG_SPACE(0)){
		nlh = nlmsg_hdr(skb);
        handle_rule_config((char*)NLMSG_DATA(nlh));
	}
    kfree_skb(skb);
}
static int init_module(void)
{
	printk("test module loaded.\n");

	// initialize input hook(pre-routing) 
	input_hook.hook = hook_input_func; // hook function
	input_hook.dev = dev_get_by_name(&init_net, "ens33");
	input_hook.pf = PF_INET; // protocol family
	input_hook.hooknum = NF_INET_LOCAL_IN; // where 
	input_hook.priority = NF_IP_PRI_FIRST;  // priority

    // initialize output hook(post-routing)
    output_hook.hook = hook_output_func;
    output_hook.dev = dev_get_by_name(&init_net, "ens33");
    output_hook.pf = PF_INET;
    output_hook.hooknum = NF_INET_LOCAL_OUT;
    output_hook.priority = NF_IP_PRI_FIRST;

    // register hook
	nf_register_net_hook(&init_net, &input_hook);
	nf_register_net_hook(&init_net, &output_hook);

    // netlink create
    struct netlink_kernel_cfg cfg = { 
        .input  = rcv_from_user, /* set recv callback */
    }; 
    nlfd = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if(!nlfd)    {
        //create failed
        return -1;
    }

	return 0;
}

static void exit_module(void)
{
	printk("test module exit ...\n");
	nf_unregister_net_hook(&init_net, &input_hook); //取消钩子注册

    sock_release(nlfd->sk_socket);
}


module_init(init_module);
module_exit(exit_module);
