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

#define uint unsigned int
#define ulong unsigned long

MODULE_LICENSE("GPL");
MODULE_AUTHOR("U201614817");

#define NETLINK_TEST 25 // value > 16
#define DEFAULT_ACTION NF_ACCEPT
// action macro
#define NOT_FIND 0
#define ALLOW 1
#define DENY 2


/****Keyword Hashtable****/
struct keyword {
	uint src_ip;
	uint dst_ip;
	uint protocol;
    uint src_port;
	uint dst_port;
};

struct state_node {
    struct keyword kw;
    ulong hash;
    int action; // 0 = not find, 1 = allow, 2 = deny
    struct hlist_node list;
};

/*----Rule LinkedList---*/
struct rule {
	uint src_ip;  
    uint src_maskoff;
	uint src_port; 
	uint dst_ip; 
	uint dst_maskoff;
	uint dst_port;
	int protocol; 
    int action; // 0 = not find, 1 = allow, 2 = deny 
	int log; 
};

struct rule_node {
  struct rule rule;
  struct list_head list;  
};

/*----global variable----*/
int user_pid; //user process id
static struct nf_hook_ops input_hook; //input hook
static struct nf_hook_ops output_hook; // output hook
static struct sock *nlfd = NULL; //netlink file description
DEFINE_HASHTABLE(state_table, 10); //init keyword hashtable
LIST_HEAD(rule_table); // init rule linkedlist


/*----declaration of function----*/
uint hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
int add_hashtable(const struct keyword *kw, uint action);
int extract_keyword(struct keyword *kw, const struct sk_buff *skb);
char* keyword_toString(char* output, const struct keyword *kw);
char* rule_toString(char* output, const struct rule *pr);
ulong hash_function(const struct keyword *kw);
int check_state_table(struct keyword *kw);
int check_rule_table(const struct keyword *kw);
int handle_rule_config(char* input);
int send_to_user(char* data);
void rcv_from_user(struct sk_buff *_skb);
int compare_keywords(const struct keyword *k1, const struct keyword *k2);
int compare_rule(const struct rule *r, const struct keyword *kw);


int add_hashtable(const struct keyword *kw, uint action){
    return 0;
}



uint hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

    // 先提取keywords
    struct keyword kw;
    int state_action, rule_action;
    char output[200];

    extract_keyword(&kw, skb);

    // 1. check state table
    state_action = check_state_table(&kw);
    if(state_action == ALLOW){
        return NF_ACCEPT;
    }else if(state_action == DENY){
        return NF_DROP;
    }

    // 2. cheack rule table
    rule_action = check_rule_table(&kw);
    if(rule_action == 0){
        // keyword_toString(output, &kw);
        // printk("[Default packet:%s]",output);
        return DEFAULT_ACTION;
    }

    //add_hashtable(&kw, rule_action);

    if(rule_action == ALLOW){
        keyword_toString(output, &kw);
        printk("[Accept packet:%s]",output);
        return NF_ACCEPT;
    }else if(rule_action == DENY){
        keyword_toString(output, &kw);
        printk("[Drop packet:%s]",output);
        return NF_DROP;
    }

    return DEFAULT_ACTION;
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
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    if(!skb) return 0; 

    // ip
    ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header) return 0;

    kw->src_ip = (uint)(ntohl(ip_header->saddr));
	kw->dst_ip = (uint)(ntohl(ip_header->daddr));
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
        // UDP 
        case 0x11:
            udp_header = udp_hdr(skb);
            kw->src_port = ntohs(udp_header->source);
            kw->dst_port = ntohs(udp_header->dest);
            break;
        default:
            return 0;
    }
    //char output[200];
    //keyword_toString(output, kw);
    // printk("[extract_keyword:%s]",output);
    return 1;
}

ulong hash_function(const struct keyword *kw){
    ulong hash = 0;
    return hash;
}
int compare_keywords(const struct keyword *k1, const struct keyword *k2){

    return \ 
        (k1->src_ip == k2->src_ip) && \
        (k1->src_port == k2->src_port) && \
        (k1->dst_ip == k2->dst_ip) && \
        (k1->dst_port == k2->src_port) && \
        (k1->protocol == k2->protocol);
}
int compare_rule(const struct rule *r, const struct keyword *kw){
    
    return \
        ((r->src_ip & r->src_maskoff) == (kw->src_ip & r->src_maskoff)) && \
        (r->src_port == kw->src_port) && \
        ((r->dst_ip & r->dst_maskoff) == (kw->dst_ip & r->dst_maskoff)) && \
        (r->dst_port == kw->dst_port) && \
        (r->protocol == kw->protocol);
}
int check_state_table(struct keyword *kw){
    ulong hash = hash_function(kw);
    struct state_node *p;
    hash_for_each_possible(state_table, p, list, hash) {
        if(p->hash == hash) {
            if(compare_keywords(&p->kw, kw)){
                return p->action;
            }
        }
    }
    return 0; //not find in state table
}

int check_rule_table(const struct keyword *kw){
    struct rule_node *p;
    list_for_each_entry(p, &rule_table, list){
        if(compare_rule(&p->rule, kw)){
            return (p->rule).action;
        }
    }
    return 0; // not find in rule table
}

// 
uint convert_ip(char* ip){
    char* token = NULL;
    int num = 0;
    uint total = 0;
    int index = 3;
     
    while((token = strsep(&ip, "."))){
        int i;
        num = simple_strtoul(token, NULL, 10);
        for(i = 0; i < index; i++){
           num *= 256;
        }
        total += num;
        index--;
    }
    return total;
}
char* keyword_toString(char* output, const struct keyword *kw){
    int src_ip_arr[4];
    uint src_port;
    int dst_ip_arr[4];
    uint dst_port;
    char* protocol = "error";

    uint src_ip = kw->src_ip;
    uint dst_ip = kw->dst_ip;

    // src_ip
    src_ip_arr[3] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[2] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[1] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[0] = src_ip % 256;

    //src_port
    src_port = kw->src_port;

    // dst_ip
    dst_ip_arr[3] = dst_ip % 256;
    dst_ip /= 256;
    dst_ip_arr[2] = dst_ip % 256;
    dst_ip /= 256;
    dst_ip_arr[1] = dst_ip % 256;
    dst_ip /= 256;
    dst_ip_arr[0] = dst_ip % 256;

    //dst_port
    dst_port = kw->dst_port;

    //protocol
    switch(kw->protocol){
        case 0x01:
            protocol = "icmp";
            break;
        case 0x06:
            protocol = "tcp";
            break;
        case 0x11:
            protocol = "udp";
            break;
        case -1:
            protocol = "all";
            break;
    }

    snprintf(output, 200, "%d.%d.%d.%d %u %d.%d.%d.%d %u %s ",src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_port,\
                                                                dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3],  dst_port,\
                                                                protocol);
    return output;     
}

char* rule_toString(char* output, const struct rule *pr){
    int src_ip_arr[4];
    uint src_port;
    int src_maskoff_num = 0;
    int dst_ip_arr[4];
    uint dst_port;
    int  dst_maskoff_num = 0;
    char* protocol = "error";
    char* action = "error";

    uint src_ip = pr->src_ip;
    uint dst_ip = pr->dst_ip;
    uint maskoff;

    // src_ip
    src_ip_arr[3] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[2] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[1] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[0] = src_ip % 256;

    //src_port
    src_port = pr->src_port;
    maskoff = pr->src_maskoff;
    while(maskoff){
        src_maskoff_num++;
        maskoff = maskoff << 1;
    }

    // dst_ip
    dst_ip_arr[3] = dst_ip % 256;
    dst_ip /= 256;
    dst_ip_arr[2] = dst_ip % 256;
    dst_ip /= 256;
    dst_ip_arr[1] = dst_ip % 256;
    dst_ip /= 256;
    dst_ip_arr[0] = dst_ip % 256;

    //dst_port
    dst_port = pr->dst_port;
    maskoff = pr->dst_maskoff;
    while(maskoff){
        dst_maskoff_num++;
        maskoff = maskoff << 1;
    }

    //protocol
    switch(pr->protocol){
        case 0x01:
            protocol = "icmp";
            break;
        case 0x06:
            protocol = "tcp";
            break;
        case 0x11:
            protocol = "udp";
            break;
        case -1:
            protocol = "all";
            break;
    }

    //action
    if(pr->action == 1){
        action = "allow";
    }else{
        action = "deny";
    }
    if(src_maskoff_num == 32 && dst_maskoff_num == 32){
        snprintf(output, 200, "%d.%d.%d.%d %u %d.%d.%d.%d %u %s %s",src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_port,\
                                                     dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3],dst_port,\
                                                     protocol, action);

    }else if(src_maskoff_num == 32){
        snprintf(output, 200, "%d.%d.%d.%d %u %d.%d.%d.%d/%d %u %s %s",src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_port,\
                                                     dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_maskoff_num, dst_port,\
                                                     protocol, action);

    }else if(dst_maskoff_num == 32){
        snprintf(output, 200, "%d.%d.%d.%d/%d %u %d.%d.%d.%d %u %s %s",src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_maskoff_num, src_port,\
                                                                dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_port,\
                                                                protocol, action);

    }else{
        snprintf(output, 200, "%d.%d.%d.%d/%d %u %d.%d.%d.%d/%d %u %s %s",src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_maskoff_num, src_port,\
                                                     dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_maskoff_num, dst_port,\
                                                     protocol, action);

    }
    return output; 
}

int generate_one_rule(char* input){
    // example: 192.168.57.0/24:20 192.168.52.0/26:40 tcp deny
    int index = 0; // index: 0~3
    int num = 1;
    char *pch;
    char *piece;

    struct rule_node *node = (struct rule_node *)kmalloc(sizeof(struct rule_node *), GFP_KERNEL);
    struct rule tmp;
    while((pch  = strsep(&input, " "))){
        // printk("[generate_one_rule no.%d]:%s", num, pch);
        switch(index){
            // source ip/maskoff
            case 0:
            {
                int in = 1;
                while((piece = strsep(&pch, "/"))){
                    if(in == 1){
                        tmp.src_ip = convert_ip(piece);
                    }else{
                        tmp.src_maskoff = 0xffffffff << (32 - simple_strtol(piece, NULL, 10));
                    }
                    in--;
                }
                if(in == 0) tmp.src_maskoff = 0xffffffff;
                // printk("[src_ip:%02X", tmp.src_ip);
                // printk("[src_maskoff:%02X",tmp.src_maskoff);
                break;
            }
            // source port
            case 1:
                tmp.src_port = (uint)simple_strtol(pch, NULL, 10);
                // printk("[src_port:%u]", tmp.src_port);
                break;

            // destination ip/maskoff
            case 2:
            {
                int in = 1;
                while((piece = strsep(&pch, "/"))){
                    if(in == 1){
                        tmp.dst_ip = convert_ip(piece);
                    }else{
                        tmp.dst_maskoff = 0xffffffff << (32 - simple_strtol(piece, NULL, 10));
                    }
                    in--;
                }
                if(in == 0) tmp.dst_maskoff = 0xffffffff;
                // printk("[dst_ip:%02X", tmp.dst_ip);
                // printk("[dst_maskoff:%02X",tmp.dst_maskoff);
                break;
            }
            case 3:
                tmp.dst_port = (uint)simple_strtol(pch, NULL, 10);
                // printk("[dst_port:%u]", tmp.dst_port);
                break;

            // protocol
            case 4:
                if(pch[0]=='a' || pch[0] == 'A')
					tmp.protocol = -1; 
				else if(pch[0]=='t' || pch[0] == 'T')
					tmp.protocol = 0x06; //tcp 
				else if(pch[0]=='u' || pch[0] == 'U')
					tmp.protocol = 0x11; //udp
				else if(pch[0]=='i' || pch[0] == 'I'){
					tmp.protocol = 0x01; //icmp
                    tmp.src_port = 0;
                    tmp.dst_port = 0;

                }
				else
					return -1;
                // printk("[protocol:%02X]:",tmp.protocol);
				break;

            // action
            case 5:
                if(pch[0] == 'a' || pch[0] == 'A'){
                    tmp.action = 1;
                }else if(pch[0] == 'd' || pch[0] == 'D'){
                    tmp.action = 2;
                }
                // printk("[action:%d]", tmp.action);
            // log
            // TODO logo 
        }
        num++;
        index++;
    }
    // add rule into rule_table
    node->rule = tmp;
    list_add_tail(&node->list, &rule_table);

    char output[200];
    rule_toString(output, &tmp);
    printk("[rule added]:%s",output);

    return 1;
}
int handle_rule_config(char* input){
    //int size = strlen(input);
    int num = 1;
    char *pch;
    printk("[handle_rule_config]:%s", input);
    while ((pch = strsep(&input, "#")))
    {  
        if(strcmp(pch, "") == 0)  continue;
        printk("[handle_rule_config no.%d]:%s", num, pch);
        generate_one_rule(pch);
        num++;
    }
    // debug: print rule table
    struct rule_node *p;
    char output[200];
    list_for_each_entry(p, &rule_table, list){
        rule_toString(output, &p->rule);
        printk("[rule table foreach]:%s", output);
    }

    send_to_user("Get it.");
    return 0;
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
    
    memset(input, '\0', 1000*sizeof(char));
    memcpy(input, data, strlen(data));
    
    size = NLMSG_SPACE(strlen(input));
    skb = alloc_skb(size, GFP_ATOMIC);
    if(!skb)
	{
	    printk("my_net_link:alloc_skb_1 error\n");
	}

    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(input))-sizeof(struct nlmsghdr) /*size of payload*/, 0);  //put msg into skb

    memcpy(NLMSG_DATA(nlh), input, strlen(input));

    NETLINK_CB(skb).portid = 0;
    NETLINK_CB(skb).dst_group = 0;

    //printk(KERN_DEBUG "[kernel space] skb->data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));
    retval = netlink_unicast(nlfd, skb, user_pid, MSG_DONTWAIT);
    printk(KERN_DEBUG "[kernel space] netlink_unicast return: %d\n", retval);
    return 0;  
}
void rcv_from_user(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh = NULL;

    skb = skb_get(__skb);

	if(skb->len >= NLMSG_SPACE(0)){
		nlh = nlmsg_hdr(skb);
        user_pid = nlh->nlmsg_pid;
        handle_rule_config((char*)NLMSG_DATA(nlh));
	}
    kfree_skb(skb);
}

int init_mod(void)
{
    struct netlink_kernel_cfg cfg = { 
        .input  = rcv_from_user, /* set recv callback */
    }; 

	printk("firewall module loaded.\n");

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
    nlfd = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if(!nlfd)    {
        //create failed
        return -1;
    }

	return 0;
}

void exit_mod(void)
{
	printk("firewall module exit ...\n");
	nf_unregister_net_hook(&init_net, &input_hook); //取消钩子注册
	nf_unregister_net_hook(&init_net, &output_hook); //取消钩子注册


    sock_release(nlfd->sk_socket);
}



module_init(init_mod);
module_exit(exit_mod);
