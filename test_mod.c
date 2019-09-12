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

//
MODULE_LICENSE("GPL");
MODULE_AUTHOR("U201614817");

#define NETLINK_TEST 25 // value > 16
#define DEFAULT_ACTION NF_ACCEPT

// action option
#define ALLOW 1
#define DENY -1
// log option
#define YES 1
#define NO -1
// msg
#define DATA_LEN 500
#define TAG_END 0
#define TAG_MSG 1

struct message
{
    int tag; // 0 = end, 0 = msg,
    int length;
    char data[DATA_LEN];
};

struct option
{
    int action; //            1 = allow, -1 = deny
    int log;    //               1 = yes, -1 = no
};

/*----Keyword Hashtable----*/
struct keyword
{
    uint src_ip;
    uint src_port;
    uint dst_ip;
    uint dst_port;
    uint protocol;
};

struct state_node
{
    struct keyword kw;
    uint hash;
    struct option op;
    struct hlist_node list;
};

/*----Rule LinkedList---*/
struct rule
{
    uint src_ip;
    uint src_maskoff;
    uint src_port;
    uint dst_ip;
    uint dst_maskoff;
    uint dst_port;
    int protocol;
    struct option op; // {action, log}
};

struct rule_node
{
    struct rule rule;
    struct list_head list;
};

/*----global variable----*/
int user_pid = 0;                      //user process id
static struct nf_hook_ops input_hook;  //input hook
static struct nf_hook_ops output_hook; // output hook
static struct sock *nlfd = NULL;       //netlink file description
DEFINE_HASHTABLE(state_table, 10);     //init keyword hashtable
LIST_HEAD(rule_table);                 // init rule linkedlist

/*----declaration of function----*/
// hook function
uint hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
uint hook_output_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// state_table
struct option *check_state_table(struct keyword *kw);
char *keyword_to_string(char *output, int length, const struct keyword *kw);
uint hash_function(const struct keyword *kw);
int keyword_compare(const struct keyword *k1, const struct keyword *k2);
int add_state_node(const struct keyword *kw, const struct option *op);

// rule table
struct option *check_rule_table(const struct keyword *kw);
int extract_keyword(struct keyword *kw, const struct sk_buff *skb);
char *rule_to_string(char *output, int length, const struct rule *r);
int rule_compare(const struct rule *r, const struct keyword *kw);
int add_rule_node(char *input);
int handle_rule_config(char *input);

// communication between user space and kernel space
int send_to_user(char *data, int tag);
void rcv_from_user(struct sk_buff *_skb);

//
uint convert_ip(char *ip);
// --------------------------------------------debug-----------------------------------//
int debug_send_to_user(char *data)
{
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

    memset(input, '\0', 1000 * sizeof(char));
    memcpy(input, data, strlen(data));

    size = NLMSG_SPACE(strlen(input));
    skb = alloc_skb(size, GFP_ATOMIC);
    if (!skb)
    {
        printk("my_net_link:alloc_skb_1 error\n");
    }

    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(input)) - sizeof(struct nlmsghdr) /*size of payload*/, 0); //put msg into skb

    memcpy(NLMSG_DATA(nlh), input, strlen(input));

    NETLINK_CB(skb).portid = 0;
    NETLINK_CB(skb).dst_group = 0;

    //printk(KERN_DEBUG "[kernel space] skb->data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));
    retval = netlink_unicast(nlfd, skb, user_pid, MSG_DONTWAIT);
    printk(KERN_DEBUG "[kernel space] netlink_unicast return: %d\n", retval);
    return 0;
}
/*-----function------*/
int send_log_to_user(const struct keyword *kw, const struct option *op)
{
    int length = 200;
    char output[400];
    char kw_str[200];
    keyword_to_string(kw_str, length, kw);

    if (op->action == ALLOW)
    {
        strcpy(output, "[log]:allow ");
        strcpy(output + 12, kw_str);
        output[strlen(kw_str) + 12] = '\0';
    }
    else
    {
        strcpy(output, "[log]:deny ");
        strcpy(output + 11, kw_str);
        output[strlen(kw_str) + 11] = '\0';
    }
    send_to_user(output, TAG_MSG);
    return 1;
}

int add_state_node(const struct keyword *kw, const struct option *op)
{
    char output[200];
    struct state_node *state = (struct state_node *)kmalloc(sizeof(struct state_node), GFP_KERNEL);

    keyword_to_string(output, 200, kw);

    state->kw = *kw;
    state->hash = hash_function(kw);
    state->op = *op;
    hash_add(state_table, &state->list, state->hash);
    printk("[add_state_node]:add %s", output);
    return 1;
}

uint hook_input_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

    // 先提取keywords
    struct keyword kw;
    struct option *state_option, *rule_option;
    char output[200];

    extract_keyword(&kw, skb);

    // 1. check state table
    state_option = check_state_table(&kw);
    if (state_option != NULL)
    {
        // log option
        if (state_option->log == YES)
        {
            send_log_to_user(&kw, state_option);
        }
        if (state_option->action == ALLOW)
        {
            keyword_to_string(output, 200, &kw);
            printk("[Hash Accept packet:%s]", output);
            return NF_ACCEPT;
        }
        else if (state_option->action == DENY)
        {
            keyword_to_string(output, 200, &kw);
            printk("[Hash Drop packet:%s]", output);
            return NF_DROP;
        }
    }

    // 2. cheack rule table
    rule_option = check_rule_table(&kw);
    if (rule_option == NULL)
    {
        return DEFAULT_ACTION;
    }

    add_state_node(&kw, rule_option);

    if (rule_option->action == ALLOW)
    {
        keyword_to_string(output, 200, &kw);
        printk("[List Accept packet:%s]", output);
        return NF_ACCEPT;
    }
    else if (rule_option->action == DENY)
    {
        keyword_to_string(output, 200, &kw);
        printk("[List Drop packet:%s]", output);
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

int extract_keyword(struct keyword *kw, const struct sk_buff *skb)
{
    /**
     * 0 extract error
     * 1 ok 
     */
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    if (!skb)
        return 0;

    // ip
    ip_header = (struct iphdr *)skb_network_header(skb);
    if (!ip_header)
        return 0;

    kw->src_ip = (uint)(ntohl(ip_header->saddr));
    kw->dst_ip = (uint)(ntohl(ip_header->daddr));
    kw->protocol = ip_header->protocol;

    switch (ip_header->protocol)
    {
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
    //keyword_to_string(output, 200, kw);
    // printk("[extract_keyword:%s]",output);
    return 1;
}

uint hash_function(const struct keyword *kw)
{
    uint seed = 4; // 31 131 1313 13131 131313 etc..
    uint hash = 0;
    hash = kw->src_ip + kw->dst_ip;
    hash = (hash << seed) + kw->protocol;
    hash = hash + kw->src_port + kw->dst_port;
    return hash;
}

int keyword_compare(const struct keyword *k1, const struct keyword *k2)
{

    return (k1->src_ip == k2->src_ip) &&
           (k1->src_port == k2->src_port) &&
           (k1->dst_ip == k2->dst_ip) &&
           (k1->dst_port == k2->src_port) &&
           (k1->protocol == k2->protocol);
}

int rule_compare(const struct rule *r, const struct keyword *kw)
{

    return ((r->src_ip & r->src_maskoff) == (kw->src_ip & r->src_maskoff)) &&
           (r->src_port == kw->src_port) &&
           ((r->dst_ip & r->dst_maskoff) == (kw->dst_ip & r->dst_maskoff)) &&
           (r->dst_port == kw->dst_port) &&
           (r->protocol == kw->protocol);
}

struct option *check_state_table(struct keyword *kw)
{
    uint hash = hash_function(kw);
    struct state_node *p;
    hash_for_each_possible(state_table, p, list, hash)
    {
        if (p->hash == hash)
        {
            if (keyword_compare(&p->kw, kw))
            {
                return &(p->op);
            }
        }
    }
    return NULL; //not find in state table
}

struct option *check_rule_table(const struct keyword *kw)
{
    struct rule_node *p;
    list_for_each_entry(p, &rule_table, list)
    {
        if (rule_compare(&p->rule, kw))
        {
            return &((p->rule).op);
        }
    }
    return NULL; // not find in rule table
}

uint convert_ip(char *ip)
{
    char *token = NULL;
    int num = 0;
    uint total = 0;
    int index = 3;

    while ((token = strsep(&ip, ".")))
    {
        int i;
        num = simple_strtoul(token, NULL, 10);
        for (i = 0; i < index; i++)
        {
            num *= 256;
        }
        total += num;
        index--;
    }
    return total;
}

char *keyword_to_string(char *output, int length, const struct keyword *kw)
{
    int src_ip_arr[4];
    uint src_port;
    int dst_ip_arr[4];
    uint dst_port;
    char *protocol = "error";

    uint src_ip = kw->src_ip;
    uint dst_ip = kw->dst_ip;

    // init char array
    memset(output, '\0', length);
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
    switch (kw->protocol)
    {
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

    snprintf(output, length, "%d.%d.%d.%d %u %d.%d.%d.%d %u %s ", src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_port,
             dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_port,
             protocol);
    return output;
}

char *rule_to_string(char *output, int length, const struct rule *r)
{
    int src_ip_arr[4];
    uint src_port;
    int src_maskoff_num = 0;
    int dst_ip_arr[4];
    uint dst_port;
    int dst_maskoff_num = 0;
    char *protocol = "error";
    char *action = "error";
    char *log = "error";

    uint src_ip = r->src_ip;
    uint dst_ip = r->dst_ip;
    uint maskoff;

    // init char array
    memset(output, '\0', length);

    // src_ip
    src_ip_arr[3] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[2] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[1] = src_ip % 256;
    src_ip /= 256;
    src_ip_arr[0] = src_ip % 256;

    //src_port
    src_port = r->src_port;
    maskoff = r->src_maskoff;
    while (maskoff)
    {
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
    dst_port = r->dst_port;
    maskoff = r->dst_maskoff;
    while (maskoff)
    {
        dst_maskoff_num++;
        maskoff = maskoff << 1;
    }

    //protocol
    switch (r->protocol)
    {
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
    if (r->op.action == ALLOW)
    {
        action = "allow";
    }
    else
    {
        action = "deny";
    }

    // log
    if (r->op.log == YES)
    {
        log = "yes";
    }
    else
    {
        log = "no";
    }
    if (src_maskoff_num == 32 && dst_maskoff_num == 32)
    {
        snprintf(output, length, "%d.%d.%d.%d %u %d.%d.%d.%d %u %s %s %s", src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_port,
                 dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_port,
                 protocol, action, log);
    }
    else if (src_maskoff_num == 32)
    {
        snprintf(output, length, "%d.%d.%d.%d %u %d.%d.%d.%d/%d %u %s %s %s", src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_port,
                 dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_maskoff_num, dst_port,
                 protocol, action, log);
    }
    else if (dst_maskoff_num == 32)
    {
        snprintf(output, length, "%d.%d.%d.%d/%d %u %d.%d.%d.%d %u %s %s %s", src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_maskoff_num, src_port,
                 dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_port,
                 protocol, action, log);
    }
    else
    {
        snprintf(output, length, "%d.%d.%d.%d/%d %u %d.%d.%d.%d/%d %u %s %s %s", src_ip_arr[0], src_ip_arr[1], src_ip_arr[2], src_ip_arr[3], src_maskoff_num, src_port,
                 dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3], dst_maskoff_num, dst_port,
                 protocol, action, log);
    }
    return output;
}

int add_rule_node(char *input)
{
    // example: 192.168.57.0/24:20 192.168.52.0/26:40 tcp deny
    int index = 0; // index: 0~3
    int num = 1;
    char *pch;
    char *piece;

    struct rule_node *node = (struct rule_node *)kmalloc(sizeof(struct rule_node *), GFP_KERNEL);
    struct rule tmp;
    while ((pch = strsep(&input, " ")))
    {
        // printk("[add_rule_node no.%d]:%s", num, pch);
        switch (index)
        {
        // source ip/maskoff
        case 0:
        {
            int in = 1;
            while ((piece = strsep(&pch, "/")))
            {
                if (in == 1)
                {
                    tmp.src_ip = convert_ip(piece);
                }
                else
                {
                    tmp.src_maskoff = 0xffffffff << (32 - simple_strtol(piece, NULL, 10));
                }
                in--;
            }
            if (in == 0)
                tmp.src_maskoff = 0xffffffff;
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
            while ((piece = strsep(&pch, "/")))
            {
                if (in == 1)
                {
                    tmp.dst_ip = convert_ip(piece);
                }
                else
                {
                    tmp.dst_maskoff = 0xffffffff << (32 - simple_strtol(piece, NULL, 10));
                }
                in--;
            }
            if (in == 0)
                tmp.dst_maskoff = 0xffffffff;
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
            if (pch[0] == 'a' || pch[0] == 'A')
                tmp.protocol = -1;
            else if (pch[0] == 't' || pch[0] == 'T')
                tmp.protocol = 0x06; //tcp
            else if (pch[0] == 'u' || pch[0] == 'U')
                tmp.protocol = 0x11; //udp
            else if (pch[0] == 'i' || pch[0] == 'I')
            {
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
            if (pch[0] == 'a' || pch[0] == 'A')
            {
                tmp.op.action = ALLOW;
            }
            else /* if(pch[0] == 'd' || pch[0] == 'D')*/
            {
                tmp.op.action = DENY;
            }
            // printk("[action:%d]", tmp.action);
        // log
        case 6:
            if (pch[0] == 'y' || pch[0] == 'Y')
            {
                tmp.op.log = YES;
            }
            else /* if(pch[0] == 'n' || pch[0] == 'N')*/
            {
                tmp.op.log = NO;
            }
        }
        num++;
        index++;
    }
    // add rule into rule_table
    node->rule = tmp;
    list_add_tail(&node->list, &rule_table);

    char output[200];
    rule_to_string(output, 200, &tmp);
    printk("[rule added]:%s", output);

    return 1;
}

int handle_rule_config(char *input)
{
    //int size = strlen(input);
    int num = 1;
    char *pch;
    printk("[handle_rule_config]:%s", input);
    while ((pch = strsep(&input, "#")))
    {
        if (strcmp(pch, "") == 0)
            continue;
        // printk("[handle_rule_config no.%d]:%s", num, pch);
        add_rule_node(pch);
        num++;
    }
    // debug: print rule table
    struct rule_node *p;
    char output[200];
    // list_for_each_entry(p, &rule_table, list){
    //     rule_to_string(output, 200, &p->rule);
    //     printk("[rule table foreach]:%s", output);
    // }
    // debug_send_to_user("Get it");
    send_to_user("Get it.", TAG_MSG);
    return 0;
}

int send_to_user(char *data, int tag)
{
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
    char input[500];
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    struct message msg;

    memset(input, '\0', 500 * sizeof(char));
    memcpy(input, data, strlen(data));

    //size = NLMSG_SPACE(strlen(input));
    size = NLMSG_SPACE(sizeof(struct message));
    skb = alloc_skb(size, GFP_ATOMIC);
    if (!skb)
    {
        printk("my_net_link:alloc_skb_1 error\n");
    }

    //
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(sizeof(struct message)) - sizeof(struct nlmsghdr) /*size of payload*/, 0); //init nlmsg header

    msg.tag = tag;
    msg.length = strlen(input);
    memcpy(msg.data, input, strlen(input));

    memcpy(NLMSG_DATA(nlh), &msg, sizeof(msg)); //put msg into skb

    NETLINK_CB(skb).portid = 0;
    NETLINK_CB(skb).dst_group = 0;

    //printk(KERN_DEBUG "[kernel space] skb->data:%s\n", (char *)NLMSG_DATA((struct nlmsghdr *)skb->data));
    retval = netlink_unicast(nlfd, skb, user_pid, MSG_DONTWAIT);
    // kfree(skb);
    // printk(KERN_DEBUG "[kernel space] netlink_unicast return: %d\n", retval);
    return 0;
}

void rcv_from_user(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh = NULL;

    skb = skb_get(__skb);

    if (skb->len >= NLMSG_SPACE(0))
    {
        nlh = nlmsg_hdr(skb);
        user_pid = nlh->nlmsg_pid;
        handle_rule_config((char *)NLMSG_DATA(nlh));
    }
    kfree_skb(skb);
}

int init_mod(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = rcv_from_user, /* set recv callback */
    };

    printk("firewall module loaded.\n");

    // initialize input hook(pre-routing)
    input_hook.hook = hook_input_func; // hook function
    input_hook.dev = dev_get_by_name(&init_net, "ens33");
    input_hook.pf = PF_INET;               // protocol family
    input_hook.hooknum = NF_INET_LOCAL_IN; // where
    input_hook.priority = NF_IP_PRI_FIRST; // priority

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
    if (!nlfd)
    {
        //create failed
        return -1;
    }

    return 0;
}

void exit_mod(void)
{
    printk("firewall module exit ...\n");
    nf_unregister_net_hook(&init_net, &input_hook);  //取消钩子注册
    nf_unregister_net_hook(&init_net, &output_hook); //取消钩子注册

    // if(user_pid != 0) send_to_user("", TAG_END);

    sock_release(nlfd->sk_socket);

    // free rule_table
    struct rule_node *r, *tmp;
    list_for_each_entry_safe(r, tmp, &rule_table, list)
    {
        list_del(&r->list);
        kfree(r);
    }

    // free state_table
    struct state_node *s;
    struct hlist_node *t;
    int bkt;
    hash_for_each_safe(state_table, bkt, t, s, list)
    {
        hash_del(&s->list);
        kfree(s);
    }
}

module_init(init_mod);
module_exit(exit_mod);
