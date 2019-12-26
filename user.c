#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <pthread.h>

#define NETLINK_TEST 25 // value > 16 
#define DATA_LEN 500

#define TAG_END 0
#define TAG_MSG 1
#define TAG_LOG 2
// command
#define TAG_INSERT 3
#define TAG_DELETE 4 
#define TAG_PRINT 5
// default action and configuration
#define TAG_CONFIG 6
#define TAG_DEFAULT 7

struct message{
    int tag; // 0 = end, 1 = ms rcv_fg, 2 = log
    int length;
    char data[DATA_LEN];
};

struct packet_info
{
    struct nlmsghdr hdr;
    struct message msg;
};

struct sockaddr_nl saddr; // source socket addr
struct sockaddr_nl daddr; // dest socket addr
int skfd; // the file description of netlink socket>

int init_socket(){

    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd < 0){
        printf("can not create a netlink socket\n");
        return -1;
    }

    //saddr
    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = getpid(); // process id
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0){
        printf("bind() error\n");
        return -1;
    }

    //daddr
    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0;   // if send to kernel space，set nl_pid and nl_groups 0
    daddr.nl_groups = 0; // 
}

int exit_socket(){
    close(skfd);
}

int rcv_from_kernel(){
    int ret, daddrlen = sizeof(struct sockaddr_nl);
    struct packet_info info;
    char *retval;

    // rcv log from kernel space
    while(1){
        memset(&info, 0, sizeof(struct packet_info));
        ret = recvfrom(skfd, &info, sizeof(struct packet_info),0, (struct sockaddr*)&daddr, &daddrlen);
        if(!ret){
            perror("recv from kerner:");
            exit(-1);
        }
        if((int)info.msg.tag == TAG_END){
            break;
        }
        if(info.msg.length == 0){
            continue;
        }else{
            //TODO: write to file
            printf("%s\n",(char*)info.msg.data);
        }
    }
    return 0;

}

int send_to_kernel(char *data, int tag){
    struct nlmsghdr *nlh;
    char input[200];
    int ret;
    struct message msg;

    memset(msg.data, '\0', DATA_LEN);
    memset(input, 0, 200 * sizeof(char));
    memcpy(input, data, strlen(data));

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(msg)));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(msg)); //length of msg
    nlh->nlmsg_flags = 0; 
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0; // sequence number
    nlh->nlmsg_pid = saddr.nl_pid; // sending process PID

    msg.tag = tag;
    msg.length = strlen(input);
    memcpy(msg.data, input, strlen(input));

    memcpy(NLMSG_DATA(nlh), &msg, sizeof(msg));
    
//    printf("[%s]:[%d]\n", (char *)NLMSG_DATA(nlh), nlh->nlmsg_len);
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0,(struct sockaddr *)&daddr, sizeof(daddr));
    if(!ret){
        perror("send pid:");
        exit(-1);
    }
    return 1;
}

int get(char *input){
    if(scanf("%s", input) != 0){
        return 0;
    }else{
        return -1;
    }
    
}

int main(int argc, char* argv[])
{
    // usage:
    //      "sip/smaskoff sport dip/dmaskoff dport protocol action log#"
    //      "A.B.C.D/x [0->65535] A.B.C.D/x [0->65535] [tcp/udp/icmp] [allow/deny] [yes/no]#"
    // example:
    //      "192.168.57.0/24 0 192.168.57.0/24 0 icmp allow yes#"
    char data[] = 
                //    "192.168.57.0/24 0 192.168.57.0/24 0 icmp allow#" // test in internal network 
                //   "222.10.23.0/24 48 222.10.52.0/24 58 tcp deny#"
                    "202.114.0.245 0 192.168.57.0/24 0 icmp deny yes"; // ping www.hust.edu.cn
                //    "182.61.200.6/31 0 192.168.57.0/24 0 icmp deny yes#"; //ping www.baidu.com
    char input[200];
    int flag = 0;
    int ret;
    unsigned int id;
    pthread_t thread;
    init_socket();

    ret = pthread_create(&thread,NULL,(void *)rcv_from_kernel, NULL); 
    if(ret != 0){ 
        printf ("Create pthread error!\n"); 
        exit (1);
    } 

    send_to_kernel("allow", TAG_DEFAULT);
    send_to_kernel(data, TAG_CONFIG);

    while(1){
        memset(input, 0, sizeof(input)/sizeof(char));
        get(input);
        if(strcmp(input, "quit") == 0 || input[0] == 'q'){ // quit, exit 
            send_to_kernel(NULL, TAG_END);
            break;
        }else if(strcmp(input, "insert") == 0 || input[0] == 'i'){ // insert
            if(flag){
                memset(input, 0, sizeof(input)/sizeof(char));
                get(input);
                send_to_kernel(input, TAG_INSERT);
                flag = 0;
            }else{
                printf("please input \"print\" first to get rule table.\n");
            }
        }else if(strcmp(input, "delete") == 0 || input[0] == 'd'){ // delete one rule
            if(flag){
                memset(input, 0, sizeof(input)/sizeof(char));
                get(input);
                send_to_kernel(input, TAG_DELETE);
                flag = 0;
            }else{
                printf("please input \"print\" first to get rule table.\n");
            }
        }else if(strcmp(input, "print") == 0 || input[0] == 'p'){ // print rule table
            flag = 1;
            send_to_kernel(NULL, TAG_PRINT);
        }
    }

    sleep(1);

    if(pthread_join(thread, NULL)){
        printf("thread is not exit");
        return -2;
    }

    exit_socket();
    return 0;
}