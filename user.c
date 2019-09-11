#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>

#define NETLINK_TEST 25 // value > 16 
#define MSG_LEN 1000

struct msg_to_kernel
{
    struct nlmsghdr hdr;
    char data[MSG_LEN];
};

struct u_packet_info
{
    struct nlmsghdr hdr;
    char msg[MSG_LEN];
};

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
                    "202.114.0.245 0 192.168.57.0/24 0 icmp deny yes";
                //   "182.61.200.6/31 0 192.168.57.0/24 0 icmp deny#"; //ping www.baidu.com

    //初始化
    struct sockaddr_nl saddr; // source socket addr
    struct sockaddr_nl daddr; // dest socket addr
    int skfd; // the file description of netlink socket
    int ret, daddrlen = sizeof(struct sockaddr_nl);
    struct nlmsghdr *nlh;
    struct u_packet_info info;
    char *retval;

    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd < 0){
        printf("can not create a netlink socket\n");
        return -1;
    }
    printf("strlen(%ld)\n", strlen(data));
    
    // saddr
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
    daddr.nl_pid = 0;   // 发往内核，nl_pid和nl_groups设为0
    daddr.nl_groups = 0; // 
    
    // 消息头
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(strlen(data)));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(strlen(data)); //length of msg
    nlh->nlmsg_flags = 0; 
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0; // sequence number
    nlh->nlmsg_pid = saddr.nl_pid; // sending process PID
    
    memcpy(NLMSG_DATA(nlh), data, strlen(data));
    
    //printf("message sent to kernel is:\n %s\n\nlen:%d", (char *)NLMSG_DATA(nlh), nlh->nlmsg_len);
    //printf("[%d]\n", /*(char *)NLMSG_DATA(nlh)*/nlh->nlmsg_len);
    printf("[%s]:[%d]\n", (char *)NLMSG_DATA(nlh), nlh->nlmsg_len);
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0,(struct sockaddr *)&daddr, sizeof(daddr));
    if(!ret){
        perror("send pid:");
        exit(-1);
    }
    //接受内核态确认信息
    ret = recvfrom(skfd, &info, sizeof(struct u_packet_info),0, (struct sockaddr*)&daddr, &daddrlen);
    if(!ret){
        perror("recv from kerner:");
        exit(-1);
    }
    
    printf("message received from kernel:[%s]\n\n",((char *)info.msg));
    //内核和用户进行通信

    
    close(skfd);
    return 0;
}