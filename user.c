#include <stdio.h>
#include <stdlib.h>
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

    char data[100] = "message from user";
//./proxy insert 0 192 168 200 153 32 -1 60 170 49 75 32 -1 tcp yes permit
//./proxy insert 1 183 78 181 60 32 -1 192 168 200 150 32 -1 tcp yes permit
//insert 0 192 168 200 150 32 -1 192 168 200 2 32 -1 tcp yes permit
//insert 1 192 168 200 150 32 -1 192 168 200 2 32 -1 udp yes permit
//./proxy insert 0 192 168 200 150 32 -1 183 78 181 60 32 -1 tcp yes snat 11 11 11 11 11
//./proxy insert 0 192 168 200 150 32 -1 183 78 181 60 32 -1 tcp yes dnat 11 11 11 11 11
//./proxy mode accept0/reject1

    //初始化
    struct sockaddr_nl saddr; // source socket addr
    struct sockaddr_nl daddr; // dest socket addr
    int skfd; // socket file description
    int ret, daddrlen = sizeof(struct sockaddr_nl);
    struct nlmsghdr *message;
    struct u_packet_info info;
    char *retval;

    message = (struct nlmsghdr *)malloc(1);
    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd < 0){
        printf("can not create a netlink socket\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = getpid(); // process id
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0){
        printf("bind() error\n");
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0;   // 发往内核，nl_pid和nl_groups设为0
    daddr.nl_groups = 0; // 
    
    // 消息头
    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(strlen(data)); //length of msg
    message->nlmsg_flags = 0; 
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0; // sequence number
    message->nlmsg_pid = saddr.nl_pid; // sending process PID
    
    retval = memcpy(NLMSG_DATA(message), data, strlen(data));
    
    printf("message sent to kernel is:\n%s\nlen:%d\n\n", (char *)NLMSG_DATA(message), message->nlmsg_len);
    ret = sendto(skfd, message, message->nlmsg_len, 0,(struct sockaddr *)&daddr, sizeof(daddr));
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
    
    printf("message received from kernel:\n%s\n\n",((char *)info.msg));
    //内核和用户进行通信
    
    close(skfd);
    return 0;
}