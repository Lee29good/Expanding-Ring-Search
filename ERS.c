#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

#define PACKET_SIZE 64

// 計算 ICMP 校驗和
unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;
    
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 建立並發送 ICMP 請求封包
int send_icmp_request(int sockfd, struct sockaddr_in *dest, int ttl, int seq) {
    char packet[sizeof(struct icmphdr)];
    struct icmphdr *icmp = (struct icmphdr *)packet;
    
    memset(packet, 0, sizeof(packet));
    
    // 設置 ICMP 標頭
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = seq;
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum(icmp, sizeof(struct icmphdr));
    
    // 設置 TTL
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    
    return sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest));
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hop-distance> <destination>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    int max_hops = atoi(argv[1]);
    const char *destination = argv[2];
    
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    
    // 需要 root 權限
    if (getuid() != 0) {
        fprintf(stderr, "This program requires root privileges.\n");
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, destination, &dest.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", destination);
        close(sockfd);
        return EXIT_FAILURE;
    }
    
    printf("Tracing route to %s with max %d hops:\n", destination, max_hops);
    
    for (int ttl = 1; ttl <= max_hops; ++ttl) {
        if (send_icmp_request(sockfd, &dest, ttl, ttl) < 0) {
            perror("sendto");
            close(sockfd);
            return EXIT_FAILURE;
        }
        
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof(reply_addr);
        char recv_buf[PACKET_SIZE];
        struct timeval timeout = {1, 0}; // 1 second timeout
        
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        int received_bytes = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, 
                                    (struct sockaddr *)&reply_addr, &addr_len);
        
        if (received_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("%d-hop: Request timed out.\n", ttl);
            } else {
                perror("recvfrom");
                close(sockfd);
                return EXIT_FAILURE;
            }
        } else {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &reply_addr.sin_addr, addr_str, sizeof(addr_str));
            printf("%d-hop router IP: %s\n", ttl, addr_str);
            
            // 若到達目標，則結束程序
            if (strcmp(addr_str, destination) == 0) {
                printf("Reached the destination.\n");
                break;
            }
        }
    }
    
    close(sockfd);
    return EXIT_SUCCESS;
}