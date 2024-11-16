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

// 定義常數
#define MAX_PACKET_SIZE 64
#define TIMEOUT_SECONDS 1
#define TIMEOUT_MICROSECONDS 0

// 計算網路封包的校驗和
// 參數: data - 要計算的資料, length - 資料長度
// 回傳: 計算出的校驗和
unsigned short calculate_network_checksum(void *data, int length) {
    unsigned short *current_word = data;
    unsigned int checksum = 0;
    
    // 每次加入2個位元組到校驗和
    while (length > 1) {
        checksum += *current_word++;
        length -= 2;
    }
    
    // 如果有剩餘1個位元組，也加入計算
    if (length == 1) {
        checksum += *(unsigned char *)current_word;
    }
    
    // 處理溢位
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    
    return (unsigned short)~checksum;
}

// 傳送ICMP探測封包
// 參數: socket - 網路socket, target - 目標位址, hop_limit - TTL值, sequence - 序號
// 回傳: 成功回傳傳送的位元組數，失敗回傳-1
int send_probe_packet(int socket, struct sockaddr_in *target, int hop_limit, int sequence) {
    // 準備ICMP封包
    char probe_packet[sizeof(struct icmphdr)];
    struct icmphdr *icmp_header = (struct icmphdr *)probe_packet;
    
    // 清空封包內容
    memset(probe_packet, 0, sizeof(probe_packet));
    
    // 設定ICMP封包內容
    icmp_header->type = ICMP_ECHO;        // Echo請求
    icmp_header->code = 0;                // Echo請求的代碼為0
    icmp_header->un.echo.id = getpid();   // 使用程序ID作為識別
    icmp_header->un.echo.sequence = sequence;
    icmp_header->checksum = 0;            // 計算校驗和前先設為0
    
    // 計算並設定校驗和
    icmp_header->checksum = calculate_network_checksum(icmp_header, sizeof(struct icmphdr));
    
    // 設定封包的存活時間(TTL)
    setsockopt(socket, IPPROTO_IP, IP_TTL, &hop_limit, sizeof(hop_limit));
    
    // 發送封包
    return sendto(socket, probe_packet, sizeof(probe_packet), 0, 
                 (struct sockaddr *)target, sizeof(*target));
}

int main(int argc, char *argv[]) {
    // 檢查命令列參數
    if (argc != 3) {
        printf("使用方式: %s <追蹤跳數> <目標IP位址>\n", argv[0]);
        printf("例如: %s 30 8.8.8.8\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    // 解析命令列參數
    int max_trace_hops = atoi(argv[1]);
    const char *destination_ip = argv[2];
    
    // 建立原始網路socket
    int network_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (network_socket < 0) {
        perror("無法建立網路socket");
        return EXIT_FAILURE;
    }
    
    // 檢查是否具有root權限
    if (getuid() != 0) {
        printf("ERROR：本程式需要root權限才能執行\n");
        printf("請使用 sudo 命令執行此程式\n");
        close(network_socket);
        return EXIT_FAILURE;
    }
    
    // 設定目標位址
    struct sockaddr_in destination;
    memset(&destination, 0, sizeof(destination));
    destination.sin_family = AF_INET;
    
    // 檢查IP位址格式是否正確
    if (inet_pton(AF_INET, destination_ip, &destination.sin_addr) <= 0) {
        printf("錯誤：無效的IP位址 '%s'\n", destination_ip);
        close(network_socket);
        return EXIT_FAILURE;
    }
    
    printf("\n開始追蹤到 %s 的路由，最多 %d 個跳點：\n\n", 
           destination_ip, max_trace_hops);
    
    // 開始追蹤路由
    for (int current_hop = 1; current_hop <= max_trace_hops; ++current_hop) {
        // 發送探測封包
        if (send_probe_packet(network_socket, &destination, current_hop, current_hop) < 0) {
            perror("發送封包失敗");
            close(network_socket);
            return EXIT_FAILURE;
        }
        
        // 準備接收回應
        struct sockaddr_in responder;
        socklen_t responder_addr_len = sizeof(responder);
        char response_buffer[MAX_PACKET_SIZE];
        
        // 設定接收超時
        struct timeval timeout = {TIMEOUT_SECONDS, TIMEOUT_MICROSECONDS};
        setsockopt(network_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        // 接收回應
        int bytes_received = recvfrom(network_socket, response_buffer, 
                                    sizeof(response_buffer), 0,
                                    (struct sockaddr *)&responder, 
                                    &responder_addr_len);
        
        // 處理接收結果
        if (bytes_received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("第 %d 跳: 等待回應超時\n", current_hop);
            } else {
                perror("接收回應時發生錯誤");
                close(network_socket);
                return EXIT_FAILURE;
            }
        } else {
            // 將回應者的IP位址轉換為字串
            char responder_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &responder.sin_addr, responder_ip, sizeof(responder_ip));
            
            printf("第 %d 跳: %s\n", current_hop, responder_ip);
            
            // 檢查是否已到達目標
            if (strcmp(responder_ip, destination_ip) == 0) {
                printf("\n已到達目標位址！\n");
                break;
            }
        }
    }
    
    // 清理資源
    close(network_socket);
    return EXIT_SUCCESS;
}