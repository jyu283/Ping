#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define DEFAULT_TTL         64
#define PING_PACKET_SIZE    64
#define RECV_TIMEOUT        1
#define SLEEP_SEC           1

struct ping_packet {
    struct icmphdr hdr;
    char msg[PING_PACKET_SIZE - sizeof(struct icmphdr)];
};

static int ping_continue = 1;

static inline void print_help(void)
{
    puts("Usage: hostname/IP");
}

unsigned short checksum(void *b, int len) 
{    
	unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

/* Perform a DNS lookup on a given hostname. */
static struct addrinfo *dns_lookup(char *hostname)
{
    int status;
    struct addrinfo hints;
    struct addrinfo *servinfo;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // just IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP stream sockets
    hints.ai_flags = AI_CANONNAME;

    if ((status = getaddrinfo(hostname, NULL, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return NULL;
    }

    if (servinfo) {
        return servinfo;
    } else {
        return NULL;
    }
} 

static int init_socket(int *ttl, struct timeval *timeout)
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(sockfd, SOL_IP, IP_TTL, ttl, sizeof(int)) != 0) {
        perror("TTL setting");
        return -1;
    }
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)timeout, sizeof(struct timeval));
    return sockfd;
}

/* Initialize an empty ping packet */
static void init_ping_packet(struct ping_packet *packet, int seqno)
{
    int i;

	// Zero out packet
	bzero((void *)packet, sizeof(*packet));

    packet->hdr.type = ICMP_ECHO;
    packet->hdr.un.echo.id = getpid();

    for (i = 0; i < sizeof(packet->msg) - 1; i++) {
        packet->msg[i] = i + '0';
    }
    packet->msg[i] = 0;
    packet->hdr.un.echo.sequence = seqno++;
    packet->hdr.checksum = checksum(packet, sizeof(*packet));
}

static inline int send_ping_packet(const int sockfd, struct ping_packet *packet, 
                                   struct addrinfo *target)
{
    int bytes;
    struct sockaddr_in *addr = (struct sockaddr_in *)target->ai_addr;
    if ((bytes = sendto(sockfd, packet, sizeof(*packet), 0,
                   (struct sockaddr *)addr, sizeof(*addr))) <= 0) {
        perror("Failed to send packet");
        return 0;
    } 
    return 1;
}

static inline int recv_ping_packet(int sockfd, struct ping_packet *packet)
{
    int bytes;
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);

    if ((bytes = recvfrom(sockfd, packet, sizeof(*packet), 0,
                 (struct sockaddr *)&recv_addr, &recv_addr_len)) <= 0) {
        perror("Failed to receive packet");
        return -1;
    }
    return bytes;
}

/* Loop to perform ping. */
static void do_ping(int sockfd, struct addrinfo *target, int *ttl)
{
    int seqno = 0, packet_sent, total_received = 0;
    struct ping_packet packet;
    struct timespec t_start, t_end;
    double time_elapsed;
    long double rtt_msec = 0;
    char hostname[256];
    char addr[64];

    getnameinfo(target->ai_addr, target->ai_addrlen,
                hostname, sizeof(hostname),
                NULL, 0, NI_DGRAM);
    getnameinfo(target->ai_addr, target->ai_addrlen,
                addr, sizeof(addr),
                NULL, 0, NI_NUMERICHOST);
    if (target->ai_canonname) {
        printf("PING %s (%s) %lu bytes of data\n", target->ai_canonname, 
                addr, PING_PACKET_SIZE - sizeof(struct icmphdr));
    } else {
        printf("PING %s (%s) %lu bytes of data\n", hostname, addr, 
                      PING_PACKET_SIZE - sizeof(struct icmphdr));
    }
    
    // TODO: ping_continue will be set to 0 on SIGINT signal.
    // while (ping_continue) {
    for (int i = 0; i < 5; i++) {   // for loop for debugging ease
        init_ping_packet(&packet, seqno);

        sleep(SLEEP_SEC);

        // Send packet and start timer
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        packet_sent = send_ping_packet(sockfd, &packet, target);
        if (packet_sent)
            seqno++;

        if (recv_ping_packet(sockfd, &packet)) {
            clock_gettime(CLOCK_MONOTONIC, &t_end);
            time_elapsed = ((double)(t_end.tv_nsec - t_start.tv_nsec))/1000000.0;
            rtt_msec = (t_end.tv_sec - t_start.tv_sec) * 1000.0 + time_elapsed; 

            if (!packet_sent) {
                continue;
            }

            printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%0.1Lf ms\n",
                   PING_PACKET_SIZE, hostname, addr, seqno, *ttl, rtt_msec);
            total_received++;  
        }
    }
}

/* Ping the given target. */
static void ping(struct addrinfo *target)
{
    int sockfd, ttl = 64;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    sockfd = init_socket(&ttl, &tv_out);
    if (sockfd == -1)
        return;

    do_ping(sockfd, target, &ttl);

    freeaddrinfo(target);
    target = NULL;
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        print_help();
        exit(0);
    }

    struct addrinfo *target = dns_lookup(argv[1]);
    if (!target)
        return 0;
    
    ping(target);

    return 0;
}
