#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define DEFAULT_TTL         64      /* default TTL */
#define PING_PACKET_SIZE    64      /* size of a ping packet */
#define RECV_TIMEOUT        1       /* receive time out in seconds */
#define SLEEP_SEC           1       /* sleep time in seconds between pings */
#define RECV_BUFF_SZ        256     /* size of buffer on receiving end */

struct ping_packet {
    struct icmphdr hdr;
    char msg[PING_PACKET_SIZE - sizeof(struct icmphdr)];
};

// flag used for SIGINT handling
static int ping_running = 0;

// user settings
static int count, ttl;

/* Ctrl-C (SIGINT) will stop the ping loop */
void sigint_handler(int dummy)
{
    if (ping_running)
        ping_running = 0;
    else 
        exit(0);
}

static inline void print_help(void)
{
    puts("Usage: ping [-c count] [-t ttl] destination");
}

/* IPv4 checksum */
static unsigned short checksum(void *b, int len) 
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

/* Initialize the socket */
static int init_socket(struct timeval *timeout)
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
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

/* Send packet to destination via socket */
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

/* Receive packet from socket */
static inline int recv_ping_packet(int sockfd, char *buff)
{
    int bytes;
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);

    if ((bytes = recvfrom(sockfd, buff, RECV_BUFF_SZ, 0,
                 (struct sockaddr *)&recv_addr, &recv_addr_len)) <= 0) {
        perror("Failed to receive packet");
        return -1;
    }
    return bytes;
}

/* Retreive the TTL of a reply packet */
static int get_reply_ttl(char const *recv_buff)
{
    struct iphdr *ip = (struct iphdr *)recv_buff;
    return ip->ttl; 
}

/* Retrieve the seqno of a reply packet */
static int get_reply_seq(char const *recv_buff)
{
    struct iphdr *ip = (struct iphdr *)recv_buff;
    struct icmphdr *icmp = (struct icmphdr *)(recv_buff + ip->ihl * 4);
    return icmp->un.echo.sequence;
}

static int check_ttl_exceeded(char const *recv_buff)
{
    struct iphdr *ip = (struct iphdr *)recv_buff;
    struct icmphdr *icmp = (struct icmphdr *)(recv_buff + ip->ihl * 4);

    if (icmp->type == ICMP_TIME_EXCEEDED) {
        struct iphdr *inner_ip = (struct iphdr *)((void *)icmp + 8);
        struct icmphdr *inner_icmp = (struct icmphdr *)
                                     ((void *)inner_ip + inner_ip->ihl * 4);
        printf("seq_no=%d Time to live exceeded.\n",
                inner_icmp->un.echo.sequence);
        return 1;
    }
    return 0;
}

// TODO: break up this function?
/* Loop to perform ping. */
static void do_ping(int sockfd, struct addrinfo *target)
{
    int seqno = 1, packet_sent, total_received = 0, total_errors = 0;
    struct ping_packet packet;
    char recv_buff[RECV_BUFF_SZ];
    struct timespec t_start, t_end;
    double time_elapsed;
    long double rtt_msec = 0, rtt_avg = 0, rtt_total = 0, 
                rtt_min = INT_MAX, rtt_max = 0;
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
    
    // ping_continue will be set to 0 on SIGINT signal.
    ping_running = 1;
    for (int i = 0; i < count; i++) {
        if (!ping_running)
            break;
        if (count == INT_MAX)   
            i--;

        init_ping_packet(&packet, seqno);

        // Send packet and start timer
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        if ((packet_sent = send_ping_packet(sockfd, &packet, target)))
            seqno++;

        if (recv_ping_packet(sockfd, recv_buff)) {
            if (check_ttl_exceeded(recv_buff)) {
                total_errors++;
            } else {
                clock_gettime(CLOCK_MONOTONIC, &t_end);
                time_elapsed = ((double)(t_end.tv_nsec - t_start.tv_nsec))/1000000.0;

                rtt_msec = (t_end.tv_sec - t_start.tv_sec) * 1000.0 + time_elapsed; 
                if (!packet_sent)
                    continue;
                if (!ping_running)  // SIGINT received
                    break;
                printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%0.1Lf ms\n",
                       PING_PACKET_SIZE, hostname, addr, 
                       get_reply_seq(recv_buff), get_reply_ttl(recv_buff), rtt_msec);
                total_received++;  
                packet_sent = 0;

                // rtt bookkeeping
                rtt_total += rtt_msec;
                if (rtt_msec > rtt_max)
                    rtt_max = rtt_msec;
                if (rtt_msec < rtt_min)
                    rtt_min = rtt_msec;
            }
        }
        sleep(SLEEP_SEC);   // sleep for 1 sec
    }

    printf("\n--- %s ping statistics ---\n", 
             target->ai_canonname == NULL ? hostname : target->ai_canonname);
    printf("%d packets transmitted, %d received, ", seqno - 1, total_received);
    if (total_errors) {  // report errors if any was detected
        printf("+%d errors, ", total_errors);
    }
    printf("%.0f%% packet loss\n", 
          ((double)(seqno - 1 - total_received) * 100)/seqno);
    if (total_received) {   // if there was a successful ping, print statistics
        rtt_avg = rtt_total / total_received;
        printf("rtt min/avg/max = %.3Lf/%.3Lf/%.3Lf ms\n", 
                rtt_min, rtt_avg, rtt_max);
    }
}

/* Ping the given target. */
static void ping(struct addrinfo *target)
{
    int sockfd;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    sockfd = init_socket(&tv_out);
    if (sockfd == -1)
        return;

    do_ping(sockfd, target);

    freeaddrinfo(target);
    target = NULL;
    close(sockfd);
}

/* Check if a flag exists in command line arguments */
static int find_flag(int argc, char *argv[], char *target)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], target) == 0) {
            return i;
        }
    }
    return -1;
}

/* Search for -t flag and return setting value if exists */
static int get_user_ttl_setting(int argc, char *argv[])
{
    int i;
    if ((i = find_flag(argc, argv, "-t")) > 0) {
        if (i == argc - 1 || i == argc - 2) {
            print_help();
            exit(0);
        } else {
            int user_ttl = atoi(argv[i+1]);
            if (user_ttl <= 0 || user_ttl > 255) {
                printf("TTL must be between 1 and 255.\n");
                exit(0);
            }
            return user_ttl;
        }
    }
    return DEFAULT_TTL;
}

/* Search for -c flag and return setting value if exists */
static int get_user_count_setting(int argc, char *argv[])
{
    int i;
    if ((i = find_flag(argc, argv, "-c")) > 0) {
        if (i == argc - 1 || i == argc - 2) {
            print_help();
            exit(0);
        } else {
            int user_count = atoi(argv[i+1]);
            if (user_count < 0) {
                printf("Count cannot be negative.\n");
                exit(0);
            }
            return user_count;
        }
    }
    return INT_MAX;
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        print_help();
        exit(0);
    }

    ttl = get_user_ttl_setting(argc, argv);
    count = get_user_count_setting(argc, argv);

    struct addrinfo *target = dns_lookup(argv[argc - 1]);
    if (!target)
        return 0;
    
    signal(SIGINT, sigint_handler);
    ping(target);

    return 0;
}
