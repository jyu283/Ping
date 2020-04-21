#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dns_result {
    char host[256];
    char addr[64];
};

static inline void print_prompt(void)
{
    printf("ping> ");
    fflush(stdout);
}

static inline void print_help(void)
{
    printf("Usage: hostname/IP\n");
    fflush(stdout);
}

/* Perform a DNS lookup on a given hostname. */
static struct dns_result *dns_lookup(char *hostname)
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

    struct dns_result *result = malloc(sizeof(struct dns_result));
    struct addrinfo *info;
    for (info = servinfo; info != NULL; info = info->ai_next) {
        getnameinfo(info->ai_addr, info->ai_addrlen, 
                    result->host, sizeof(result->host),
                    NULL, 0, NI_DGRAM);
        getnameinfo(info->ai_addr, info->ai_addrlen, 
                    result->addr, sizeof(result->addr),
                    NULL, 0, NI_NUMERICHOST);
    }
    freeaddrinfo(info);
    return result;
} 

/* Parse hostname from user input. */
static int parse_input(char *input)
{
    char *hostname;

    // Remove leading whitespace and trailing newline.
    input[strlen(input)-1] = '\0';
    if (!(hostname = strtok(input, "\t ")))
        return 0;

    // Built-in commands.
    if (strcmp(hostname, "exit") == 0) {
        return -1;
    } else if (strcmp(hostname, "help") == 0) {
        print_help();
        return 0;
    }

    printf("Looking up hostname/IP: %s...\n", hostname);
    struct dns_result *result = dns_lookup(hostname);
    if (result) {
        printf("%s\t%s\n", result->host, result->addr);
        free(result);
    }
    return 0;
}

/* Interactive Shell */
static void cli(void)
{
    int status;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    print_prompt();
    while ((nread = getline(&line, &len, stdin)) != -1) {
        if ((status = parse_input(line)) == -1){
            break;
        }
        print_prompt();
    }
    free(line);
}

int main(int argc, char *argv[])
{
    printf("PING v0.1-4.20.20\n");
    printf("Copyright (c) 2020 Jerry Yu.\n");
    printf("Type \"help\" for more information. ");
    printf("Type \"exit\" to quit the program.\n");
    cli();
    printf("Better hire Jerry!\n");
}
