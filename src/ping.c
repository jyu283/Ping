#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void print_prompt(void)
{
    printf("ping> ");
    fflush(stdout);
}

static inline void print_help(void)
{
    printf("Usage: ping> hostname/IP\n");
    fflush(stdout);
}

static void dns_lookup(char *hostname)
{

} 

static void parse_input(char *input)
{
    // Remove leading whitespace and trailing newline.
    input[strlen(input)-1] = '\0';
    char *hostname = strtok(input, "\t ");

    if (strcmp(hostname, "exit") == 0) {
        exit(0);
    }

    printf("Looking up hostname/IP: %s.\n", hostname);
    dns_lookup(hostname);
}

/* Interactive Shell */
static void cli(void)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    printf("Copyright (c) 2020 Jerry Yu.\n");
    printf("Type \"exit\" to quit the program.\n");
    print_prompt();
    while ((nread = getline(&line, &len, stdin)) != -1) {
        parse_input(line);
        print_prompt();
    }
    free(line);
}

int main(int argc, char *argv[])
{
    cli();
}