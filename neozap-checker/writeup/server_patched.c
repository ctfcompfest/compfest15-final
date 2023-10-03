#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>
#include <openssl/sha.h>
#include <signal.h>
#include <time.h>

#define PORT 8080
#define REQUEST_SIZE 969
#define RESPONSE_SIZE 4096
#define HASH_LENGTH 48 // patch #1: change HASH_LENGTH from 44 to 48
#define FORK_N 30
#define TIMEOUT_SEC 5

void init();
void initServer();
int compareHash(unsigned char* a, const unsigned char* b);
short isNeoZap(const char* password);
void handleRequest(int client_fd);
void cleanup(int signo);

int server_fd, client_fd;
struct sockaddr_in server_addr, client_addr;

int main() {
    init();
    initServer();

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    socklen_t client_addr_len = sizeof(client_addr);

    for (unsigned int i = 1; ; i++) {
        printf("[*] Connection #%d\n", i);
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("[!] accept()");
            continue;
        }
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            perror("[!] setsockopt(RCVTIMEO)");
            continue;
        }

        if (i % FORK_N) {
            handleRequest(client_fd);
            close(client_fd);
            continue;
        }
        
        pid_t pid = fork();
        if (pid < 0) {
            perror("[!] fork()");
            exit(1);
        } else if (pid == 0) {
            close(server_fd);
            handleRequest(client_fd);
            close(client_fd);
            exit(0);
        } else {
            close(client_fd);
        }
    }

    close(server_fd);
}

void init() {
    signal(SIGINT, cleanup);
    signal(SIGSEGV, cleanup);
}

void initServer() {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[!] socket()");
        exit(1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("[!] setsockopt(REUSE_ADDR)");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[!] bind()");
        exit(1);
    }

    if (listen(server_fd, 5) < 0) {
        perror("[!] listen()");
        exit(1);
    }

    printf("[*] Server listening on port %d...\n", PORT);
}

int compareHash(unsigned char* a, const unsigned char* b) {
    int ret = 1;
    unsigned char expected_hash[HASH_LENGTH];
    for (int i = 0; i < HASH_LENGTH; i++) {
        sscanf(b + 2 * i, "%02hhx", &expected_hash[i]);
    }

    for (int i = 0; i < HASH_LENGTH; i++) {
        if (a[i] != expected_hash[i])
            ret = 0;
    }
    return ret;
}

short isNeoZap(const char* password) {
    int ret = 0;
    unsigned char hash[HASH_LENGTH];
    SHA384(password, strlen(password), hash);
    if (compareHash(hash, "eee2d8627ec0e8f21b114898e78fc3a2058c865669006c1daf7a28d26c9e3308bbde8a3f097f0c9689bc3cbdc55ce20b"))
        ret = 0xfada;
    return ret;
}

void handleRequest(int client_fd) {
    puts("[*] Processing request...");
    sleep(1);

    char* buffer = (char*)malloc(REQUEST_SIZE);
    char* response;
    ssize_t bytes_received;

    bytes_received = recv(client_fd, buffer, REQUEST_SIZE, 0);
    if (bytes_received < 0) {
        perror("[!] recv() @ handleRequest()");
        free(buffer);
        return;
    }
    buffer[bytes_received] = '\0'; // patch #2: add null terminator (optional if we did patch #3)

    char request[bytes_received];
    strncpy(request, buffer, bytes_received);
    request[bytes_received] = '\0';
    printf("Received request from client:\n%s\n", request);
    if (strstr(request, "..") != NULL || strstr(request, "flag") != NULL) {
        response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nB-baka!! What are you doing?? NeoZap I knew wasn't this naughty! (>//<)\0";
        send(client_fd, response, strlen(response), 0);
        free(buffer);
        return;
    }

    regex_t regex;
    regcomp(&regex, "^GET\\ +\\/([^\\/\\?]*)(\\?password=(\\S+))?\\ +HTTP\\/1", REG_EXTENDED); // patch #3: disable / on route (optional if we did patch #2)
    regmatch_t match[4];
    if (regexec(&regex, buffer, 4, match, 0) == 0) {
        int ROUTE_LEN = match[1].rm_eo - match[1].rm_so;
        char route[ROUTE_LEN + 69];
        strncpy(route, buffer + match[1].rm_so, ROUTE_LEN);
        route[ROUTE_LEN] = '\0';

        if (ROUTE_LEN == 0) {
            strcpy(route, "login.html\0");
            ROUTE_LEN = strlen(route);
        }

        int PASSWORD_LEN = match[3].rm_eo - match[3].rm_so;
        char password[PASSWORD_LEN + 69];
        strncpy(password, buffer + match[3].rm_so, PASSWORD_LEN);
        password[PASSWORD_LEN] = '\0';

        printf("Route: %s\n", route);
        printf("Password: %s\n", password);

        if (strcmp(route, "login.html")) {
            if (PASSWORD_LEN == 0) {
                response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nHmm, to prove that you are NeoZap, you need to provide a password! Simply put the password as query string. (e.g. /foo?password=insert_pass_here)\0";
                send(client_fd, response, strlen(response), 0);
                free(buffer);
                return;
            } else if (isNeoZap(password) != (short)0xfada) {
                response = "HTTP/1.1 401 Forbidden\r\nContent-Type: text/plain\r\n\r\nWho are you? You are not NeoZap! Go away >:(\0";
                send(client_fd, response, strlen(response), 0);
                free(buffer);
                return;
            }
        }

        FILE* file = fopen(route, "r");
        if (file == NULL) {
            response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found\0";
            send(client_fd, response, strlen(response), 0);
        } else {
            char* header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
            send(client_fd, header, strlen(header), 0);

            char* file_buffer = (char*)malloc(RESPONSE_SIZE);
            size_t bytes_read;
            while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
                send(client_fd, file_buffer, bytes_read, 0);
            }
            free(file_buffer);
            fclose(file);
        }
    } else {
        response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nBad Request, please follow the access schema: GET /foo?password=bar\0";
        send(client_fd, response, strlen(response), 0);
    }

    free(buffer);
    regfree(&regex);
}

void cleanup(int signo) {
    close(server_fd);
    close(client_fd);
    puts("Socket closed due to signal()");
    exit(0);
}
