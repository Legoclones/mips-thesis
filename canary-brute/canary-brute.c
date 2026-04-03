#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define PORT 7777

int g_client_fd;

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void win() {
    // pipe the shell to the client (just getting here is proof enough)
    dup2(g_client_fd, 0);  // stdin
    dup2(g_client_fd, 1);  // stdout
    dup2(g_client_fd, 2);  // stderr
    system("/bin/sh");
    exit(0);
}

void handle_client(int client_fd) {
    char buf[0x20];

    // leak win()
    dprintf(client_fd, "%p\n", win);
    
    g_client_fd = client_fd; // store client_fd for use in win()
    int n = read(client_fd, buf, 0x60);
    return;
}

int main(int argc, char *argv[]) {
    int port = PORT;
    int server_fd, client_fd;
    struct sockaddr_in addr;
    
    signal(SIGCHLD, SIG_IGN); // Prevent zombie processes
    
    // listen on the specified port for incoming connections
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 2);
    
    printf("Server listening on port %d\n", port);
    
    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        
        if (fork() == 0) {
            close(server_fd);

            // Force socket to close immediately when process exits
            struct linger sl;
            sl.l_onoff = 1;
            sl.l_linger = 0;
            setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

            alarm(1);

            // child process calls handle_client
            handle_client(client_fd);

            // write a message to the client before exiting
            dprintf(client_fd, "Goodbye!\n");
            shutdown(client_fd, SHUT_WR);

            // close the client connection and exit
            close(client_fd);
            exit(0);
        }
        // parent process continues to accept new connections
        close(client_fd);
    }
    
    return 0;
}