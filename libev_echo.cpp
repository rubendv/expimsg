#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ev.h>

#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <unistd.h>

#include <string>
#include <queue>
#include <iostream>
#include <mutex>

#define DEFAULT_PORT    3333
#define BUF_SIZE        4096

// Lots of globals, what's the best way to get rid of these?
int sd; // socket descriptor
struct sockaddr_in addr;
int addr_len = sizeof(addr);
char buffer[BUF_SIZE];
std::queue<std::string> messages;
//std::mutex messages_mutex;

ev_io udp_read_watcher, udp_write_watcher;
struct ev_loop *loop;

// This callback is called when data is readable on the UDP socket.
static void udp_read_cb(EV_P_ ev_io *w, int revents) {
    //std::cout << "Socket became readable" << std::endl;
    socklen_t bytes = recvfrom(sd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*) &addr, (socklen_t *) &addr_len);

    // add a null to terminate the input, as we're going to use it as a string
    buffer[bytes] = '\0';
    std::cout << "<< " << buffer << std::endl;
    //messages_mutex.lock();
    messages.push(std::string(buffer));
    //messages_mutex.unlock();

    ev_io_start(loop, &udp_write_watcher);
}

static void udp_write_cb(EV_P_ ev_io *w, int revents) {
    //std::cout << "Socket became writable" << std::endl;
    // Echo it back.
    if(messages.size() > 0) {
        //messages_mutex.lock();
        std::string message = messages.front();
        messages.pop();
        //messages_mutex.unlock();
        std::cout << ">> " << message << std::endl;
        sendto(sd, message.c_str(), message.size(), 0, (struct sockaddr*) &addr, sizeof(addr));
    }
    if(messages.size() == 0) {
        ev_io_stop(loop, &udp_write_watcher);
    }
}

int main(void) {
    int port = DEFAULT_PORT;
    puts("udp_echo server started...");

    // Setup a udp listening socket.
    sd = socket(PF_INET, SOCK_DGRAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0)
        perror("bind");

    // Do the libev stuff.
    loop = ev_default_loop(0);
    ev_io_init(&udp_read_watcher, udp_read_cb, sd, EV_READ);
    ev_io_init(&udp_write_watcher, udp_write_cb, sd, EV_WRITE);
    ev_io_start(loop, &udp_read_watcher);
    ev_loop(loop, 0);

    // This point is never reached.
    close(sd);
    return EXIT_SUCCESS;
}

