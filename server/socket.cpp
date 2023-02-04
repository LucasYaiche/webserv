#include "socket.hpp"

void    socket_exit(std::string error_msg)
{
    perror(error_msg.c_str());
    exit(-1);
}


void Socket::setup(std::string port, std::string ip) 
{
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // responding to anything
    servaddr.sin_port = htons(stoi(port));

    if(ip.empty())
        ip = "0.0.0.0";

    if((serv_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        socket_exit("socket error");

    fcntl(serv_socket, F_SETFL, O_NONBLOCK);

    int n = 1;
    if (setsockopt(serv_socket, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n)))
        socket_exit("setsockopt error");

    servaddr.sin_addr.s_addr = inet_addr(ip.c_str());
    if((bind(serv_socket, (struct sockaddr *)&servaddr, sizeof(servaddr))))
        socket_exit("bind error");
    if (listen(serv_socket, 42) != 0) // voir si on peut changer le nbr de connection
        socket_exit("listen error");
    else
    {
        time_t current_time = time(NULL);
        tm *ltm = localtime(&current_time);
        std::cout << colors::bright_yellow << "[" << ltm->tm_hour << ":" << ltm->tm_min << ":" << ltm->tm_sec << "]" << "[" << port << "] listening ..." << std::endl;
    }
}


