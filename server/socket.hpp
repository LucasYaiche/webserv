#ifndef SOCKET_HPP
#define SOCKET_HPP


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <istream>
#include <iostream>
#include <unistd.h>
#include <string>  
#include <fcntl.h>
#include <stdio.h>
#include <vector>
#include <iostream>

#include "../client/client.hpp"
#include "../utils/colors.hpp"
#include <arpa/inet.h>


class Socket
{
    public :
    
        void setup(std::string port, std::string ip); // setup the server and client socket
        void start(); // Wait for client
        void showPage(std::string dir); // Send a request to the server for show page requested
        void waitClient(); // Wait for client to connect

        int getServerSocket() 
        { 
            return serv_socket;
        };

    private :

        int serv_socket;

};


#endif