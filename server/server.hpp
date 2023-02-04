#ifndef SERVER_HPP
#define SERVER_HPP

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
#include <netdb.h>
#include <map>
#include <sstream>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdlib.h>
#include <dirent.h>

#include "../parsing/webserv.hpp"
#include "../parsing/requete.hpp"
#include "../utils/colors.hpp"
#include "../client/client.hpp"
#include "../cgi/cgi.hpp"
#include "socket.hpp"

class Server
{
    public :
        void initServer(); // put all sockets in the list
        void waitClient(); // wait until client is connected
        void acceptClient(); // accept client and register them in vec
        void handleRequest(); // handle GET POST
        void showPage(Client client, std::string dir, int code);
        void showError(int err, Client &client);
        bool kill_client(Client client, Requete req);
        bool is_allowed(std::vector<std::string> methodlist, std::string methodreq); // say if a method is allowed
        void rep_listing(int socket, std::string path, std::string fullurl, Client client);
        bool is_cgi(std::string filename);
        bool is_timeout(Client client);
        bool kill_client(Client client);
        void addtowait(int socket, fd_set *set);
        void addtoqueue(int socket, fd_set *set, fd_set *read, fd_set *write);
        bool writeWithPoll(std::string url, Client client, Requete req);
        bool writeWithPoll(std::string url, Client client, std::string str);


        std::string getRootPath(std::string url, int i);
        Location *getLocation(std::string url, int i);

        void getMethod(Client &client, std::string url, Requete req);
        void deleteMethod(Client &client, std::string url);
        void postMethod(Client client, std::string url, Requete req);

        void do_redir(Client client, std::string url);



        std::vector<Socket> getSocketList() {return sockets; }
        std::vector<Client> getClientsList() {return clients; }


        std::vector<Servers*> servers;

        char **envp;

        int max_fd;
        fd_set readSet;
        fd_set writeSet;

        Location *loc;
        std::string query;

    private :
        std::vector<Socket> sockets;
        std::vector<Client> clients;
        std::map<int , std::string> errors;


};

std::string find_type(std::string dir);

#endif