
#ifndef CGI_HPP
# define CGI_HPP

#include <unistd.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <stdlib.h>
#include <climits>
#include <sys/stat.h>

#include "../parsing/webserv.hpp"
#include "../parsing/requete.hpp"

std::string execCGI(std::string filePwd, char **envp, Requete &req, Servers * serv);

#endif
