#include "../server/server.hpp"
#include "../parsing/requete.hpp"
#include "../parsing/webserv.hpp"

// void	Server::addtoqueue(int socket, fd_set *set, fd_set *read, fd_set *write)
// {
// 	FD_SET(socket, set);
//     if(socket > max_fd)
//         max_fd = socket;
//     int r = 0;
// 	if((r = select(max_fd + 1, read, write, 0, 0)) < 0)
//         exit(-1);
//     else if (r == 0)
//         std::cout << "Select time out" << std::endl;
//     writeSet = *write;
//     readSet = *read;
// }

void    Server::initServer()
{
    for(size_t i = 0; i < servers.size(); i++)
    {
        Socket socket;
        socket.setup(servers[i]->getListen(), servers[i]->getName());
        sockets.push_back(socket);
    }
	errors.insert(std::make_pair(200, "200 OK"));
	errors.insert(std::make_pair(201, "201 Created"));
	errors.insert(std::make_pair(204, "204 No Content"));
	errors.insert(std::make_pair(300, "300 Multiple Choices"));
	errors.insert(std::make_pair(301, "301 Moved Permanently"));
	errors.insert(std::make_pair(302, "302 Found"));
	errors.insert(std::make_pair(303, "303 See Other"));
	errors.insert(std::make_pair(307, "307 Temporary Redirect"));
	errors.insert(std::make_pair(400, "400 Bad Request"));
	errors.insert(std::make_pair(404, "404 Not Found"));
	errors.insert(std::make_pair(405, "405 Method Not Allowed"));
	errors.insert(std::make_pair(408, "408 Request Timeout"));
	errors.insert(std::make_pair(411, "411 Length Required"));
	errors.insert(std::make_pair(413, "413 Request Entity Too Large"));
	errors.insert(std::make_pair(414, "414 Request-URI Too Long"));
	errors.insert(std::make_pair(500, "500 Internal Server Error"));
	errors.insert(std::make_pair(502, "502 Bad Gateway"));
	errors.insert(std::make_pair(505, "505 HTTP Version Not Supported"));
    max_fd = -1;
}

void Server::showError(int err, Client &client)
{
    std::map<std::string , std::string> errpages = servers[client.getNServer()]->getError();
    if(errpages.find(std::to_string(err)) != errpages.end())
    {
        int fd = open(errpages[std::to_string(err)].c_str(), O_RDONLY);
        if(fd < 0)
        {
            std::cout << colors::on_bright_red << "Show error : " << errors[err] << " !" << colors::on_grey << std::endl;
            std::cout << colors::on_bright_red << "Pre-Config Error Page don't exist : " << errpages[std::to_string(err)] << colors::on_grey << std::endl;
            close(fd);
            return ;
        }
        close(fd);
        showPage(client, errpages[std::to_string(err)], 200);
    }
    else
    {
        std::map<int , std::string>::iterator it = errors.find(err);
        if(it != errors.end())
        {
            std::cout << colors::on_bright_red << "Show error : " << it->second << " !" << colors::on_grey << std::endl;
            std::string msg = "HTTP/1.1 " + it->second + "\nContent-Type: text/plain\nContent-Length: " + std::to_string(it->second.size()) + "\n\n" + it->second + "\n";
            int sendret = send(client.getClientSocket() , msg.c_str(), msg.size(), 0);
            if(sendret < 0)
                std::cout << "Client disconnected" << std::endl;
            else if (sendret == 0)
                std::cout << "0 byte passed to server" << std::endl;
        }
    }
}


bool Server::kill_client(Client client, Requete req)
{
    (void)req;
    close(client.getClientSocket());
    for(size_t i = 0; i < clients.size(); i++)
    {
        if(clients[i].getClientSocket() == client.getClientSocket())
        {
            clients.erase(clients.begin() + i);
            return true;
        }
    }
    exit(1);
}

bool Server::kill_client(Client client)
{
    std::cout << colors::red << "Client Killed" << colors::grey << std::endl;
    close(client.getClientSocket());
    for(size_t i = 0; i < clients.size(); i++)
    {
        if(clients[i].getClientSocket() == client.getClientSocket())
        {
            clients.erase(clients.begin() + i);
            return true;
        }
    }
    exit(1);
}

std::string find_type(std::string dir)
{
    char *dot = strrchr((char *)dir.c_str(), '.');
    if(strcmp(dot, ".css") == 0) return "text/css";
    if(strcmp(dot, ".jpeg") == 0) return "image/jpeg";
    if(strcmp(dot, ".jpg") == 0) return "image/jpg";
    if(strcmp(dot, ".gif") == 0) return "image/gif";
    if(strcmp(dot, ".png") == 0) return "image/png";
    if(strcmp(dot, ".js") == 0) return "application/javascript";
    if(strcmp(dot, ".mp4") == 0) return "video/mp4 ";
    if(strcmp(dot, ".json") == 0) return "application/json";
    if(strcmp(dot, ".pdf") == 0) return "application/pdf";
    if(strcmp(dot, ".html") == 0) return "text/html";

    return "text/plain";
}

bool Server::is_allowed(std::vector<std::string> methodlist, std::string methodreq)
{
    for(size_t i = 0; i < methodlist.size(); i++)
    {
        if(methodlist[i] == methodreq)
            return true;
    }
    return false;
}

std::string Server::getRootPath(std::string urlrcv, int i)
{
    std::string urlroot = servers[i]->getRoot();
    if(urlroot[urlroot.size() - 1] == '/')
        urlroot.erase(urlroot.size() - 1, 1);
    if(loc && !(loc->getRoot().empty()))
        urlrcv.erase(urlrcv.find(loc->getDir()), urlrcv.find(loc->getDir()) + loc->getDir().size());



    std::cout << "Url To Send : " << colors::green << urlroot + urlrcv << std::endl;
    return urlroot + urlrcv;
}

bool Server::is_cgi(std::string filename)
{
    std::vector<std::string>  cgi_list;
    cgi_list.push_back(".py");
    cgi_list.push_back(".pl");
    if(filename.find('.') == std::string::npos)
        return false;
    std::string extension = filename.substr(filename.find('.'), filename.size());
    for(size_t i = 0; i < cgi_list.size(); i++)
    {
        if(cgi_list[i] == extension)
            return true;
    }
    return false;
}


void Server::showPage(Client client, std::string dir, int code)
{
    int r;

    if(dir != "")
        std::cout << colors::on_cyan << "Show Page : " << dir << colors::on_grey << std::endl;

    if(dir.empty())
    {
        std::string err_msg = "HTTP/1.1 " + errors[code] + "\n\n";
        if((r = send(client.getClientSocket() , err_msg.c_str(), err_msg.size(), 0)) < 0)
            showError(500, client);
        else if(r == 0)
            showError(400, client);
        return ;
    }
    else
    {
        FILE *fd_s = fopen(dir.c_str(), "rb");
        fseek (fd_s , 0, SEEK_END);
        int lSize = ftell (fd_s);
        rewind (fd_s);
        fclose(fd_s);

        std::string type = find_type(dir);

        std::string msg = "HTTP/1.1 " + errors.find(code)->second + "\n" + "Content-Type: " + type + "\nContent-Length: " + std::to_string(lSize) + "\n\n";
        int ret = send(client.getClientSocket() , msg.c_str(), msg.size(), 0);
        if(ret < 0)
            showError(500, client);
        else if(ret == 0)
            showError(400, client);



        int fd_r = open(dir.c_str(), O_RDONLY);
        if (fd_r < 0)
        {
            showError(500, client);
            return ;
        }

        // ADD to read queue =================================
		//addtoqueue(fd_r, &readSet, &readSet, &writeSet);

        // ==========================

        char file[1024];
        int r2;
        int r = read(fd_r, file, 1024);
        if(r < 0)
            showError(500, client);
        else // Get big file
        {
            while(r)
            {
                if((r2 = send(client.getClientSocket(), file, r, 0)) < 0)
                {
                    showError(500, client);
                    break;
                }
                else if (r2 == 0)
                {
                    showError(400, client);
                    break;
                }

                // ADD to read queue =================================
				//addtoqueue(fd_r, &readSet, &readSet, &writeSet);
				// ==========================
                

                if((r = read(fd_r, file, 1024)) < 0)
                {
                    showError(500, client);
                    break;
                }
                if(r == 0)
                    break;
            }
        }
        close(fd_r);
    }

}

void Server::rep_listing(int socket, std::string path, std::string fullurl, Client client)
{
    std::cout << colors::on_cyan << "Show Repository Listing" << colors::on_grey << std::endl;

    DIR *dir;
    struct dirent *ent;
    std::string data;

    std::string tosend = "HTTP/1.1 200 OK\n\n<!DOCTYPE html>\n<html>\n<body>\n<h1>" + path + "</h1>\n<pre>\n";

    if ((dir = opendir (fullurl.c_str())) != NULL)
    {
        while ((ent = readdir (dir)) != NULL)
            tosend += "<a href=\"" + ((std::string(ent->d_name) == ".") ? std::string(path) : (std::string(path) + "/" + std::string(ent->d_name))) + "\">" + std::string(ent->d_name) + "</a>\n";
        closedir (dir);
    }
    else
    {
        perror ("Directory listing");
        return ;
    }
    tosend += "</pre>\n</body>\n</html>\n";
    int r = send(socket , tosend.c_str(), tosend.size(), 0);
    if(r < 0)
        showError(500, client);
    else if (r == 0)
        showError(400, client);
     
}

bool Server::writeWithPoll(std::string url, Client client, std::string str)
{
    int r = 0;
    int fd = open(url.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if(fd < 0)
    {
        showError(500, client);
        close(fd);
        return false;
    }

    // ADD to write queue =================================
	//addtoqueue(fd, &writeSet, &readSet, &writeSet);
	// =======================

    r = write(fd, str.c_str(), str.size());
    if(r < 0)
    {
        showError(500, client);
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

bool Server::writeWithPoll(std::string url, Client client, Requete req)
{
    int r = 0;
    int fd = open(url.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if(fd < 0)
    {
        showError(500, client);
        close(fd);
        return false;
    }

    // ADD to write queue =================================
	//addtoqueue(fd, &writeSet, &readSet, &writeSet);
	// =======================

    std::cout << colors::green << req.getFullBody() << std::endl;
    r = write(fd, req.getFullBody().c_str(), req.getFullBody().size());
    if(r < 0)
    {
        showError(500, client);
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

Location *Server::getLocation(std::string url, int i)
{
    std::vector<Location *> locs = servers[i]->getLocation();
    for(size_t i = 0; i < locs.size(); i++)
    {
        if(strncmp(locs[i]->getDir().c_str(), url.c_str(), locs[i]->getDir().size()) == 0)
        {
            std::cout << colors::on_cyan << url << " is Location !" << colors::on_grey << std::endl;
            return locs[i];
        }
    }
    return NULL;
}

void Server::do_redir(Client client, std::string url)
{
    std::cout << colors::on_cyan << "Is a redirection to : " << url << colors::on_grey << std::endl;
    std::string tosend = "HTTP/1.1 200 OK\n\n<head><meta http-equiv = \"refresh\" content = \"0; url =" + url + "\" /></head>";

    int r = send(client.getClientSocket(), tosend.c_str(), tosend.size(), 0);
    if(r < 0)
        showError(500, client);
    else if (r == 0)
        showError(400, client);
}
