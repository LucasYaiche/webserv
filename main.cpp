#include "server/server.hpp"

Server serv;


void deleteallfd(Server serv)
{
    for(size_t i = 0; i < serv.getSocketList().size(); i++)
    {
        close(serv.getSocketList()[i].getServerSocket());
    }
    for(size_t i = 0; i < serv.getClientsList().size(); i++)
    {
        close(serv.getClientsList()[i].getClientSocket());
    }
    std::cout << colors::green << "Clean All Fd" << std::endl;
}

void sig_handler(int signal)
{
    (void)signal;
    for(size_t i = 0; i < serv.getSocketList().size(); i++)
        close(serv.getSocketList()[i].getServerSocket());
    for(size_t i = 0; i < serv.getClientsList().size(); i++)
        close(serv.getClientsList()[i].getClientSocket());

    exit(0);
}

int main(int ac, char **av, char **envp)
{
    Conf data;
	try
	{
		parsing(ac, av, data);
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return (1);
	}
    serv.servers = data.getServers();
    serv.envp = envp;
    serv.initServer();
    signal(SIGINT, sig_handler);
    while(1)
    {
        serv.waitClient();
        serv.acceptClient();
        serv.handleRequest();
    }
    

}
