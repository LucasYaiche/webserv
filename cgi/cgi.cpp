#include "cgi.hpp"

std::string fileExtent(std::string filePwd)
{
    size_t  i = 0;

    while (filePwd[i])
        i++;
    while(i && filePwd[i] != '.')
        i--;
    if (!strcmp(&filePwd[i], ".py"))
        return "/usr/bin/python3";
    if (!strcmp(&filePwd[i], ".pl"))
        return "/usr/bin/perl";
    return "";
}

std::string searchExec(std::string filePwd, char **envp)
{
    (void)envp;
    std::string path;
    std::string token;
    std::string const exec = fileExtent(filePwd);

    if (exec == "")
    {
        std::cerr << "uncompatible CGI-script" << std::endl;
        return ("");
    }

    if (!access(exec.c_str(), X_OK))
        return exec;
    return ("");
}

void newEnv(char **envp, Requete &req, std::vector<std::string> &my_env, Servers * serv)
{
    {
        size_t  i = 0;

        while (envp[i])
            i++;

        i = 0;
        while (envp[i])
        {
            my_env.push_back(envp[i]);
            i++;
        }
    }
    my_env.push_back("CONTENT_TYPE=" + req.getHeader()["Content-Type"]);
    
    my_env.push_back("GATEWAY_INTERFACE=CGI/1.1");
    
    char path[124] = {0};
    my_env.push_back("PATH_TRANSLATED=" + std::string(getcwd(path, 124)));
    
    if (!req.getQuery().empty())
        my_env.push_back("QUERY_STRING=" + req.getQuery());//getQS pour querry string
   
    if (!req.getMethod().empty())
        my_env.push_back("REQUEST_METHOD=" + req.getMethod());

    if (req.getLen())
        my_env.push_back("CONTENT_LENGTH=" + std::to_string(req.getLen()));
    
    if (!req.getProtocol().empty())
        my_env.push_back("SERVER_SOFTWARE=" + req.getProtocol());
    
    my_env.push_back("SERVER_NAME=" + serv->getName());
    
    my_env.push_back("HTTP_ACCEPT=" + req.getHeader()["Accept"]);
    
    my_env.push_back("HTTP_ACCEPT_LANGUAGE=" + req.getHeader()["Accept-Language"]);
    
    my_env.push_back("HTTP_USER_AGENT=" + req.getHeader()["User-Agent"]);
    
    my_env.push_back("SCRIPT_NAME=" + req.getUrl());
    
    my_env.push_back("HTTP_REFERER=" + req.getHeader()["Referer"]);
}

char **vecToTab(std::vector<std::string> &vec)
{
    char **tab;
    int i = 0;

    tab = (char **)malloc(sizeof(char *) * (vec.size() + 1));
    if (!tab)
    {
        perror("malloc vecToTab");
        exit(1);
    }

    for (std::vector<std::string>::iterator it = vec.begin(); it != vec.end(); it++)
    {
        tab[i++] = (char *)(*it).c_str();
    }
    tab[i] = 0;
    return tab;
}

std::string execCGI(std::string filePwd, char **envp, Requete &req, Servers * serv)
{
    std::string execPwd = searchExec(filePwd, envp);
    if (execPwd == "")
    {
        std::cerr << "Bad file" << std::endl;
        return ("");
    }

    int fdIn;
    int fd_in[2];
    int fd_out[2];
    char *tab[3];

    tab[0] = (char *)execPwd.c_str();
    tab[1] = (char *)filePwd.c_str();
    tab[2] = 0;

    char **my_env;

    std::vector<std::string> env;
    newEnv(envp, req, env, serv);
    my_env = vecToTab(env);

    pipe(fd_in);
    pipe(fd_out);
    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork()");
        exit(1);
    }



    if (pid == 0)
    {
        close(fd_in[1]);
        close(fd_out[0]);
        if (dup2(fd_in[0], 0) == -1)
        {
            perror("dup2");
            exit(1);
        }
        if (dup2(fd_out[1], 1) == -1)
        {
            perror("dup2");
            exit(1);
        }
        execve(tab[0], tab, my_env);
        perror("execve");
        exit(1);
    }




    else
    {
        fdIn = dup(0);
        if (fdIn == -1)
        {
            perror("dup");
            exit(1);
        }
        if (dup2(fd_in[0], 0) == -1)
        {
            perror("dup2");
            exit(1);
        }
        if (!req.getFullBody().empty())
        {
            write(fd_in[1], req.getFullBody().c_str(), req.getLen());//req.getBody ou req.getBodyComplet
        }
        close(fd_in[0]);
        close(fd_in[1]);
        waitpid(pid, 0, 0);
        if (dup2(fdIn, 0) == -1)
        {
            perror("dup2");
            exit(1);
        }

        free(my_env);


        char buff[2041] = {0};
        std::string ret = "";
        int  i;



        close(fd_out[1]);
        i = read(fd_out[0], buff, 2040);
        if (i == -1)
        {
            perror("read");
            exit(1);
        }
        buff[i] = 0;
        ret += std::string(buff);
        while (i > 0)
        {
            i = read(fd_out[0], buff, 2040);
            if (i == -1)
            {
                perror("read");
                exit(1);
            
            }
            buff[i] = 0;
            ret += std::string(buff);
        }
        close(fd_out[0]);
        return ret;
    }
    return "";

}
