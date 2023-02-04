/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   conf.cpp                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tmartial <tmartial@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/31 14:41:12 by tmartial          #+#    #+#             */
/*   Updated: 2022/09/13 19:19:04 by tmartial         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "webserv.hpp"

Conf::Conf()
{	
	_directives.push_back("server");
	_directives.push_back("listen");
	_directives.push_back("server_name");
	_directives.push_back("allowed_methods");
	_directives.push_back("root");
	_directives.push_back("error_page");
	_directives.push_back("index");
	_directives.push_back("client_max_body_size");
	_directives.push_back("location");
	_directives.push_back("dir_listing");
	_directives.push_back("redir");
}

Conf::~Conf()
{
	for (size_t i = 0; i < _servers.size(); i++)
	{
		delete _servers[i];
	}
	_servers.clear();
	_file.clear();
	_file_pos.clear();
	_directives.clear();
}


/* --- FUNCTIONS --- */

/* Check all data is correct */
void Conf::check_data()
{
	for (size_t i = 0; i < _servers.size(); i++)
	{
		if (_servers[i]->getName().empty() || _servers[i]->getListen().empty() || _servers[i]->getRoot().empty() 
			|| _servers[i]->getIndex().empty() || _servers[i]->getMethod().empty()  || _servers[i]->getBody().empty()
			|| _servers[i]->getListing().empty())
			throw DirMissing();
		if (!_servers[i]->check_locations())
			throw DirMissing();
		if (_servers[i]->getListen().size() > 4 || !my_atoi(_servers[i]->getListen()) || !my_atoi(_servers[i]->getBody()))
			throw NotINT();
		if (!_servers[i]->check_error_page())
			throw ErrorPage();
		if (!_servers[i]->check_method())
			throw MethWrong();
		if (!_servers[i]->check_root())
			throw RootErr();
		if (!_servers[i]->check_index())
			throw IndexLoc();
		if (!_servers[i]->check_listing())
			throw ListingErr();
		if (!_servers[i]->check_client_size())
			throw SizeErr();
	}
	
}


/* Print all data in conf */
void Conf::print_all_data()
{
	for (size_t i = 0; i < _servers.size(); i++)
	{
		cout << "--- server "<< i << ":" << endl;
		cout << "name = " << _servers[i]->getName() << endl;
		cout << "listen = " << _servers[i]->getListen() << endl;
		cout << "root = " << _servers[i]->getRoot() << endl;
		cout << "index = " << _servers[i]->getIndex() << endl;
		cout << "body = " << _servers[i]->getBody() << endl;
		cout << "listing = " << _servers[i]->getListing() << endl;
		cout << "methods = ";
		for (size_t len = 0; len < _servers[i]->getMethod().size(); len++)
			cout << _servers[i]->getMethod()[len] << " ";
		cout << endl;
		cout << "error pages:" << endl;
		std::map<std::string, std::string> copy = _servers[i]->getError();
		std::map<std::string, std::string>::iterator it = copy.begin();
		for (size_t len = 0; len < _servers[i]->getError().size(); len++)
		{
		 	cout << "error " << it->first << " = " << it->second << endl;
			it++;
		}

		for (size_t x = 0; x < _servers[i]->getLocation().size(); x++)
		{
			cout << "- location "<< x << ":" << endl;
			cout << "dir = " << _servers[i]->getLocation()[x]->getDir() << endl;
			cout << "root = " << _servers[i]->getLocation()[x]->getRoot() << endl;
			cout << "index = " << _servers[i]->getLocation()[x]->getIndex() << endl;
			cout << "listing = " << _servers[i]->getLocation()[x]->getListing() << endl;
			cout << "redir = " << _servers[i]->getLocation()[x]->getRedir() << endl;
			cout << "methods = ";
			for (size_t len = 0; len < _servers[i]->getLocation()[x]->getMethod().size(); len++)
				cout << _servers[i]->getLocation()[x]->getMethod()[len] << " ";
			cout << endl;
		}
	}
}

/* Vector with pos of directive if location or server */
void Conf::init_file_pos()
{
	//0 = server; 1 = location;
	size_t len =_file.size(), pos = 0;
	std::string word;

	for (size_t i = 0; i < len; i++)
	{
		word = ft_first_word(_file[i]);
		if (i == 0 && word != "server")
			throw DirMissing();
		if (word == "server")
			pos = 0;
		else if (word == "location")
			pos = 1;
		_file_pos.push_back(pos);
	}
}

/* Check if all lines are directive */
void Conf::check_directive()
{
	std::size_t len = _file.size();

	for (size_t i = 0; i < len; i++)
		this->is_directive(_file[i], i);
}

/* Stock all the datas */
void Conf::stock_data()
{
	std::size_t len = _file.size();
	int nb_server = -1, nb_locations = -1;
	
	for (size_t i = 0; i < len; i++)
	{
		if (_file_pos[i] == 0)
		{
			if (ft_first_word(_file[i]) == "server")
			{
				setServers();//New server
				nb_server++;
				nb_locations = -1;
			}
			else
			{
				stock_server(_file[i], _servers[nb_server]);
			}
		}
		else
		{
			if (ft_first_word(_file[i]) == "location")
			{
				_servers[nb_server]->setLocation();//New locations
				nb_locations++;
			}
			_servers[nb_server]->stock_location(_file[i], nb_locations);
		}
	}
}

/* Stock directive in server */
void Conf::stock_server(std::string line, Servers* server)
{
	std::size_t count = count_words(line);
	std::string word = ft_first_word(line), last;
	
	if (count == 2)
	{
		last = ft_last_word(line);
		if (word == "listen")
		{
			if (!server->getListen().empty())
				throw DirTwice();
			server->setListen(last);
		}
		else if (word == "server_name")
		{
			if (!server->getName().empty())
				throw DirTwice();
			server->setName(last);
		}
		else if (word == "root")
		{
			if (!server->getRoot().empty())
				throw DirTwice();
			server->setRoot(last);
		}
		else if (word == "index")
		{
			if (!server->getIndex().empty())
				throw DirTwice();
			server->setIndex(last);
		}
		else if (word == "client_max_body_size")
		{
			if (!server->getBody().empty())
				throw DirTwice();
			server->setBody(last);
		}
		else if (word == "allowed_methods")
			server->setMethod(last);
		else if (word == "dir_listing")
		{
			if (!server->getListing().empty())
				throw DirTwice();
			server->setListing(last);
		}
	}
	else if (count >= 3)
	{
		std::stringstream ss(line);
		std::string token;
		last = ft_last_word(line);

		while (ss >> token)
		{
			if (line.find(token) != line.rfind(last) && token != word)
    			server->setError(token, last);
		}
	}
	
}

/* Check if word is a directive */
void Conf::is_directive(std::string line, int pos)
{
	std::size_t count = count_words(line), len = _directives.size();
	std::string word = ft_first_word(line);

	for (size_t i = 0; i < len; i++)
	{
		if (word == _directives[i])
		{
			if (count == 1 && word != "server")
				throw MissingArgv();
			else if (count >= 3 && word != "error_page")
				throw TooMuchArgv();
			else if (count == 2 && word == "error_page")
				throw MissingArgv();
			else if (_file_pos[pos] == 1 && (word == "listen" || word == "client_max_body_size" || word == "server_name")) //0 == server, 1 == location
				throw DirWrongPlace();
			else if (_file_pos[pos] == 0 && (word == "redir" )) //0 == server, 1 == location
				throw DirWrongPlace();
			return ;
		}
	}
	throw DirWrong();
}

/* Fill data will all read lines Insert in _file all lines except empty line */
void Conf::read_file(std::string name)
{
	std::ifstream file(name);
	std::string output;

	while (std::getline(file, output))
	{
		std::size_t len = output.length();

		for (std::size_t i = 0; i < len; i++)
		{
			if (!isspace(output[i]))
			{
				_file.push_back(output);
				break;
			}
		}
	}
	if (_file.empty())
		throw DirMissing();
}