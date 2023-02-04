/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   webserv.hpp                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tmartial <tmartial@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/09 15:53:02 by tmartial          #+#    #+#             */
/*   Updated: 2022/09/13 19:20:40 by tmartial         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */


#ifndef WEBSERV_HPP
# define WEBSERV_HPP

# include <iostream>
# include <fstream>
# include <vector>
# include <map>
# include <set>
# include <cctype>
# include <string>
# include <sstream>
# include <cstdlib>

/* john */
#include <unistd.h>
#include <istream>

using std::cout;
using std::endl;
using std::cerr;

class Location;
class Servers;
class Conf;

/* cmd f */
/* PARSE_CONF */
void parsing(int argc, char **argv, Conf &data);
void parse_basic(int argc, char **argv);
int count_words(std::string line);
std::string ft_first_word(std::string line);
std::string ft_last_word(std::string line);
std::string ft_last_part(std::string line);
bool my_atoi(std::string word);


class Location
{
	public:
		Location() {;};
		~Location() {_method.clear();};
		
		/* Setteres */
		void setDir(std::string word)		{_dir = word;};
		void setRoot(std::string word)		{_root = word;};
		void setIndex(std::string word)		{_index = word;};
		void setMethod(std::string word)	{_method.push_back(word);};
		void setListing(std::string word)	{_listing = word;};
		void setRedir(std::string word)		{_redir = word;};

		/* Getters */
		std::string					getDir()		{return _dir;};
		std::vector<std::string>	getMethod()		{return _method;};
		std::string					getRoot()		{return _root;};
		std::string					getIndex()		{return _index;};
		std::string					getListing()	{return _listing;};
		std::string					getRedir()		{return _redir;};
		
	private:
		std::string					_dir;
		std::vector<std::string>	_method;
		std::string					_root;
		std::string					_index;
		std::string					_listing;
		std::string					_redir;
};

class Servers
{
	public:
		Servers();
		~Servers();

		/* Setters */
		void setListen(std::string word)					{_listen = word;};
		void setName(std::string word)						{_name = word;};
		void setMethod(std::string word)					{_method.push_back(word);};
		void setRoot(std::string word)						{_root = word;};
		void setError(std::string error, std::string page)	{_error.insert(std::pair<std::string, std::string>(error, page));};
		void setIndex(std::string word)						{_index = word;};
		void setBody(std::string word)						{_body_size = word;};
		void setLocation()									{_locations.push_back(new Location());};
		void setListing(std::string word)					{_listing = word;};

		/* Getters */
		std::string							getListen()		{return _listen;};
		std::string							getName()		{return _name;};
		std::vector<std::string>			getMethod()		{return _method;};
		std::string							getRoot()		{return _root;};
		std::map<std::string, std::string>	getError()		{return _error;};
		std::string							getIndex()		{return _index;};
		std::string							getBody()		{return _body_size;};
		std::vector<Location*>				getLocation()	{return _locations;};
		std::string							getListing()	{return _listing;};
		
		/* Functions */
		void stock_location(std::string line, int pos);
		bool check_method();
		bool check_error_page();
		bool check_root();
		bool check_index();
		bool check_listing();
		bool check_locations();
		bool check_client_size();

	private:
		std::string							_listen;
		std::string							_name;
		std::vector<std::string>			_method;
		std::string							_root;
		std::map<std::string, std::string>	_error;
		std::string							_index;
		std::string							_body_size;
		std::vector<Location*>				_locations;
		std::string							_listing;

};

class Conf
{
	public:
		Conf();
		~Conf();

		/* Getters */
		std::vector<std::string> get_file() const {return (this->_file);};

		/* Setters */
		void setServers() {_servers.push_back(new Servers());};

		/* Functions */
		void read_file(std::string name);
		void is_directive(std::string line, int pos);
		void check_directive();
		void stock_server(std::string line, Servers *server);
		void init_file_pos();
		void stock_data();
		void print_all_data();
		void check_data();
		std::vector<Servers*> getServers() { return _servers; }
	
	private:
		std::vector<Servers*>		_servers;
		std::vector<std::string>	_file;
		std::vector<int>			_file_pos;
		std::vector<std::string>	_directives;
};


/* Errors */
#define EXCEPTION public std::exception
#define WHAT const char * what () const

class ArgvErr : EXCEPTION {WHAT throw () { return ("Usage : ./Webserv <config_file>"); }};
class MissingArgv : EXCEPTION {WHAT throw () { return ("Error: Missing argument after a directive"); }};
class TooMuchArgv : EXCEPTION {WHAT throw () { return ("Error: Too much arguments after a directive"); }};
class DirWrongPlace : EXCEPTION {WHAT throw () { return ("Error: Directive is in wrong place"); }};
class DirWrong : EXCEPTION {WHAT throw () { return ("Error: Directive doesn't exist"); }};
class DirMissing : EXCEPTION {WHAT throw () { return ("Error: Missing a directive"); }};
class NotINT : EXCEPTION {WHAT throw () { return ("Error: Argument needs to be a number"); }};
class MethWrong : EXCEPTION {WHAT throw () { return ("Error: Method is wrong"); }};
class ErrorPage : EXCEPTION {WHAT throw () { return ("Error: Error page is wrong"); }};
class DirTwice : EXCEPTION {WHAT throw () { return ("Error: Two times the same directive"); }};
class RequestErr : EXCEPTION {WHAT throw () { return ("Error: Request method wrong"); }};
class RootErr : EXCEPTION {WHAT throw () { return ("Error: In root path"); }};
class IndexLoc : EXCEPTION {WHAT throw () { return ("Error: Missing index in location"); }};
class ListingErr : EXCEPTION {WHAT throw () { return ("Error: Dir_listing must be on or off"); }};
class SizeErr : EXCEPTION {WHAT throw () { return ("Error: Client size"); }};

#endif