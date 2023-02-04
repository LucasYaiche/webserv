/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   Requete.hpp                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tmartial <tmartial@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/08/22 16:18:03 by tmartial          #+#    #+#             */
/*   Updated: 2022/08/31 14:45:43 by tmartial         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef REQUETE_HPP
# define REQUETE_HPP

# include <iostream>
# include <sstream>
# include <map>
# include <vector>
# include <iterator>
# include <string>
# include <unistd.h>
# include <string.h>
# include <fstream>


class Requete
{
	public:
		Requete(char *requete);
		~Requete();

		/* Getters */
		std::string							getMethod() const	{return _method;};
		std::string							getUrl() const		{return _url;};
		std::string							getProtocol() const	{return _protocol;};
		std::string							getBoundary() const	{return _boundary;};
		std::string							getName() const		{return _boundary;};
		std::string							getFileName() const	{return _file_name;};
		std::string							getType() const		{return _type;};
		std::string							getBody() const		{return _body;};
		size_t								getLen() const		{return _len;};
		std::string							getFullBody() const	{return _full_body;};
		std::string							getRequest() const	{return _request;};
		std::string							getQuery() const	{return _query;};
		std::map<std::string, std::string>	getHeader() const	{return _header;};
		std::vector<std::string>			getText() const		{return _text;};

		/* Functions */
		int check_tim();
		void make_body(std::stringstream& ss, std::string token);
		void make_query();
		void make_GET(std::stringstream& ss);
		void make_POST(std::stringstream& ss);
		void print_all_data();
		void print_text();


	protected:
		std::string							_method;// Method from Header
		std::string							_url;//URL from Header
		std::string							_protocol;//Protocol from Header
		std::string							_boundary;//Boundary from Header
		std::string							_name;//Name in body
		std::string							_file_name;//File name in body if exist not always
		std::string							_type;//File name in body if exist not always
		std::string							_body;//Content body without boundary
		size_t								_len;//Len from Header
		std::string							_full_body;//Content body with boundary
		std::string							_request;//FULL Request
		char *								_char_request;//FULL Request
		std::string							_query;//Query text after url without ?
		std::map<std::string, std::string>	_header;//Header
		std::vector<std::string>			_text;//For JOHN divided with the word NewFile
};

#endif

