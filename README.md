<h1 align="center">
	📖 Webserv
</h1>

<p align="center">
	<b><i>A C++ High Performance Web Server</i></b><br>
</p>

<p align="center">
	<img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/lxu-wu/42_webserv?color=lightblue" />
	<img alt="Number of lines of code" src="https://img.shields.io/tokei/lines/github/lxu-wu/42_webserv?color=critical" />
	<img alt="Code language count" src="https://img.shields.io/github/languages/count/lxu-wu/42_webserv?color=yellow" />
	<img alt="GitHub top language" src="https://img.shields.io/github/languages/top/lxu-wu/42_webserv?color=blue" />
	<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/lxu-wu/42_webserv?color=green" />
</p>

<h3 align="center">
	<a href="#%EF%B8%8F-about">About</a>
	<span> · </span>
	<a href="#%EF%B8%8F-usage">Usage</a>
	<span> · </span>
	<a href="#-testing">Testing</a>
</h3>

---

*"This is when you finally understand why a URL starts with HTTP"*

![Alt text](https://github.com/llefranc/42_webserv/blob/main/webserv_example.png)

## About

Webserv is a project of the mandatory part of the cursus that I made with my friend [Helene Herin][2].
<br/><br/>It's only made in C++ and was about creating a web server able to handle one of the most famous web protocol, HTTP 1.1.
Our program is working with a configuration file, so you can setup the port, some routes, the allowed methods and some other basic paramaters for a webserver.
<br/>It's build based on UNIX sockets, and since it's an HTTP server you can access web pages using your favorite browser.

Our server handles the following HTTP features :
- The basics of HTTP protocol (status line / request line, a few headers, and payload).
- GET, POST and DELETE methods.
- HTTP response status codes (200, 404, ...).
- Error pages for the appropriate status code.
- CGI, like rendering a .php file in your browser thanks to php-cgi for example.

## Understanding the configuration file

Webserv need a configuration file that will be loaded at the beginning of the program, setting up all the necessary parameters. It works in a similar way than Nginx configuration file.
</br>It will allow you to setup the following parameters :
- `server` -- to define several virtual servers (with multiple server blocks).
- `server_name` -- to identify a specific server block thanks to host header.
- `listen` -- to configure on which port the server will be listening (only one `listen` per `server` block).
- `error` -- to set a path for custom error pages.
- `location` -- to set parameters for a specific route.
- `index` -- to serve a default file if none match the requested URI.
- `root` -- to route the requested URI to another directory.
- `upload_path` -- to set a specific directory for upload requests.
- `autoindex` -- to list all files present in the targeted directory.
- `allow_method` -- to define the allowed methods for HTTP requests.
- `cgi` -- to configure a cgi to execute for a specific file extenstion (php-cgi for .php files for example).

![Alt text](https://github.com/llefranc/42_webserv/blob/main/config_file_example.png)

Here is a short example of a configuration file, where webserv will : 
- :white_check_mark: : serve requests made on port 8080.
- :white_check_mark: : have custom error pages stored in `./webserv/www/errors/test_changing_path` directory.
- :white_check_mark: : route any requests made to `/cgi/*` to `/www/tests/test_cgi` directory.
- :white_check_mark: : execute `/cgi/*.php` files with php-cgi program.
- :white_check_mark: : accept only POST requests for URIs targeting `/post`.

You can fing more examples in `conf` directory. `www` is a directory which allow you to test some cases / requests. If testing with your broser, use the browser*.conf files.

## Building and running the project

1. Download/Clone this repo

        git clone https://github.com/lxu-wu/42_webserv

2. `cd` into the root directory and run `make`

        cd 42_webserv
        make

3.  Run `webserv` with a configuration file.
	
		./webserv conf/browser.conf

4. Make `curl` request to webserv without omitting host header.
	
		curl -H "host:localhost" http://localhost:8080/cgi/hello_world.php

5.	Access web pages using your browser.
	
		# Example of a valid URI to request with a browser, with the config file from step 3
		http://localhost:8080/cgi/index.php

