NAME = webserv

SRCS_PATH		= ./srcs
INCS_PATH		= ./includes

SRCS =	main.cpp client/client.cpp parsing/parse_conf.cpp parsing/requete.cpp parsing/servers.cpp parsing/conf.cpp\
		server/server.cpp server/socket.cpp utils/utils_server.cpp cgi/cgi.cpp

OBJS			= $(SRCS:.cpp=.o)

CXX				= clang++ 
CXXFLAGS		= -Wall -Werror -Wextra -std=c++98

all:			$(NAME)

$(NAME):		$(OBJS)
				$(CXX) $(CXXFLAGS) -I $(INCS_PATH) -o $(NAME) $(OBJS)

clean:
				rm -f $(OBJS)

fclean:			clean
				rm -f $(NAME)

re:				fclean $(NAME)

.PHONY:			all clean fclean re