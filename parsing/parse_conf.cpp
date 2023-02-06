# include "webserv.hpp"

void parsing(int argc, char **argv, Conf &data)
{
	parse_basic(argc, argv);
	data.read_file(argv[1]);
	data.init_file_pos();
	data.check_directive();
	data.stock_data();
	data.check_data();
} 

/* Check if file is good to use */
void parse_basic(int argc, char **argv)
{
	if (argc != 2)
		throw ArgvErr();

	std::ifstream file(argv[1]);

	if (!file)
		throw ArgvErr();
	else
	{
		std::string name = std::string(argv[1]);
		
		if (name.find(".conf") == std::string::npos) //npos == -1 in size_t
			throw ArgvErr();
	}
}

/* Count words in a sentence */ 
int count_words(std::string sentence)
{
	int ret = 0, i = 0;

	while (sentence[i + 1])
	{
		if (!isspace(sentence[i]) && isspace(sentence[i + 1]))
			ret++;
		i++;
	}
	if (!isspace(sentence[i]))
		ret++;
	return (ret);
}

/* Check is str is int */
bool my_atoi(std::string word)
{
	int i = 0;
	while (word[i])
	{
		if (!isdigit(word[i]))
			return false;
		i++;
	}
	return true;
}

/* Retun first word from line */
std::string ft_first_word(std::string line)
{
	int i = 0, j = 0;
	while (isspace(line[i]) && line[i])
		i++;
	j = i;
	while (!isspace(line[j]) && line[j])
		j++;
	return (line.substr(i, j - i));
}

/* Return last word from line */
std::string ft_last_word(std::string line)
{
	int i = line.length() - 1, j = 0;
	while (isspace(line[i]) && line[i])
		i--;
	j = i;
	while (j > 0 && !isspace(line[j]))
		j--;
	return (line.substr(j + 1, i - j));
}

/* Return last part from line starting fron first word */
std::string ft_last_part(std::string line)
{
	std::string first = ft_first_word(line);
	int pos = line.find(first), i = pos + 1;
	
	while (line[i])
		i++;
	return (line.substr(pos, i - pos));
}
