#include "client.hpp"
#include <stdlib.h>

void Client::init(int i)
{
    last_time = 0;
    n_server = i;
    bzero(request, MAX_REQUEST_SIZE + 1);
    requestSize = 0;
}
