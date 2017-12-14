#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/types.h>

int exit_error(char *str, int err){
    perror(str);
    exit(err);    
}

int make_nonblock(int fd) {
    int flags, s;
    flags = fcntl (fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror ("fcntl() - F_GETFL");
        return -1;
    }
    flags |= O_NONBLOCK;
    s = fcntl (fd, F_SETFL, flags);
    if (s == -1)
    {
        perror ("fcntl() - F_SETFL, flags |= O_NONBLOCK");
        return -1;
    }
    return 0;
}