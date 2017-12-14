#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int exit_error(char *str, int err){
    printf("%s - %s\n", str, strerror(err));
    exit(err);    
}
