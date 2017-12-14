#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "utils.h"
int main(int argc, char **argv, char **envp){
    int read_pipe[2], write_pipe[2];
    int pid, err;
    char result[1024];
    char new_path[1024];
    ssize_t count = readlink( "/proc/self/exe", result, 1024 );
    result[count] = 0;
    sprintf(new_path, "%s-orig\n", result);
    printf("%s", new_path);
    argv[0] = new_path;
    err = execve(new_path, argv, envp);
    if (err == -1)
        exit_error("execve()", errno);
    exit(0);
    err = pipe(read_pipe);
    if (err == -1)
        exit_error("pipe()", errno);       
    err = pipe(write_pipe);
    if (err == -1)
        exit_error("pipe()", errno);
    pid = fork();
    if (pid == -1) 
        exit_error("fork()", errno);
    else if (pid == 0){
        //parent
        close(read_pipe[1]);
        close(write_pipe[0]);
    } else {
        //children
        dup2(0, read_pipe[1]);
        close(read_pipe[0]);
        dup2(1, write_pipe[0]);
        close(write_pipe[1]);
        //ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        //execve();
    }
    
    return 0;
}
