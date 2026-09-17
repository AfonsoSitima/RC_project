#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <stdio.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <sstream>
#define STANDARD_DSIP "193.136.138.142"
#define STANDARD_DSPORT "58001" //Change port number

using namespace std;

int fd, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res;
struct sockaddr_in addr;
char buffer[128];

bool only_digits(char arg[]) {
    if (arg[0] == '\0') return false;

    size_t len = strlen(arg);

    return all_of(arg, arg + len, [](unsigned char c) {return isdigit(c);});
}

void argument_handler(int argc, char* argv[], string *peerport, string *DSIP, string *DSport) {
    for(int i = 1; i < argc; i += 2) {
        if (!strcmp(argv[i], "-m")) {
            if (!only_digits(argv[i+1]) || atoi(argv[i+1]) < 1 || atoi(argv[i+1]) > 65535) {
                cout << "peerport inválido: " << argv[i+1] << endl;
                exit(-1);
            }
            *peerport = argv[i+1];
        }
        else if (!strcmp(argv[i], "-n")) { 
            *DSIP = argv[i+1]; // Não sei se é preciso fazer verificação aqui
        }
        else if (!strcmp(argv[i], "-p")) { 
            *DSport = argv[i+1]; // Não sei se é preciso fazer verificação aqui
        }
    }

    if (*peerport == "") {
        cout << "ERRO: Não foi fornecido peerport!" << endl;
        exit(-1);
    }
    if (*DSIP == "") *DSIP = STANDARD_DSIP;
    if (*DSport == "") *DSport = STANDARD_DSPORT;
}


int main(int argc, char* argv[]) {
    string peerport;
    string DSIP;
    string DSport;
    int fd, errcode;
    struct addrinfo hints, *res;

    argument_handler(argc, argv, &peerport, &DSIP, &DSport);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        cout << "Erro a criar o socket" << endl;
        exit(-1);
    }

    memset(&hints,0,sizeof hints); 
    hints.ai_family=AF_INET;
    hints.ai_socktype=SOCK_DGRAM;

    errcode=getaddrinfo(DSIP.c_str(), peerport.c_str(), &hints,&res); 
    if(errcode!=0) exit(1);

    string input, command, UID, password;

    while (1) { 
        getline(cin, input);
        istringstream iss(input);
        iss >> command;
        if (command == "login") {
            
        } else if (command == "unregister") {

        } else if (command == "logout") {

        } else if (command == "exit") {

        }
    }
}
