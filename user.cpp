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
#define STANDARD_DSPORT "59000" //Change port number

using namespace std;

struct User {
    string UID;
    string password;
    string peerport;
    int login_state = 0;
};

bool only_digits(const char str[]) {
    if (str[0] == '\0') return false;

    size_t len = strlen(str);

    return all_of(str, str + len, [](unsigned char c) {return isdigit(c);});
}

bool only_alnum(const char str[]) {
    if (str[0] == '\0') return false;

    size_t len = strlen(str);

    return all_of(str, str + len, [](unsigned char c) {return isalnum(c);});
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
        cerr << "Erro: Não foi fornecido peerport!" << endl;
        exit(-1);
    }
    if (*DSIP == "") *DSIP = STANDARD_DSIP;
    if (*DSport == "") *DSport = STANDARD_DSPORT;
}


int main(int argc, char* argv[]) {
    struct User user;
    string DSIP;
    string DSport;
    int fd, errcode;
    socklen_t addrlen;
    struct addrinfo hints, *res;
    struct sockaddr_in addr;
    char buffer[128], status[10], message[32];

    argument_handler(argc, argv, &user.peerport, &DSIP, &DSport);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        cerr << "Erro: Criação de socket não foi bem sucedida!" << endl;
        exit(-1);
    }

    memset(&hints,0,sizeof hints); 
    hints.ai_family=AF_INET;
    hints.ai_socktype=SOCK_DGRAM;

    errcode=getaddrinfo(DSIP.c_str(), DSport.c_str(), &hints, &res); 
    if(errcode!=0) exit(1);

    string input, command, extra;
    ssize_t n;

    while (1) { 
        getline(cin, input);
        istringstream iss(input);
        iss >> command;
        if (command == "login") {
            if (!(iss >> user.UID >> user.password)) {
                cerr << "Erro: Não intruduziu todos os parametros necessários!" << endl;
                continue;
            } 
            if (iss >> extra) {
                cerr << "Erro: Introduziu parametros a mais!" << endl;
                continue;
            } 
            if (user.UID.length() != 6 || !only_digits(user.UID.c_str())) {
                cerr << "Erro: UID inválido!" << endl;
                continue;
            } 
            if (user.password.length() != 8 || !only_alnum(user.password.c_str())) {
                cerr << "Erro: password inválida!" << endl;
                continue;
            } 
            snprintf(message, sizeof(message), "LIN %s %s %s\n", user.UID.c_str(), user.password.c_str(), user.peerport.c_str());
            n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
            if (n == -1) {
                cerr << "Erro: Não foi possível enviar o comando de login!" << endl;
                continue;
            } 
            n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
            if (n == -1) {
                cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
                continue;
            } 
            sscanf(buffer, "RLI %s", status);
            if (strcmp(status, "OK")) {
                cout << "Login bem sucedido!\n";
                user.login_state = 1;
            }
            else if (strcmp(status, "NOK")) cout << "Password errada!\n";
            else if (strcmp(status, "REG")) cout << "Utilizador registado e login bem sucedido!\n";
        } else if (command == "unregister") {
            if (iss >> extra) {
                cerr << "Erro: Introduziu parametros a mais!\n";
                continue;
            } 
            if (user.login_state == 0) { // Verificação de utilizador sem sessão iniciada antes ou depois de enviar o comando?
                cerr << "Erro: Não tem sessão iniciada!\n";
                continue;
            } 
            snprintf(message, sizeof(message), "UNR %s %s", user.UID.c_str(), user.password.c_str());
            n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
            if (n == -1) {
                cerr << "Erro: Não foi possível enviar o comando de unregister!" << endl;
                continue;
            }
            n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
            if (n == -1) {
                cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
                continue;
            } 
            sscanf(buffer, "RUR %s", status);
            if (strcmp(status, "OK")) {
                cout << "Unregister bem sucedido!\n";
            }
            else if (strcmp(status, "NOK")) cout << "Utilizador não tem sessão iniciada!\n";
            else if (strcmp(status, "UNR")) cout << "Utilizador não está registado!\n";
            else if (strcmp(status, "WRP")) cout << "Password incorreta!\n";
        } else if (command == "logout") {

        } else if (command == "exit") {

        }
    }
}
