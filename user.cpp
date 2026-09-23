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
#include <signal.h>

#define STANDARD_DSIP "193.136.138.142" // Fora do Técnico
// #define STANDARD_DSIP "192.168.1.1" // No LT5
#define STANDARD_DSPORT "59000" //Change port number
#define UPD_TIMEOUT 5

using namespace std;

volatile sig_atomic_t sigint_received = 0;

void handle_sigint(int signo) {
    (void)signo;
    sigint_received = 1;
}

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
                cerr << "Erro: peerport inválido " << argv[i+1] << endl;
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

bool login(istringstream& iss, User* user, int fd, struct addrinfo *res) {
    string extra;
    char buffer[128], message[32], status[10];
    ssize_t n;
    struct sockaddr_in addr;
    socklen_t addrlen;

    if (user->login_state) {
        cerr << "Erro: Já tem a sessão iniciada!\n";
        return false;
    }
    if (!(iss >> user->UID >> user->password)) {
        cerr << "Erro: Não intruduziu todos os parametros necessários!" << endl;
        return false;
    } 
    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!" << endl;
        return false;
    } 
    if (user->UID.length() != 6 || !only_digits(user->UID.c_str())) {
        cerr << "Erro: UID inválido!" << endl;
        return false;
    } 
    if (user->password.length() != 8 || !only_alnum(user->password.c_str())) {
        cerr << "Erro: password inválida!" << endl;
        return false;
    } 
    snprintf(message, sizeof(message), "LIN %s %s %s\n", user->UID.c_str(), user->password.c_str(), user->peerport.c_str());
    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível enviar o comando de login!" << endl;
        return false;
    } 
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    // COMPARAR SE O ENDEREÇO QUE ENVIOU É O MESMO QUE ESTÁ A RECEBER

    if (n == -1) {
        cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
        return false;
    } 
    if (n >= 0) {buffer[n] = '\0';}

    if (strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        return false;
    }
    
    sscanf(buffer, "RLI %s", status);
    if (!strcmp(status, "OK")) {
        cout << "Login bem sucedido!\n";
        user->login_state = 1;
    }
    else if (!strcmp(status, "NOK")) cout << "Password errada!\n";
    else if (!strcmp(status, "REG")) {
        cout << "Utilizador registado e login bem sucedido!\n";
        user->login_state = 1;
    }
    else if (!strcmp(status, "ERR")) cout << "Erro: Sintaxe da messagem está errado\n";
    return true;
}

bool unregisterUser(istringstream& iss, User* user, int fd, struct addrinfo *res) {
    string extra;
    char buffer[128], message[32], status[10];
    ssize_t n;
    struct sockaddr_in addr;
    socklen_t addrlen;

    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!\n";
        return false;
    } 
    if (user->login_state == 0) { // Verificação de utilizador sem sessão iniciada antes ou depois de enviar o comando?
        cerr << "Erro: Não tem sessão iniciada!\n";  //POIS YA COM O ERR NLG NÃO FAZ MUITO SENTIDO
        return false;
    } 
    snprintf(message, sizeof(message), "UNR %s %s\n", user->UID.c_str(), user->password.c_str());
    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível enviar o comando de unregister!" << endl;
        return false;
    }
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    // COMPARAR SE O ENDEREÇO QUE ENVIOU É O MESMO QUE ESTÁ A RECEBER
    if (n == -1) {
        cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
        return false;
    } 
    if (n >= 0) {buffer[n] = '\0';}

    if (strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        return false;
    }

    sscanf(buffer, "RUR %s", status);
    if (!strcmp(status, "OK")) {
        cout << "Unregister bem sucedido!\n";
        user->login_state = 0; // ACHO QUE TEMOS QUE METER ISTO
    }
    else if (!strcmp(status, "NOK")) cout << "Utilizador não tem sessão iniciada!\n";
    else if (!strcmp(status, "UNR")) cout << "Utilizador não está registado!\n";
    else if (!strcmp(status, "WRP")) cout << "Password incorreta!\n";
    else if (!strcmp(status, "ERR")) cout << "Erro: Sintaxe da messagem está errada\n";
    return true;
}

bool logout(istringstream& iss, User* user, int fd, struct addrinfo *res) {
    string extra;
    char buffer[128], message[32], status[10];
    ssize_t n;
    struct sockaddr_in addr;
    socklen_t addrlen;

    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!" << endl;
        return false;
    } 
    if (user->login_state == 0) { // Verificação de utilizador sem sessão iniciada antes ou depois de enviar o comando?
        cerr << "Erro: Não tem sessão iniciada!\n";  //POIS YA COM O ERR NLG NÃO FAZ MUITO SENTIDO
        return false;
    } 

    snprintf(message, sizeof(message), "LOU %s %s\n", user->UID.c_str(), user->password.c_str());
    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível enviar o comando de unregister!" << endl;
        return false;
    }

    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    // COMPARAR SE O ENDEREÇO QUE ENVIOU É O MESMO QUE ESTÁ A RECEBER
    if (n == -1) {
        cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
        return false;
    } 
    if (n >= 0) {buffer[n] = '\0';}

    if (strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        return false;
    }

    sscanf(buffer, "RLO %s", status);
    if (!strcmp(status, "OK")) {
        cout << "Logout bem sucedido!\n";
        user->login_state = 0;
    }
    else if(!strcmp(status, "NLG")) cout << "Utilizador não tem sessão iniciada!\n";
    else if (!strcmp(status, "UNR")) cout << "Utilizador não está registado!\n";
    else if (!strcmp(status, "WRP")) cout << "Password incorreta!\n";
    else if (!strcmp(status, "ERR")) cout << "Erro: Sintaxe da messagem está errada\n";
    return true;
}

bool exitUser(istringstream& iss, User* user, int fd, struct addrinfo *res) {
    string extra;

    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!" << endl;
        return false;
    } 
    if (user->login_state == 1) {
        cout << "Execute logout primeiro!\n";
        return false;
    }
    freeaddrinfo(res);
    close(fd);
    return true;
}

void help() {
    cout << "Available commands:\n"
         << "  login <UID> <password>\n"
         << "  unregister\n"
         << "  logout\n"
         << "  exit\n"
         << "  help\n";
}

bool publishFile(istringstream& iss, User* user, int fd, struct addrinfo *res) {
    string filename, label, extra;
    char buffer[128], message[32], status[10];
    ssize_t n;
    struct sockaddr_in addr;
    socklen_t addrlen;

    if (!(iss >> filename >> label)) {
        cerr << "Erro: Não intruduziu todos os parametros necessários!" << endl;
        return false;
    } 
    
    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!" << endl;
        return false;
    } 

    // confirmar que file existe

    // confirmar label em formato "***p"
    
}

int main(int argc, char* argv[]) {
    struct User user;
    string DSIP;
    string DSport;
    int fd, errcode;
    struct addrinfo hints, *res;
    string input, command;
    bool status;

    struct timeval timeout = {UPD_TIMEOUT, 0};

    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        cerr << "sigaction SIGINT\n";
        exit(-1);
    }

    signal(SIGPIPE, SIG_IGN);

    argument_handler(argc, argv, &user.peerport, &DSIP, &DSport);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        cerr << "Erro: Criação de socket não foi bem sucedida!" << endl;
        exit(-1);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        cerr << "Erro: Definição de timeout do socket UDP não foi bem sucedida!\n";
        exit(-1);
    }

    memset(&hints,0,sizeof hints); 
    hints.ai_family=AF_INET;
    hints.ai_socktype=SOCK_DGRAM;

    errcode=getaddrinfo(DSIP.c_str(), DSport.c_str(), &hints, &res); 
    if(errcode!=0) exit(1);

    while (1) {
        getline(cin, input);
        istringstream iss(input);
        if (sigint_received) {
            freeaddrinfo(res);
            close(fd);
            cout << "Cliente fechado com sucesso!\n";
            exit(0);
        }
        iss >> command;
        if (command == "login") {
            login(iss, &user, fd, res);
        } 
        else if (command == "unregister") {
            unregisterUser(iss, &user, fd, res);
        } 
        else if (command == "logout") {
            logout(iss, &user, fd, res);
        } 
        else if (command == "exit") {
            if (exitUser(iss, &user, fd, res)) break;
        }
        else { help(); }
    }
}
