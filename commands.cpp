#include "commands.hpp"
#include "aux.hpp"
#include <sys/socket.h>
#include <cstring>
#include <string>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <unistd.h>

using namespace std;

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
    if (n == -1) {
        cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
        return false;
    } 
    if (n >= 0) {buffer[n] = '\0';}

    if (!strcmp(buffer, "ERR")) {
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

    if (!strcmp(buffer, "ERR")) {
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

    if (!strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        user->login_state = 0;
        return false;
    }

    sscanf(buffer, "RLO %s", status);
    if (!strcmp(status, "OK")) {
        cout << "Logout bem sucedido!\n";
        user->login_state = 0;
    }
    else if(!strcmp(status, "NLG")) {
        cout << "Utilizador não tem sessão iniciada!\n";
        user->login_state = 0;
    } 
    else if (!strcmp(status, "UNR")) {
        cout << "Utilizador não está registado!\n";
        user->login_state = 0;
    } 
    else if (!strcmp(status, "WRP")) cout << "Password incorreta!\n";
    else if (!strcmp(status, "ERR")) cout << "Erro: Sintaxe da messagem está errada\n";
    return true;
}

bool exitUser(istringstream& iss, User* user, int fd, struct addrinfo *res, struct addrinfo *res_tcp) {
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
    freeaddrinfo(res_tcp);
    close(fd);
    return true;
}

bool publishFile(istringstream& iss, User* user, int fd, struct addrinfo *res) {
    string filename, label, extra;
    char buffer[128], message[64], status[10]; //tive que aumentar o numero de char na message
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

    if (!user->login_state) {
        cerr << "Erro: Não tem sessão iniciada!\n";
        return false; 
    }

    if (filename.length() < 1 || filename.length() > 24) {
        cerr << "Erro: Tamanho do nome do ficheiro inválido!" << endl;
        return false;
    }

    ssize_t dot = filename.find('.');
    if (dot == string::npos){
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    if (dot != filename.find_last_of('.') || dot == 0) {
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    if (filename.length() != dot + 4) {
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    for (int i = 0; i < filename.length(); i++ ) {
        if (dot < i && !isalnum(filename[i])) {
            cerr << "Erro: Filename inválido!" << endl;
            return false;
        }
        else if (!isalnum(filename[i]) && filename[i] != '_' && filename[i] != '-' && filename[i] != '.') {
            cerr << "Erro: Filename inválido!" << endl;
            return false;
        }
    }
    if (!(filesystem::exists(filename))) {
        cerr << "Erro: File não existe!" << endl;
        return false;
    }

    if (label.length() < 1||  label.length() > 20) {
        cerr << "Erro: Label inválida!" << endl;
        return false;
    }
    for (int i = 0; i < label.length(); i++ ) {
        if (!isalnum(label[i]) && label[i] != '_' && label[i] != '-') {
            cerr << "Erro: Label inválida!" << endl;
            return false;
        }
    }

    snprintf(message, sizeof(message), "PUB %s %s %s %ju %s\n", user->UID.c_str(), user->password.c_str(), filename.c_str(), filesystem::file_size(filename), label.c_str());
    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível enviar o comando de login!" << endl;
        return false;
    }
    
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
        return false;
    } 
    if (n >= 0) {buffer[n] = '\0';}

    if (!strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        return false;
    }
    
    sscanf(buffer, "RPB %s", status);
    if (!strcmp(status, "OK")) {cout << "Operação bem sucedida!\n";}
    else if (!strcmp(status, "NLG")) cout << "Utilizador não tem sessão iniciada!\n";
    else if (!strcmp(status, "UNR")) cout << "Utilizador não registado!\n";
    else if (!strcmp(status, "WRP")) cout << "Password incorreta\n";
    else if (!strcmp(status, "NOK")) cout << "Ficheiro não pode ser publicado\n";
    else if (!strcmp(status, "ERR")) cout << "Erro de syntax no comando\n";
    return true;
}

bool removeFile(istringstream& iss, User* user, int fd, struct addrinfo *res) {
    string filename, label, extra;
    char buffer[128], message[64], status[10]; //tive que aumentar o numero de char na message
    ssize_t n;
    struct sockaddr_in addr;
    socklen_t addrlen;

    if (!(iss >> filename)) {
        cerr << "Erro: Não intruduziu todos os parametros necessários!" << endl;
        return false;
    } 
    
    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!" << endl;
        return false;
    } 

    if (!user->login_state) {
        cerr << "Erro: Não tem sessão iniciada!\n";
        return false;
    }

    ssize_t dot = filename.find('.');
    if (dot == string::npos){
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    if (filename.length() < 1 || filename.length() > 24) {
        cerr << "Erro: Tamanho do nome do ficheiro inválido!" << endl;
        return false;
    }

    if (dot != filename.find_last_of('.')) {
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    if (filename.length() != dot + 4 || dot == 0) {
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    for (int i = 0; i < filename.length(); i++ ) {
        if (dot < i && !isalnum(filename[i])) {
            cerr << "Erro: Filename inválido!" << endl;
            return false;
        }
        else if (!isalnum(filename[i]) && filename[i] != '_' && filename[i] != '-' && filename[i] != '.') {
            cerr << "Erro: Filename inválido!" << endl;
            return false;
        }
    }
    
    snprintf(message, sizeof(message), "REM %s %s %s\n", user->UID.c_str(), user->password.c_str(), filename.c_str());
    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível enviar o comando de login!" << endl;
        return false;
    }
    
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
        return false;
    } 
    if (n >= 0) {buffer[n] = '\0';}

    if (!strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        return false;
    }
    
    sscanf(buffer, "RRM %s", status);
    if (!strcmp(status, "OK")) {cout << "Operação bem sucedida!\n";}
    else if (!strcmp(status, "NLG")) cout << "Utilizador não tem sessão iniciada!\n";
    else if (!strcmp(status, "UNR")) cout << "Utilizador não registado!\n";
    else if (!strcmp(status, "WRP")) cout << "Password incorreta\n";
    else if (!strcmp(status, "NOK")) cout << "Ficheiro não foi publicado\n";
    else if (!strcmp(status, "ERR")) cout << "Erro de syntax no comando\n";
    return true;
}

bool list(istringstream& iss, int fd, struct addrinfo *res) {
    string extra;
    ssize_t n;
    char buffer[5000], status[10], files[1024];
    struct sockaddr_in addr;
    socklen_t addrlen;

    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!\n";
        return false;
    }

    char message[] = "LST\n";
    n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível enviar o comando de unregister!" << endl;
        return false;
    }

    n = recvfrom(fd, buffer, 1024, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível receber resposta do DS!" << endl;
        return false;
    } 
    if (n >= 0) {buffer[n] = '\0';}

    if (!strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        return false;
    }

    sscanf(buffer, "RLS %s", status);
    if (!strcmp(status, "OK")) {
        cout << "Ficheiros no DS:\n";
        istringstream iss(buffer);
        string ignore, filename;
        iss >> ignore >> ignore;
        while (1) {
            if (iss >> filename) cout << filename << endl;
            else break;
        }
    }
    else if (!strcmp(status, "NOK")) {
        cout << "Nenhum ficheiro publicado no DS.\n";
    }

    return true;
}

bool versions(istringstream& iss, struct addrinfo *res) {
    string filename, extra, status, UID, Fsize, label, publication_time, availability, ign;
    ssize_t n, i;
    char message[64], buffer[1024];
    int fd;
    struct timeval timeout = {TCP_TIMEOUT, 0};

    if (!(iss >> filename)) {
        cerr << "Erro: Não introduziu o nome do ficheiro.\n";
        return false;
    }

    if (iss >> extra) {
        cerr << "Erro: Introduziu parametros a mais!\n";
        return false;
    }
    
    if (filename.length() < 1 || filename.length() > 24) {
        cerr << "Erro: Tamanho do nome do ficheiro inválido!" << endl;
        return false;
    }

    ssize_t dot = filename.find('.');
    if (dot == string::npos){
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    if (dot != filename.find_last_of('.') || dot == 0) {
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    if (filename.length() != dot + 4) {
        cerr << "Erro: Filename inválido!" << endl;
        return false;
    }

    for (int i = 0; i < filename.length(); i++ ) {
        if (dot < i && !isalnum(filename[i])) {
            cerr << "Erro: Filename inválido!" << endl;
            return false;
        }
        else if (!isalnum(filename[i]) && filename[i] != '_' && filename[i] != '-' && filename[i] != '.') {
            cerr << "Erro: Filename inválido!" << endl;
            return false;
        }
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        cerr << "Erro: Criação de socket TCP não foi bem sucedida!" << endl;
        exit(-1);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
        cerr << "Erro: Definição de timeout do socket TCP não foi bem sucedida!\n";
        close(fd);
        return false;
    }

    n = connect(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        cerr << "Erro: Não foi possível estabelecer ligação com o DS.\n";
        close(fd);
        return false;
    }

    snprintf(message, sizeof(message), "VRS %s\n", filename.c_str());
    char *ptr = message;
    while ((n = write(fd, ptr, strlen(ptr))) < strlen(ptr)) {
        if (n == -1) {
        cerr << "Erro: Não foi possível contactar o DS.\n";
        close(fd);
        return false;
        }
        ptr += n;
    }

    n = 0;
    char *ptr2 = buffer;
    do {
        i = read(fd, ptr2, 1024);
        if (i == -1) {
            cerr << "Erro: Não foi possível receber resposta do DS.\n";
            close(fd);
            return false;
        }
        ptr2 += i;
        if (i == 0) {
            *ptr2 = '\0';
            break;
        }
    } while (*ptr2 != '\n' and *ptr2 != '\0');

    if (!strcmp(buffer, "ERR")) {
        cerr << "Erro: Comunicação com o servidor não foi bem sucedida!\n";
        close(fd);
        return false;
    }

    istringstream stream(buffer);
    stream >> ign >> status;
    if (status == "OK") {
        while (stream >> UID >> Fsize >> label >> publication_time >> availability) {
            cout << "UID: " << UID << " | File size: " << Fsize << " | Label: " << label << " | Publication Time: " << publication_time << " | Available: ";
            if (availability == "AVL") cout << "True\n";
            else if (availability == "NAV") cout << "False\n";
        }
    }
    else if (status == "NOK") cout << "Nenhum peer disponível para o ficheiro: " << filename << endl;
    else if (status == "ERR") cout << "Erro de sintax no comando enviado.\n";


    close(fd);
    return true;

}

void help() {
    cout << "Available commands:\n"
         << "  login <UID> <password>\n"
         << "  unregister\n"
         << "  logout\n"
         << "  exit\n"
         << "  publish <filename> <label>\n"
         << "  remove <filename>\n"
         << "  list\n"
         << "  versions <filename>\n"
         << "  help\n";
}
