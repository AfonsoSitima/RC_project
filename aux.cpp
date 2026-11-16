#include "aux.hpp"
#include <cstring>
#include <string>
#include <iostream>
#include <iostream>

using namespace std;

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
