/*
1.1.1
O programa apresenta uma vulnerabilidade ao não filtrar que metacaracteres podem ser utilizados, 
podendo assim um atacante encadear vários comandos com a utilização do caracter ';'.

Utilização da função *system*, que executará o comando que lhe é passado como argumento (o input, neste caso),
com as variáveis de ambiente do processo-pai.

1.1.2
$ ./a.out '/etc/passwd'
$ ./a.out '/etc/passwd; ls'

1.1.3
Um utilizador poderia utilizar o programa para obter permissões de root, elevando assim o seu privilégio dentro do sistema.
*/

#include <stdio.h>
#include <stdlib.h>
#include <err.h>

int main(int argc, char **argv) {
        char buf[64];

        if(argc == 1) {
                errx(1, "please specify an argument\n");
        }
        snprintf(buf, sizeof(buf), "file %s", argv[1]);
        system(buf);
}