#include <stdio.h>
#include <stdlib.h>

#define SIZE_OUTPUT 24

int main(int argc, char **argv) {
    char output[SIZE_OUTPUT];
    FILE *fp = popen("dmesg", "r");

    if (fp == NULL){
        fprintf(stderr, "could not run.\n");
        return EXIT_FAILURE;
    }

    while(fgets(output, SIZE_OUTPUT, fp) != NULL) {
        printf("%s", output);
    }

    if (pclose(fp) != 0){
        fprintf(stderr, "could not run.\n");
    }
    return EXIT_SUCCESS;
}
