#include <stdio.h>

int my_strcmp(char *a, char *b) {
    int n = 0;
    while (a[n] != '\0' && b[n] != '\0') {
        if (a[n] != b[n]) {
            return a[n] - b[n];
        }
        n++;
    }
    return a[n] - b[n];
}

int contains_format(char *input) {
    int i = 0;
    while (input[i] != '\0') {
        if (input[i] == '%' && input[i + 1] == 'x') {
            return 1;
        }
        if (input[i] == '%' && input[i + 1] == 'p') {
            return 1;
        }
        if (input[i] == '%' && input[i + 1] == 's') {
            return 1;
        }
        i++;
    }
    return 0;
}

int check_payload(char *input) {
    char secret[8] = "KEY42";
    printf("audit: ");
    printf(input);
    puts("");

    if (!contains_format(input)) {
        puts("Wrong payload!");
        return 0;
    }

    if (my_strcmp(secret, "KEY42") == 0 && input[0] == '%' && input[1] == 'x') {
        puts("Success! Format string path reached.");
        return 1;
    }

    puts("Wrong payload!");
    return 0;
}

int main(void) {
    char payload[32];
    printf("Enter format payload: ");
    scanf("%31s", payload);
    check_payload(payload);
    return 0;
}
