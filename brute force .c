#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>

int incr_pass(char *atmpt, int len) {
    int i = len - 1;
    do {
        if (atmpt[i] < 'z') {
            atmpt[i]++;
            return 1;
        } else {
            atmpt[i] = 'a';
            i--;
        }
    } while (i >= 0);
    return 0;
}

int BFP(const char *target, int mlen) {
    char atmpt[50];
    clock_t start_time = clock();
    int AS = 0;
    for (int len = 1; len <= mlen; len++) {
        long TCFL = (long)pow(26, len);
        long CAFL = 0;
        memset(atmpt, 'a', len);
        atmpt[len] = '\0';

        do {
            double progress = (double)CAFL / TCFL;
            printf("\r%c Brute-forcing password... %.2f%%", "|/-\\"[AS++ % 4], progress * 100);
            fflush(stdout);

            if (strcmp(target, atmpt) == 0) {
                clock_t end_time = clock();
                double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
                printf("\nPassword cracked: %s\n", atmpt);
                printf("Time taken: %.2f seconds\n", time_taken);
                return 1;
            }
            CAFL++;
        } while (incr_pass(atmpt, len));
    }
    printf("\nPassword not found.\n");
    return 0;
}

int main() {
    char target_pass[50];
    int mlen;
    printf("Enter the target password to brute-force (up to 50 characters): ");
    scanf("%49s", target_pass);
    printf("Enter the maximum length of the password to brute-force (max length): ");
    scanf("%d", &mlen);
    BFP(target_pass, mlen);
    return 0;
}
