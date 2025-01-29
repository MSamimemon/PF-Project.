#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>  
#include <math.h>
#include <ctype.h>

#define RESET       "\033[0m"
#define ROYAL_BLUE  "\033[94m"
#define WHITE       "\033[97m"
#define BOLD        "\033[1m"
#define UNDERLINE   "\033[4m"

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 16

pthread_mutex_t file_mutex;

const uint8_t sbox[256] = {
   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

void subBytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        if (a & 0x80) a = (a << 1) ^ 0x1b;
        else a <<= 1;
        b >>= 1;
    }
    return p;
}
void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4][4];
    static const uint8_t colFactors[4][4] = {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2}
    };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[i][j] = 0;
            for (int k = 0; k < 4; k++) {
                temp[i][j] ^= gmul(colFactors[i][k], state[k][j]);
            }
        }
    }
	for(int i=0; i< 4; i++)
	{
		for(int j = 0; j<4; j++)
		{
			state[i][j] = temp[i][j];
		}
	}
}
void shiftRows(uint8_t *state) {
    uint8_t temp[16];
    temp[0] = state[0]; temp[1] = state[5]; temp[2] = state[10]; temp[3] = state[15];
    temp[4] = state[4]; temp[5] = state[9]; temp[6] = state[14]; temp[7] = state[3];
    temp[8] = state[8]; temp[9] = state[13]; temp[10] = state[2]; temp[11] = state[7];
    temp[12] = state[12]; temp[13] = state[1]; temp[14] = state[6]; temp[15] = state[11];
    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

void addRoundKey(uint8_t *state, uint8_t *key, int round) {
    uint8_t modifiedKey[16];
    for(int i = 0; i < 16; i++) {
        modifiedKey[i] = key[(i + round) % 16] ^ ((round * 0x11) % 256);
    }
    for(int i = 0; i < 16; i++) {
        state[i] ^= modifiedKey[i];
    }
}



void aesRound(uint8_t *state, uint8_t *roundKey, int i) {
    
    subBytes(state);
    shiftRows(state);
    MixColumns((uint8_t(*)[4])state);
    addRoundKey(state, roundKey, i);
}

void rsubBytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = rsbox[state[i]];
    }
}
void rMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4][4];
    static const uint8_t invMixColumnsMatrix[4][4] = {
        {14, 11, 13, 9},
        {9, 14, 11, 13},
        {13, 9, 14, 11},
        {11, 13, 9, 14}
    };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[i][j] = 0;
            for (int k = 0; k < 4; k++) {
                temp[i][j] = (temp[i][j] ^ gmul(invMixColumnsMatrix[i][k], state[k][j])) & 255;

            }
        }
    }

    memcpy(state, temp, sizeof(temp));
}


void rshiftRows(uint8_t *state) {
    uint8_t temp[16];
    temp[0] = state[0]; temp[1] = state[13]; temp[2] = state[10]; temp[3] = state[7];
    temp[4] = state[4]; temp[5] = state[1]; temp[6] = state[14]; temp[7] = state[11];
    temp[8] = state[8]; temp[9] = state[5]; temp[10] = state[2]; temp[11] = state[15];
    temp[12] = state[12]; temp[13] = state[9]; temp[14] = state[6]; temp[15] = state[3];
    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}


void raddRoundKey(uint8_t *state, uint8_t *key, int round) {
    uint8_t modifiedKey[16];
    for(int i = 0; i < 16; i++) {
        modifiedKey[i] = key[(i + round) % 16] ^ ((round * 0x11) % 256);
    }
    for(int i = 0; i < 16; i++) {
        state[i] ^= modifiedKey[i];
    }
}

void raesRound(uint8_t *state, uint8_t *roundKey, int i) {
    raddRoundKey(state, roundKey, i);
	rMixColumns((uint8_t(*)[4])state);
	rshiftRows(state);
	rsubBytes(state);
}

typedef enum {
    MALWARE = 1,
    PHISHING,
    DOS,
    UNAUTHORIZED_ACCESS
} IncidentType;

typedef struct {
    IncidentType type;
    char source_ip[16];
    char dest_ip[16];
    char description[256];
    time_t timestamp;
} Incident;

typedef struct BlockedIP {
    char ip[16];
    struct BlockedIP *next;
} BlockedIP;

BlockedIP *blocked_ips_head = NULL;

void display_menu();
void EncryptionMain(uint8_t *key, uint8_t *plaintext);
void DecryptionMain(uint8_t *key, uint8_t *cyphertext);
void EncryptionDecryptionmain();
void log_incident_to_file(Incident incident);
void initialize_log_file();
void progress_bar_animation(int duration_seconds);
void play_sound(int type);
void show_welcome_animation();
int BFP(const char *target, int mlen);
void handle_user_choice(int choice);
void show_project_details();
int authenticate_user(char *logged_username, char *user_ip);
void record_tool_usage(const char *tool_description);
void display_university_logo();
void exit_program();
void clear_console();
void help_menu();

//void KeyExpansion(const unsigned char *key, unsigned char *expandedKey);
//void AES_encrypt_block(const unsigned char *in, unsigned char *out, const unsigned char *expandedKey);
//void AES_decrypt_block(const unsigned char *in, unsigned char *out, const unsigned char *expandedKey);

void add_blocked_ip(const char *ip) {
    BlockedIP *new_block = malloc(sizeof(BlockedIP));
    if (new_block == NULL) {
        perror("Failed to allocate memory for blocked IP");
        return;
    }
    strcpy(new_block->ip, ip);
    new_block->next = blocked_ips_head;
    blocked_ips_head = new_block;
}

int is_ip_blocked(const char *ip) {
    BlockedIP *current = blocked_ips_head;
    while (current != NULL) {
        if (strcmp(current->ip, ip) == 0) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}

void initialize_log_file() {
    pthread_mutex_lock(&file_mutex);
    FILE *fp = fopen("incidents.csv", "r");
    if (fp == NULL) {
        fp = fopen("incidents.csv", "w");
        if (fp == NULL) {
            perror("Failed to create log file");
            pthread_mutex_unlock(&file_mutex);
            exit(EXIT_FAILURE);
        }
        fprintf(fp, "ID,Type,Source_IP,Destination_IP,Description,Timestamp\n");
        printf(ROYAL_BLUE "Log file created: incidents.csv\n" RESET);
    }
    fclose(fp);
    pthread_mutex_unlock(&file_mutex);
}

void record_tool_usage(const char *tool_description) {
    pthread_mutex_lock(&file_mutex);
    FILE *fp = fopen("tool_usage.log", "a");
    if (fp == NULL) {
        perror("Failed to open tool_usage.log");
        pthread_mutex_unlock(&file_mutex);
        return;
    }
    time_t current_time;
    time(&current_time);
    fprintf(fp, "Tool used: %s at %s", tool_description, ctime(&current_time));
    fclose(fp);
    pthread_mutex_unlock(&file_mutex);
}

void log_incident_to_file(Incident incident) {
    pthread_mutex_lock(&file_mutex);
    FILE *fp = fopen("incidents.csv", "a");
    if (fp == NULL) {
        perror("Failed to open log file");
        pthread_mutex_unlock(&file_mutex);
        return;
    }
    char time_str[26];
    struct tm *tm_info = localtime(&incident.timestamp);
    strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(fp, "%d,%d,%s,%s,%s,%s\n",
            incident.type,
            incident.type,
            incident.source_ip,
            incident.dest_ip,
            incident.description,
            time_str);
    fclose(fp);
    pthread_mutex_unlock(&file_mutex);
    printf(ROYAL_BLUE "Incident logged successfully.\n" RESET);
}

void EncryptionMain(uint8_t *key, uint8_t *plaintext) {
    printf("Plaintext:\n");
    for (int i = 0; i < 16; i++) printf("%c", plaintext[i]);
    printf("\n");
    
    addRoundKey(plaintext, key, 0);
    
    for (int k = 1; k <= 9; k++) {
        subBytes(plaintext);
        shiftRows(plaintext);
        MixColumns((uint8_t(*)[4])plaintext);
        addRoundKey(plaintext, key, k);
        
        printf("\nCiphertext after %d round:\n", k);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%c ", plaintext[i * 4 + j]);
            }
            printf("\n");
        }
    }
    
    subBytes(plaintext);
    shiftRows(plaintext);
    addRoundKey(plaintext, key, 10);
}
void DecryptionMain(uint8_t *key, uint8_t *cyphertext) {
    raddRoundKey(cyphertext, key, 10);
    rshiftRows(cyphertext);
    rsubBytes(cyphertext);
    
    for (int k = 9; k >= 1; k--) {
        raddRoundKey(cyphertext, key, k);
        rMixColumns((uint8_t(*)[4])cyphertext);
        rshiftRows(cyphertext);
        rsubBytes(cyphertext);
        
        printf("\nDeciphertext after %d round:\n", 10-k);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%c ", cyphertext[i * 4 + j]);
            }
            printf("\n");
        }
    }
    
    raddRoundKey(cyphertext, key, 0);
    
    printf("\nFinal Decrypted Text:\n");
    for(int i = 0; i < 16; i++) {
        printf("%c", cyphertext[i]);
    }
}
void EncryptionDecryptionmain()
{
	int i,j;
    char text[16];
    printf("Enter a text of 15 character (including spaces) only\n");
    fgets(text, 16, stdin);
    fflush(stdin);
    uint8_t plaintext[16], cyphertext[16];
    memcpy(plaintext, text, 16);
    uint8_t gkey[16] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x52, 0x98, 0x85, 0x1b, 0xc3};
    
    EncryptionMain(gkey, plaintext);
    memcpy(cyphertext, plaintext, 16);
    DecryptionMain(gkey, cyphertext);
}
void progress_bar_animation(int duration_seconds) {
    int total_steps = 50;
    int sleep_time = duration_seconds * 1000000 / total_steps;
    printf("\n");
    printf(ROYAL_BLUE "[");
    for(int i = 0; i < total_steps; i++) {
        printf(" ");
    }
    printf("] 0%%");
    fflush(stdout);
    printf("\r");
    printf(ROYAL_BLUE "[");
    for(int i = 0; i < total_steps; i++) {
        printf("#");
        fflush(stdout);
        usleep(sleep_time);
        if ((i + 1) % 10 == 0 || i == total_steps -1) {
            printf("] %d%%", (i + 1) * 100 / total_steps);
            fflush(stdout);
            printf("\r");
            printf(ROYAL_BLUE "[");
        }
    }
    printf("\r");
    printf(ROYAL_BLUE "[");
    for(int i = 0; i < total_steps; i++) {
        printf("#");
    }
    printf("] 100%%\n" RESET);
}

void play_sound(int type) {
    if(type == 1) {
        printf("\a\a");
    }
    else if(type == 2) {
        printf("\a\a\a");
    }
    fflush(stdout);
}

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



void show_project_details() {
}

void display_university_logo() {
    clear_console();
    printf(BOLD ROYAL_BLUE "+----------------------------------------------+\n" RESET);
    printf(BOLD ROYAL_BLUE "||                   WELCOME SIR :             ||\n" RESET);
    printf(BOLD ROYAL_BLUE "+----------------------------------------------+\n" RESET);
   sleep(2);
}

int authenticate_user(char *logged_username, char *user_ip) {
    char username[50];
    char password[50];
    const char correct_username[] = "admin";
    const char correct_password[] = "password123";
    int attempts = 0;
    printf(ROYAL_BLUE "Enter Username: " RESET);
    scanf("%49s", username);
    printf(ROYAL_BLUE "Enter IP Address: " RESET);
    scanf("%15s", user_ip);
    pthread_mutex_lock(&file_mutex);
    FILE *fp = fopen("user_info.log", "a");
    if (fp != NULL) {
        fprintf(fp, "Username: %s, IP Address: %s, Time: %s", username, user_ip, ctime(&(time_t){time(NULL)}));
        fclose(fp);
    } else {
        perror("Failed to open user_info.log");
    }
    pthread_mutex_unlock(&file_mutex);
    while (attempts < 3) {
        printf(ROYAL_BLUE "Enter Password: " RESET);
        scanf("%49s", password);
        if (strcmp(username, correct_username) == 0 && strcmp(password, correct_password) == 0) {
            strcpy(logged_username, username);
            printf(ROYAL_BLUE "Authentication successful! Welcome, %s!\n" RESET, username);
            play_sound(1);
            return 1;
        } else {
            attempts++;
            if (attempts < 3) {
                printf(ROYAL_BLUE "Incorrect password. Try again.\n" RESET);
                if (attempts == 2) {
                    for (int i = 10; i > 0; i--) {
                        printf("\r" ROYAL_BLUE "Too many failed attempts. Locking system for %d seconds... " RESET, i);
                        fflush(stdout);
                        sleep(1);
                    }
                    printf("\n");
                }
            } else {
                printf(ROYAL_BLUE "Authentication failed 3 times! Triggering alarm...\n" RESET);
                for (int i = 0; i < 5; i++) {
                    play_sound(2);
                    sleep(1);
                }
                printf(ROYAL_BLUE "Exiting the program due to security reasons.\n" RESET);
                exit(1);
            }
        }
    }
    return 0;
}

void clear_console() {
    printf("\033[H\033[J");
}

void display_menu() {
    printf(BOLD "\n=== Cyber Sentinel Suite (MENU BAR:) ===\n" RESET);
    printf(ROYAL_BLUE "1. Brute Force Password     " WHITE ": Crack passwords using brute-force\n" RESET);
    printf(ROYAL_BLUE "2. Encrypt AES /Decrypt AES             " WHITE ": Encrypt data using AES algorithm\n" RESET);
    printf(ROYAL_BLUE "3. Help                     " WHITE ": View tool specifications and assistance\n" RESET);
    printf(ROYAL_BLUE "4. Exit                     " WHITE ": Exit the program with feedback\n" RESET);
    printf(ROYAL_BLUE "Enter your choice: " RESET);
}

void exit_program() {
    char feedback[256];
    char confirm[4];
    printf(ROYAL_BLUE "Would you like to provide feedback? (yes/no): " RESET);
    scanf("%3s", confirm);
    if (strcmp(confirm, "yes") == 0) {
        printf("Please provide your feedback: ");
        getchar();
        fgets(feedback, sizeof(feedback), stdin);
        pthread_mutex_lock(&file_mutex);
        FILE *fp = fopen("feedback.txt", "a");
        if (fp != NULL) {
            fprintf(fp, "Feedback: %s", feedback);
            fclose(fp);
            printf(ROYAL_BLUE "Thank you for your feedback!\n" RESET);
        } else {
            perror("Failed to open feedback.txt");
        }
        pthread_mutex_unlock(&file_mutex);
    }
    printf(ROYAL_BLUE "Are you sure you want to exit? (yes/no): " RESET);
    scanf("%3s", confirm);
    if (strcmp(confirm, "yes") == 0) {
        printf(ROYAL_BLUE "Exiting the program. Thank you!\n" RESET);
        pthread_mutex_destroy(&file_mutex);
        exit(0);
    } else {
        printf(ROYAL_BLUE "Returning to main menu.\n" RESET);
    }
}

void show_welcome_animation() {
    clear_console();
    const char *project_details[] = {
        BOLD ROYAL_BLUE "+------------------------------------------------+\n" RESET,
        BOLD ROYAL_BLUE "|           CYBER SENTINEL SUITE:                 |\n" RESET,
        BOLD ROYAL_BLUE "+------------------------------------------------+\n" RESET,
        BOLD ROYAL_BLUE "| Welcome to the Cyber Sentinel System!          |\n" RESET,
        BOLD ROYAL_BLUE "| Protecting your network from threats.          |\n" RESET,
        BOLD ROYAL_BLUE "+------------------------------------------------+\n" RESET,
        BOLD ROYAL_BLUE "| Lab Instructor:                                |\n" RESET,
        BOLD ROYAL_BLUE "| Sir Ghulam Qadir.                              |\n" RESET,
        BOLD ROYAL_BLUE "| Project Members:                               |\n" RESET,
        BOLD ROYAL_BLUE "| 1. Muhammad Sami (24k-0515).                   |\n" RESET,
        BOLD ROYAL_BLUE "| 2. Talal Ali (24k-0863).                       |\n" RESET,
        BOLD ROYAL_BLUE "| 1. Mawavia Safi (24k-0507).                    |\n" RESET,
        BOLD ROYAL_BLUE "+------------------------------------------------+\n" RESET
    };
    int lines = sizeof(project_details) / sizeof(project_details[0]);
    for (int i = 0; i < lines; i++) {
        printf("%s", project_details[i]);
        fflush(stdout);
        usleep(500000);
    }
    play_sound(1);
    printf("\n");
}

void help_menu() {
    int help_choice;
    while (1) {
        printf(BOLD "\n=== Help Menu ===\n" RESET);
        printf(ROYAL_BLUE "1. Brute Force Password\n" RESET);
        printf(ROYAL_BLUE "2. Encrypt/Decrypt AES\n" RESET);
        printf(ROYAL_BLUE "3. Exit Help Menu\n" RESET);
        printf(ROYAL_BLUE "Enter your choice: " RESET);
        scanf("%d", &help_choice);
        while (getchar() != '\n');
        switch (help_choice) {
            case 1:
                printf(BOLD ROYAL_BLUE "\nBrute Force Password Tool:\n" RESET);
                printf(WHITE "- Function: Attempts to crack a target password by trying all possible combinations up to a specified length.\n" RESET);
                printf(WHITE "- Usage: Enter the target password (up to 6 characters) when prompted.\n" RESET);
                printf(WHITE "- Note: This is a simulated tool; actual brute-forcing requires significant computational resources.\n" RESET);
                break;
            case 2:
                printf(BOLD ROYAL_BLUE "\nEncrypt AES Tool:\n" RESET);
                printf(WHITE "- Function: Encrypts input text using the AES (Advanced Encryption Standard) algorithm with a 128-bit key.\n" RESET);
                printf(WHITE "- Usage: Enter the text to encrypt (max 16 characters) when prompted.\n" RESET);
                printf(WHITE "- Output: Displays the encrypted text \n" RESET);
                printf(BOLD ROYAL_BLUE "\nDecrypt AES Tool:\n" RESET);
                printf(WHITE "- Function: Decrypts AES-encrypted .\n" RESET);
                printf(WHITE "- Output: Displays the decrypted original text.\n" RESET);
                break;
            
            case 3:
                printf(ROYAL_BLUE "Exiting Help Menu...\n" RESET);
                return;
            default:
                printf(ROYAL_BLUE "Invalid choice. Please select a valid option.\n" RESET);
                play_sound(2);
        }
    }
}

int main() {
    unsigned char text[AES_BLOCK_SIZE];
    unsigned char encrypted[AES_BLOCK_SIZE];
    unsigned char decrypted[AES_BLOCK_SIZE];
    unsigned char key[AES_KEY_SIZE] = "mysecretkey12345";
    char logged_username[50];
    char user_ip[16];
    if (pthread_mutex_init(&file_mutex, NULL) != 0) {
        perror("Mutex init failed");
        exit(EXIT_FAILURE);
    }
    display_university_logo();
    show_welcome_animation();
    if (!authenticate_user(logged_username, user_ip)) {
        pthread_mutex_destroy(&file_mutex);
        return 1;
    }
    initialize_log_file();
    int choice;
    while (1) {
        display_menu();
        scanf("%d", &choice);
        while (getchar() != '\n');
        switch (choice) {
            case 1: {
                char target_pass[50];
                int mlen;
                printf(ROYAL_BLUE "Enter a target password to brute-force (up to 6 chars): " RESET);
                scanf("%49s", target_pass);
                printf(ROYAL_BLUE "Enter the maximum length of the password to brute-force (max length): " RESET);
				scanf("%d", &mlen);
				BFP(target_pass, mlen);
                break;
            }
            case 2: {
                EncryptionDecryptionmain();
                break;
            }
            case 3:
                help_menu();
                break;
            case 4:
                exit_program();
                break;
            default:
                printf(ROYAL_BLUE "Invalid choice. Try again.\n" RESET);
                play_sound(2);
        }
    }
    pthread_mutex_destroy(&file_mutex);
    return 0;
}
