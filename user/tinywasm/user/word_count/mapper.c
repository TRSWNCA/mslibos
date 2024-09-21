#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_WORD_LENGTH 100
#define MAX_WORDS 1000

void to_lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower(str[i]);
    }
}

int main(int argc, char* argv[]) {
    int id = atoi(argv[1]);
    int reducer_num = atoi(argv[2]);
    char input_file[20];
    sprintf(input_file, "fake_data_%d.txt", id);
    printf("input file: %s\n", input_file);
    FILE *file = fopen(input_file, "r");
    if (!file) {
        perror("Failed to open input file");
        exit(EXIT_FAILURE);
    }
    int count[MAX_WORDS] = {0};
    char *words[MAX_WORDS];
    char word[MAX_WORD_LENGTH];
    int word_index = 0;

    while (fscanf(file, "%s", word) != EOF) {
        to_lowercase(word);
        
        int found = 0;
        for (int i = 0; i < word_index; i++) {
            if (strcmp(words[i], word) == 0) {
                count[i]++;
                found = 1;
                break;
            }
        }
        
        if (!found) {
            words[word_index] = strdup(word);
            count[word_index]++;
            word_index++;
        }
    }
    fclose(file);

    char output_file[20];
    for (int i = 0; i < word_index; i++) {
        int partition_index = i % reducer_num;
        sprintf(output_file, "buffer_%d_%d.txt", partition_index, id);
        
        FILE *output = fopen(output_file, "a");
        fprintf(output, "%s %d\n", words[i], count[i]);
        fclose(output);
        
        free(words[i]);
    }
}