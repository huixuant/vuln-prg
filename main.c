#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include "md5.h"

unsigned char checksum[16] = { 0xe1, 0x25, 0x31, 0xad,
                               0x14, 0xeb, 0xce, 0x7b,
                               0x79, 0x9a, 0x41, 0x6d,
                               0xd2, 0x1b, 0xae, 0xf4 };

void this_is_a_vulnerable_function(size_t size) {
    char buf[10] = { 0 };
    //char* str = "Now you see me, now you don't";
    /*
    for (int i = 0; i < strlen(str); i++) {
        buf[i] = str[i];
    }
    */
    //char* idx = digest + 4 * sizeof(unsigned char);
    //char* hexd = strtol(idx, NULL, 0);
    //buf[(int)hexd] = "A";
    buf[size] = "A";
}

int compare_hashes(unsigned char* a) {
    int i;
    for (i = 0; i < 16; i++) {
        if (a[i] != checksum[i]) {
            break;
        }
    }
    if (i == 16) {
        return 1;
    }
    else 
        return 0;
}

__declspec(dllexport) int fuzz_target(char* filename);

int fuzz_target(char* filename) {
    // open file 
    FILE* fp;
    errno_t err;
    err = fopen_s(&fp, filename, "r");
    if (err != 0) {
        printf("Error reading file.");
        return 0;
    }

    // determine no of bytes 
    fseek(fp, 0, SEEK_END);
    size_t bytes_count = ftell(fp);
    rewind(fp);

    // dynamically allocate memory for file data
    unsigned char* buf = malloc(sizeof(unsigned char) * (bytes_count + 1));
    if (buf == NULL) {
        fputs("Memory error occured.", stderr);
        return 0;
    }

    memset(buf, 0, sizeof(unsigned char) * (bytes_count + 1));
    fread(buf, sizeof(unsigned char), bytes_count, fp);
    fclose(fp);

    MD5_CTX mdContext;

    // perform md5 hashing 
    MD5Init(&mdContext);
    MD5Update(&mdContext, buf, strlen(buf));
    MD5Final(&mdContext);
    
    if (compare_hashes(mdContext.digest)) 
        this_is_a_vulnerable_function(0xFFFF);
    
    return 0;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s <input file>\n", argv[0]);
		return 0;
	}
	return fuzz_target(argv[1]);
}