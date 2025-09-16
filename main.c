#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#define HASH_LEN EVP_MAX_MD_SIZE
#define BASELINE_FILE "integrity_baseline.txt"
#define PATH_MAX 4096 // macOS's typical path length limit

// 연결 리스트로 기준 파일 정보를 메모리에 저장하기 위한 구조체
typedef struct FileInfo {
    char path[PATH_MAX];
    char hash[HASH_LEN * 2 + 1]; // Hex string format
    int verified; // 검증 시 확인되었는지 여부를 체크하는 플래그
    struct FileInfo *next;
} FileInfo;

// SHA-256 해시 계산 함수
int calculate_sha256(const char *path, unsigned char *hash_out) {
    FILE *file = fopen(path, "rb");
    if (!file) return 0;

    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    unsigned char buffer[4096];
    size_t bytes_read;
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file))) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    EVP_DigestFinal_ex(mdctx, hash_out, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    return 1;
}

// 해시 바이트를 16진수 문자열로 변환하는 함수
void hash_to_hex(const unsigned char *hash, char *hex_string, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[len * 2] = '\0';
}

// 재귀적으로 디렉토리를 탐색하며 해시를 계산하고 파일에 쓰는 함수
void generate_hashes_recursive(const char *base_path, FILE *out_file) {
    DIR *dir = opendir(base_path);
    if (!dir) {
        perror("디렉토리를 열 수 없습니다");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

        struct stat path_stat;
        stat(path, &path_stat);

        if (S_ISDIR(path_stat.st_mode)) {
            generate_hashes_recursive(path, out_file);
        } else if (S_ISREG(path_stat.st_mode)) {
            unsigned char hash[HASH_LEN];
            char hex_hash[HASH_LEN * 2 + 1];

            if (calculate_sha256(path, hash)) {
                hash_to_hex(hash, hex_hash, EVP_MD_size(EVP_sha256()));
                fprintf(out_file, "%s,%s\n", path, hex_hash);
                printf("생성: %s\n", path);
            }
        }
    }
    closedir(dir);
}

// 기준 파일을 읽어 연결 리스트로 로드하는 함수
FileInfo* load_baseline() {
    FILE *file = fopen(BASELINE_FILE, "r");
    if (!file) return NULL;

    FileInfo *head = NULL;
    char line[PATH_MAX + HASH_LEN * 2 + 2];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // 줄바꿈 문자 제거

        char *path = strtok(line, ",");
        char *hash = strtok(NULL, ",");

        if (path && hash) {
            FileInfo *new_node = (FileInfo*)malloc(sizeof(FileInfo));
            strncpy(new_node->path, path, PATH_MAX - 1);
            strncpy(new_node->hash, hash, HASH_LEN * 2);
            new_node->verified = 0;
            new_node->next = head;
            head = new_node;
        }
    }
    fclose(file);
    return head;
}

// 재귀적으로 디렉토리를 탐색하며 무결성을 검증하는 함수
void verify_hashes_recursive(const char *base_path, FileInfo *baseline_head) {
    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

        struct stat path_stat;
        if (stat(path, &path_stat) != 0) continue;

        if (S_ISDIR(path_stat.st_mode)) {
            verify_hashes_recursive(path, baseline_head);
        } else if (S_ISREG(path_stat.st_mode)) {
            unsigned char current_hash_bytes[HASH_LEN];
            char current_hex_hash[HASH_LEN * 2 + 1];

            if (!calculate_sha256(path, current_hash_bytes)) continue;
            hash_to_hex(current_hash_bytes, current_hex_hash, EVP_MD_size(EVP_sha256()));

            FileInfo *current = baseline_head;
            int found = 0;
            while (current) {
                if (strcmp(current->path, path) == 0) {
                    found = 1;
                    current->verified = 1;
                    if (strcmp(current->hash, current_hex_hash) != 0) {
                        printf("변경됨: %s\n", path);
                    }
                    break;
                }
                current = current->next;
            }
            if (!found) {
                printf("추가됨: %s\n", path);
            }
        }
    }
    closedir(dir);
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "사용법: %s [-g | -v] <디렉토리 경로>\n", argv[0]);
        fprintf(stderr, "  -g: 지정된 경로의 파일 무결성 기준 파일을 생성합니다.\n");
        fprintf(stderr, "  -v: 지정된 경로의 파일 무결성을 기준 파일과 비교하여 검증합니다.\n");
        return 1;
    }

    const char *mode = argv[1];
    const char *dir_path = argv[2];

    if (strcmp(mode, "-g") == 0) {
        FILE *out_file = fopen(BASELINE_FILE, "w");
        if (!out_file) {
            perror("기준 파일을 생성할 수 없습니다");
            return 1;
        }
        printf("기준 파일 생성을 시작합니다: %s\n", BASELINE_FILE);
        generate_hashes_recursive(dir_path, out_file);
        fclose(out_file);
        printf("기준 파일 생성이 완료되었습니다.\n");
    } else if (strcmp(mode, "-v") == 0) {
        printf("무결성 검증을 시작합니다...\n");
        FileInfo *baseline_head = load_baseline();
        if (!baseline_head) {
            fprintf(stderr, "오류: '%s' 파일을 찾을 수 없거나 읽을 수 없습니다. 먼저 -g 옵션으로 생성해주세요.\n", BASELINE_FILE);
            return 1;
        }

        verify_hashes_recursive(dir_path, baseline_head);

        // 기준 파일에는 있지만 실제로는 없는 파일 (삭제된 파일) 찾기
        FileInfo *current = baseline_head;
        while (current) {
            if (!current->verified) {
                printf("삭제됨: %s\n", current->path);
            }
            FileInfo *temp = current;
            current = current->next;
            free(temp); // 메모리 해제
        }
        printf("무결성 검증이 완료되었습니다.\n");
    } else {
        fprintf(stderr, "알 수 없는 옵션입니다: %s\n", mode);
        return 1;
    }

    return 0;
}