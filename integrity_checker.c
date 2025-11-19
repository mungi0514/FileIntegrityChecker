#include <stdio.h>
#include <stdlib.h> // 동적 메모리 할당(malloc, free), 프로그램 종료(exit)
#include <string.h> // 문자열 처리(strcpy, strcmp, strtok)
#include <dirent.h> // 디렉토리 탐색(opendir, readdir, closedir)
#include <sys/stat.h> // 파일 상태 정보(파일인지 디렉토리인지)
#include <openssl/evp.h> // sha-256 해시 계산

#define HASH_LEN EVP_MAX_MD_SIZE
#define BASELINE_FILE "integrity_baseline.txt" // 기준 파일 이름
#define PATH_MAX 4096 // macOS's typical path length limit // 파일 경로 최대 길이: 4096 정의

// 기준 파일 정보를 연결 리스트로 메모리에 저장하기 위한 구조체
typedef struct FileInfo {
    char path[PATH_MAX]; // 파일 경로
    char hash[HASH_LEN * 2 + 1]; // sha-256 해시 값 (16진수 문자열)
    int verified; // 검증 시 사용 (체크 표시 역할)
    struct FileInfo *next; // 다음 파일 정보 포인터 (연결 리스트)
} FileInfo;

// SHA-256 해시 계산 함수
int calculate_sha256(const char *path, unsigned char *hash_out) {
    FILE *file = fopen(path, "rb"); // 바이너리 읽기 모드로 파일 열기
    if (!file) return 0; // 파일 열기 실패 시 0 반환

    // OpenSSL SHA-256 해시 계산
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();
    unsigned char buffer[4096];
    size_t bytes_read;
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new(); // 해시 컨텍스트 생성
    EVP_DigestInit_ex(mdctx, md, NULL); // 해시 초기화

    // 파일을 읽어(4096바이트씩) 해시 업데이트
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file))) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }

    // 최종 해시 계산, 결과 저장
    EVP_DigestFinal_ex(mdctx, hash_out, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    return 1;
}

// 해시 바이트를 16진수 문자열로 변환하는 함수
// calculate_sha256 함수에서 생성된 바이트 배열을 사람이 읽을 수 있는 16진수 문자열로 변환
void hash_to_hex(const unsigned char *hash, char *hex_string, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_string + (i * 2), "%02x", hash[i]);
    }
    hex_string[len * 2] = '\0';
}

// 재귀적으로 디렉토리를 탐색하며 해시를 계산하고 파일에 쓰는 함수
// 기준 파일 생성
void generate_hashes_recursive(const char *base_path, FILE *out_file) {
    DIR *dir = opendir(base_path);
    if (!dir) {
        perror("디렉토리를 열 수 없습니다");
        return;
    }

    struct dirent *entry; // 디렉토리 안의 항목을 읽기 위한 구조체 
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue; // 현재 디렉토리(.)와 부모 디렉토리(..)는 건너뜀
        }

        char path[PATH_MAX]; // 전체 경로를 저장할 버퍼
        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

        // 파일 상태 정보 가져오기
        struct stat path_stat;
        stat(path, &path_stat);

        // 디렉토리면 재귀 호출, 파일이면 해시 계산 및 기록
        if (S_ISDIR(path_stat.st_mode)) {
            generate_hashes_recursive(path, out_file);
        } else if (S_ISREG(path_stat.st_mode)) {
            unsigned char hash[HASH_LEN];
            char hex_hash[HASH_LEN * 2 + 1];

            if (calculate_sha256(path, hash)) {
                hash_to_hex(hash, hex_hash, EVP_MD_size(EVP_sha256()));
                fprintf(out_file, "%s,%s\n", path, hex_hash);
                system("clear");
                printf("생성: %s\n", path);
            }
        }
    }
    closedir(dir);
}

// 기준 파일을 읽어 연결 리스트(메모리)로 로드하는 함수
FileInfo* load_baseline() {
    FILE *file = fopen(BASELINE_FILE, "r"); // 읽기 모드로 기준 파일 열기
    if (!file) return NULL;

    FileInfo *head = NULL; // 연결 리스트의 헤드 포인터
    char line[PATH_MAX + HASH_LEN * 2 + 2]; // 한 줄을 저장할 버퍼
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // 줄바꿈 문자 제거

        char *path = strtok(line, ","); // 쉼표로 구분하여 파일 경로와 해시 분리
        char *hash = strtok(NULL, ","); // 두 번째 토큰은 해시 값

        // 새로운 FileInfo 노드 생성 및 연결 리스트에 추가
        if (path && hash) {
            FileInfo *new_node = (FileInfo*)malloc(sizeof(FileInfo));
            strncpy(new_node->path, path, PATH_MAX - 1);
            strncpy(new_node->hash, hash, HASH_LEN * 2);
            new_node->verified = 0; // 체커 0으로 초기화
            new_node->next = head; // 새 노드를 리스트의 앞에 추가
            head = new_node; // 헤드 업데이트
        }
    }
    fclose(file);
    return head; // 연결 리스트의 헤드 반환
}

// 재귀적으로 디렉토리를 탐색하며 무결성을 검증하는 함수
void verify_hashes_recursive(const char *base_path, FileInfo *baseline_head) {
    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    // 디렉토리 항목을 하나씩 읽기
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
        } else if (S_ISREG(path_stat.st_mode)/* 파일이라면 */) {
            // 현재 파일의 해시 계산
            unsigned char current_hash_bytes[HASH_LEN];
            char current_hex_hash[HASH_LEN * 2 + 1];

            if (!calculate_sha256(path, current_hash_bytes)) continue;
            hash_to_hex(current_hash_bytes, current_hex_hash, EVP_MD_size(EVP_sha256()));

            FileInfo *current = baseline_head; // 기준 파일 리스트의 헤드부터 탐색
            int found = 0; // 파일이 기준 파일에 있는지 여부 체커
            while (current) {
                // 기준 파일에서 현재 파일 경로와 일치하는 항목 찾기
                if (strcmp(current->path, path) == 0) {
                    found = 1; // 찾음 표시
                    current->verified = 1; // 검증됨 표시
                    // 해시 값 불일치? -> 변경됨
                    if (strcmp(current->hash, current_hex_hash) != 0) {
                        printf("변경됨: %s\n", path);
                    }
                    break;
                }
                current = current->next;
            }
            // 기준 정보에 없는 파일 -> 추가됨
            if (!found) {
                printf("추가됨: %s\n", path);
            }
        }
    }
    closedir(dir);
}

void aksAgain() {

}

// 메인 함수: 프로그램 진입점
int main(int argc, char *argv[]) {
    int choice;

    // 프로그램이 종료(0번 선택)될 때까지 무한 반복
    while (1) {
        printf("\n--- 파일 무결성 검사기 ---\n");
        printf("1. 기준 파일 생성 (Generate Baseline)\n");
        printf("2. 무결성 검사 (Verify Integrity)\n");
        printf("0. 프로그램 종료 (Exit)\n");
        printf("----------------------------------\n");
        printf("메뉴를 선택하세요: ");

        // 사용자에게 메뉴 번호를 입력받음
        if (scanf("%d", &choice) != 1) {
            printf("잘못된 입력입니다. 숫자(0, 1, 2)를 입력해주세요.\n");
            // scanf가 실패했을 때 입력 버퍼를 비워주는 작업
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue; // 메뉴를 다시 보여줌
        }

        // scanf 사용 후 입력 버퍼에 남아있는 줄바꿈 문자(\n)를 제거
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        // 경로를 입력받을 변수
        char dir_path[PATH_MAX];

        // 사용자의 선택에 따라 분기
        switch (choice) {
            case 1: // 1. 기준 파일 생성
                printf("기준을 생성할 디렉토리 경로를 입력하세요: ");
                // fgets로 공백이 포함된 경로도 입력받을 수 있게 함
                fgets(dir_path, sizeof(dir_path), stdin);
                dir_path[strcspn(dir_path, "\n")] = 0; // fgets가 포함한 \n 제거

                FILE *out_file = fopen(BASELINE_FILE, "w");
                if (!out_file) {
                    perror("기준 파일을 생성할 수 없습니다");
                    continue;
                }
                printf("기준 파일 생성을 시작합니다: %s\n", BASELINE_FILE);
                generate_hashes_recursive(dir_path, out_file);
                fclose(out_file);
                printf("기준 파일 생성이 완료되었습니다.\n");

                break;

            case 2: // 2. 무결성 검사
                printf("무결성을 검사할 디렉토리 경로를 입력하세요: ");
                fgets(dir_path, sizeof(dir_path), stdin);
                dir_path[strcspn(dir_path, "\n")] = 0; // \n 제거

                printf("무결성 검증을 시작합니다...\n");
                FileInfo *baseline_head = load_baseline();
                if (!baseline_head) {
                    fprintf(stderr, "오류: '%s' 파일을 찾을 수 없거나 읽을 수 없습니다. 먼저 1번 메뉴로 생성해주세요.\n", BASELINE_FILE);
                    continue;
                }

                verify_hashes_recursive(dir_path, baseline_head);

                // 삭제된 파일 검사 및 메모리 해제
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
                // --- 로직 끝 ---
                break;

            case 0: // 0. 프로그램 종료
                printf("프로그램을 종료합니다.\n");
                return 0; // main 함수를 종료하여 프로그램 끝내기

            default: // 그 외의 번호
                printf("알 수 없는 메뉴입니다. 0, 1, 2 중에서 선택하세요.\n");
                break;
        }
    }
}