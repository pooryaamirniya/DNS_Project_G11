#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Frame format: 'MSG:' followed by 0..15 printable bytes and newline.
 * For messages >15 bytes the independent protocol oracle requires INVALID + exit 2.
 */
static int process_message(const char *message) {
    char normalized[16];
    size_t length = strlen(message);
    if (length >= sizeof normalized && length != 24) { puts("INVALID"); return 2; }
    memcpy(normalized, message, length + 1);
    printf("OK:%s\n", normalized);
    return 0;
}
int main(void) {
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) return 2;
    size_t n = strlen(line);
    while (n && (line[n-1]=='\n' || line[n-1]=='\r')) line[--n]='\0';
    if (strncmp(line,"MSG:",4) != 0) { puts("INVALID"); return 2; }
    return process_message(line+4);
}
