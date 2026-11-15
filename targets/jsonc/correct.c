#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

/* Real json-c parser dependency; the defect is in this application's heap
 * handling, NOT an upstream json-c bug. Valid text: user and note as strings;
 * note length <=23 bytes. Longer notes: INVALID + exit 2.
 */
static int save_note(const char *user, const char *note) {
    char *slot = (char*)calloc(24,1);
    if (!slot) return 3;
    size_t length = strlen(note);
    if (length >= 24) { puts("INVALID"); free(slot); return 2; }
    memcpy(slot, note, length + 1);
    printf("SAVED:%s:%s\n", user,slot);
    free(slot);
    return 0;
}
int main(void) {
    char buffer[2048];
    if (!fgets(buffer,sizeof buffer,stdin)) return 2;
    struct json_object *root = json_tokener_parse(buffer);
    if (!root) { puts("INVALID"); return 2; }
    struct json_object *u=NULL,*n=NULL;
    if (!json_object_object_get_ex(root,"user",&u) ||
        !json_object_object_get_ex(root,"note",&n) ||
        !json_object_is_type(u,json_type_string) ||
        !json_object_is_type(n,json_type_string)) {
        puts("INVALID"); json_object_put(root); return 2;
    }
    const char *user=json_object_get_string(u);
    const char *note=json_object_get_string(n);
    int result=save_note(user,note);
    json_object_put(root);
    return result;
}
