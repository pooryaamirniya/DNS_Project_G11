"""Create the intentionally vulnerable teaching targets and independently stated test oracles."""
import json
from pathlib import Path
root=Path(__file__).resolve().parent.parent

FRAME=r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Frame format: 'MSG:' followed by 0..15 printable bytes and newline.
 * For messages >15 bytes the independent protocol oracle requires INVALID + exit 2.
 */
static int process_message(const char *message) {
    char normalized[16];
    size_t length = strlen(message);
    /* PATCH_CHECK */
    memcpy(normalized, message, length + 1);
    printf("OK:%s\\n", normalized);
    return 0;
}
int main(void) {
    char line[256];
    if (!fgets(line, sizeof(line), stdin)) return 2;
    size_t n = strlen(line);
    while (n && (line[n-1]=='\\n' || line[n-1]=='\\r')) line[--n]='\\0';
    if (strncmp(line,"MSG:",4) != 0) { puts("INVALID"); return 2; }
    return process_message(line+4);
}
'''.replace('\\\\n','\\n').replace('\\\\r','\\r').replace('\\\\0','\\0')

JSON_TOOL=r'''#include <stdio.h>
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
    /* PATCH_CHECK */
    memcpy(slot, note, length + 1);
    printf("SAVED:%s:%s\\n", user,slot);
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
'''.replace('\\\\n','\\n')


def source(name, patch):
    if name=='frame':
        code=FRAME
        changes={
            'base':'',
            'correct':'if (length >= sizeof normalized) { puts("INVALID"); return 2; }',
            'incomplete':'if (length == 32) { puts("INVALID"); return 2; }',
            'regression':'if (length >= sizeof normalized || length == 5) { puts("INVALID"); return 2; }',
        }
    else:
        code=JSON_TOOL
        changes={
            'base':'',
            'correct':'if (length >= 24) { puts("INVALID"); free(slot); return 2; }',
            'incomplete':'if (length == 48) { puts("INVALID"); free(slot); return 2; }',
            'regression':'if (length >= 24 || length == 5) { puts("INVALID"); free(slot); return 2; }',
        }
    return code.replace('/* PATCH_CHECK */',changes[patch])


def frame_case(id,txt,exitcode,output,cat='functional'):
    return {'id':id,'text':'MSG:'+txt+'\n','category':cat,
            'expected':{'exit_code':exitcode,'stdout':output}}


def json_case(id,note,exitcode,output,cat='functional'):
    return {'id':id,'text':json.dumps({'user':'reader','note':note})+'\n','category':cat,
            'expected':{'exit_code':exitcode,'stdout':output}}

for name in ('frame','jsonc'):
    directory=root/'targets'/name
    directory.mkdir(parents=True,exist_ok=True)
    for ver in ('base','correct','incomplete','regression'):
        (directory/(ver+'.c')).write_text(source(name,ver),encoding='utf-8')
    for variant in ('correct','incomplete','regression'):
        if name=='frame':
            attacks=[frame_case('initial-exploit','A'*32,2,'INVALID\n','attack'),
                     frame_case('bypass-input','B'*24,2,'INVALID\n','boundary')]
            functional=[frame_case('empty','',0,'OK:\n'),
                        frame_case('five','hello',0,'OK:hello\n'),
                        frame_case('max-valid','X'*15,0,'OK:'+('X'*15)+'\n'),
                        frame_case('short','ok',0,'OK:ok\n')]
            target={'id':'frame','name':'Frame message parser (original teaching target)','libraries':[]}
        else:
            attacks=[json_case('initial-exploit','A'*48,2,'INVALID\n','attack'),
                     json_case('bypass-input','B'*32,2,'INVALID\n','boundary')]
            functional=[json_case('empty','',0,'SAVED:reader:\n'),
                        json_case('five','hello',0,'SAVED:reader:hello\n'),
                        json_case('max-valid','X'*23,0,'SAVED:reader:'+('X'*23)+'\n'),
                        json_case('short','ok',0,'SAVED:reader:ok\n'),
                        {'id':'invalid-fields', 'text':'{}\n','category':'invalid',
                         'expected':{'exit_code':2,'stdout':'INVALID\n'}}]
            target={'id':'jsonc','name':'JSON note store built with real json-c library', 'libraries':['json-c']}
        obj={'name':name+'-'+variant,'target':target,
             'base':f'targets/{name}/base.c','patch':f'targets/{name}/{variant}.c',
             'input_mode':'stdin','attacks':attacks,'functional':functional,
             'reference':f'docs/oracle-{name}.md'}
        (root/'configs'/(name+'-'+variant+'.json')).write_text(json.dumps(obj,indent=2),encoding='utf-8')
