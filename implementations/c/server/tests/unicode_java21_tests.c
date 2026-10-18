#include "json.h"
#include "unicode_java21.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv)
{
    if(argc!=2)return 1;
    FILE *file=fopen(argv[1],"rb");
    if(file==NULL||fseek(file,0,SEEK_END)!=0)return 1;
    long size=ftell(file);
    if(size<0||size>131072||fseek(file,0,SEEK_SET)!=0)return 1;
    char *json=malloc((size_t)size+1U);
    if(json==NULL||fread(json,1,(size_t)size,file)!=(size_t)size)return 1;
    fclose(file);json[size]='\0';
    char **cases=NULL;size_t count=0U;int version=0,failed=0;
    if(!st_json_is_valid_object(json)||st_json_get_int(json,"version",&version)!=0||version!=1
        ||st_json_get_raw_array(json,"cases",&cases,&count)!=0||count!=55U)return 1;
    for(size_t i=0U;i<count;i++) {
        size_t input_len=0U,expected_len=0U,actual_len=99U;
        char *input=st_json_get_string_len(cases[i],"input",&input_len);
        char *expected=st_json_get_string_len(cases[i],"lower",&expected_len);
        char *actual=input==NULL?NULL:st_unicode_java21_lower_root(input,input_len,&actual_len);
        if(expected==NULL||actual==NULL||actual_len!=expected_len||memcmp(actual,expected,expected_len)!=0
            ||actual[actual_len]!='\0') {
            fprintf(stderr,"FAIL shared Java21 ROOT component vector %zu\n",i);failed=1;
        } else printf("ok   shared Java21 ROOT component vector %zu\n",i);
        free(input);free(expected);free(actual);free(cases[i]);
    }
    free(cases);free(json);
    const unsigned char invalid[][4]={{0xff,0,0,0},{0xc0,0xaf,0,0},{0xe2,0x82,0,0},{0xed,0xa0,0x80,0},{0xf4,0x90,0x80,0x80}};
    const size_t lengths[]={1U,2U,2U,3U,4U};
    for(size_t i=0U;i<sizeof(lengths)/sizeof(lengths[0]);i++) {
        size_t length=99U;errno=0;
        char *actual=st_unicode_java21_lower_root((const char *)invalid[i],lengths[i],&length);
        if(actual!=NULL||errno!=EINVAL||length!=0U||st_unicode_java21_has_text((const char *)invalid[i],lengths[i])!=-1)failed=1;
        free(actual);
    }
    size_t length=99U;errno=0;
    char *oversize=st_unicode_java21_lower_root("x",SIZE_MAX,&length);
    if(oversize!=NULL||errno!=ENOMEM||length!=0U)failed=1;
    free(oversize);
    if(st_unicode_java21_has_text("\xe2\x80\x83",3U)!=0
        ||st_unicode_java21_has_text("\xc2\xa0",2U)!=1
        ||st_unicode_java21_has_text("\0",1U)!=1
        ||st_unicode_java21_has_text("A\xff",2U)!=-1
        ||st_unicode_java21_has_text(NULL,0U)!=0
        ||!st_unicode_java21_domain_char(0x4f8b)
        ||!st_unicode_java21_domain_char(0xe9)
        ||st_unicode_java21_domain_char(0x1f600)
        ||st_unicode_java21_domain_char(0x10400)
        ||st_unicode_java21_domain_char(-1))failed=1;
    if(failed)return 1;
    printf("Java21 Unicode component: %zu vectors, invalid UTF-8, overflow, Unicode whitespace/domain checks passed\n",count);
    return 0;
}
