#include "unicode_java21.h"

#include <errno.h>
#include <stdlib.h>
#include <utf8proc.h>

#include "unicode_java21_data.h"

enum { LETTER=1, NUMBER=2, MARK=4, IGNORE=8, MID_WORD=16, MID_NUMBER=32,
       PRE_NUMBER=64, POST_NUMBER=128, POST_WORD=256, CASED=512, WHITE=1024, DOMAIN=2048 };

typedef struct { size_t begin, end; unsigned flags; int marks; } st_java21_unit;

static unsigned flags_for(uint32_t point)
{
    size_t lo=0U, hi=sizeof(st_java21_flags)/sizeof(st_java21_flags[0]);
    while(lo<hi) {
        size_t mid=lo+(hi-lo)/2U;
        if(point<st_java21_flags[mid].first)hi=mid;
        else if(point>st_java21_flags[mid].last)lo=mid+1U;
        else return st_java21_flags[mid].flags;
    }
    return 0U;
}

static int32_t simple_lower(uint32_t point)
{
    size_t lo=0U, hi=sizeof(st_java21_lower)/sizeof(st_java21_lower[0]);
    while(lo<hi) {
        size_t mid=lo+(hi-lo)/2U;
        if(point<st_java21_lower[mid].first)hi=mid;
        else if(point>st_java21_lower[mid].last)lo=mid+1U;
        else return (int32_t)point+st_java21_lower[mid].delta;
    }
    return (int32_t)point;
}

int st_unicode_java21_domain_char(int32_t point)
{
    return point>=0 && (flags_for((uint32_t)point)&DOMAIN)!=0U;
}

int st_unicode_java21_whitespace(int32_t point)
{
    return point>=0 && (flags_for((uint32_t)point)&WHITE)!=0U;
}

int st_unicode_java21_digit(int32_t point,int radix)
{
    int value=-1;
    if(point<0||point>0xFFFF)return -1;
    if(point>='0'&&point<='9')value=point-'0';
    else if(point>='A'&&point<='Z')value=point-'A'+10;
    else if(point>='a'&&point<='z')value=point-'a'+10;
    else if(point>=0xFF21&&point<=0xFF3A)value=point-0xFF21+10;
    else if(point>=0xFF41&&point<=0xFF5A)value=point-0xFF41+10;
    else if(utf8proc_category(point)==UTF8PROC_CATEGORY_ND) {
        /* Decimal digits come in runs of ten from zero; none of the BMP's runs touch. */
        int32_t start=point;
        while(point-start<9&&utf8proc_category(start-1)==UTF8PROC_CATEGORY_ND)start--;
        value=point-start;
    }
    return value<radix?value:-1;
}

int st_unicode_java21_has_text(const char *text,size_t length)
{
    if(text==NULL)return length==0U?0:-1;
    if(length>(size_t)PTRDIFF_MAX)return -1;
    size_t offset=0U;
    int present=0;
    while(offset<length) {
        utf8proc_int32_t point;
        utf8proc_ssize_t width=utf8proc_iterate((const utf8proc_uint8_t *)text+offset,
                                              (utf8proc_ssize_t)(length-offset),&point);
        if(width<=0)return -1;
        if((flags_for((uint32_t)point)&WHITE)==0U)present=1;
        offset+=(size_t)width;
    }
    return present;
}

static int has(const st_java21_unit *items,size_t count,size_t at,unsigned flag)
{
    return at<count && (items[at].flags&flag)!=0U;
}

static int bare(const st_java21_unit *items,size_t count,size_t at,unsigned flag)
{
    return has(items,count,at,flag)&&!items[at].marks;
}

static size_t word_end(const st_java21_unit *items,size_t count,size_t at)
{
    while(has(items,count,at,LETTER)) {
        at++;
        if(!has(items,count,at,LETTER)&&bare(items,count,at,MID_WORD)&&has(items,count,at+1U,LETTER))at++;
    }
    if(bare(items,count,at,POST_WORD))at++;
    return at;
}

static size_t number_end(const st_java21_unit *items,size_t count,size_t at)
{
    while(has(items,count,at,NUMBER)) {
        at++;
        if(!has(items,count,at,NUMBER)&&bare(items,count,at,MID_NUMBER)&&has(items,count,at+1U,NUMBER))at++;
    }
    return at;
}

static size_t group_end(const st_java21_unit *items,size_t count,size_t start)
{
    size_t at=start;
    if(bare(items,count,at,PRE_NUMBER)&&has(items,count,at+1U,NUMBER))at++;
    if(has(items,count,at,LETTER))at=word_end(items,count,at);
    while(has(items,count,at,NUMBER)) {
        at=number_end(items,count,at);
        if(has(items,count,at,LETTER))at=word_end(items,count,at);
        else {if(bare(items,count,at,POST_NUMBER))at++;break;}
    }
    return at>start?at:start+1U;
}

char *st_unicode_java21_lower_root(const char *text,size_t length,size_t *out_len)
{
    if(out_len!=NULL)*out_len=0U;
    if(text==NULL){errno=EINVAL;return NULL;}
    if(length>(size_t)PTRDIFF_MAX || length>(SIZE_MAX-1U)/3U
        || length>SIZE_MAX/sizeof(st_java21_unit)-1U || length>SIZE_MAX/sizeof(int32_t)-1U) {
        errno=ENOMEM;return NULL;
    }
    int32_t *points=malloc((length+1U)*sizeof(*points));
    st_java21_unit *items=malloc((length+1U)*sizeof(*items));
    unsigned char *boundaries=calloc(length+1U,1U),*final=calloc(length+1U,1U);
    char *output=malloc(length*3U+1U);
    if(points==NULL||items==NULL||boundaries==NULL||final==NULL||output==NULL) {
        free(points);free(items);free(boundaries);free(final);free(output);errno=ENOMEM;return NULL;
    }
    size_t offset=0U,count=0U,units=0U;
    while(offset<length) {
        utf8proc_ssize_t width=utf8proc_iterate((const utf8proc_uint8_t *)text+offset,
                                              (utf8proc_ssize_t)(length-offset),&points[count]);
        if(width<=0){free(points);free(items);free(boundaries);free(final);free(output);errno=EINVAL;return NULL;}
        offset+=(size_t)width;count++;
    }
    for(size_t i=0U;i<count;i++) {
        unsigned flags=flags_for((uint32_t)points[i]);
        if((flags&IGNORE)!=0U)continue;
        if((flags&MARK)!=0U&&units>0U) {
            items[units-1U].end=i+1U;items[units-1U].marks=1;
        } else items[units++]=(st_java21_unit){.begin=i,.end=i+1U,.flags=flags,.marks=0};
    }
    for(size_t i=0U;i<units;) {
        size_t end=group_end(items,units,i);
        boundaries[items[i].begin]=1U;boundaries[items[end-1U].end]=1U;i=end;
    }
    boundaries[0]=boundaries[count]=1U;
    /* Preserve the reference's isBoundary queries, not merely its next() iterator.
     * After a noninitial supplementary scalar those APIs differ in JDK 21. This
     * splits the casing search inside a marked unit without re-tokenizing it. */
    for(size_t i=1U;i<count;i++)if(points[i]>0xffff)boundaries[i+1U]=1U;
    for(size_t begin=0U;begin<count;) {
        size_t end=begin+1U,first=SIZE_MAX,last=SIZE_MAX;
        while(end<count&&!boundaries[end])end++;
        for(size_t p=begin;p<end;p++)if((flags_for((uint32_t)points[p])&CASED)!=0U){if(first==SIZE_MAX)first=p;last=p;}
        if(first!=SIZE_MAX&&last!=SIZE_MAX&&first<last&&points[last]==0x3a3)final[last]=1U;
        begin=end;
    }
    size_t written=0U;
    for(size_t i=0U;i<count;i++) {
        int32_t point=points[i];
        if(point==0x130){output[written++]='i';output[written++]=(char)0xcc;output[written++]=(char)0x87;continue;}
        point=point==0x3a3&&final[i]?0x3c2:simple_lower((uint32_t)point);
        utf8proc_ssize_t width=utf8proc_encode_char(point,(utf8proc_uint8_t *)output+written);
        if(width<=0){free(points);free(items);free(boundaries);free(final);free(output);errno=EINVAL;return NULL;}
        written+=(size_t)width;
    }
    output[written]='\0';if(out_len!=NULL)*out_len=written;
    free(points);free(items);free(boundaries);free(final);
    return output;
}
