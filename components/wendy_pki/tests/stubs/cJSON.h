#pragma once
#include <stddef.h>
typedef struct cJSON
{
    char *valuestring;
    struct cJSON *child, *next;
    int array;
} cJSON;
cJSON *cJSON_CreateObject(void);
cJSON *cJSON_AddStringToObject(cJSON *, const char *, const char *);
char *cJSON_PrintUnformatted(const cJSON *);
cJSON *cJSON_ParseWithLength(const char *, size_t);
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *, const char *);
int cJSON_IsString(const cJSON *);
int cJSON_IsArray(const cJSON *);
int cJSON_GetArraySize(const cJSON *);
#define cJSON_ArrayForEach(item, array) for ((item)=(array)->child; (item); (item)=(item)->next)
void cJSON_Delete(cJSON *);
