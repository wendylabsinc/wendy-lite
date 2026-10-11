#pragma once
#include <stddef.h>
typedef struct
{
    char *valuestring;
} cJSON;
cJSON *cJSON_CreateObject(void);
cJSON *cJSON_AddStringToObject(cJSON *, const char *, const char *);
char *cJSON_PrintUnformatted(const cJSON *);
cJSON *cJSON_ParseWithLength(const char *, size_t);
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *, const char *);
int cJSON_IsString(const cJSON *);
void cJSON_Delete(cJSON *);
