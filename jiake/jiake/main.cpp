#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "PE.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <inputfile> <outputfile>\n", argv[0]);
        return 0;
    }
    char PePath[260], outpath[260];
    strcpy(PePath, argv[1]);
    strcpy(outpath, argv[2]);

    DWORD PeSize = 0;
    char* PeHmoudle = GetFileHmoudle(PePath, &PeSize);
    if (!PeHmoudle) {
        printf("[-] Read input file failed.\n");
        return 1;
    }

    StubInfo pstub = { 0 };
    LoadStub(&pstub);

    // 使用 GPU 进行加密；失败则回退到 CPU Encry
    if (!EncryGPU(PeHmoudle, pstub)) {
        printf("[!] GPU encryption failed, fallback to CPU.\n");
        Encry(PeHmoudle, pstub);
    }
    else {
        printf("[+] GPU encryption ok.\n");
    }

    char SecName[] = ".bogger";
    char* PeNewHmoudle = AddSec(PeHmoudle, PeSize, SecName, GetSecByName(pstub.dllbase, ".text")->Misc.VirtualSize);
    FixStub(GetOptHeader(PeNewHmoudle)->ImageBase,
        (DWORD)pstub.dllbase,
        GetLastSec(PeNewHmoudle)->VirtualAddress,
        GetSecByName(pstub.dllbase, ".text")->VirtualAddress);

    auto b = (DWORD*)GetProcAddress((HMODULE)pstub.dllbase, "OriginEntry");
    pstub.pStubConf->srcOep = GetOptHeader(PeNewHmoudle)->AddressOfEntryPoint;
    memcpy(GetLastSec(PeNewHmoudle)->PointerToRawData + PeNewHmoudle,
        GetSecByName(pstub.dllbase, ".text")->VirtualAddress + pstub.dllbase,
        GetSecByName(pstub.dllbase, ".text")->Misc.VirtualSize);

    GetOptHeader(PeNewHmoudle)->AddressOfEntryPoint =
        pstub.pfnStart - (DWORD)pstub.dllbase - GetSecByName(pstub.dllbase, ".text")->VirtualAddress + GetLastSec(PeNewHmoudle)->VirtualAddress;

    GetOptHeader(PeNewHmoudle)->DllCharacteristics &= (~0x40);
    SaveFile(outpath, PeNewHmoudle, PeSize);
    return 0;
}
