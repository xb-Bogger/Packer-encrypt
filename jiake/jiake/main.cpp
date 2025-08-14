#include <Windows.h>
//#include "stdafx.h"
#include <tchar.h>
#include <stdio.h>
#include "PE.h"

int main(int argc, char* argv[]) {
	if (argc < 3)
	{
		printf("Usage: %s <inputfile> <outputfile>\n", argv[0]);
		return 0;
	}
	char PePath[128], outpath[128];
	strcpy(PePath, argv[1]);
	strcpy(outpath, argv[2]);
	DWORD PeSize;
	char* PeHmoudle = GetFileHmoudle(PePath,&PeSize);
	StubInfo pstub = { 0 };
	LoadStub(&pstub);
	Encry(PeHmoudle,pstub);
	char SecName[] = ".bogger";
	char* PeNewHmoudle = AddSec(PeHmoudle, PeSize, SecName, GetSecByName(pstub.dllbase, ".text")->Misc.VirtualSize);
	FixStub(GetOptHeader(PeNewHmoudle)->ImageBase,
		(DWORD)pstub.dllbase,
		GetLastSec(PeNewHmoudle)->VirtualAddress,
		GetSecByName(pstub.dllbase,".text")->VirtualAddress);
	auto b = (DWORD*)GetProcAddress((HMODULE)pstub.dllbase, "OriginEntry");
	pstub.pStubConf->srcOep = GetOptHeader(PeNewHmoudle)->AddressOfEntryPoint;
	memcpy(GetLastSec(PeNewHmoudle)->PointerToRawData+ PeNewHmoudle,
		GetSecByName(pstub.dllbase, ".text")->VirtualAddress+pstub.dllbase,
		GetSecByName(pstub.dllbase,".text")->Misc.VirtualSize);
	GetOptHeader(PeNewHmoudle)->AddressOfEntryPoint =
		pstub.pfnStart-(DWORD)pstub.dllbase-GetSecByName(pstub.dllbase,".text")->VirtualAddress+GetLastSec(PeNewHmoudle)->VirtualAddress;
	auto a =pstub.pfnStart-(DWORD)pstub.dllbase-GetSecByName(pstub.dllbase,".text")->VirtualAddress+GetLastSec(PeNewHmoudle)->VirtualAddress;
	auto d =GetProcAddress((HMODULE)pstub.dllbase, "OriginEntry");
	GetOptHeader(PeNewHmoudle)->DllCharacteristics &= (~0x40);
	SaveFile(outpath, PeNewHmoudle, PeSize);
	return 0;
}