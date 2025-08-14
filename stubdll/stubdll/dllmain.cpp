#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
#include <Windows.h>
#include <iostream>
#include <string>  
using namespace std;
typedef struct _StubConf
{
	DWORD srcOep;
	DWORD textScnRVA;
	DWORD textScnSize;
	DWORD key;
}StubConf;

extern "C" __declspec(dllexport)StubConf g_conf = { 0 };

typedef FARPROC(WINAPI* FnGetProcAddress)(HMODULE, LPCSTR);
FnGetProcAddress MyGetProcAddress;

typedef HMODULE(WINAPI* FnLoadLibraryA)(LPCSTR);
FnLoadLibraryA MyLoadLibraryA;

typedef void* (WINAPI* FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
FnVirtualProtect MyVirtualProtect;


void Decrypt()
{
	/*//unsigned char* pText = (unsigned char*)(g_conf.textScnRVA + MyGetModuleHandleA(NULL));
	HMODULE hModule = MyGetModuleHandleA(NULL);
	BYTE* pBaseAddr = (BYTE*)hModule;

	BYTE* pText = pBaseAddr + g_conf.textScnRVA;*/
	unsigned char* pText = (unsigned char*)g_conf.textScnRVA + 0x400000;
	DWORD old = 0;
	MyVirtualProtect(pText, g_conf.textScnSize, PAGE_READWRITE, &old);
	for (DWORD i = 0; i < g_conf.textScnSize; i++)
	{
		pText[i] ^= g_conf.key;
	}
	MyVirtualProtect(pText, g_conf.textScnSize, old, &old);

}
void GetApis()
{
	HMODULE hKernel32, hUser32;

	_asm
	{
		pushad;
		mov eax, fs: [0x30] ;
		mov eax, [eax + 0ch];
		mov eax, [eax + 0ch];
		mov eax, [eax];
		mov eax, [eax];
		mov eax, [eax + 018h];
		mov hKernel32, eax;
		mov ebx, [eax + 03ch];
		add ebx, eax;
		add ebx, 078h;
		mov ebx, [ebx];
		add ebx, eax;
		lea ecx, [ebx + 020h];
		mov ecx, [ecx];
		add ecx, eax;
		xor edx, edx;
	_WHILE:;
		mov esi, [ecx + edx * 4];
		lea esi, [esi + eax];
		cmp dword ptr[esi], 050746547h; 47657450 726F6341 64647265 7373;
		jne _LOOP;
		cmp dword ptr[esi + 4], 041636f72h;
		jne _LOOP;
		cmp dword ptr[esi + 8], 065726464h;
		jne _LOOP;
		cmp word  ptr[esi + 0ch], 07373h;
		jne _LOOP;
		mov edi, [ebx + 024h];
		add edi, eax;

		mov di, [edi + edx * 2];
		and edi, 0FFFFh;
		mov edx, [ebx + 01ch];
		add edx, eax;
		mov edi, [edx + edi * 4];
		add edi, eax; ;
		mov MyGetProcAddress, edi;
		jmp _ENDWHILE;
	_LOOP:;
		inc edx;
		jmp _WHILE;
	_ENDWHILE:;
		popad;
	}


	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibraryA");
	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");
}
extern "C" __declspec(dllexport) __declspec(naked)
void Start()
{
	GetApis();
	Decrypt();
	__asm
	{
		mov eax, g_conf.srcOep;
		add eax, 0x400000
			jmp eax
	}
}