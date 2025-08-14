#include <Windows.h>

typedef struct _StubConf
{
	DWORD srcOep;
	DWORD textScnRVA;
	DWORD textScnSize;
	DWORD key;
}StubConf;

struct StubInfo
{
	char* dllbase;
	DWORD pfnStart;
	StubConf* pStubConf;
};


PIMAGE_DOS_HEADER GetDosHeader(_In_ char* pBase) {
	return PIMAGE_DOS_HEADER(pBase);
}

PIMAGE_NT_HEADERS GetNtHeader(_In_ char* pBase) {
return PIMAGE_NT_HEADERS(GetDosHeader(pBase)->e_lfanew+(SIZE_T)pBase);
}

PIMAGE_FILE_HEADER GetFileHeader(_In_ char* pBase) {
	return &(GetNtHeader(pBase)->FileHeader);
}

PIMAGE_OPTIONAL_HEADER32 GetOptHeader(_In_ char* pBase) {
	return &(GetNtHeader(pBase)->OptionalHeader);
}

PIMAGE_SECTION_HEADER GetLastSec(_In_ char* pBase) {
	DWORD SecNum = GetFileHeader(pBase)->NumberOfSections;
	PIMAGE_SECTION_HEADER FirstSec = IMAGE_FIRST_SECTION(GetNtHeader(pBase));
	PIMAGE_SECTION_HEADER LastSec = FirstSec + SecNum - 1;
	return LastSec;
}

PIMAGE_SECTION_HEADER GetSecByName(_In_ char* pBase,_In_ const char* name) {
	DWORD Secnum = GetFileHeader(pBase)->NumberOfSections;
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(GetNtHeader(pBase));
	char buf[10] = { 0 };
	for (DWORD i = 0; i < Secnum; i++) {
		memcpy_s(buf, 8, (char*)Section[i].Name, 8);
		if (!strcmp(buf, name)) {
				return Section + i;
		}
	}
	return nullptr;
}

char* GetFileHmoudle(_In_ const char* path,_Out_opt_ DWORD* nFileSize) {
	HANDLE hFile = CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	DWORD FileSize = GetFileSize(hFile, NULL);
	if(nFileSize)
		*nFileSize = FileSize;
	char* pFileBuf = new CHAR[FileSize]{ 0 };
	DWORD dwRead;
	ReadFile(hFile, pFileBuf, FileSize, &dwRead, NULL);
	CloseHandle(hFile);
	return pFileBuf;
}

int AlignMent(_In_ int size, _In_ int alignment) {
	return (size) % (alignment)==0 ? (size) : ((size) / alignment+1) * (alignment);
}

char* AddSec(_In_ char*& hpe, _In_ DWORD& filesize, _In_ const char* secname, _In_ const int secsize) {
	GetFileHeader(hpe)->NumberOfSections++;
	PIMAGE_SECTION_HEADER pesec = GetLastSec(hpe);
	memcpy(pesec->Name, secname, 8);
	pesec->Misc.VirtualSize = secsize;
	pesec->VirtualAddress = (pesec - 1)->VirtualAddress + AlignMent((pesec - 1)->SizeOfRawData,GetOptHeader(hpe)->SectionAlignment);
	pesec->SizeOfRawData = AlignMent(secsize, GetOptHeader(hpe)->FileAlignment);
	pesec->PointerToRawData = AlignMent(filesize,GetOptHeader(hpe)->FileAlignment);
	pesec->Characteristics = 0xE00000E0;
	GetOptHeader(hpe)->SizeOfImage = pesec->VirtualAddress + pesec->SizeOfRawData;
	int newSize = pesec->PointerToRawData + pesec->SizeOfRawData;
	char* nhpe = new char [newSize] {0};
	memcpy(nhpe, hpe, filesize);
	delete hpe;
	filesize = newSize;
	return nhpe;
}

void SaveFile(_In_ const char* path, _In_ const char* data, _In_ int FileSize) {
	HANDLE hFile = CreateFileA(
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	DWORD Buf = 0;
	WriteFile(hFile, data, FileSize, &Buf,NULL);
	CloseHandle(hFile);
}

void FixStub(DWORD targetDllbase, DWORD stubDllbase,DWORD targetNewScnRva,DWORD stubTextRva )
{
	DWORD dwRelRva = GetOptHeader((char*)stubDllbase)->DataDirectory[5].VirtualAddress;
	IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)(dwRelRva + stubDllbase);

	while (pRel->SizeOfBlock)
	{
		struct TypeOffset
		{
			WORD offset : 12;
			WORD type : 4;

		};
		TypeOffset* pTypeOffset = (TypeOffset*)(pRel + 1);
		DWORD dwCount = (pRel->SizeOfBlock - 8) / 2;
		for (int i = 0; i < dwCount; i++)
		{
			if (pTypeOffset[i].type != 3)
			{
				continue;
			}
			DWORD* pFixAddr = (DWORD*)(pRel->VirtualAddress + pTypeOffset[i].offset + stubDllbase);

			DWORD dwOld;
			VirtualProtect(pFixAddr, 4, PAGE_READWRITE, &dwOld);
			*pFixAddr -= stubDllbase;
			*pFixAddr -= stubTextRva;
			*pFixAddr += targetDllbase;
			*pFixAddr += targetNewScnRva;
			VirtualProtect(pFixAddr, 4, dwOld, &dwOld);
		}
		pRel = (IMAGE_BASE_RELOCATION*)((DWORD)pRel + pRel->SizeOfBlock);
	}

}
PIMAGE_SECTION_HEADER GetSectionByEntryPoint(_In_ char* pBase, _In_ StubInfo* pstub) {
	PIMAGE_OPTIONAL_HEADER32 optHeader = GetOptHeader(pBase);
	if (!optHeader) {
		return nullptr;
	}

	DWORD entryPointRVA = optHeader->AddressOfEntryPoint;

	DWORD sectionCount = GetFileHeader(pBase)->NumberOfSections;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(GetNtHeader(pBase));

	for (DWORD i = 0; i < sectionCount; i++, section++) {
		DWORD sectionStart = section->VirtualAddress;
		DWORD sectionEnd = sectionStart + max(section->Misc.VirtualSize, section->SizeOfRawData);

		if (entryPointRVA >= sectionStart && entryPointRVA < sectionEnd) {
			return section;
		}
	}

	return nullptr;
}

void Encry(_In_ char* hpe,_In_ StubInfo pstub) {
	PIMAGE_SECTION_HEADER section = GetSectionByEntryPoint(hpe, &pstub);
	BYTE* TargetText = section->PointerToRawData + (BYTE*)hpe;
	DWORD TargetTextSize = section->Misc.VirtualSize;
	for (int i = 0; i < TargetTextSize; i++) {
		TargetText[i] ^= 0x99;
	}
	pstub.pStubConf->textScnRVA = section->VirtualAddress;
	pstub.pStubConf->textScnSize = TargetTextSize;
	pstub.pStubConf->key = 0x99;
}

void LoadStub(_In_ StubInfo* pstub) {
	pstub->dllbase = (char*)LoadLibraryEx(L"stubdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	pstub->pfnStart = (DWORD)GetProcAddress((HMODULE)pstub->dllbase, "Start");
	pstub->pStubConf = (StubConf*)GetProcAddress((HMODULE)pstub->dllbase, "g_conf");
}