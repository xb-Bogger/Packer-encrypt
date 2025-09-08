#include <Windows.h>
#include <CL/cl.h>
#include <vector>
#include <string>
#include <iostream>

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

// 简单的 OpenCL kernel：对 data[i] ^= key
static const char* kXorKernelSrc = R"CLC(
__kernel void xor_encrypt(__global uchar* data,
                          const uint offset,
                          const uint len,
                          const uchar key) {
    size_t gid = get_global_id(0);
    if (gid < len) {
        data[offset + gid] ^= key;
    }
}
)CLC";

static bool buildProgram(cl_context ctx, cl_device_id dev, const char* src, cl_program* out_prog, std::string* build_log) {
    cl_int err = CL_SUCCESS;
    const char* sources[] = { src };
    size_t lengths[] = { strlen(src) };
    cl_program prog = clCreateProgramWithSource(ctx, 1, sources, lengths, &err);
    if (err != CL_SUCCESS) return false;
    err = clBuildProgram(prog, 1, &dev, nullptr, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // 获取 build log
        size_t log_size = 0;
        clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        std::string log(log_size, '\0');
        if (log_size) {
            clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, log_size, &log[0], nullptr);
        }
        if (build_log) *build_log = log;
        clReleaseProgram(prog);
        return false;
    }
    *out_prog = prog;
    return true;
}

bool EncryGPU(char* hpe, StubInfo& pstub) {
    // 1) 找到入口所在节，与原 Encry 对齐
    PIMAGE_SECTION_HEADER section = GetSectionByEntryPoint(hpe, &pstub);
    if (!section) return false;
    BYTE* target = section->PointerToRawData + (BYTE*)hpe;
    DWORD target_size = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
    if (target_size == 0) return false;

    const unsigned char key = 0x99; // 与原逻辑一致

    // 2) OpenCL 初始化（选择一个 GPU，若没有则选 CPU）
    cl_int err = CL_SUCCESS;
    cl_uint num_platforms = 0;
    err = clGetPlatformIDs(0, nullptr, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) return false;

    std::vector<cl_platform_id> platforms(num_platforms);
    clGetPlatformIDs(num_platforms, platforms.data(), nullptr);

    cl_device_id chosen_dev = nullptr;
    cl_platform_id chosen_plat = nullptr;

    for (auto plat : platforms) {
        cl_uint num_devs = 0;
        // 优先 GPU
        if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &chosen_dev, &num_devs) == CL_SUCCESS && num_devs > 0) {
            chosen_plat = plat;
            break;
        }
        // 退而求其次 CPU
        if (clGetDeviceIDs(plat, CL_DEVICE_TYPE_CPU, 1, &chosen_dev, &num_devs) == CL_SUCCESS && num_devs > 0) {
            chosen_plat = plat;
            break;
        }
    }
    if (!chosen_dev) return false;

    char name[128];
    clGetDeviceInfo(chosen_dev, CL_DEVICE_NAME, sizeof(name), name, NULL);
    printf("Using OpenCL device: %s\n", name);

    cl_context ctx = clCreateContext(nullptr, 1, &chosen_dev, nullptr, nullptr, &err);
    if (err != CL_SUCCESS) return false;

#if CL_TARGET_OPENCL_VERSION >= 200
    const cl_queue_properties props[] = { 0 };
    cl_command_queue queue = clCreateCommandQueueWithProperties(ctx, chosen_dev, props, &err);
#else
    cl_command_queue queue = clCreateCommandQueue(ctx, chosen_dev, 0, &err);
#endif
    if (err != CL_SUCCESS) { clReleaseContext(ctx); return false; }

    cl_program prog = nullptr;
    std::string build_log;
    if (!buildProgram(ctx, chosen_dev, kXorKernelSrc, &prog, &build_log)) {
        // 可根据需要打印 build_log 进行调试
        if (!build_log.empty()) {
            // std::cerr << build_log << std::endl;
        }
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return false;
    }

    cl_kernel kernel = clCreateKernel(prog, "xor_encrypt", &err);
    if (err != CL_SUCCESS) {
        clReleaseProgram(prog);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return false;
    }

    // 3) 将待加密的节数据放入 OpenCL Buffer
    // 为了避免复制两次，可以直接创建 READ_WRITE | COPY_HOST_PTR
    cl_mem buf = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, target_size, target, &err);
    if (err != CL_SUCCESS) {
        clReleaseKernel(kernel);
        clReleaseProgram(prog);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return false;
    }

    // 4) 设置参数并执行
    const cl_uint offset = 0;
    const cl_uint len = static_cast<cl_uint>(target_size);
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &buf);
    err |= clSetKernelArg(kernel, 1, sizeof(cl_uint), &offset);
    err |= clSetKernelArg(kernel, 2, sizeof(cl_uint), &len);
    err |= clSetKernelArg(kernel, 3, sizeof(unsigned char), &key);
    if (err != CL_SUCCESS) {
        clReleaseMemObject(buf);
        clReleaseKernel(kernel);
        clReleaseProgram(prog);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return false;
    }

    size_t global = len;
    err = clEnqueueNDRangeKernel(queue, kernel, 1, nullptr, &global, nullptr, 0, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        clReleaseMemObject(buf);
        clReleaseKernel(kernel);
        clReleaseProgram(prog);
        clReleaseCommandQueue(queue);
        clReleaseContext(ctx);
        return false;
    }

    // 5) 读回结果覆盖原数据
    err = clEnqueueReadBuffer(queue, buf, CL_TRUE, 0, target_size, target, 0, nullptr, nullptr);
    clFinish(queue);

    // 6) 更新 Stub 配置，与原 Encry 一致
    pstub.pStubConf->textScnRVA = section->VirtualAddress;
    pstub.pStubConf->textScnSize = target_size;
    pstub.pStubConf->key = key;

    // 7) 释放资源
    clReleaseMemObject(buf);
    clReleaseKernel(kernel);
    clReleaseProgram(prog);
    clReleaseCommandQueue(queue);
    clReleaseContext(ctx);

    return (err == CL_SUCCESS);
}
