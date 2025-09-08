#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
#include <Windows.h>
#include <iostream>
#include <CL/cl.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <chrono>
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

typedef int (WINAPI* FnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
FnMessageBoxA MyMessageBoxA;

typedef int (WINAPI* FnwsprintfA)(LPSTR, LPCSTR, ...);
FnwsprintfA MywsprintfA;

typedef cl_int(CL_API_CALL* FnclGetPlatformIDs)(cl_uint, cl_platform_id*, cl_uint*);
FnclGetPlatformIDs MyclGetPlatformIDs;

typedef cl_int(CL_API_CALL* FnclGetDeviceIDs)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*);
FnclGetDeviceIDs MyclGetDeviceIDs;

typedef cl_context(CL_API_CALL* FnclCreateContext)(const cl_context_properties*, cl_uint, const cl_device_id*, void (CL_CALLBACK*)(const char*, const void*, size_t, void*), void*, cl_int*);
FnclCreateContext MyclCreateContext;

typedef cl_command_queue(CL_API_CALL* FnclCreateCommandQueueWithProperties)(cl_context, cl_device_id, const cl_queue_properties*, cl_int*);
FnclCreateCommandQueueWithProperties MyclCreateCommandQueueWithProperties;

typedef cl_int(CL_API_CALL* FnclReleaseContext)(cl_context);
FnclReleaseContext MyclReleaseContext;

typedef cl_int(CL_API_CALL* FnclReleaseCommandQueue)(cl_command_queue);
FnclReleaseCommandQueue MyclReleaseCommandQueue;

typedef cl_kernel(CL_API_CALL* FnclCreateKernel)(cl_program, const char*, cl_int*);
FnclCreateKernel MyclCreateKernel;

typedef cl_int(CL_API_CALL* FnclReleaseProgram)(cl_program);
FnclReleaseProgram MyclReleaseProgram;

typedef cl_mem(CL_API_CALL* FnclCreateBuffer)(cl_context, cl_mem_flags, size_t, void*, cl_int*);
FnclCreateBuffer MyclCreateBuffer;

typedef cl_int(CL_API_CALL* FnclReleaseKernel)(cl_kernel);
FnclReleaseKernel MyclReleaseKernel;

typedef cl_int(CL_API_CALL* FnclEnqueueWriteBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void*, cl_uint, const cl_event*, cl_event*);
FnclEnqueueWriteBuffer MyclEnqueueWriteBuffer;

typedef cl_int(CL_API_CALL* FnclReleaseMemObject)(cl_mem);
FnclReleaseMemObject MyclReleaseMemObject;

typedef cl_int(CL_API_CALL* FnclSetKernelArg)(cl_kernel, cl_uint, size_t, const void*);
FnclSetKernelArg MyclSetKernelArg;

typedef cl_int(CL_API_CALL* FnclEnqueueNDRangeKernel)(cl_command_queue, cl_kernel, cl_uint, const size_t*, const size_t*, const size_t*, cl_uint, const cl_event*, cl_event*);
FnclEnqueueNDRangeKernel MyclEnqueueNDRangeKernel;

typedef cl_int(CL_API_CALL* FnclEnqueueReadBuffer)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void*, cl_uint, const cl_event*, cl_event*);
FnclEnqueueReadBuffer MyclEnqueueReadBuffer;

typedef cl_int(CL_API_CALL* FnclFinish)(cl_command_queue);
FnclFinish MyclFinish;

typedef cl_program(CL_API_CALL* FnclCreateProgramWithSource)(cl_context, cl_uint, const char**, const size_t*, cl_int*);
FnclCreateProgramWithSource MyclCreateProgramWithSource;

typedef cl_int(CL_API_CALL* FnclBuildProgram)(cl_program, cl_uint, const cl_device_id*, const char*, void*, void*);
FnclBuildProgram MyclBuildProgram;

typedef cl_int(CL_API_CALL* FnclGetProgramBuildInfo)(cl_program, cl_device_id, cl_program_build_info, size_t, void*, size_t*);
FnclGetProgramBuildInfo MyclGetProgramBuildInfo;

size_t mystrlen(const char* s) {
    size_t n = 0;
    while (s && *s++) n++;
    return n;
}


// OpenCL kernel：对 data[offset + gid] ^= key
static const char* kXorKernelSrc = R"CLC(
__kernel void xor_decrypt(__global uchar* data, const uint offset, const uint len, const uchar key) {
    uint gid = get_global_id(0);
    if (gid < len) {
        data[offset + gid] ^= key;
    }
}
)CLC";

static bool buildProgram(cl_context ctx, cl_device_id dev, const char* src, cl_program* out_prog, std::string* build_log) {
    cl_int err = CL_SUCCESS;
    const char* sources[] = { src };
    size_t lengths[] = { mystrlen(src) };
    cl_program prog = MyclCreateProgramWithSource(ctx, 1, sources, lengths, &err);
    if (err != CL_SUCCESS) return false;
    //err = MyclBuildProgram(prog, 1, &dev, nullptr, nullptr, nullptr);
    // Modify the MyclBuildProgram function call to match the expected number of arguments.  
    err = MyclBuildProgram(prog, 1, &dev, nullptr, nullptr, nullptr);
    if (err != CL_SUCCESS) {
        size_t log_size = 0;
        MyclGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_size);
        if (log_size) {
            std::string log(log_size, '\0');
            MyclGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, log_size, &log[0], nullptr);
            if (build_log) *build_log = log;
        }
        MyclReleaseProgram(prog);
        return false;
    }
    *out_prog = prog;
    return true;
}

bool GpuDecrypt(unsigned char* pText, DWORD textSize, DWORD key) {
    cl_int err = CL_SUCCESS;

    // [S1] 平台数量
    cl_uint num_platforms = 0;
    err = MyclGetPlatformIDs(0, NULL, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        MyMessageBoxA(NULL, "S1 fail: no platform", "ERR", MB_OK);
        return false;
    }

    // [S2] 平台列表（最多4个）
    cl_platform_id plats[4] = { 0 };
    if (num_platforms > 4) num_platforms = 4;
    err = MyclGetPlatformIDs(num_platforms, plats, NULL);
    if (err != CL_SUCCESS || !plats[0]) {
        MyMessageBoxA(NULL, "S2 fail: get platforms", "ERR", MB_OK);
        return false;
    }

    // [S3] 设备选择：只选用 GPU；先只“查询数量”避免某些驱动崩溃
    cl_device_id dev = NULL;
    err = MyclGetDeviceIDs(plats[0], CL_DEVICE_TYPE_GPU, 1, &dev, NULL);
    if (err != CL_SUCCESS || dev == NULL) {
        MyMessageBoxA(NULL, "S3 info: Failed GPU", "INFO", MB_OK);
        err = MyclGetDeviceIDs(plats[0], CL_DEVICE_TYPE_CPU, 1, &dev, NULL);
        return false;
    }

    // [S4] 上下文
    cl_context ctx = MyclCreateContext(NULL, 1, &dev, NULL, NULL, &err);
    if (!ctx || err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S4 fail: create context", "ERR", MB_OK);
        return false;
    }

    // [S5] 队列
    cl_command_queue queue = MyclCreateCommandQueueWithProperties(ctx, dev, NULL, &err);
    if (!queue || err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S5 fail: create queue", "ERR", MB_OK);
        MyclReleaseContext(ctx);
        return false;
    }

    // [S6] 内核源码
    const char* kernelSrc =
        "__kernel void xor_decrypt(__global uchar* data, uint len, uchar key) {"
        "   size_t gid = get_global_id(0);"
        "   if (gid < len) data[gid] ^= key;"
        "}";
    // Program
    cl_program prog = MyclCreateProgramWithSource(ctx, 1, &kernelSrc, NULL, &err);
    if (!prog || err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S6 fail: create program", "ERR", MB_OK);
        MyclReleaseCommandQueue(queue);
        MyclReleaseContext(ctx);
        return false;
    }
    err = MyclBuildProgram(prog, 1, &dev, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        // 可选：dump build log
        MyMessageBoxA(NULL, "S6 fail: build program", "ERR", MB_OK);
        MyclReleaseProgram(prog);
        MyclReleaseCommandQueue(queue);
        MyclReleaseContext(ctx);
        return false;
    }

    // [S7] Kernel
    cl_kernel kernel = MyclCreateKernel(prog, "xor_decrypt", &err);
    if (!kernel || err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S7 fail: create kernel", "ERR", MB_OK);
        MyclReleaseProgram(prog);
        MyclReleaseCommandQueue(queue);
        MyclReleaseContext(ctx);
        return false;
    }

    // [S8] Buffer
    cl_mem buf = MyclCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, (size_t)textSize, pText, &err);
    if (!buf || err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S8 fail: create buffer", "ERR", MB_OK);
        MyclReleaseKernel(kernel);
        MyclReleaseProgram(prog);
        MyclReleaseCommandQueue(queue);
        MyclReleaseContext(ctx);
        return false;
    }

    // [S9] 设置参数（逐一检查返回值）
    err = MyclSetKernelArg(kernel, 0, sizeof(cl_mem), &buf);
    err |= MyclSetKernelArg(kernel, 1, sizeof(cl_uint), &textSize);
    cl_uchar ukey = (cl_uchar)(key & 0xFF);
    err |= MyclSetKernelArg(kernel, 2, sizeof(cl_uchar), &ukey);
    if (err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S9 fail: set args", "ERR", MB_OK);
        MyclReleaseMemObject(buf);
        MyclReleaseKernel(kernel);
        MyclReleaseProgram(prog);
        MyclReleaseCommandQueue(queue);
        MyclReleaseContext(ctx);
        return false;
    }

    // [S10] 执行 + Finish
    size_t gws = (size_t)textSize;
    err = MyclEnqueueNDRangeKernel(queue, kernel, 1, NULL, &gws, NULL, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S10 fail: enqueue", "ERR", MB_OK);
        // 继续释放资源
    }
    MyclFinish(queue); // 明确等待完成

    // [S11] 读回（阻塞）
    err = MyclEnqueueReadBuffer(queue, buf, CL_TRUE, 0, (size_t)textSize, pText, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        MyMessageBoxA(NULL, "S11 fail: read buffer", "ERR", MB_OK);
        // 继续释放资源
    }

    int rc;
	char bufMsg[128];
    if (buf) {
        rc = MyclReleaseMemObject(buf);
    }
    if (kernel) {
        rc = MyclReleaseKernel(kernel);
    }
    if (prog) {
        rc = MyclReleaseProgram(prog);
    }
    if (queue) {
        rc = MyclReleaseCommandQueue(queue);
    }
    if (ctx) {
        rc = MyclReleaseContext(ctx);
    }

    return true;
}

void Decrypt() {
    unsigned char* pText = (unsigned char*)g_conf.textScnRVA + 0x400000;
    DWORD size = g_conf.textScnSize;
    DWORD key = g_conf.key;

    // 先把页面权限改为可写
    DWORD old = 0;
    MyVirtualProtect(pText, size, PAGE_READWRITE, &old);

    GpuDecrypt(pText, size, key);

    // 恢复页面权限
    MyVirtualProtect(pText, size, old, &old);
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

    hUser32 = MyLoadLibraryA("user32.dll");
    MyMessageBoxA = (FnMessageBoxA)MyGetProcAddress(hUser32, "MessageBoxA");
    MywsprintfA = (FnwsprintfA)MyGetProcAddress(hUser32, "wsprintfA");

    HMODULE hOpenCL = MyLoadLibraryA("OpenCL.dll");
    if (!hOpenCL) {
        MyMessageBoxA(NULL, "LoadLibrary OpenCL.dll failed!", "Error", MB_OK);
        return;
    }

    MyclGetPlatformIDs = (FnclGetPlatformIDs)MyGetProcAddress(hOpenCL, "clGetPlatformIDs");
    MyclGetDeviceIDs = (FnclGetDeviceIDs)MyGetProcAddress(hOpenCL, "clGetDeviceIDs");
    MyclCreateContext = (FnclCreateContext)MyGetProcAddress(hOpenCL, "clCreateContext");
    MyclCreateCommandQueueWithProperties = (FnclCreateCommandQueueWithProperties)MyGetProcAddress(hOpenCL, "clCreateCommandQueueWithProperties");
    MyclReleaseCommandQueue = (FnclReleaseCommandQueue)MyGetProcAddress(hOpenCL, "clReleaseCommandQueue");
    MyclCreateKernel = (FnclCreateKernel)MyGetProcAddress(hOpenCL, "clCreateKernel");
    MyclReleaseProgram = (FnclReleaseProgram)MyGetProcAddress(hOpenCL, "clReleaseProgram");
    MyclCreateBuffer = (FnclCreateBuffer)MyGetProcAddress(hOpenCL, "clCreateBuffer");
    MyclReleaseKernel = (FnclReleaseKernel)MyGetProcAddress(hOpenCL, "clReleaseKernel");
    MyclEnqueueWriteBuffer = (FnclEnqueueWriteBuffer)MyGetProcAddress(hOpenCL, "clEnqueueWriteBuffer");
    MyclReleaseMemObject = (FnclReleaseMemObject)MyGetProcAddress(hOpenCL, "clReleaseMemObject");
    MyclSetKernelArg = (FnclSetKernelArg)MyGetProcAddress(hOpenCL, "clSetKernelArg");
    MyclEnqueueNDRangeKernel = (FnclEnqueueNDRangeKernel)MyGetProcAddress(hOpenCL, "clEnqueueNDRangeKernel");
    MyclEnqueueReadBuffer = (FnclEnqueueReadBuffer)MyGetProcAddress(hOpenCL, "clEnqueueReadBuffer");
    MyclFinish = (FnclFinish)MyGetProcAddress(hOpenCL, "clFinish");
    MyclCreateProgramWithSource = (FnclCreateProgramWithSource)MyGetProcAddress(hOpenCL, "clCreateProgramWithSource");
    MyclBuildProgram = (FnclBuildProgram)MyGetProcAddress(hOpenCL, "clBuildProgram");
    MyclGetProgramBuildInfo = (FnclGetProgramBuildInfo)MyGetProcAddress(hOpenCL, "clGetProgramBuildInfo");
    MyclReleaseContext = (FnclReleaseContext)MyGetProcAddress(hOpenCL, "clReleaseContext");
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