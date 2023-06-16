#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>
#include "hde64.h"


#define MAX_HOOK_COUNT 0x100

using uint64_t = unsigned long long;
using uint16_t = unsigned short;
using uint8_t = unsigned char;


typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	DWORD32 systemInformationClass,
	PVOID systemInformation,
	ULONG systemInformationLength,
	PULONG returnLength);

typedef struct _HOOK_INFO_ {

	HANDLE hook_pid;
	void* ori_hook_addr;
	void* target_hook_addr;
	unsigned char old_bytes[14];//一般是FF 25 00 00 00 00  JMP 因此损坏14个字节 保存方便恢复

}HOOK_INFO,*PHOOK_INFO;
class Utils {


public:
	static Utils* m_Instance;
	static Utils* fn_get_instance();
	uint32_t fn_get_os_build_number();
	//获取指定获取系统模块的基质
	uint64_t fn_get_moudle_address(const char* name, unsigned long* size);
	uint64_t fn_find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask);
	unsigned long long fn_find_pattern_image(unsigned long long addr, const char* pattern, const char* mask, const char* name = ".text");
	//获取镜像基质
	unsigned long long fn_get_image_address(unsigned long long addr, const char* name, unsigned long* size);
	//内核内联Hook(PG)
	bool fn_hook_by_address(void** ori_func_addr, void* target_func_addr);
	//移除内核内联Hook
	bool fn_remove_hook_by_address(void* ori_func_addr);
private:
	uint64_t m_count;
	uint8_t* m_tramp_line;//存放蹦床的 
	uint64_t m_tramp_line_used;

	HOOK_INFO m_hook_info_table[MAX_HOOK_COUNT];

	//模式匹配
	bool fn_pattern_check(const char* data, const char* pattern, const char* mask);
	void fn_logger(const char* log_str, bool is_err, long err_code);
	KIRQL fn_wp_bit_off();//强制读写开启
	void fn_wp_bit_on(KIRQL irql);
	void* fn_tramp_line_init(void* ret_address, uint64_t break_bytes_count, unsigned char* break_bytes);//初始化蹦床
};