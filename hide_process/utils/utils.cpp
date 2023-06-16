#include "utils.h"

Utils* Utils::m_Instance;

Utils* Utils::fn_get_instance()
{
	if (m_Instance == 0) {

		m_Instance = (Utils*)ExAllocatePoolWithTag(NonPagedPool, sizeof(Utils), 'util');
	
		//分配蹦床内存 清空HookInfo数组
		m_Instance->m_tramp_line = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE*10, 'util');
		m_Instance->m_tramp_line_used = 0;
		m_Instance->m_count = 0;
		if (m_Instance == 0 || m_Instance->m_tramp_line==0) {
			
			DbgPrintEx(77, 0, "[+]failed to alloc instance\r\n");
			return 0;
		}

		RtlSecureZeroMemory(m_Instance->m_hook_info_table, MAX_HOOK_COUNT * sizeof(HOOK_INFO));

	}

	return m_Instance;
}

uint32_t Utils::fn_get_os_build_number()
{
	unsigned long number = 0;
	RTL_OSVERSIONINFOEXW info{ 0 };
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	if (NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&info))) number = info.dwBuildNumber;
	return number;
}

//获取系统模块的基质
uint64_t Utils::fn_get_moudle_address(const char* name, unsigned long* size)
{
	unsigned long long result = 0;

	unsigned long length = 0;
	ZwQuerySystemInformation(11, &length, 0, &length);
	if (!length) return result;

	const unsigned long tag = 'VMON';
	PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
	if (!system_modules) return result;

	NTSTATUS status = ZwQuerySystemInformation(11, system_modules, length, 0);
	if (NT_SUCCESS(status))
	{
		for (unsigned long long i = 0; i < system_modules->ulModuleCount; i++)
		{
			PSYSTEM_MODULE mod = &system_modules->Modules[i];
			if (strstr(mod->ImageName, name))
			{
				result = (unsigned long long)mod->Base;
				if (size) *size = (unsigned long)mod->Size;
				break;
			}
		}
	}

	ExFreePoolWithTag(system_modules, tag);
	return result;
}

uint64_t Utils::fn_find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
{
	size -= (unsigned long)strlen(mask);

	for (unsigned long i = 0; i < size; i++)
	{
		if (fn_pattern_check((const char*)addr + i, pattern, mask))
			return addr + i;
	}

	return 0;
}

unsigned long long Utils::fn_find_pattern_image(unsigned long long addr, const char* pattern, const char* mask, const char* name)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER p = &section[i];

		if (strstr((const char*)p->Name, name))
		{
			unsigned long long result = fn_find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
			if (result) return result;
		}
	}

	return 0;
}

unsigned long long Utils::fn_get_image_address(unsigned long long addr, const char* name, unsigned long* size)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER p = &section[i];

		if (strstr((const char*)p->Name, name))
		{
			if (size) *size = p->SizeOfRawData;
			return (unsigned long long)p + p->VirtualAddress;
		}
	}

	return 0;
}

bool Utils::fn_hook_by_address(void** ori_func_addr, void* target_func_addr)
{
	uint64_t break_bytes = 0;
	
	if (m_Instance->m_count >= 100) {

		fn_logger("hooks too many!", true, STATUS_TOO_MANY_NODES);
		return false;
	}

	void* hook_addr = *ori_func_addr;
	hde64s hde;
	while (break_bytes < 14) {

		hde64_disasm(hook_addr, &hde);

		break_bytes += hde.len;

	}

	//复制原先14字节
	auto& cur_count = m_Instance->m_count;
	auto& info = m_Instance->m_hook_info_table;
	info[cur_count].hook_pid=PsGetCurrentProcessId();
	info[cur_count].ori_hook_addr=hook_addr;
	info[cur_count].target_hook_addr = target_func_addr;
	memcpy(info->old_bytes, hook_addr, 14);

	//初始化蹦床
	*ori_func_addr = fn_tramp_line_init(hook_addr, 14, info->old_bytes);
	
	unsigned char jmp_code[14] = { 0xff,0x25,0x0,0,0,0,0,0,0,0,0,0,0,0 };

	*(void**)(&jmp_code[6]) = target_func_addr;

	//auto irql = fn_wp_bit_off();
	
	//Hook
	memcpy(hook_addr, jmp_code, 14);

	//fn_wp_bit_on(irql);

	cur_count++;

	return true;
}

bool Utils::fn_remove_hook_by_address(void* ori_func_addr)
{

	
	for (int i = 0; i < this->m_count; i++) {

		if (this->m_hook_info_table[i].ori_hook_addr == ori_func_addr) {
			//Find
			auto& info = m_hook_info_table[i];

			memcpy(ori_func_addr, info.old_bytes, 14);
			info.target_hook_addr = 0;

			fn_logger("remove hook success", false, 0);

			return true;
		}

	}

	fn_logger("no target hook!",true,0);
	return false;
}

bool Utils::fn_pattern_check(const char* data, const char* pattern, const char* mask)
{
	size_t len = strlen(mask);

	for (size_t i = 0; i < len; i++)
	{
		if (data[i] == pattern[i] || mask[i] == '?')
			continue;
		else
			return false;
	}

	return true;
}

void Utils::fn_logger(const char* log_str, bool is_err, long err_code)
{
	if (is_err) DbgPrintEx(77, 0, "[utils.cpp]err:%s err_code :%x\r\n", log_str, err_code);
	else DbgPrintEx(77, 0, "[utils.cpp]info: %s\r\n", log_str);

}

KIRQL Utils::fn_wp_bit_off()
{

	//关闭CR0
	auto irql = KeRaiseIrqlToDpcLevel();//关闭线程切换
	UINT64 Cr0 = __readcr0();
	Cr0 &= 0xfffffffffffeffff;
	__writecr0(Cr0);
	_disable();
	return irql;

}

void Utils::fn_wp_bit_on(KIRQL irql)
{
	//开启CR0
	UINT64 Cr0 = __readcr0();
	Cr0 |= 0x10000;
	_enable();
	__writecr0(Cr0);
	KeLowerIrql(irql);
}

void* Utils::fn_tramp_line_init(void* ret_address,uint64_t break_bytes_count,unsigned char* break_bytes)
{
	const ULONG TrampLineBreakBytes = 20;

	


	unsigned char TrampLineCode[TrampLineBreakBytes] = {//push xxx mov  ret 不影响任何寄存器
	0x6A, 0x00, 0x3E, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
	0x3E, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC3
	};

	//复制绝对跳转
	*((PUINT32)&TrampLineCode[6]) = (UINT32)(((uint64_t)ret_address + break_bytes_count) & 0XFFFFFFFF);
	*((PUINT32)&TrampLineCode[15]) = (UINT32)((((uint64_t)ret_address + break_bytes_count) >> 32) & 0XFFFFFFFF);

	auto& used = m_Instance->m_tramp_line_used;
	auto& tramp_line_base = m_Instance->m_tramp_line;

	//复制原先毁掉的字节
	RtlCopyMemory(tramp_line_base + used, break_bytes, break_bytes_count);
	RtlCopyMemory(tramp_line_base + used+break_bytes_count, TrampLineCode, sizeof(TrampLineCode));

	auto ret = tramp_line_base + used;
	used += TrampLineBreakBytes + break_bytes_count;
	
	return ret;
}
