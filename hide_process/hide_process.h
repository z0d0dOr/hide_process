#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "utils/utils.h"

#pragma warning (disable :4201)
typedef struct _HANDLE_TABLE_W7
{
	ULONGLONG TableCode;                                                    //0x0
	PEPROCESS QuotaProcess;                                         //0x8
	VOID* UniqueProcessId;                                                  //0x10
	VOID* HandleLock;                                        //0x18
	struct _LIST_ENTRY HandleTableList;                                     //0x20
	VOID* HandleContentionEvent;                             //0x30
	VOID* DebugInfo;                             //0x38
	LONG ExtraInfoPages;                                                    //0x40
	union
	{
		ULONG Flags;                                                        //0x44
		UCHAR StrictFIFO : 1;                                                 //0x44
	};
	ULONG FirstFreeHandle;                                                  //0x48
	struct _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                        //0x50
	ULONG HandleCount;                                                      //0x58
	ULONG NextHandleNeedingPool;                                            //0x5c
	ULONG HandleCountHighWatermark;                                         //0x60
}HANDLE_TABLE_W7, * PHANDLE_TABLE_W7;

typedef struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;                                            //0x0
	LONG ExtraInfoPages;                                                    //0x4
	volatile ULONGLONG TableCode;                                           //0x8
	struct _EPROCESS* QuotaProcess;                                         //0x10
	struct _LIST_ENTRY HandleTableList;                                     //0x18
	char pad01[0X58];

}HANDLE_TABLE, * PHANDLE_TABLE;
typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;                //Uint4B
	ULONG MaxRelativeAccessMask;    //Uint4b
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY
{
	union                                           //that special class
	{
		ULONG64 VolatileLowValue;                   //Int8B
		ULONG64 LowValue;                           //Int8B
		ULONG64 RefCountField;                      //Int8B
		_HANDLE_TABLE_ENTRY_INFO* InfoTable;        //Ptr64 _HANDLE_TABLE_ENTRY_INFO
		struct
		{
			ULONG64 Unlocked : 1;        //1Bit
			ULONG64 RefCnt : 16;       //16Bits
			ULONG64 Attributes : 3;        //3Bits
			ULONG64 ObjectPointerBits : 44;       //44Bits
		};
	};
	union
	{
		ULONG64 HighValue;                          //Int8B
		_HANDLE_TABLE_ENTRY* NextFreeHandleEntry;   //Ptr64 _HANDLE_TABLE_ENTRY
	};
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _CID_PROCESS_INFO { //

	HANDLE cid;
	HANDLE_TABLE_ENTRY entry;
	PHANDLE_TABLE_ENTRY pentry;

}CID_PROCESS_INFO, * PCID_PROCESS_INFO;


typedef BOOLEAN(*fn_ExDestroyHandle)(PHANDLE_TABLE table, HANDLE handle, PHANDLE_TABLE_ENTRY entry);


#define MYLOG(text,is_err,...) DbgPrintEx(77,0,"[HIDE_PROCESS]:");\
	if (is_err) DbgPrintEx(77, 0, "[HIDE_PROCESS]func_name:%s,line:%d err:", __FUNCTION__, __LINE__);\
	DbgPrintEx(77,0,text,__VA_ARGS__);
namespace HIDE_PROCESS{

	bool init();
	bool uninstall();
	ULONG get_e_process_link_offset();
	ULONG get_k_process_link_offset(DWORD32 build_number);
	ULONG get_e_process_handle_table_offset(DWORD32 build_number);
	bool get_table_and_destroy_hanlde(DWORD32 build_number,HANDLE_TABLE** table,UINT64* ExDestroyHandle);
	void unlink_handle_table(PEPROCESS process, DWORD32 build_number);
	bool unlink_process(HANDLE pid);
	bool remove_handle_table(HANDLE_TABLE* table, HANDLE handle);
	PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(HANDLE_TABLE* table, HANDLE handle);
	int find_empty();
	int find_entry_by_cid(HANDLE cid);

	VOID on_process_notify(_In_ HANDLE ParentId,_In_ HANDLE ProcessId,_In_ BOOLEAN Create);
}