#include "hide_process.h"

VOID Unload(PDRIVER_OBJECT) {

	HIDE_PROCESS::uninstall();
}


EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT drv_object, PUNICODE_STRING) {

	HIDE_PROCESS::init();
	drv_object->DriverUnload = Unload;
	//__debugbreak();
	HIDE_PROCESS::unlink_process((HANDLE)7940);

	return STATUS_SUCCESS;
}