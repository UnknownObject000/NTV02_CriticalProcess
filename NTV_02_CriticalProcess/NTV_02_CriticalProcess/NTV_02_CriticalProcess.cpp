// NTV_02_CriticalProcess.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

//系统关键进程的设置、取消、查询演示程序

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <utility>

//准备未定义类型
enum PROCESSINFOCLASS
{
	ProcessBasicInformation = 0x00,
	ProcessQuotaLimits = 0x01,
	ProcessIoCounters = 0x02,
	ProcessVmCounters = 0x03,
	ProcessTimes = 0x04,
	ProcessBasePriority = 0x05,
	ProcessRaisePriority = 0x06,
	ProcessDebugPort = 0x07,
	ProcessExceptionPort = 0x08,
	ProcessAccessToken = 0x09,
	ProcessLdtInformation = 0x0A,
	ProcessLdtSize = 0x0B,
	ProcessDefaultHardErrorMode = 0x0C,
	ProcessIoPortHandlers = 0x0D,
	ProcessPooledUsageAndLimits = 0x0E,
	ProcessWorkingSetWatch = 0x0F,
	ProcessUserModeIOPL = 0x10,
	ProcessEnableAlignmentFaultFixup = 0x11,
	ProcessPriorityClass = 0x12,
	ProcessWx86Information = 0x13,
	ProcessHandleCount = 0x14,
	ProcessAffinityMask = 0x15,
	ProcessPriorityBoost = 0x16,
	ProcessDeviceMap = 0x17,
	ProcessSessionInformation = 0x18,
	ProcessForegroundInformation = 0x19,
	ProcessWow64Information = 0x1A,
	ProcessImageFileName = 0x1B,
	ProcessLUIDDeviceMapsEnabled = 0x1C,
	ProcessBreakOnTermination = 0x1D,
	ProcessDebugObjectHandle = 0x1E,
	ProcessDebugFlags = 0x1F,
	ProcessHandleTracing = 0x20,
	ProcessIoPriority = 0x21,
	ProcessExecuteFlags = 0x22,
	ProcessResourceManagement = 0x23,
	ProcessCookie = 0x24,
	ProcessImageInformation = 0x25,
	ProcessCycleTime = 0x26,
	ProcessPagePriority = 0x27,
	ProcessInstrumentationCallback = 0x28,
	ProcessThreadStackAllocation = 0x29,
	ProcessWorkingSetWatchEx = 0x2A,
	ProcessImageFileNameWin32 = 0x2B,
	ProcessImageFileMapping = 0x2C,
	ProcessAffinityUpdateMode = 0x2D,
	ProcessMemoryAllocationMode = 0x2E,
	ProcessGroupInformation = 0x2F,
	ProcessTokenVirtualizationEnabled = 0x30,
	ProcessConsoleHostProcess = 0x31,
	ProcessWindowInformation = 0x32,
	ProcessHandleInformation = 0x33,
	ProcessMitigationPolicy = 0x34,
	ProcessDynamicFunctionTableInformation = 0x35,
	ProcessHandleCheckingMode = 0x36,
	ProcessKeepAliveCount = 0x37,
	ProcessRevokeFileHandles = 0x38,
	ProcessWorkingSetControl = 0x39,
	ProcessHandleTable = 0x3A,
	ProcessCheckStackExtentsMode = 0x3B,
	ProcessCommandLineInformation = 0x3C,
	ProcessProtectionInformation = 0x3D,
	ProcessMemoryExhaustion = 0x3E,
	ProcessFaultInformation = 0x3F,
	ProcessTelemetryIdInformation = 0x40,
	ProcessCommitReleaseInformation = 0x41,
	ProcessDefaultCpuSetsInformation = 0x42,
	ProcessAllowedCpuSetsInformation = 0x43,
	ProcessSubsystemProcess = 0x44,
	ProcessJobMemoryInformation = 0x45,
	ProcessInPrivate = 0x46,
	ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
	ProcessIumChallengeResponse = 0x48,
	ProcessChildProcessInformation = 0x49,
	ProcessHighGraphicsPriorityInformation = 0x4A,
	ProcessSubsystemInformation = 0x4B,
	ProcessEnergyValues = 0x4C,
	ProcessActivityThrottleState = 0x4D,
	ProcessActivityThrottlePolicy = 0x4E,
	ProcessWin32kSyscallFilterInformation = 0x4F,
	ProcessDisableSystemAllowedCpuSets = 0x50,
	ProcessWakeInformation = 0x51,
	ProcessEnergyTrackingState = 0x52,
	ProcessManageWritesToExecutableMemory = 0x53,
	ProcessCaptureTrustletLiveDump = 0x54,
	ProcessTelemetryCoverage = 0x55,
	ProcessEnclaveInformation = 0x56,
	ProcessEnableReadWriteVmLogging = 0x57,
	ProcessUptimeInformation = 0x58,
	ProcessImageSection = 0x59,
	ProcessDebugAuthInformation = 0x5A,
	ProcessSystemResourceManagement = 0x5B,
	ProcessSequenceNumber = 0x5C,
	ProcessLoaderDetour = 0x5D,
	ProcessSecurityDomainInformation = 0x5E,
	ProcessCombineSecurityDomainsInformation = 0x5F,
	ProcessEnableLogging = 0x60,
	ProcessLeapSecondInformation = 0x61,
	ProcessFiberShadowStackAllocation = 0x62,
	ProcessFreeFiberShadowStackAllocation = 0x63,
	MaxProcessInfoClass = 0x64
};

//准备函数指针
typedef VOID(WINAPI* type_RtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);

typedef VOID(WINAPI* type_RtlSetThreadIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);

typedef NTSTATUS(__kernel_entry* type_NtQueryInformationProcess)(IN HANDLE, IN PROCESSINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG);

//准备存储进程信息的类型
using ProcessInfo = std::vector<std::pair<std::wstring, int>>;

//提取SE_DEBUG_PRIVILIEGE
bool GetDebug()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tpNew = { 0 };
	LUID PriviliegeID;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &PriviliegeID);
	tpNew.PrivilegeCount = 1;
	tpNew.Privileges[0].Luid = PriviliegeID;
	tpNew.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tpNew, NULL, NULL, NULL))
		return false;
	else
		return true;
}

//从ntdll.dll加载三个API

VOID RtlSetProcessIsCritical(BOOLEAN NewValue, PBOOLEAN OldValue, BOOLEAN IsWinlogon)
{
	HMODULE hDll = LoadLibrary(L"ntdll.dll");
	if (hDll == NULL)
		return;
	type_RtlSetProcessIsCritical func = (type_RtlSetProcessIsCritical)GetProcAddress(hDll, "RtlSetProcessIsCritical");
	if (func != NULL)
	{
		FreeLibrary(hDll);
		return func(NewValue, OldValue, IsWinlogon);
	}
	else
	{
		FreeLibrary(hDll);
		return;
	}
}

VOID RtlSetThreadIsCritical(BOOLEAN NewValue, PBOOLEAN OldValue, BOOLEAN IsWinlogon)
{
	HMODULE hDll = LoadLibrary(L"ntdll.dll");
	if (hDll == NULL)
		return;
	type_RtlSetThreadIsCritical func = (type_RtlSetThreadIsCritical)GetProcAddress(hDll, "RtlSetThreadIsCritical");
	if (func != NULL)
	{
		FreeLibrary(hDll);
		return func(NewValue, OldValue, IsWinlogon);
	}
	else
	{
		FreeLibrary(hDll);
		return;
	}
}

NTSTATUS NtQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength)
{
	HMODULE hDll = LoadLibrary(L"ntdll.dll");
	if (hDll == NULL)
		return -1;
	type_NtQueryInformationProcess func = (type_NtQueryInformationProcess)GetProcAddress(hDll, "NtQueryInformationProcess");
	if (func != NULL)
	{
		FreeLibrary(hDll);
		return func(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	}
	else
	{
		FreeLibrary(hDll);
		return -2;
	}
}

//根据API编写设置进程为关键进程代码
void SetSystemProcess()
{
	RtlSetProcessIsCritical(TRUE, NULL, FALSE);
	RtlSetThreadIsCritical(TRUE, NULL, FALSE);
	return;
}

//取消系统关键进程
void CalcelSystemProcess()
{
	RtlSetProcessIsCritical(FALSE, NULL, FALSE);
	RtlSetThreadIsCritical(FALSE, NULL, FALSE);
	return;
}

//检查是否为系统关键进程
bool IsSystemProcess(DWORD ProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessID);
	if (hProcess == NULL)
		return false;
	ULONG iRet = 0;
	NtQueryInformationProcess(hProcess, ProcessBreakOnTermination, &iRet, sizeof(iRet), NULL);
	CloseHandle(hProcess);
	return (iRet == 1);
}

//遍历全部进程查找系统关键进程
ProcessInfo GetAllSystemProcess()
{
	ProcessInfo info;
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return info;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			if (IsSystemProcess(pe32.th32ProcessID))
				info.push_back({ pe32.szExeFile,pe32.th32ProcessID });
		} while (Process32Next(hProcessSnap, &pe32));
	}
	else
	{
		CloseHandle(hProcessSnap);
		return info;
	}
	CloseHandle(hProcessSnap);
	return info;
}

/*
* 此处UP会编写4个演示用主程序
* 分别为：
* 1. 设置系统关键进程后直接退出
* 2. 设置系统关键进程后等待（用于演示任务管理器结束）
* 3. 设置系统关键进程，取消设置系统关键进程，退出
* 4. 遍历列出所有的系统关键进程
*/


int main_1()
{
	GetDebug();
	SetSystemProcess();
	return 0;
}

int main_2()
{
	GetDebug();
	SetSystemProcess();
	getchar();	//使用等待输入来暂停程序运行
	return 0;
}

int main_3()
{
	GetDebug();
	SetSystemProcess();
	CalcelSystemProcess();
	return 0;
}

int main_4()
{
	GetDebug();
	ProcessInfo list = GetAllSystemProcess();
	if (list.size() == 0)
		printf("未找到任何系统关键进程\n");
	else
	{
		std::wcout <<  "Process Name\t\tPID" << std::endl;
		for (auto& info : list)
		{
			std::wcout << info.first << "\t\t" << info.second << std::endl;
		}
	}
	system("pause");
	return 0;
}

int main()
{
	//main_1();
	//main_2();
	//main_3();
	//main_4();
	return 0;
}