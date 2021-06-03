#include <iostream>
#include <ctime>
#include <string>
#include <tchar.h>
#include <map>
#include <windows.h>
#include "atlstr.h"
#include <TlHelp32.h>
#include <WtsApi32.h>
#include <psapi.h>
#pragma comment(lib, "WtsApi32.lib")
#define MAX_PATH          260
using namespace std;
struct Process {
	WCHAR name[MAX_PATH];			//进程名
	WCHAR user_name[MAX_PATH];		//用户名
	float CPU;						//CPU占用
	int64_t last_time = 0;			//用于记录第一次的时间，求差算CPU占用
	int64_t last_system_time = 0;
	SIZE_T memory;					//内存占用
	DWORD IOread;					//IO读字节数
	DWORD IOwrite;					//IO写字节数
	DWORD pagefault;				//页错误数
	DWORD thread_cnt;				//线程数
	DWORD handle_cnt;				//句柄数
	DWORD GDI_cnt;					//GDI对象数
};

void GetPidAndProcessNameAndThreadCnt(map<DWORD, Process>& list,HANDLE hSnapShot) {
	PROCESSENTRY32 processInfo = { sizeof(PROCESSENTRY32) };
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		return;
	}
	if (Process32First(hSnapShot, &processInfo)) {
		do {
			Process p = {0};
			//p.name = processInfo.szExeFile;
			for (int i = 0; i < MAX_PATH; i++) {
				p.name[i] = processInfo.szExeFile[i];
				if (processInfo.szExeFile[i] == '\0')
					break;
			}
			p.thread_cnt = processInfo.cntThreads;
			list.insert(make_pair(processInfo.th32ProcessID, p));

		} while (Process32Next(hSnapShot, &processInfo));
	}

	return;
}
void GetProcessUser(map<DWORD, Process>& list, HANDLE hSnapShot) {
	CString userName;
	SID_NAME_USE snu;
	TCHAR buffUsername[MAX_PATH];
	TCHAR buffDomainname[MAX_PATH];
	DWORD unSize;
	DWORD dnSize;

	WTS_PROCESS_INFO* ppProcessInfo;
	WTS_PROCESS_INFO* ppTemp;
	DWORD pCount;
	if (WTSEnumerateProcesses(&hSnapShot, 0, 1, &ppProcessInfo, &pCount)){
		ppTemp = ppProcessInfo;
		for (DWORD i = 0; i < pCount; i++)
		{
			unSize = sizeof(buffUsername);
			dnSize = sizeof(buffDomainname);
			if (LookupAccountSid(NULL, ppTemp->pUserSid, buffUsername, &unSize, buffDomainname, &dnSize, &snu))
			{
				userName = buffUsername;
				auto iter = list.find(ppTemp->ProcessId);
				for (int cnt = 0; cnt < MAX_PATH; cnt++) {
					iter->second.user_name[cnt] = userName.GetBuffer()[cnt];
				}
			}
			ppTemp++;
		}
		WTSFreeMemory(ppProcessInfo);
	}
	//pid为0和4的进程无法获得其用户名，故特例
	WCHAR pid_0[MAX_PATH] = TEXT("SYSTEM");
	auto iter0 = list.find(0);
	auto iter4 = list.find(4);
	for (int cnt = 0; cnt < MAX_PATH; cnt++) {
		iter0->second.user_name[cnt] = pid_0[cnt];
		iter4->second.user_name[cnt] = pid_0[cnt];
	}
}
uint64_t convert_time_format(const FILETIME* ftime) {
	LARGE_INTEGER li;
	li.LowPart = ftime->dwLowDateTime;
	li.HighPart = ftime->dwHighDateTime;
	return li.QuadPart;
}
void GetCpu(map<DWORD, Process>& list) {
	//First Time 
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	int cpu_num = info.dwNumberOfProcessors;
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		FILETIME now,creationTime, exitTime, kernelTime, userTime;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		GetSystemTimeAsFileTime(&now);
		if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
			iter->second.last_system_time = (convert_time_format(&kernelTime) + convert_time_format(&userTime)) / cpu_num;
			iter->second.last_time = convert_time_format(&now);
		}
		CloseHandle(hProcess);
	}
	//Second Time
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		FILETIME now, creationTime, exitTime, kernelTime, userTime;
		int64_t system_time, time, system_time_delta, time_delta;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		GetSystemTimeAsFileTime(&now);
		if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
			system_time = (convert_time_format(&kernelTime) + convert_time_format(&userTime)) / cpu_num;
			time = convert_time_format(&now);
			system_time_delta = system_time - iter->second.last_system_time;
			time_delta = time - iter->second.last_time;
			iter->second.CPU = (float)system_time_delta * 100 / (float)time_delta;
		}
		CloseHandle(hProcess);
	}
	//处理空余CPU
	float sum = 0;
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		sum += iter->second.CPU;
	}
	auto Process0 = list.find(0);
	Process0->second.CPU = 100.0 - sum;
}
void GetMemoryAndPageFault(map<DWORD, Process>& list) {
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
		PROCESS_MEMORY_COUNTERS pmc;
		if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
			iter->second.memory = pmc.PeakWorkingSetSize;
			iter->second.pagefault = pmc.PageFaultCount;
			
		}
		CloseHandle(hProcess);
	}
}
void GetIOReadAndWrite(map<DWORD, Process>& list) {
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,processID);
		IO_COUNTERS io_counter;
		if (GetProcessIoCounters(hProcess, &io_counter)) {
			iter->second.IOread = io_counter.ReadTransferCount;
			iter->second.IOwrite = io_counter.WriteTransferCount;
		}
		CloseHandle(hProcess);
	}
}
void GetHandleCnt(map<DWORD, Process>& list) {
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		DWORD dwHandleCnt = 0;
		if (GetProcessHandleCount(hProcess, &dwHandleCnt)) {
			iter->second.handle_cnt = dwHandleCnt;
		}
		CloseHandle(hProcess);
	}
}
void GetGdiCnt(map<DWORD, Process>& list) {
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		DWORD dwGdi = GetGuiResources(hProcess, GR_GDIOBJECTS);
		iter->second.GDI_cnt = dwGdi;
		CloseHandle(hProcess);
	}
}
void GetInfo() {
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	map<DWORD, Process>list;
	GetPidAndProcessNameAndThreadCnt(list, hSnapShot);
	GetProcessUser(list, hSnapShot);
	GetCpu(list);
	GetMemoryAndPageFault(list);
	GetIOReadAndWrite(list);
	GetHandleCnt(list);
	GetGdiCnt(list);
	CloseHandle(hSnapShot);
	printf("There are %d processes!\n", list.size());
	printf("%-35s|%-10s|%-15s|%10s|%10s|%10s|%10s|%10s|%10s|%10s|%10s\n", "Process Name", "ProcessID", "User Name", "CPU(%)", "Memory(B)", "IO Read", "IO Write", "Page Fault", "Threads", "Handles", "GDI");
	for (auto i = list.begin(); i != list.end(); i++) {
		Process* iter = &i->second;
		printf("%-35ls|%-10d|%-15ls|%10f|%10d|%10d|%10d|%10d|%10d|%10d|%10d\n", iter->name, i->first, iter->user_name, iter->CPU, iter->memory, iter->IOread, iter->IOwrite, iter->pagefault, iter->thread_cnt, iter->handle_cnt, iter->GDI_cnt);
	}
}
int main()
{

	string command;
	long start = clock();
	GetInfo();
	long end = clock();
	double s = (double)(end - start) / CLOCKS_PER_SEC * 1000;
	cout << s;
	while (cin >> command) {
		if (command == "refresh") {
			cout << "Get command refresh\n";
			system("cls");
			GetInfo();
		}
		else if (command == "quit") {
			cout << "Get command quit\n";
			break;
		}
		else {
			cout << "Wrong Command!\n";
		}
	}

	return 0;
}