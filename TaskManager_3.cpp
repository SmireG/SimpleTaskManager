#include <iostream>
#include <string>
#include <tchar.h>
#include <map>
#include <set>
#include <mutex>
#include <windows.h>
#include <pthread.h>
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
	ULONGLONG IOread;					//IO读字节数
	ULONGLONG IOwrite;					//IO写字节数
	DWORD pagefault;				//页错误数
	DWORD thread_cnt;				//线程数
	DWORD handle_cnt;				//句柄数
	DWORD GDI_cnt;					//GDI对象数
};
std::mutex mt;
map<DWORD, Process>list;
bool signalThread = false;
//如果PID在list中，更新；若不在，新增；若快照中无此PID，删除
void GetPidAndProcessNameAndThreadCnt(HANDLE hSnapShot);
void GetProcessUser(HANDLE hSnapShot);
uint64_t convert_time_format(const FILETIME* ftime);
void GetCpu();
void GetMemoryAndPageFault();
void GetIOReadAndWrite();
void GetHandleCnt();
void GetGdiCnt();
void Show();
void CALLBACK GetInfo(HWND hwnd, UINT message, UINT idTimer, DWORD dwTime);
DWORD WINAPI Thread(LPVOID lpParameter);
int main()
{
	HANDLE handle = NULL;
	//主线程
	string command;
	while (cin >> command) {
		if (command == "show") {
			printf("Get command show\n");
			system("cls");
			Show();
		}
		else if (command == "quit") {
			printf("Get command quit\n");
			CloseHandle(handle);
			signalThread = false;
			break;
		}
		else if (command == "b" && signalThread == false) {
			printf("Get command begin to get information\n");
			handle = CreateThread(NULL, 0, Thread, NULL, 0, NULL);
			signalThread = true;
		}
		else if (command == "b" && signalThread == true) {
			printf("There is already a thread to update information\n");
		}
		else if (command == "e" && signalThread == true) {
			printf("Get command stop updating information\n");
			CloseHandle(handle);
			signalThread = false;
		}
		else if (command == "e" && signalThread == false) {
			printf("There is no update thread\n");
		}
		else {
			printf("Wrong Command!\n");
			printf("show: Show the information\n");
			printf("quit: Exit the program\n");
			printf("b: Creat a thread to update information per second\n");
			printf("e: Close the thread and stop updating information\n");
		}
	}
	return 0;
}

void CALLBACK GetInfo(HWND hwnd, UINT message, UINT idTimer, DWORD dwTime)
{
	//printf("Update info\n");
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	GetPidAndProcessNameAndThreadCnt(hSnapShot);
	GetProcessUser(hSnapShot);
	GetCpu();
	GetMemoryAndPageFault();
	GetIOReadAndWrite();
	GetHandleCnt();
	GetGdiCnt();
	CloseHandle(hSnapShot);
}

DWORD WINAPI Thread(LPVOID lpParameter)
{
	HWND hwnd = NULL;
	SetTimer(hwnd, 1, 1000, GetInfo);
	//下面的while循环必须要
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)){
		if (msg.message == WM_TIMER)
			DispatchMessage(&msg);
		if (signalThread == false) {
			KillTimer(hwnd, NULL);
			break;
		}
	}
	return 0;
}
void GetPidAndProcessNameAndThreadCnt(HANDLE hSnapShot) {
	mt.lock();
	PROCESSENTRY32 processInfo = { sizeof(PROCESSENTRY32) };
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		return;
	}
	set<DWORD>mySet;
	if (Process32First(hSnapShot, &processInfo)) {
		do {
			auto iter = list.find(processInfo.th32ProcessID);
			//找到则更新
			if (iter!=list.end()) {
				for (int i = 0; i < MAX_PATH; i++) {
					iter->second.name[i] = processInfo.szExeFile[i];
					if (processInfo.szExeFile[i] == '\0')
						break;
				}
				iter->second.thread_cnt = processInfo.cntThreads;
			}
			else {
				Process p = { 0 };
				for (int i = 0; i < MAX_PATH; i++) {
					p.name[i] = processInfo.szExeFile[i];
					if (processInfo.szExeFile[i] == '\0')
						break;
				}
				p.thread_cnt = processInfo.cntThreads;
				list.insert(make_pair(processInfo.th32ProcessID, p));
			}
			mySet.insert(processInfo.th32ProcessID);
		} while (Process32Next(hSnapShot, &processInfo));
	}
	//删除已经关闭的PID
	for (auto iter = list.begin(); iter != list.end();) {
		if (mySet.find(iter->first) != mySet.end()) {
			iter++;
		}
		else {
			list.erase(iter++);
		}
	}
	mySet.clear();
	mt.unlock();
	return;
}
void GetProcessUser(HANDLE hSnapShot) {
	mt.lock();
	CString userName;
	SID_NAME_USE snu;
	TCHAR buffUsername[MAX_PATH];
	TCHAR buffDomainname[MAX_PATH];
	DWORD unSize;
	DWORD dnSize;

	WTS_PROCESS_INFO* ppProcessInfo;
	WTS_PROCESS_INFO* ppTemp;
	DWORD pCount;
	if (WTSEnumerateProcesses(&hSnapShot, 0, 1, &ppProcessInfo, &pCount)) {
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
	mt.unlock();
}
uint64_t convert_time_format(const FILETIME* ftime) {
	LARGE_INTEGER li;
	li.LowPart = ftime->dwLowDateTime;
	li.HighPart = ftime->dwHighDateTime;
	return li.QuadPart;
}
void GetCpu() {
	mt.lock();
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	int cpu_num = info.dwNumberOfProcessors;
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		FILETIME now, creationTime, exitTime, kernelTime, userTime;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		GetSystemTimeAsFileTime(&now);
		if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
			int64_t time = (convert_time_format(&kernelTime) + convert_time_format(&userTime)) / cpu_num;
			int64_t system_time = convert_time_format(&now);
			if (iter->second.last_system_time != 0 && iter->second.last_time != 0) {
				int64_t time_delta = time - iter->second.last_time;
				int64_t system_time_delta = system_time - iter->second.last_system_time;
				iter->second.CPU = (float)time_delta * 100 / (float)system_time_delta;
			}
			iter->second.last_time = time;
			iter->second.last_system_time = system_time;
		}
		CloseHandle(hProcess);
	}
	//处理空余CPU
	float sum = 0.0;
	for (auto iter = ++list.begin(); iter != list.end(); iter++) {
		sum += iter->second.CPU;
	}
	auto Process0 = list.find(0);
	Process0->second.CPU = 100.0 - sum;
	mt.unlock();
}
void GetMemoryAndPageFault() {
	mt.lock();
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
	mt.unlock();
}
void GetIOReadAndWrite() {
	mt.lock();
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		IO_COUNTERS io_counter;
		if (GetProcessIoCounters(hProcess, &io_counter)) {
			iter->second.IOread = io_counter.ReadTransferCount;
			iter->second.IOwrite = io_counter.WriteTransferCount;
		}
		CloseHandle(hProcess);
	}
	mt.unlock();
}
void GetHandleCnt() {
	mt.lock();
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		DWORD dwHandleCnt = 0;
		if (GetProcessHandleCount(hProcess, &dwHandleCnt)) {
			iter->second.handle_cnt = dwHandleCnt;
		}
		CloseHandle(hProcess);
	}
	mt.unlock();
}
void GetGdiCnt() {
	mt.lock();
	for (auto iter = list.begin(); iter != list.end(); iter++) {
		DWORD processID = iter->first;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
		DWORD dwGdi = GetGuiResources(hProcess, GR_GDIOBJECTS);
		iter->second.GDI_cnt = dwGdi;
		CloseHandle(hProcess);
	}
	mt.unlock();
}
void Show() {
	if (list.empty()) {
		printf("Please enter \"b\" to get information.\n");
		return;
	}
	mt.lock();
	printf("There are %d processes!\n", list.size());
	printf("%-35s|%-10s|%-15s|%10s|%10s|%10s|%10s|%10s|%10s|%10s|%10s\n", "Process Name", "ProcessID", "User Name", "CPU(%)", "Memory(B)", "IO Read", "IO Write", "Page Fault", "Threads", "Handles", "GDI");
	for (auto i = list.begin(); i != list.end(); i++) {
		Process* iter = &i->second;
		printf("%-35ls|%-10d|%-15ls|%10f|%10d|%10lld|%10lld|%10d|%10d|%10d|%10d\n", iter->name, i->first, iter->user_name, iter->CPU, iter->memory, iter->IOread, iter->IOwrite, iter->pagefault, iter->thread_cnt, iter->handle_cnt, iter->GDI_cnt);
	}
	mt.unlock();
}