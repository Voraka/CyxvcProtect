#ifdef SHELL_EXPORTS
#define SHELL_API __declspec(dllexport)
#else
#define SHELL_API __declspec(dllimport)
#endif

//导出ShellData结构体
extern"C"  typedef struct _SHELL_DATA
{
	DWORD dwStartFun;							//启动函数
	DWORD dwPEOEP;								//程序入口点
	DWORD dwXorKey;								//解密KEY
	DWORD dwCodeBase;							//代码段起始地址
	DWORD dwXorSize;							//代码段加密大小
	DWORD dwPEImageBase;						//PE文件映像基址

	IMAGE_DATA_DIRECTORY	stcPERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	stcPEImportDir;		//导入表信息

	DWORD					dwIATSectionBase;	//IAT所在段基址
	DWORD					dwIATSectionSize;	//IAT所在段大小

	BOOL					bIsShowMesBox;		//是否显示MessageBox

}SHELL_DATA, *PSHELL_DATA;

//导出ShellData结构体变量
extern"C" SHELL_API SHELL_DATA g_stcShellData;



//Shell部分用到的函数的类型定义
typedef DWORD(WINAPI *fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
typedef HMODULE(WINAPI *fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef HMODULE(WINAPI *fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
typedef BOOL(WINAPI *fnVirtualProtect)(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
typedef LPVOID(WINAPI *fnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef void(WINAPI *fnExitProcess)(_In_ UINT uExitCode);
typedef int(WINAPI *fnMessageBox)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
