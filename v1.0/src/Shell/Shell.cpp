// Shell.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "Shell.h"

#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

//函数和变量的声明
DWORD MyGetProcAddress();		//自定义GetProcAddress
HMODULE	GetKernel32Addr();		//获取Kernel32加载基址
void Start();					//启动函数(Shell部分的入口函数)
void InitFun();					//初始化函数指针和变量
void DeXorCode();				//解密操作
void RecReloc();				//修复重定位操作
void RecIAT();					//修复IAT操作
SHELL_DATA g_stcShellData = { (DWORD)Start };
								//Shell用到的全局变量结构体
DWORD dwImageBase	= 0;		//整个程序的镜像基址
DWORD dwPEOEP		= 0;		//PE文件的OEP

//Shell部分用到的函数定义
fnGetProcAddress	g_pfnGetProcAddress		= NULL;
fnLoadLibraryA		g_pfnLoadLibraryA		= NULL;
fnGetModuleHandleA	g_pfnGetModuleHandleA	= NULL;
fnVirtualProtect	g_pfnVirtualProtect		= NULL;
fnVirtualAlloc		g_pfnVirtualAlloc		= NULL;
fnExitProcess		g_pfnExitProcess		= NULL;
fnMessageBox		g_pfnMessageBoxA		= NULL;

 //************************************************************
// 函数名称:	Start
// 函数说明:	启动函数(Shell部分的入口函数)
// 作	者:	cyxvc
// 时	间:	2015/12/28
// 返 回	值:	void
//************************************************************
__declspec(naked) void Start()
{
 	__asm pushad

	InitFun();

	DeXorCode();

	if (g_stcShellData.stcPERelocDir.VirtualAddress)
	{
		RecReloc();
	}
	RecIAT();

	if (g_stcShellData.bIsShowMesBox)
	{
		g_pfnMessageBoxA(0, "欢迎使用CyxvcProtect, by 15PB !", "Hello!", 0);
	}

	__asm popad

	//获取OEP信息
	dwPEOEP = g_stcShellData.dwPEOEP + dwImageBase;
	__asm jmp dwPEOEP
	
	g_pfnExitProcess(0);	//实际不会执行此条指令
}

//************************************************************
// 函数名称:	RecIAT
// 函数说明:	修复IAT操作
// 作	者:	cyxvc
// 时	间:	2015/12/28
// 返 回	值:	void
//************************************************************
void RecIAT()
{
	//1.获取导入表结构体指针
	PIMAGE_IMPORT_DESCRIPTOR pPEImport = 
		(PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase + g_stcShellData.stcPEImportDir.VirtualAddress);
	
	//2.修改内存属性为可写
	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect(
		(LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
		PAGE_EXECUTE_READWRITE, &dwOldProtect);

	//3.开始修复IAT
	while (pPEImport->Name)
	{
		//获取模块名
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(dwImageBase + dwModNameRVA);
		HMODULE hMod = g_pfnLoadLibraryA(pModName);

		//获取IAT信息(有些PE文件INT是空的，最好用IAT解析，也可两个都解析作对比)
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->FirstThunk);
		
		//获取INT信息(同IAT一样，可将INT看作是IAT的一个备份)
		//PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(dwImageBase + pPEImport->OriginalFirstThunk);

		//通过IAT循环获取该模块下的所有函数信息(这里之获取了函数名)
		while (pIAT->u1.AddressOfData)
		{
			//判断是输出函数名还是序号
			if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
			{
				//输出序号
				DWORD dwFunOrdinal = (pIAT->u1.Ordinal) & 0x7FFFFFFF;
				DWORD dwFunAddr = g_pfnGetProcAddress(hMod, (char*)dwFunOrdinal);
				*(DWORD*)pIAT = (DWORD)dwFunAddr;
			}
			else
			{
				//输出函数名
				DWORD dwFunNameRVA = pIAT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase + dwFunNameRVA);
				DWORD dwFunAddr = g_pfnGetProcAddress(hMod, pstcFunName->Name);
				*(DWORD*)pIAT = (DWORD)dwFunAddr;
			}
			pIAT++;
		}
		//遍历下一个模块
		pPEImport++;
	}

	//4.恢复内存属性
	g_pfnVirtualProtect(
		(LPBYTE)(dwImageBase + g_stcShellData.dwIATSectionBase), g_stcShellData.dwIATSectionSize,
		dwOldProtect, &dwOldProtect);
}

//************************************************************
// 函数名称:	RecReloc
// 函数说明:	修复重定位操作
// 作	者:	cyxvc
// 时	间:	2015/12/28
// 返 回	值:	void
//************************************************************
void RecReloc()
{
	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;		//偏移值
		WORD Type : 4;			//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;

	//1.获取重定位表结构体指针
	PIMAGE_BASE_RELOCATION	pPEReloc=
		(PIMAGE_BASE_RELOCATION)(dwImageBase + g_stcShellData.stcPERelocDir.VirtualAddress);
	
	//2.开始修复重定位
	while (pPEReloc->VirtualAddress)
	{
		//2.1修改内存属性为可写
		DWORD dwOldProtect = 0;
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);

		//2.2修复重定位
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		DWORD dwNumber = (pPEReloc->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == NULL)
				break;
			//RVA
			DWORD dwRVA = pTypeOffset[i].offset + pPEReloc->VirtualAddress;
			//FAR地址
			DWORD AddrOfNeedReloc = *(PDWORD)((DWORD)dwImageBase + dwRVA);
			*(PDWORD)((DWORD)dwImageBase + dwRVA) = 
				AddrOfNeedReloc - g_stcShellData.dwPEImageBase + dwImageBase;
		}

		//2.3恢复内存属性
		g_pfnVirtualProtect((PBYTE)dwImageBase + pPEReloc->VirtualAddress,
			0x1000, dwOldProtect, &dwOldProtect);

		//2.4修复下一个区段
		pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
	}
}


//************************************************************
// 函数名称:	DeXorCode
// 函数说明:	解密操作
// 作	者:	cyxvc
// 时	间:	2015/12/28
// 返 回	值:	void
//************************************************************
void DeXorCode()
{
	PBYTE pCodeBase = (PBYTE)g_stcShellData.dwCodeBase + dwImageBase;

	DWORD dwOldProtect = 0;
	g_pfnVirtualProtect(pCodeBase, g_stcShellData.dwXorSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	for (DWORD i = 0; i < g_stcShellData.dwXorSize; i++)
	{
		pCodeBase[i] ^= i;
	}

	g_pfnVirtualProtect(pCodeBase, g_stcShellData.dwXorSize, dwOldProtect, &dwOldProtect);
}

//************************************************************
// 函数名称:	InitFun
// 函数说明:	初始化函数指针和变量
// 作	者:	cyxvc
// 时	间:	2015/12/28
// 返 回	值:	void
//************************************************************
void InitFun()
{
	//从Kenel32中获取函数
	HMODULE hKernel32		= GetKernel32Addr();
	g_pfnGetProcAddress		= (fnGetProcAddress)MyGetProcAddress();
	g_pfnLoadLibraryA		= (fnLoadLibraryA)g_pfnGetProcAddress(hKernel32, "LoadLibraryA");
	g_pfnGetModuleHandleA	= (fnGetModuleHandleA)g_pfnGetProcAddress(hKernel32, "GetModuleHandleA");
	g_pfnVirtualProtect		= (fnVirtualProtect)g_pfnGetProcAddress(hKernel32, "VirtualProtect");
	g_pfnExitProcess		= (fnExitProcess)g_pfnGetProcAddress(hKernel32, "ExitProcess");
	g_pfnVirtualAlloc		= (fnVirtualAlloc)g_pfnGetProcAddress(hKernel32, "VirtualAlloc");

	//从user32中获取函数
	HMODULE hUser32			= g_pfnLoadLibraryA("user32.dll");
	g_pfnMessageBoxA		= (fnMessageBox)g_pfnGetProcAddress(hUser32, "MessageBoxA");

	//初始化镜像基址
	dwImageBase =			(DWORD)g_pfnGetModuleHandleA(NULL);
}


//************************************************************
// 函数名称:	GetKernel32Addr
// 函数说明:	获取Kernel32加载基址
// 作	者:	cyxvc
// 时	间:	2015/12/28
// 返 回	值:	HMODULE
//************************************************************
HMODULE GetKernel32Addr()
{
	HMODULE dwKernel32Addr = 0;
	__asm
	{
		push eax
			mov eax, dword ptr fs : [0x30]   // eax = PEB的地址
			mov eax, [eax + 0x0C]            // eax = 指向PEB_LDR_DATA结构的指针
			mov eax, [eax + 0x1C]            // eax = 模块初始化链表的头指针InInitializationOrderModuleList
			mov eax, [eax]                   // eax = 列表中的第二个条目
			mov eax, [eax]                   // eax = 列表中的第三个条目
			mov eax, [eax + 0x08]            // eax = 获取到的Kernel32.dll基址(Win7下第三个条目是Kernel32.dll)
			mov dwKernel32Addr, eax
			pop eax
	}
	return dwKernel32Addr;
}


//************************************************************
// 函数名称:	MyGetProcAddress
// 函数说明:	自定义GetProcAddress
// 作	者:	cyxvc
// 时	间:	2015/12/28
// 返 回	值:	DWORD
//************************************************************
DWORD MyGetProcAddress()
{
	HMODULE hModule = GetKernel32Addr();

	//1.获取DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hModule;
	//2.获取NT头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//3.获取导出表的结构体指针
	PIMAGE_DATA_DIRECTORY pExportDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

	PIMAGE_EXPORT_DIRECTORY pExport = 
		(PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pExportDir->VirtualAddress);

	//EAT
	PDWORD pEAT = (PDWORD)((DWORD)hModule + pExport->AddressOfFunctions);
	//ENT
	PDWORD pENT = (PDWORD)((DWORD)hModule + pExport->AddressOfNames);
	//EIT
	PWORD pEIT = (PWORD)((DWORD)hModule + pExport->AddressOfNameOrdinals);

	//4.遍历导出表，获取GetProcAddress()函数地址
	DWORD dwNumofFun = pExport->NumberOfFunctions;
	DWORD dwNumofName = pExport->NumberOfNames;
	for (DWORD i = 0; i < dwNumofFun; i++)
	{
		//如果为无效函数，跳过
		if (pEAT[i] == NULL)
			continue;
		//判断是以函数名导出还是以序号导出
		DWORD j = 0;
		for (; j < dwNumofName; j++)
		{
			if (i == pEIT[j])
			{
				break;
			}
		}
		if (j != dwNumofName)
		{
			//如果是函数名方式导出的
			//函数名
			char* ExpFunName = (CHAR*)((PBYTE)hModule + pENT[j]);
			//进行对比,如果正确返回地址
			if (!strcmp(ExpFunName, "GetProcAddress"))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
		else
		{
			//序号
		}
	}
	return 0;
}