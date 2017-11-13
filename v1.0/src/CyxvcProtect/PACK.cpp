#include "stdafx.h"
#include "PACK.h"
#include <psapi.h>
#include "../Shell/Shell.h"
#pragma comment(lib,"../Debug/Shell.lib")

CPACK::CPACK()
{
}


CPACK::~CPACK()
{
}

//************************************************************
// 函数名称:	Pack
// 函数说明:	加壳
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	CString strFilePath
// 参	数:	BOOL bIsShowMesBox
// 返 回	值:	BOOL
//************************************************************
BOOL CPACK::Pack(CString strFilePath, BOOL bIsShowMesBox)
{
	//1.读取PE文件信息并保存
	CPE objPE;
	if (objPE.InitPE(strFilePath) == FALSE)
		return FALSE;

	//2.加密代码段操作
	DWORD dwXorSize = 0;
	dwXorSize=objPE.XorCode(0x15);

	//3.将必要的信息保存到Shell
	HMODULE hShell = LoadLibrary(L"Shell.dll");
	if (hShell == NULL)
	{
		MessageBox(NULL, _T("加载Shell.dll模块失败，请确保程序的完整性！"), _T("提示"), MB_OK);
		//释放资源
		delete[] objPE.m_pFileBuf;
		return FALSE;
	}

	PSHELL_DATA pstcShellData = (PSHELL_DATA)GetProcAddress(hShell, "g_stcShellData");

	pstcShellData->dwXorKey = 0x15;
	pstcShellData->dwCodeBase = objPE.m_dwCodeBase;
	pstcShellData->dwXorSize = dwXorSize;
	pstcShellData->dwPEOEP = objPE.m_dwPEOEP;
	pstcShellData->dwPEImageBase = objPE.m_dwImageBase;
	pstcShellData->stcPERelocDir = objPE.m_PERelocDir;
	pstcShellData->stcPEImportDir = objPE.m_PEImportDir;
	pstcShellData->dwIATSectionBase = objPE.m_IATSectionBase;
	pstcShellData->dwIATSectionSize = objPE.m_IATSectionSize;
	pstcShellData->bIsShowMesBox = bIsShowMesBox;

	//4.将Shell附加到PE文件
	//4.1.读取Shell代码
	MODULEINFO modinfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), hShell, &modinfo, sizeof(MODULEINFO));
	PBYTE  pShellBuf = new BYTE[modinfo.SizeOfImage];
	memcpy_s(pShellBuf, modinfo.SizeOfImage, hShell, modinfo.SizeOfImage);
	//4.2.设置Shell重定位信息
	objPE.SetShellReloc(pShellBuf, (DWORD)hShell);	
	//4.3.修改被加壳程序的OEP，指向Shell
	DWORD dwShellOEP = pstcShellData->dwStartFun - (DWORD)hShell;
	objPE.SetNewOEP(dwShellOEP);
	//4.4.合并PE文件和Shell的代码到新的缓冲区
	LPBYTE pFinalBuf = NULL;
	DWORD dwFinalBufSize = 0;
	objPE.MergeBuf(objPE.m_pFileBuf, objPE.m_dwImageSize,
		pShellBuf, modinfo.SizeOfImage, 
		pFinalBuf, dwFinalBufSize);

	//5.保存文件（处理完成的缓冲区）
	SaveFinalFile(pFinalBuf, dwFinalBufSize, strFilePath);
	
	//6.释放资源
	delete[] objPE.m_pFileBuf;
	delete[] pShellBuf;
	delete[] pFinalBuf;
	objPE.InitValue();

	return TRUE;
}


//************************************************************
// 函数名称:	SaveFinalFile
// 函数说明:	保存文件测试
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	LPBYTE pFinalBuf
// 参	数:	DWORD pFinalBufSize
// 参	数:	CString strFilePath
// 返 回	值:	BOOL
//************************************************************
BOOL CPACK::SaveFinalFile(LPBYTE pFinalBuf, DWORD pFinalBufSize, CString strFilePath)
{
	//修正区段信息中 文件对齐大小（文件对齐大小同内存对齐大小）
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFinalBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFinalBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		pSectionHeader->PointerToRawData = pSectionHeader->VirtualAddress;
	}

	//清除不需要的目录表信息
	//只留输出表，重定位表，资源表
	DWORD dwCount = 15;
	for (DWORD i = 0; i < dwCount; i++)
	{
		if (i != IMAGE_DIRECTORY_ENTRY_EXPORT && 
			i != IMAGE_DIRECTORY_ENTRY_RESOURCE &&
			i != IMAGE_DIRECTORY_ENTRY_BASERELOC )
		{
			pNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
			pNtHeader->OptionalHeader.DataDirectory[i].Size = 0;
		}
	}

	//获取保存路径
	TCHAR strOutputPath[MAX_PATH] = { 0 };
	LPWSTR strSuffix = PathFindExtension(strFilePath);
	wcsncpy_s(strOutputPath, MAX_PATH, strFilePath, wcslen(strFilePath));
	PathRemoveExtension(strOutputPath);
	wcscat_s(strOutputPath, MAX_PATH, L"_cyxvc");
	wcscat_s(strOutputPath, MAX_PATH, strSuffix);

	//保存文件
	HANDLE hNewFile = CreateFile(
		strOutputPath,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, _T("保存文件失败！"), _T("提示"), MB_OK);
		return FALSE;
	}
	DWORD WriteSize = 0;
	BOOL bRes = WriteFile(hNewFile, pFinalBuf, pFinalBufSize, &WriteSize, NULL);
	if (bRes)
	{
		CloseHandle(hNewFile);
		return TRUE;
	}
	else
	{
		CloseHandle(hNewFile);
		MessageBox(NULL, _T("保存文件失败！"), _T("提示"), MB_OK);
		return FALSE;
	}
}
