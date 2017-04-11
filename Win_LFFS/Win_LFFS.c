// Win_LFFS.cpp : Defines the entry point for the console application.
//

#include "C:\Program Files\Dokan\Dokan Library-1.0.2\include\dokan\dokan.h"
#include "C:\Program Files\Dokan\Dokan Library-1.0.2\include\dokan\fileinfo.h"
#include <stdio.h>
#include <Windows.h>
#include <wchar.h>

#define TEST_FILE L"\\test.txt"
#define TEST_STRING "My test"

// global variables
int BLOCKSIZE = 512;	// blocksize of storage system
int ENTRYSIZE = 41;		// size of one entry in directory
int DATABEGIN = 512;	// beginning of user data at point 512 (513th space in array)
int ENTRIES = 0;		// number of entries within the directory
char block[512];		// array to store first block
struct entry *HEAD;		// head of array for the entries
HANDLE dataHandle;		// reference to the primary handle in the program
struct entry *FFRESULT;	// pointer that FindFile uses to point to found file

struct entry {
	char filename[16];		/* char array of the filename (w/ extension) */
	int start, end, off;	/* block locations and offset amount */
	struct stat *info;		/* not really used in Windows version */
	struct entry *next;		/* pointer to next entry in list */
};

/*
 * Function that takes a handle to the USB drive. Called before the initializing
 * DOKAN call. Loads the directory block (512 bytes) into memory and parses the
 * containing information to generate a linked list of the files and attributes
 * whose data is stored inside the rest of the drive.
 *
 * @param usbHandle -	HANDLE to the USB device to read from
 *
 */
void init_dir(HANDLE usbHandle)
{
	int count, i, begin;
	char filename[17];
	char start[11];
	char end[11];
	char off[3];
	struct entry *prev;

	if (usbHandle == INVALID_HANDLE_VALUE) {
		fwprintf(stdout, L"ERROR\t%d: Invalid handle value\n", GetLastError());
		Sleep(5000);
	}

	wprintf(L"[!] retreiving directory\n");

	// read dir from beginning into buffer
	memset(&block, '\0', sizeof(block));
	SetFilePointer(usbHandle, 0, NULL, FILE_BEGIN);			// seek to beginning of storage
															// read a block into memory
	ReadFile(usbHandle, block, sizeof(block), NULL, NULL);

	count = block[0] - '0';				// convert to int

	if (count < 0) ENTRIES = 0;
	else ENTRIES = count;

	// print result for debugging
	wprintf(L"Number of files:\t%d\n", count);

	// reads directories, currently printing locations of dirs in the block
	for (i = 1; i < ENTRIES + 1; i++) {

		if (i == 1) {
			prev = (struct entry*)malloc(sizeof(struct entry));
			printf("[!] Entry %d location\t10\n", i);

			memcpy(filename, &block[10], 16);
			filename[16] = '\0';
			printf("[+] filename\t%s\n", filename);
			memcpy(prev->filename, &filename, 16);

			// copy start location from directory
			memcpy(start, &block[26], 11);
			start[10] = '\0';
			printf("[+] begin\t%s|%d\n", start, atoi(start));
			prev->start = atoi(start);

			// copy end location from directory
			memcpy(end, &block[37], 11);
			end[10] = '\0';
			printf("[+] end\t\t%s|%d\n", end, atoi(end));
			prev->end = atoi(end);

			// copy the offset of the last block from mem
			memcpy(off, &block[48], 3);
			off[2] = '\0';
			printf("[+] offset\t%s|%d\n", off, atoi(off));
			prev->off = atoi(off);

			HEAD = prev;

		} else {
			struct entry *tmp = malloc(sizeof(struct entry));

			begin = 10 + (41 * (i - 1));		// calculate the location of entry
			printf("[!] Entry %d location\t%d\n", i, begin);

			// copy filename from dir and into array for struct use
			memcpy(filename, &block[begin], 16);
			filename[15] = '\0';
			printf("[+] filename\t%s\n", filename);
			memcpy(tmp->filename, filename, 16);

			// copy start location from directory
			memcpy(start, &block[begin + 16], 11);
			start[10] = '\0';
			printf("[+] begin\t%s|%d\n", start, atoi(start));
			tmp->start = atoi(start);

			// copy end location from directory
			memcpy(end, &block[begin + 27], 11);
			end[10] = '\0';
			printf("[+] end\t\t%s|%d\n", end, atoi(end));
			tmp->end = atoi(end);

			// copy the offset of the last block from mem
			memcpy(off, &block[begin + 38], 3);
			off[2] = '\0';
			printf("[+] offset\t%s|%d\n", off, atoi(off));
			tmp->off = atoi(end);

			prev->next = tmp;
			prev = tmp;
		}
	}
}

/*
 * Function that takes a pointer to a string of 16-bit Unicode chars which make
 * up the filename that the OS is searching for. Cleaner than looping through
 * on individual functions. If the file is in the filesystem directory, it will
 * set global pointer FFRESULT to the entry struct representing that file and 
 * return a 0. If it is not in the system, it will set the pointer to NULL and 
 * return a 1.
 *
 * @param FileName - pointer to the string of the file to search for
 *
 */
static int FindFile(LPWSTR FileName) {
	// found online: http://stackoverflow.com/questions/4295754/how-to-remove-first-character-from-c-string
	LPWSTR CleanFileName = memmove(FileName + 1, FileName + 1, strlen(FileName));
	wchar_t ConvertedExisting[50];
	struct entry *tmp;

	fwprintf(stderr, L"[!] FindFile for %s\n", CleanFileName);

	tmp = HEAD;
	int i = 0;
	while (i < ENTRIES) {
		mbstowcs_s(NULL, ConvertedExisting, 50, tmp->filename, 16);
		fwprintf(stderr, L"[!] testing conversion...\t%s\n", ConvertedExisting);
		if (lstrcmpW(CleanFileName, ConvertedExisting) == 0) {
			FFRESULT = tmp;
			return 0;
		} else {
			tmp = tmp->next;
			i++;
		}
	}

	FFRESULT = NULL;
	return 1;
}

static NTSTATUS DOKAN_CALLBACK LFFSGetVolumeInformation(LPWSTR VolumeNameBuffer,
	DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
	LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
	LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "LFFSGetVolumeInformation\n");

	/* TODO: Pull info directly from drive and calculate used space */
	wcscpy_s(VolumeNameBuffer, VolumeNameSize, L"USB");
	*VolumeSerialNumber = 0x123456789;
	*MaximumComponentLength = 15;
	FileSystemFlags = 0;
	wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, L"LFFS");

	return STATUS_SUCCESS;
}

/* Will be fairly open, returns STATUS_SUCCESS unless something goes wrong */
static NTSTATUS DOKAN_CALLBACK LFFSZwCreateFile(
	LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess, ULONG FileAtrributes, ULONG ShareAccess,
	ULONG CreateDisposition, ULONG CreateOptions,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	LPSECURITY_ATTRIBUTES lpSecurityAttributes;
	/* variables for the CreateFile file handle */
	HANDLE handle;
	DWORD desiredAccess;
	DWORD shareMode;
	DWORD creationDisposition;
	DWORD flagsAndAttributes;


	/* if IsDirectory and CreateDisposition is 1 (or True) we create a directory and file */
	fwprintf(stderr, L"[+] LFFSZwCreateFile\n"
		L"\t FileName\t%s\n"
		L"\t IsDirectory\t%d\n"
		L"\t CreateDisposition\t%d\n"
		, FileName, DokanFileInfo->IsDirectory, CreateDisposition);

	/* check if the request is made for the root directory. If so, then create a
	Windows file handle struct to attach to the DokanFileInfo->Context */
	if (lstrcmpW(FileName, L"\\") == 0) {
		fprintf(stderr, "[+] Root directory. Creating link.\n");
		/* return success once handle created and linked */
		DokanFileInfo->IsDirectory = TRUE;
		return STATUS_SUCCESS;
	}

	/* if it is our file, give it the attributes */
	else if (lstrcmpW(FileName, L"\\desktop.ini") == 0) {
		/* use fwprintf from now on! */
		fwprintf(stderr, L"[!] File found:\t%s", FileName);
		return STATUS_NOT_FOUND;
	}

	/*else if (lstrcmpW(FileName, L"\\file2.iso") == 0) {
		fprintf(stderr, "[+] file addition test\n");
		DokanFileInfo->IsDirectory = FALSE;
		return STATUS_SUCCESS;
	}*/
	else {
		return STATUS_SUCCESS;
	}
}

static NTSTATUS DOKAN_CALLBACK LFFSGetFileInformation(LPCWSTR FileName,
	LPBY_HANDLE_FILE_INFORMATION Buffer, PDOKAN_FILE_INFO DokanFileInfo)
{
	/* variables for the file information struct */
	DWORD fileAttributes;
	DWORD volumeSerialNumber;
	DWORD fileSizeHigh;
	DWORD fileSizeLow;
	DWORD numberOfLinks;
	DWORD fileIndexHigh;
	DWORD fileIndexLow;

	fprintf(stderr, L"[!] GetFileInformation called on %s\n", FileName);

	if (lstrcmpW(FileName, L"\\") == 0) {
		/* only dealing with the root dir here */
		Buffer->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY | FILE_FLAG_BACKUP_SEMANTICS;
		return STATUS_SUCCESS;
	}
	/*else if (lstrcmpW(FileName, L"\\testfile.txt") == 0) {
		fwprintf(stderr, L"[!] LFFSGetFileInformation on %s", FileName);

		/* setting up generic attributes */
		/*Buffer->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
		Buffer->nFileSizeHigh = 0;
		Buffer->nFileSizeLow = ((HEAD->end - HEAD->start) * 512) + HEAD->off;

		return STATUS_SUCCESS;
	} 

	/* second condition to test file addition */
	/*else if(lstrcmpW(FileName, L"\\file2.iso") == 0) {
		fwprintf(stderr, "[!] LFFSGetFileInformation called on the new file\n");
		Buffer->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
		Buffer->nFileSizeHigh = 0;
		Buffer->nFileSizeLow = 0;
		return STATUS_SUCCESS;
	}*/ 

	else if (FindFile(FileName) == 0) {
		Buffer->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
		Buffer->nFileSizeHigh = 0;
		Buffer->nFileSizeLow = ((FFRESULT->end - FFRESULT->start) * 512) + FFRESULT->off;
		fprintf(stderr, "[+] File Found!\t%s\n", FFRESULT->filename);
	} else {
		fprintf(stderr, "[-] No file info to show\n");
		return STATUS_FILE_NOT_AVAILABLE;
	}
}

/*
 * If the file is complete, the buffer will not be filled all the way. Otherwise,
 * you must fill the buffer in order to get the program to keep requesting more.
 *
 * @param FileName      - pointer to the string of requested file
 * @param Buffer	    - pointer to the buffer to write to
 * @param BufferLength  - buffer size
 * @param ReadLength    - amount of data read (in bytes)
 * @param Offset	    - space already written
 * @param DokanFileInfo - optional reference passed (not used yet)
 *
 */
static NTSTATUS DOKAN_CALLBACK LFFSReadFile(LPCWSTR FileName, LPVOID Buffer,
	DWORD BufferLength, LPDWORD ReadLength, LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	double dataLocation, fileSize;

	if (lstrcmpW(FileName, L"\\testfile.txt") == 0) {
		fwprintf(stderr, L"[!] Read called on %s.\n"
			L"\tBufferLength:\t%d\n"
			L"\tReadLength:\t%d\n"
			L"\tOffset:\t%d\n"
			, FileName, BufferLength, *ReadLength, Offset);

		/* calculates location of data in memory */
		dataLocation = HEAD->start * 512;										// normally would find file, but only one for now
		fwprintf(stderr, L"\tdata begin location %lf\n", dataLocation);			// debugging 
		fileSize = (HEAD->start - HEAD->end) + HEAD->off;						// calculated bytes to write
		fwprintf(stderr, L"\tfilesize calculated at %lf byte(s)\n", fileSize);	// more debugging
		

		/* retrieving data */
		char *retrieveData;

		/* temp check to make sure we can fit file into buffer */
		retrieveData = (char *)malloc(BufferLength);
		SetFilePointer(dataHandle, dataLocation, 0, FILE_BEGIN);
		ReadFile(dataHandle, retrieveData, BufferLength, NULL, NULL);
		fprintf(stderr, "Size of data retrieved %s\n", retrieveData);

		/* moving data to buffer and modifying values */
		memcpy_s(Buffer, BufferLength, retrieveData, BufferLength);		//use this since it doesn't add a space (null term)
		*ReadLength = BufferLength;

		free(retrieveData);

		return STATUS_SUCCESS;
	}
}

/*
 * DOKAN API Callback that takes a buffer filled with data and has to write that data to
 * the filesystem. 
 */
static NTSTATUS DOKAN_CALLBACK LFFSWriteFile(LPCWSTR FileName, LPCVOID Buffer,
	DWORD NumberOfBytesToWrite, LPDWORD NumberOfBytesWritten,
	LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
	fwprintf(stderr, L"[!] Write called.\n"
		L"\tfilename\t%s\n"
		L"\tbytes to write\t%d\n"
		L"\toffset\t%d\n",
		FileName, NumberOfBytesToWrite, Offset);
	return STATUS_SUCCESS;
}

static VOID DOKAN_CALLBACK LFFSCleanup(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo)
{
	fwprintf(stderr, L"[!] CloseFile called on %s\n", FileName);
	DokanFileInfo->Context = NULL;
}

static VOID DOKAN_CALLBACK LFFSCloseFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo)
{
	fwprintf(stderr, L"[!] CloseFile called on %s\n", FileName);
}

static NTSTATUS DOKAN_CALLBACK LFFSMounted(PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] Mount called.\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK LFFSFindFiles(LPCWSTR FileName, PFillFindData ffd, PDOKAN_FILE_INFO DokanFileInfo)
{
	PWIN32_FIND_DATA findData = (PWIN32_FIND_DATA)malloc(sizeof(PWIN32_FIND_DATA));
	struct entry *tmp;
	wchar_t namebuf[64];
	int i;

	tmp = HEAD;
	/*for (i = 0; i < ENTRIES; i++) {
		fprintf(stderr, "[+] Listing filename %s\n", tmp->filename);
		mbstowcs_s(NULL, namebuf, 50, tmp->filename, 16);
		wcscpy_s(findData->cFileName, sizeof(namebuf), namebuf);
		findData->nFileSizeHigh = 0;
		findData->nFileSizeLow = ((HEAD->end - HEAD->start) * 512) + HEAD->off;
		fprintf(stderr, "filesize is %d\n", findData->nFileSizeLow);
		ffd(findData, DokanFileInfo);
		tmp = tmp->next;
	}*/

	/* test for handling one file */
	fprintf(stderr, "[!] Listing filename %s\n", HEAD->filename);	// debugging
	mbstowcs_s(NULL, namebuf, 50, tmp->filename, 16);				// convert char array to wchar_t array
	wcscpy_s(findData->cFileName, sizeof(namebuf), namebuf);		// copy filename to struct for file listing
	findData->nFileSizeHigh = 0;									// high order set to zero for testing purposes (only small files)
	findData->nFileSizeLow = (tmp->end - tmp->start) + tmp->off;	// calculates and sets the low order value
	ffd(findData, DokanFileInfo);									// uses function pointer to return data to Dokan



	free(findData);

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK LFFSSetFileAttributes(LPCWSTR FileName,
	DWORD FileAttributes, PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] LFFSSetFileAttributes called\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK LFFSSetAllocationSize(LPCWSTR FileName, 
	LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] SetAllocationSizeCalled on %s\n", FileName);
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK LFFSSetFileTime(LPCWSTR FileName, CONST FILETIME
	*CreationTime, CONST FILETIME *LastAccessTime, CONST FILETIME *LastWriteTime,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] LFFSSetFileTime called on %s\n", FileName);
	return STATUS_SUCCESS;
}

/*
 * DOKAN API Callback for truncating or extending the file size.
 *
 * @param FileName		- file path requested
 * @param ByteOffset	- file length to set
 * @param DokanFileInfo	- additional file info I have added | optional
 */
static NTSTATUS DOKAN_CALLBACK LFFSSetEndOfFile(LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO
	DokanFileInfo)
{
	fprintf(stderr, "[!] LFFSSetEndOfFile\n"
		"\tfilename\t%s\n"
		"\tnew size\t%d\n"
		, FileName, ByteOffset);
	return STATUS_SUCCESS;
}


static NTSTATUS DOKAN_CALLBACK LFFSGetFileSecurity(LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength, PULONG LengthNeeded,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] LFFSGetSecurity called on file %s\n", FileName);
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK LFFSDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] LFFSDeleteDirectory called\n");
	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK LFFSGetDiskFreeSpace(PULONGLONG FreeBytesAvailable,
	PULONGLONG TotalNumberOfBytes, PULONGLONG TotalNumberOfFreeBytes,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] LFFSGetDiskFreeSpace");

	/* put random stuff here for now */
	*FreeBytesAvailable = 10240000000;
	*TotalNumberOfBytes = 20480000000;
	*TotalNumberOfFreeBytes = 10240000000;

	return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK LFFSFindFilesWithPattern(LPCWSTR PathName, LPCWSTR SearchPattern,
	PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo)
{
	fprintf(stderr, "[!] LFFSFindFilesWithPattern called\n");
	return STATUS_NOT_IMPLEMENTED;
}

int main()
{
	/* Dokan operations */
	PDOKAN_OPERATIONS dokanOperations = (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
	PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));

	/* init operations */
	HANDLE usbHandle;
	char Buffer[512];
	char *toWrite = "My Test String";
	DWORD bytesRead;
	int i;

	usbHandle = CreateFile("\\\\.\\PhysicalDrive1", GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_DEVICE, NULL);

	if (usbHandle == INVALID_HANDLE_VALUE) {
		fwprintf(stdout, L"ERROR\t%d: Invalid handle value\n", GetLastError());
		Sleep(5000);
	}

	// seek to beginning
	if (SetFilePointer(usbHandle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		fprintf(stdout, "ERROR setting pointer:\t%d\n", GetLastError());
		Sleep(5000);
	}

	// seek and read back
	SetFilePointer(usbHandle, 0, NULL, FILE_BEGIN);
	if (!ReadFile(usbHandle, Buffer, 512, &bytesRead, NULL)) fprintf(stdout, "ERROR reading from file:\t%d\n", GetLastError());
	fprintf(stdout, "Bytes Read:\t%d\n", bytesRead);

	init_dir(usbHandle);
	dataHandle = usbHandle;

	for (i = 0; i < 512; i++) fprintf(stdout, "%c", Buffer[i]);

	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));

	dokanOptions->MountPoint = L"E";
	/* seems to cause some issues if uncommented. Not sure why. */
	//dokanOptions->Options = DOKAN_OPTION_DEBUG | DOKAN_OPTION_STDERR;
	//dokanOptions->Options = DOKAN_OPTIONS
	dokanOptions->Version = DOKAN_VERSION;
	dokanOptions->ThreadCount = 1;

	dokanOperations->FindFiles = LFFSFindFiles;
	dokanOperations->ZwCreateFile = LFFSZwCreateFile;
	dokanOperations->Mounted = LFFSMounted;
	dokanOperations->Cleanup = LFFSCleanup;
	dokanOperations->ReadFile = LFFSReadFile;
	dokanOperations->WriteFile = LFFSWriteFile;
	dokanOperations->GetVolumeInformationA = LFFSGetVolumeInformation;
	dokanOperations->GetFileInformation = LFFSGetFileInformation;
	dokanOperations->CloseFile = LFFSCloseFile;
	dokanOperations->DeleteDirectory = LFFSDeleteDirectory;
	dokanOperations->FindFilesWithPattern = NULL;
	dokanOperations->SetFileAttributesA = LFFSSetFileAttributes;
	dokanOperations->GetDiskFreeSpaceA = LFFSGetDiskFreeSpace;
	dokanOperations->GetFileSecurityA = LFFSGetFileSecurity;
	dokanOperations->FindFilesWithPattern = LFFSFindFilesWithPattern;
	dokanOperations->SetAllocationSize = LFFSSetAllocationSize;
	dokanOperations->SetFileTime = LFFSSetFileTime;
	dokanOperations->SetEndOfFile = LFFSSetEndOfFile;

	printf("Handing off to DOKAN\n");
	int status = DokanMain(dokanOptions, dokanOperations);
	return 0;
}

