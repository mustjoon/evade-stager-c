.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data

.code

EXTERN SW2_GetSyscallNumber: PROC

WhisperMain PROC
    pop eax                        ; Remove return address from CALL instruction
    call SW2_GetSyscallNumber      ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, fs:[0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword ptr fs:[0c0h]
    ret
WhisperMain ENDP

NtAccessCheck PROC
    push 07EDB3767h
    call WhisperMain
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
    push 0822AA280h
    call WhisperMain
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
    push 01EB83726h
    call WhisperMain
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
    push 0A01CF8D6h
    call WhisperMain
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
    push 004DD6C41h
    call WhisperMain
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
    push 021633CECh
    call WhisperMain
NtCallbackReturn ENDP

NtReadFile PROC
    push 054937C10h
    call WhisperMain
NtReadFile ENDP

NtDeviceIoControlFile PROC
    push 0B519DD91h
    call WhisperMain
NtDeviceIoControlFile ENDP

NtWriteFile PROC
    push 00ABB4412h
    call WhisperMain
NtWriteFile ENDP

NtRemoveIoCompletion PROC
    push 01ED61275h
    call WhisperMain
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
    push 0F8AA2D02h
    call WhisperMain
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
    push 020B34760h
    call WhisperMain
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
    push 02BB1A1AFh
    call WhisperMain
NtReplyPort ENDP

NtSetInformationThread PROC
    push 0AC97AA3Dh
    call WhisperMain
NtSetInformationThread ENDP

NtSetEvent PROC
    push 000A31324h
    call WhisperMain
NtSetEvent ENDP

NtClose PROC
    push 04295B4C5h
    call WhisperMain
NtClose ENDP

NtQueryObject PROC
    push 06C56C57Ch
    call WhisperMain
NtQueryObject ENDP

NtQueryInformationFile PROC
    push 024313EB6h
    call WhisperMain
NtQueryInformationFile ENDP

NtOpenKey PROC
    push 0A522D2DCh
    call WhisperMain
NtOpenKey ENDP

NtEnumerateValueKey PROC
    push 0398DD6FBh
    call WhisperMain
NtEnumerateValueKey ENDP

NtFindAtom PROC
    push 068FF496Eh
    call WhisperMain
NtFindAtom ENDP

NtQueryDefaultLocale PROC
    push 011192390h
    call WhisperMain
NtQueryDefaultLocale ENDP

NtQueryKey PROC
    push 0320CD316h
    call WhisperMain
NtQueryKey ENDP

NtQueryValueKey PROC
    push 046E45177h
    call WhisperMain
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
    push 007951D07h
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
    push 08F2C8EB0h
    call WhisperMain
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
    push 090992C57h
    call WhisperMain
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
    push 0F3A2F537h
    call WhisperMain
NtWriteFileGather ENDP

NtCreateKey PROC
    push 06ADF754Ch
    call WhisperMain
NtCreateKey ENDP

NtFreeVirtualMemory PROC
    push 00F503BECh
    call WhisperMain
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
    push 0A032C5E0h
    call WhisperMain
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
    push 0E38DCA1Bh
    call WhisperMain
NtReleaseMutant ENDP

NtQueryInformationToken PROC
    push 00396492Eh
    call WhisperMain
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
    push 0A4FEA16Eh
    call WhisperMain
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
    push 0CE53A6B2h
    call WhisperMain
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
    push 0E8ACE432h
    call WhisperMain
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
    push 0329CADAFh
    call WhisperMain
NtQueryInformationThread ENDP

NtOpenProcess PROC
    push 00FA30E32h
    call WhisperMain
NtOpenProcess ENDP

NtSetInformationFile PROC
    push 0393951B9h
    call WhisperMain
NtSetInformationFile ENDP

NtMapViewOfSection PROC
    push 00C8E0A3Bh
    call WhisperMain
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
    push 0F4B2F01Bh
    call WhisperMain
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
    push 0F4A5D271h
    call WhisperMain
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
    push 06FD2B3B6h
    call WhisperMain
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
    push 0DD863C12h
    call WhisperMain
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
    push 0F37A3C2Bh
    call WhisperMain
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
    push 08134CBE9h
    call WhisperMain
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
    push 0069FCBD9h
    call WhisperMain
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
    push 0091E59C7h
    call WhisperMain
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
    push 02B945D15h
    call WhisperMain
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
    push 00A1F2D84h
    call WhisperMain
NtEnumerateKey ENDP

NtOpenFile PROC
    push 0B4829E16h
    call WhisperMain
NtOpenFile ENDP

NtDelayExecution PROC
    push 045107C57h
    call WhisperMain
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
    push 03AB8E01Fh
    call WhisperMain
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
    push 0D847DAD3h
    call WhisperMain
NtQuerySystemInformation ENDP

NtOpenSection PROC
    push 09B30FBFEh
    call WhisperMain
NtOpenSection ENDP

NtQueryTimer PROC
    push 0195ADA00h
    call WhisperMain
NtQueryTimer ENDP

NtFsControlFile PROC
    push 01CBA4F8Ch
    call WhisperMain
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
    push 0C749CDDBh
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
    push 01091F08Ch
    call WhisperMain
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
    push 0A880439Ch
    call WhisperMain
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
    push 0E6DC31EFh
    call WhisperMain
NtQueryAttributesFile ENDP

NtClearEvent PROC
    push 02E85D502h
    call WhisperMain
NtClearEvent ENDP

NtReadVirtualMemory PROC
    push 00F93E2F4h
    call WhisperMain
NtReadVirtualMemory ENDP

NtOpenEvent PROC
    push 0D1BBD22Ch
    call WhisperMain
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
    push 0F5C0E760h
    call WhisperMain
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
    push 007910B08h
    call WhisperMain
NtDuplicateToken ENDP

NtContinue PROC
    push 002A6734Ah
    call WhisperMain
NtContinue ENDP

NtQueryDefaultUILanguage PROC
    push 0FFCC61F5h
    call WhisperMain
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
    push 0EB4C665Dh
    call WhisperMain
NtQueueApcThread ENDP

NtYieldExecution PROC
    push 0089F2A0Fh
    call WhisperMain
NtYieldExecution ENDP

NtAddAtom PROC
    push 0B721B2CBh
    call WhisperMain
NtAddAtom ENDP

NtCreateEvent PROC
    push 00A09099Eh
    call WhisperMain
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
    push 0F4A4FA30h
    call WhisperMain
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
    push 038EE5A3Fh
    call WhisperMain
NtCreateSection ENDP

NtFlushBuffersFile PROC
    push 06979F640h
    call WhisperMain
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
    push 07DE25571h
    call WhisperMain
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
    push 0B198C362h
    call WhisperMain
NtCreateProcessEx ENDP

NtCreateThread PROC
    push 08C91B60Fh
    call WhisperMain
NtCreateThread ENDP

NtIsProcessInJob PROC
    push 079C2697Fh
    call WhisperMain
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
    push 01F81091Fh
    call WhisperMain
NtProtectVirtualMemory ENDP

NtQuerySection PROC
    push 00F582D95h
    call WhisperMain
NtQuerySection ENDP

NtResumeThread PROC
    push 08A13C4B9h
    call WhisperMain
NtResumeThread ENDP

NtTerminateThread PROC
    push 0CE6B8849h
    call WhisperMain
NtTerminateThread ENDP

NtReadRequestData PROC
    push 018B5020Eh
    call WhisperMain
NtReadRequestData ENDP

NtCreateFile PROC
    push 01D7CF73Bh
    call WhisperMain
NtCreateFile ENDP

NtQueryEvent PROC
    push 0C850CDE6h
    call WhisperMain
NtQueryEvent ENDP

NtWriteRequestData PROC
    push 064DE9348h
    call WhisperMain
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
    push 01CB0CDFDh
    call WhisperMain
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
    push 09A527C02h
    call WhisperMain
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
    push 0A12CABB5h
    call WhisperMain
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
    push 0BA968629h
    call WhisperMain
NtSetInformationObject ENDP

NtCancelIoFile PROC
    push 07CEB7240h
    call WhisperMain
NtCancelIoFile ENDP

NtTraceEvent PROC
    push 0F4AACF0Dh
    call WhisperMain
NtTraceEvent ENDP

NtPowerInformation PROC
    push 064826E27h
    call WhisperMain
NtPowerInformation ENDP

NtSetValueKey PROC
    push 0991F9880h
    call WhisperMain
NtSetValueKey ENDP

NtCancelTimer PROC
    push 07FE47178h
    call WhisperMain
NtCancelTimer ENDP

NtSetTimer PROC
    push 025A31D26h
    call WhisperMain
NtSetTimer ENDP

NtAccessCheckByType PROC
    push 09CFB40CCh
    call WhisperMain
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
    push 0FEA205AAh
    call WhisperMain
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
    push 0D295F4C0h
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push 09F33ADAAh
    call WhisperMain
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
    push 0EF5B7866h
    call WhisperMain
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
    push 009EB792Ch
    call WhisperMain
NtAddAtomEx ENDP

NtAddBootEntry PROC
    push 00D801510h
    call WhisperMain
NtAddBootEntry ENDP

NtAddDriverEntry PROC
    push 00F96130Ah
    call WhisperMain
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
    push 0079B0B0Ah
    call WhisperMain
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
    push 03FE51ABDh
    call WhisperMain
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
    push 0AE84A83Eh
    call WhisperMain
NtAlertResumeThread ENDP

NtAlertThread PROC
    push 0120D5CA7h
    call WhisperMain
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
    push 0B32F1E2Fh
    call WhisperMain
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
    push 00D9D5D20h
    call WhisperMain
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
    push 00C5638EDh
    call WhisperMain
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
    push 00B1D70EAh
    call WhisperMain
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
    push 0FC4B0A01h
    call WhisperMain
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
    push 09C9DC64Fh
    call WhisperMain
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
    push 07EB57F38h
    call WhisperMain
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
    push 00D93C13Ah
    call WhisperMain
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
    push 024B6391Ch
    call WhisperMain
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
    push 065A4531Bh
    call WhisperMain
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
    push 026B72025h
    call WhisperMain
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
    push 00A96323Dh
    call WhisperMain
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
    push 03E933BF9h
    call WhisperMain
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
    push 066B80343h
    call WhisperMain
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
    push 0D5492841h
    call WhisperMain
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
    push 0E8CF01D4h
    call WhisperMain
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
    push 08F3F87CCh
    call WhisperMain
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
    push 06EF16D6Bh
    call WhisperMain
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
    push 0CE562D06h
    call WhisperMain
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
    push 024B2311Ch
    call WhisperMain
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
    push 060F04D6Eh
    call WhisperMain
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
    push 0AC48D9D6h
    call WhisperMain
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
    push 0D7B7D605h
    call WhisperMain
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
    push 03561C534h
    call WhisperMain
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
    push 034AA17FBh
    call WhisperMain
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
    push 098394519h
    call WhisperMain
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
    push 016CA12BAh
    call WhisperMain
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
    push 022B01F1Eh
    call WhisperMain
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
    push 0160F149Fh
    call WhisperMain
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
    push 0E10AD282h
    call WhisperMain
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
    push 016A93E35h
    call WhisperMain
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
    push 0793C7FAEh
    call WhisperMain
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
    push 0D7B0F77Bh
    call WhisperMain
NtCallEnclave ENDP

NtCancelIoFileEx PROC
    push 000AAC2F0h
    call WhisperMain
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
    push 0CA5BC2ECh
    call WhisperMain
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
    push 0079BE74Dh
    call WhisperMain
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
    push 0B9BAC176h
    call WhisperMain
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
    push 0267BE1D1h
    call WhisperMain
NtCommitComplete ENDP

NtCommitEnlistment PROC
    push 09FC2A676h
    call WhisperMain
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
    push 0980C9A99h
    call WhisperMain
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
    push 09C079AAFh
    call WhisperMain
NtCommitTransaction ENDP

NtCompactKeys PROC
    push 057E6BAB8h
    call WhisperMain
NtCompactKeys ENDP

NtCompareObjects PROC
    push 0871A919Fh
    call WhisperMain
NtCompareObjects ENDP

NtCompareSigningLevels PROC
    push 048CA485Eh
    call WhisperMain
NtCompareSigningLevels ENDP

NtCompareTokens PROC
    push 004956A4Ch
    call WhisperMain
NtCompareTokens ENDP

NtCompleteConnectPort PROC
    push 054B54538h
    call WhisperMain
NtCompleteConnectPort ENDP

NtCompressKey PROC
    push 067DB5062h
    call WhisperMain
NtCompressKey ENDP

NtConnectPort PROC
    push 05C0F439Ch
    call WhisperMain
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push 003DA2D47h
    call WhisperMain
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
    push 08E34AEA8h
    call WhisperMain
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
    push 084B7BCFBh
    call WhisperMain
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
    push 0B24DF2F4h
    call WhisperMain
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
    push 05E3BB548h
    call WhisperMain
NtCreateEnclave ENDP

NtCreateEnlistment PROC
    push 0086017F3h
    call WhisperMain
NtCreateEnlistment ENDP

NtCreateEventPair PROC
    push 02B3421ABh
    call WhisperMain
NtCreateEventPair ENDP

NtCreateIRTimer PROC
    push 09D1E8B9Ah
    call WhisperMain
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
    push 018161881h
    call WhisperMain
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
    push 08AB1822Dh
    call WhisperMain
NtCreateJobObject ENDP

NtCreateJobSet PROC
    push 0B4BDF26Fh
    call WhisperMain
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
    push 0102C5800h
    call WhisperMain
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
    push 08AB5CB61h
    call WhisperMain
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
    push 035883F2Ch
    call WhisperMain
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
    push 07D3DB699h
    call WhisperMain
NtCreateMailslotFile ENDP

NtCreateMutant PROC
    push 0B2B4D0A2h
    call WhisperMain
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
    push 066C0B87Bh
    call WhisperMain
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
    push 094850EA2h
    call WhisperMain
NtCreatePagingFile ENDP

NtCreatePartition PROC
    push 0DA83D813h
    call WhisperMain
NtCreatePartition ENDP

NtCreatePort PROC
    push 021B33C3Bh
    call WhisperMain
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
    push 02E905103h
    call WhisperMain
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
    push 0952A98B2h
    call WhisperMain
NtCreateProcess ENDP

NtCreateProfile PROC
    push 0861D8E7Eh
    call WhisperMain
NtCreateProfile ENDP

NtCreateProfileEx PROC
    push 08863C4A7h
    call WhisperMain
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
    push 01E58C114h
    call WhisperMain
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
    push 083A9178Ch
    call WhisperMain
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
    push 0124CCF74h
    call WhisperMain
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
    push 03A940429h
    call WhisperMain
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
    push 09C9FDC26h
    call WhisperMain
NtCreateThreadEx ENDP

NtCreateTimer PROC
    push 00FB8E5C0h
    call WhisperMain
NtCreateTimer ENDP

NtCreateTimer2 PROC
    push 0CFB70F29h
    call WhisperMain
NtCreateTimer2 ENDP

NtCreateToken PROC
    push 007A29182h
    call WhisperMain
NtCreateToken ENDP

NtCreateTokenEx PROC
    push 0242F6E9Ch
    call WhisperMain
NtCreateTokenEx ENDP

NtCreateTransaction PROC
    push 0CCA8B07Bh
    call WhisperMain
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
    push 08A349C97h
    call WhisperMain
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
    push 0E5392C64h
    call WhisperMain
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
    push 01B3D63B1h
    call WhisperMain
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
    push 024BD0B2Eh
    call WhisperMain
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
    push 02CCD054Fh
    call WhisperMain
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
    push 04094085Ah
    call WhisperMain
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
    push 0862C964Fh
    call WhisperMain
NtDebugActiveProcess ENDP

NtDebugContinue PROC
    push 04CC093E4h
    call WhisperMain
NtDebugContinue ENDP

NtDeleteAtom PROC
    push 07EEB3332h
    call WhisperMain
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
    push 00D800D08h
    call WhisperMain
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
    push 00B963124h
    call WhisperMain
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
    push 0B6B82682h
    call WhisperMain
NtDeleteFile ENDP

NtDeleteKey PROC
    push 03B8E5A76h
    call WhisperMain
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
    push 0D15435C5h
    call WhisperMain
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
    push 01CB62325h
    call WhisperMain
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
    push 0B233D3C9h
    call WhisperMain
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
    push 00289E800h
    call WhisperMain
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
    push 0349BF1C3h
    call WhisperMain
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
    push 0B7872BB0h
    call WhisperMain
NtDisableLastKnownGood ENDP

NtDisplayString PROC
    push 0069E4C34h
    call WhisperMain
NtDisplayString ENDP

NtDrawText PROC
    push 03ACD255Eh
    call WhisperMain
NtDrawText ENDP

NtEnableLastKnownGood PROC
    push 015B68084h
    call WhisperMain
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
    push 00A523BC9h
    call WhisperMain
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
    push 09C03755Fh
    call WhisperMain
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
    push 0B1A4F558h
    call WhisperMain
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
    push 0163EC165h
    call WhisperMain
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
    push 0128C3815h
    call WhisperMain
NtExtendSection ENDP

NtFilterBootOption PROC
    push 032AA0A27h
    call WhisperMain
NtFilterBootOption ENDP

NtFilterToken PROC
    push 039917F3Ah
    call WhisperMain
NtFilterToken ENDP

NtFilterTokenEx PROC
    push 0C6A919EFh
    call WhisperMain
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
    push 0EB39DD86h
    call WhisperMain
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
    push 0F097F70Bh
    call WhisperMain
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
    push 02E3BD02Bh
    call WhisperMain
NtFlushInstructionCache ENDP

NtFlushKey PROC
    push 07BE1425Eh
    call WhisperMain
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
    push 08A930B85h
    call WhisperMain
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
    push 00F99213Fh
    call WhisperMain
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
    push 0411C5587h
    call WhisperMain
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
    push 019B1E0DBh
    call WhisperMain
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
    push 04763C063h
    call WhisperMain
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
    push 00B9914F3h
    call WhisperMain
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
    push 033172392h
    call WhisperMain
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
    push 0CD4BEDD9h
    call WhisperMain
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
    push 0309C6235h
    call WhisperMain
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
    push 0EE5BC102h
    call WhisperMain
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
    push 0A7596104h
    call WhisperMain
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
    push 0B2296868h
    call WhisperMain
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
    push 0A6B15DF8h
    call WhisperMain
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
    push 0DF853DE9h
    call WhisperMain
NtGetNextProcess ENDP

NtGetNextThread PROC
    push 0A892F42Ah
    call WhisperMain
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
    push 0E697D758h
    call WhisperMain
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
    push 009BE9396h
    call WhisperMain
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
    push 012AB2BFAh
    call WhisperMain
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
    push 02086F1A5h
    call WhisperMain
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
    push 0892F0F0Ch
    call WhisperMain
NtImpersonateThread ENDP

NtInitializeEnclave PROC
    push 028975004h
    call WhisperMain
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
    push 028904B6Eh
    call WhisperMain
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
    push 0069F1A09h
    call WhisperMain
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
    push 046C22417h
    call WhisperMain
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
    push 0E2601736h
    call WhisperMain
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
    push 0DB80003Fh
    call WhisperMain
NtIsUILanguageComitted ENDP

NtListenPort PROC
    push 0C774F4FBh
    call WhisperMain
NtListenPort ENDP

NtLoadDriver PROC
    push 05CBF3462h
    call WhisperMain
NtLoadDriver ENDP

NtLoadEnclaveData PROC
    push 09C03CEB2h
    call WhisperMain
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
    push 070ED3FCAh
    call WhisperMain
NtLoadHotPatch ENDP

NtLoadKey PROC
    push 0B91ED8C6h
    call WhisperMain
NtLoadKey ENDP

NtLoadKey2 PROC
    push 07FA79006h
    call WhisperMain
NtLoadKey2 ENDP

NtLoadKeyEx PROC
    push 05BD8ACA7h
    call WhisperMain
NtLoadKeyEx ENDP

NtLockFile PROC
    push 058C4AA90h
    call WhisperMain
NtLockFile ENDP

NtLockProductActivationKeys PROC
    push 0E747F8ECh
    call WhisperMain
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
    push 073C0665Ch
    call WhisperMain
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
    push 03BAFD23Fh
    call WhisperMain
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
    push 0A29ED870h
    call WhisperMain
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
    push 00AD3329Fh
    call WhisperMain
NtMakeTemporaryObject ENDP

NtManagePartition PROC
    push 0C68FC41Fh
    call WhisperMain
NtManagePartition ENDP

NtMapCMFModule PROC
    push 03E981FC6h
    call WhisperMain
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
    push 0059C6C06h
    call WhisperMain
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
    push 086B4C00Ah
    call WhisperMain
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
    push 01D9B3728h
    call WhisperMain
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
    push 001941B16h
    call WhisperMain
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
    push 094039498h
    call WhisperMain
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
    push 0009AA3A1h
    call WhisperMain
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
    push 05B5B7EC4h
    call WhisperMain
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
    push 065FB7192h
    call WhisperMain
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
    push 0F7A736F5h
    call WhisperMain
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
    push 07BA1064Bh
    call WhisperMain
NtOpenEnlistment ENDP

NtOpenEventPair PROC
    push 0B296D207h
    call WhisperMain
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
    push 0290F17A4h
    call WhisperMain
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
    push 05E92045Fh
    call WhisperMain
NtOpenJobObject ENDP

NtOpenKeyEx PROC
    push 051FEB285h
    call WhisperMain
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
    push 0177F8C40h
    call WhisperMain
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
    push 06B3EAB05h
    call WhisperMain
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
    push 0CA810DCAh
    call WhisperMain
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
    push 0D597B846h
    call WhisperMain
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
    push 00A876C8Eh
    call WhisperMain
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
    push 0064D669Fh
    call WhisperMain
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
    push 034944B0Fh
    call WhisperMain
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
    push 00396888Fh
    call WhisperMain
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
    push 094CE539Eh
    call WhisperMain
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
    push 001B92EE8h
    call WhisperMain
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
    push 01499E0C8h
    call WhisperMain
NtOpenSemaphore ENDP

NtOpenSession PROC
    push 09201B08Dh
    call WhisperMain
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
    push 0069C6031h
    call WhisperMain
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
    push 0AC88A63Eh
    call WhisperMain
NtOpenThread ENDP

NtOpenTimer PROC
    push 087168D8Eh
    call WhisperMain
NtOpenTimer ENDP

NtOpenTransaction PROC
    push 01856DDFDh
    call WhisperMain
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
    push 08520EFDCh
    call WhisperMain
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
    push 0018E7945h
    call WhisperMain
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
    push 0F89A1710h
    call WhisperMain
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
    push 0DA5C190Ah
    call WhisperMain
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
    push 056B4723Ah
    call WhisperMain
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
    push 0D946EAC1h
    call WhisperMain
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
    push 014B7C60Ah
    call WhisperMain
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
    push 0D4B3EA72h
    call WhisperMain
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
    push 00E890E26h
    call WhisperMain
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
    push 00A9419FAh
    call WhisperMain
NtPropagationComplete ENDP

NtPropagationFailed PROC
    push 0F257ECECh
    call WhisperMain
NtPropagationFailed ENDP

NtPulseEvent PROC
    push 02094CA02h
    call WhisperMain
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
    push 0B80DDFF2h
    call WhisperMain
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
    push 01B09F413h
    call WhisperMain
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
    push 05F905903h
    call WhisperMain
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
    push 0E749E829h
    call WhisperMain
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
    push 0B8A68E18h
    call WhisperMain
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
    push 004A03C15h
    call WhisperMain
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
    push 0A33C7E6Fh
    call WhisperMain
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
    push 0623848BFh
    call WhisperMain
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
    push 052983E0Eh
    call WhisperMain
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
    push 0D33BCABFh
    call WhisperMain
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
    push 024BA572Dh
    call WhisperMain
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
    push 0199F3809h
    call WhisperMain
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
    push 0E758ECC7h
    call WhisperMain
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
    push 0AB3AACB1h
    call WhisperMain
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
    push 04F9F9CC2h
    call WhisperMain
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
    push 0168C35D1h
    call WhisperMain
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
    push 0173773AAh
    call WhisperMain
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
    push 004921BF2h
    call WhisperMain
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
    push 095B6D48Ch
    call WhisperMain
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
    push 0C55E33C3h
    call WhisperMain
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
    push 082AC61BCh
    call WhisperMain
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
    push 00CBE39E6h
    call WhisperMain
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
    push 05DA55A38h
    call WhisperMain
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
    push 01C123F85h
    call WhisperMain
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
    push 04F324AB8h
    call WhisperMain
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
    push 0038AD3D1h
    call WhisperMain
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
    push 0781C9F75h
    call WhisperMain
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
    push 06E3634F6h
    call WhisperMain
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
    push 00C187A9Dh
    call WhisperMain
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
    push 0049E2DC3h
    call WhisperMain
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
    push 0953FEADEh
    call WhisperMain
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
    push 0089B7084h
    call WhisperMain
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
    push 076C48FC9h
    call WhisperMain
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
    push 00E9D710Ah
    call WhisperMain
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
    push 08F96BB2Ah
    call WhisperMain
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
    push 00E94B1A3h
    call WhisperMain
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
    push 004924441h
    call WhisperMain
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
    push 060BB4E74h
    call WhisperMain
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
    push 00E942417h
    call WhisperMain
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
    push 00311C06Ah
    call WhisperMain
NtQueueApcThreadEx ENDP

NtRaiseException PROC
    push 09F30B7AAh
    call WhisperMain
NtRaiseException ENDP

NtRaiseHardError PROC
    push 0011071FFh
    call WhisperMain
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
    push 0D6BB33D1h
    call WhisperMain
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
    push 009874C4Dh
    call WhisperMain
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
    push 0B763E3A6h
    call WhisperMain
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
    push 033A30322h
    call WhisperMain
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
    push 00C8E2613h
    call WhisperMain
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
    push 0FE73C5FCh
    call WhisperMain
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
    push 0F056F5C4h
    call WhisperMain
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
    push 0F2DAC678h
    call WhisperMain
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
    push 000A3406Ah
    call WhisperMain
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
    push 010AE0720h
    call WhisperMain
NtRemoveProcessDebug ENDP

NtRenameKey PROC
    push 00B3D109Ch
    call WhisperMain
NtRenameKey ENDP

NtRenameTransactionManager PROC
    push 0093D2361h
    call WhisperMain
NtRenameTransactionManager ENDP

NtReplaceKey PROC
    push 096D5A368h
    call WhisperMain
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
    push 014BF2816h
    call WhisperMain
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
    push 02CB52B26h
    call WhisperMain
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
    push 020B03914h
    call WhisperMain
NtRequestPort ENDP

NtResetEvent PROC
    push 038A12520h
    call WhisperMain
NtResetEvent ENDP

NtResetWriteWatch PROC
    push 034A10E32h
    call WhisperMain
NtResetWriteWatch ENDP

NtRestoreKey PROC
    push 061EB5848h
    call WhisperMain
NtRestoreKey ENDP

NtResumeProcess PROC
    push 05DA2787Ah
    call WhisperMain
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
    push 0E649E4D5h
    call WhisperMain
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
    push 028B1B28Eh
    call WhisperMain
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
    push 057956A3Fh
    call WhisperMain
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
    push 07FA05362h
    call WhisperMain
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
    push 018005AADh
    call WhisperMain
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
    push 06DB36122h
    call WhisperMain
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
    push 09BA3FE41h
    call WhisperMain
NtSaveKey ENDP

NtSaveKeyEx PROC
    push 065E5E2A5h
    call WhisperMain
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
    push 0EB778898h
    call WhisperMain
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
    push 060F14762h
    call WhisperMain
NtSecureConnectPort ENDP

NtSerializeBoot PROC
    push 03EA81C39h
    call WhisperMain
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
    push 017358F1Fh
    call WhisperMain
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
    push 00D9B0B13h
    call WhisperMain
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
    push 02A9AE1C4h
    call WhisperMain
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
    push 0EEB02921h
    call WhisperMain
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
    push 01033CE81h
    call WhisperMain
NtSetContextThread ENDP

NtSetDebugFilterState PROC
    push 0F6699EA6h
    call WhisperMain
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
    push 01CA9EFE6h
    call WhisperMain
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
    push 03DAFFA8Fh
    call WhisperMain
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
    push 09789EB90h
    call WhisperMain
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
    push 0D008F4D2h
    call WhisperMain
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
    push 07CBF1A7Ch
    call WhisperMain
NtSetEaFile ENDP

NtSetHighEventPair PROC
    push 08412BAA3h
    call WhisperMain
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
    push 08A12B095h
    call WhisperMain
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
    push 003CB1D48h
    call WhisperMain
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
    push 08E34A6A8h
    call WhisperMain
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
    push 0096C0AFBh
    call WhisperMain
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
    push 0735C8152h
    call WhisperMain
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
    push 0938DA431h
    call WhisperMain
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
    push 09F87C14Fh
    call WhisperMain
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
    push 07CAA5072h
    call WhisperMain
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
    push 021807724h
    call WhisperMain
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
    push 09901F9D0h
    call WhisperMain
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
    push 079209378h
    call WhisperMain
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
    push 01F81090Fh
    call WhisperMain
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
    push 087109F93h
    call WhisperMain
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
    push 04AA24C1Eh
    call WhisperMain
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
    push 0D44AF519h
    call WhisperMain
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
    push 0A1536D06h
    call WhisperMain
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
    push 086AE7EC6h
    call WhisperMain
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
    push 030AFACA1h
    call WhisperMain
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
    push 070CD90BBh
    call WhisperMain
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
    push 0EDDEB3EBh
    call WhisperMain
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
    push 0A0BBCC40h
    call WhisperMain
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
    push 0C23DEFB4h
    call WhisperMain
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
    push 09788A5FCh
    call WhisperMain
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
    push 054965203h
    call WhisperMain
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
    push 062D84854h
    call WhisperMain
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
    push 01241C901h
    call WhisperMain
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
    push 0D614A8C0h
    call WhisperMain
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
    push 00386ECA7h
    call WhisperMain
NtSetTimer2 ENDP

NtSetTimerEx PROC
    push 0B886C600h
    call WhisperMain
NtSetTimerEx ENDP

NtSetTimerResolution PROC
    push 0A731A7A3h
    call WhisperMain
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
    push 0F15D7160h
    call WhisperMain
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
    push 024B1D2A2h
    call WhisperMain
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
    push 0802A89B6h
    call WhisperMain
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
    push 0149CCDD0h
    call WhisperMain
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
    push 01C8F0802h
    call WhisperMain
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
    push 09A2592B9h
    call WhisperMain
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
    push 0AA859A39h
    call WhisperMain
NtSinglePhaseReject ENDP

NtStartProfile PROC
    push 0CC9AFA09h
    call WhisperMain
NtStartProfile ENDP

NtStopProfile PROC
    push 08139F5ADh
    call WhisperMain
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
    push 01CA1E98Ch
    call WhisperMain
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
    push 0F1A41038h
    call WhisperMain
NtSuspendProcess ENDP

NtSuspendThread PROC
    push 0B41FBEB9h
    call WhisperMain
NtSuspendThread ENDP

NtSystemDebugControl PROC
    push 0CC1BC882h
    call WhisperMain
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
    push 0E2131E80h
    call WhisperMain
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
    push 0369D0215h
    call WhisperMain
NtTerminateJobObject ENDP

NtTestAlert PROC
    push 0D13BD8A7h
    call WhisperMain
NtTestAlert ENDP

NtThawRegistry PROC
    push 0CD5121C2h
    call WhisperMain
NtThawRegistry ENDP

NtThawTransactions PROC
    push 01F8A351Dh
    call WhisperMain
NtThawTransactions ENDP

NtTraceControl PROC
    push 0F5B7F620h
    call WhisperMain
NtTraceControl ENDP

NtTranslateFilePath PROC
    push 0A60E9A5Ah
    call WhisperMain
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
    push 003A11017h
    call WhisperMain
NtUmsThreadYield ENDP

NtUnloadDriver PROC
    push 05E973E66h
    call WhisperMain
NtUnloadDriver ENDP

NtUnloadKey PROC
    push 0E83A0A46h
    call WhisperMain
NtUnloadKey ENDP

NtUnloadKey2 PROC
    push 0AED262CCh
    call WhisperMain
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
    push 07A7C2CA3h
    call WhisperMain
NtUnloadKeyEx ENDP

NtUnlockFile PROC
    push 09A1FF414h
    call WhisperMain
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
    push 0F595E13Eh
    call WhisperMain
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
    push 006D5E1ABh
    call WhisperMain
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
    push 0E0BC976Ch
    call WhisperMain
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
    push 01086E314h
    call WhisperMain
NtUpdateWnfStateData ENDP

NtVdmControl PROC
    push 0CB8BE11Dh
    call WhisperMain
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
    push 07EA34C74h
    call WhisperMain
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
    push 0B89844F1h
    call WhisperMain
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
    push 078A33D72h
    call WhisperMain
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
    push 05E926624h
    call WhisperMain
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
    push 016BF362Dh
    call WhisperMain
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
    push 0104C34FDh
    call WhisperMain
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
    push 01ACD7E1Ah
    call WhisperMain
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
    push 00FAA3118h
    call WhisperMain
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
    push 0E048E6DDh
    call WhisperMain
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
    push 0EACE346Eh
    call WhisperMain
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
    push 002E60077h
    call WhisperMain
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
    push 0D70CF7DEh
    call WhisperMain
NtSavepointTransaction ENDP

NtSavepointComplete PROC
    push 048B45638h
    call WhisperMain
NtSavepointComplete ENDP

NtCreateSectionEx PROC
    push 012D15A10h
    call WhisperMain
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
    push 0B0E24384h
    call WhisperMain
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
    push 0C853D1DEh
    call WhisperMain
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
    push 027930B25h
    call WhisperMain
NtListTransactions ENDP

NtMarshallTransaction PROC
    push 00254DE1Fh
    call WhisperMain
NtMarshallTransaction ENDP

NtPullTransaction PROC
    push 0D48FD41Dh
    call WhisperMain
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
    push 060A5782Eh
    call WhisperMain
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
    push 075DF6EB9h
    call WhisperMain
NtWaitForWnfNotifications ENDP

NtStartTm PROC
    push 0939E70E3h
    call WhisperMain
NtStartTm ENDP

NtSetInformationProcess PROC
    push 0EF2CCEB0h
    call WhisperMain
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
    push 03B993D0Eh
    call WhisperMain
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
    push 072966906h
    call WhisperMain
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
    push 0A08736ACh
    call WhisperMain
NtQuerySystemTime ENDP

NtManageHotPatch PROC
    push 020BEDDABh
    call WhisperMain
NtManageHotPatch ENDP

NtContinueEx PROC
    push 06FED9389h
    call WhisperMain
NtContinueEx ENDP

end