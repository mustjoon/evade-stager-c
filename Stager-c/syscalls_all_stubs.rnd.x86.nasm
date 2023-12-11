[SECTION .data align=4]
stubReturn:     dd  0
returnAddress:  dd  0
espBookmark:    dd  0
syscallNumber:  dd  0
syscallAddress: dd  0

[SECTION .text]

BITS 32
DEFAULT REL

global _NtAccessCheck
global _NtWorkerFactoryWorkerReady
global _NtAcceptConnectPort
global _NtMapUserPhysicalPagesScatter
global _NtWaitForSingleObject
global _NtCallbackReturn
global _NtReadFile
global _NtDeviceIoControlFile
global _NtWriteFile
global _NtRemoveIoCompletion
global _NtReleaseSemaphore
global _NtReplyWaitReceivePort
global _NtReplyPort
global _NtSetInformationThread
global _NtSetEvent
global _NtClose
global _NtQueryObject
global _NtQueryInformationFile
global _NtOpenKey
global _NtEnumerateValueKey
global _NtFindAtom
global _NtQueryDefaultLocale
global _NtQueryKey
global _NtQueryValueKey
global _NtAllocateVirtualMemory
global _NtQueryInformationProcess
global _NtWaitForMultipleObjects32
global _NtWriteFileGather
global _NtCreateKey
global _NtFreeVirtualMemory
global _NtImpersonateClientOfPort
global _NtReleaseMutant
global _NtQueryInformationToken
global _NtRequestWaitReplyPort
global _NtQueryVirtualMemory
global _NtOpenThreadToken
global _NtQueryInformationThread
global _NtOpenProcess
global _NtSetInformationFile
global _NtMapViewOfSection
global _NtAccessCheckAndAuditAlarm
global _NtUnmapViewOfSection
global _NtReplyWaitReceivePortEx
global _NtTerminateProcess
global _NtSetEventBoostPriority
global _NtReadFileScatter
global _NtOpenThreadTokenEx
global _NtOpenProcessTokenEx
global _NtQueryPerformanceCounter
global _NtEnumerateKey
global _NtOpenFile
global _NtDelayExecution
global _NtQueryDirectoryFile
global _NtQuerySystemInformation
global _NtOpenSection
global _NtQueryTimer
global _NtFsControlFile
global _NtWriteVirtualMemory
global _NtCloseObjectAuditAlarm
global _NtDuplicateObject
global _NtQueryAttributesFile
global _NtClearEvent
global _NtReadVirtualMemory
global _NtOpenEvent
global _NtAdjustPrivilegesToken
global _NtDuplicateToken
global _NtContinue
global _NtQueryDefaultUILanguage
global _NtQueueApcThread
global _NtYieldExecution
global _NtAddAtom
global _NtCreateEvent
global _NtQueryVolumeInformationFile
global _NtCreateSection
global _NtFlushBuffersFile
global _NtApphelpCacheControl
global _NtCreateProcessEx
global _NtCreateThread
global _NtIsProcessInJob
global _NtProtectVirtualMemory
global _NtQuerySection
global _NtResumeThread
global _NtTerminateThread
global _NtReadRequestData
global _NtCreateFile
global _NtQueryEvent
global _NtWriteRequestData
global _NtOpenDirectoryObject
global _NtAccessCheckByTypeAndAuditAlarm
global _NtWaitForMultipleObjects
global _NtSetInformationObject
global _NtCancelIoFile
global _NtTraceEvent
global _NtPowerInformation
global _NtSetValueKey
global _NtCancelTimer
global _NtSetTimer
global _NtAccessCheckByType
global _NtAccessCheckByTypeResultList
global _NtAccessCheckByTypeResultListAndAuditAlarm
global _NtAccessCheckByTypeResultListAndAuditAlarmByHandle
global _NtAcquireProcessActivityReference
global _NtAddAtomEx
global _NtAddBootEntry
global _NtAddDriverEntry
global _NtAdjustGroupsToken
global _NtAdjustTokenClaimsAndDeviceGroups
global _NtAlertResumeThread
global _NtAlertThread
global _NtAlertThreadByThreadId
global _NtAllocateLocallyUniqueId
global _NtAllocateReserveObject
global _NtAllocateUserPhysicalPages
global _NtAllocateUuids
global _NtAllocateVirtualMemoryEx
global _NtAlpcAcceptConnectPort
global _NtAlpcCancelMessage
global _NtAlpcConnectPort
global _NtAlpcConnectPortEx
global _NtAlpcCreatePort
global _NtAlpcCreatePortSection
global _NtAlpcCreateResourceReserve
global _NtAlpcCreateSectionView
global _NtAlpcCreateSecurityContext
global _NtAlpcDeletePortSection
global _NtAlpcDeleteResourceReserve
global _NtAlpcDeleteSectionView
global _NtAlpcDeleteSecurityContext
global _NtAlpcDisconnectPort
global _NtAlpcImpersonateClientContainerOfPort
global _NtAlpcImpersonateClientOfPort
global _NtAlpcOpenSenderProcess
global _NtAlpcOpenSenderThread
global _NtAlpcQueryInformation
global _NtAlpcQueryInformationMessage
global _NtAlpcRevokeSecurityContext
global _NtAlpcSendWaitReceivePort
global _NtAlpcSetInformation
global _NtAreMappedFilesTheSame
global _NtAssignProcessToJobObject
global _NtAssociateWaitCompletionPacket
global _NtCallEnclave
global _NtCancelIoFileEx
global _NtCancelSynchronousIoFile
global _NtCancelTimer2
global _NtCancelWaitCompletionPacket
global _NtCommitComplete
global _NtCommitEnlistment
global _NtCommitRegistryTransaction
global _NtCommitTransaction
global _NtCompactKeys
global _NtCompareObjects
global _NtCompareSigningLevels
global _NtCompareTokens
global _NtCompleteConnectPort
global _NtCompressKey
global _NtConnectPort
global _NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
global _NtCreateDebugObject
global _NtCreateDirectoryObject
global _NtCreateDirectoryObjectEx
global _NtCreateEnclave
global _NtCreateEnlistment
global _NtCreateEventPair
global _NtCreateIRTimer
global _NtCreateIoCompletion
global _NtCreateJobObject
global _NtCreateJobSet
global _NtCreateKeyTransacted
global _NtCreateKeyedEvent
global _NtCreateLowBoxToken
global _NtCreateMailslotFile
global _NtCreateMutant
global _NtCreateNamedPipeFile
global _NtCreatePagingFile
global _NtCreatePartition
global _NtCreatePort
global _NtCreatePrivateNamespace
global _NtCreateProcess
global _NtCreateProfile
global _NtCreateProfileEx
global _NtCreateRegistryTransaction
global _NtCreateResourceManager
global _NtCreateSemaphore
global _NtCreateSymbolicLinkObject
global _NtCreateThreadEx
global _NtCreateTimer
global _NtCreateTimer2
global _NtCreateToken
global _NtCreateTokenEx
global _NtCreateTransaction
global _NtCreateTransactionManager
global _NtCreateUserProcess
global _NtCreateWaitCompletionPacket
global _NtCreateWaitablePort
global _NtCreateWnfStateName
global _NtCreateWorkerFactory
global _NtDebugActiveProcess
global _NtDebugContinue
global _NtDeleteAtom
global _NtDeleteBootEntry
global _NtDeleteDriverEntry
global _NtDeleteFile
global _NtDeleteKey
global _NtDeleteObjectAuditAlarm
global _NtDeletePrivateNamespace
global _NtDeleteValueKey
global _NtDeleteWnfStateData
global _NtDeleteWnfStateName
global _NtDisableLastKnownGood
global _NtDisplayString
global _NtDrawText
global _NtEnableLastKnownGood
global _NtEnumerateBootEntries
global _NtEnumerateDriverEntries
global _NtEnumerateSystemEnvironmentValuesEx
global _NtEnumerateTransactionObject
global _NtExtendSection
global _NtFilterBootOption
global _NtFilterToken
global _NtFilterTokenEx
global _NtFlushBuffersFileEx
global _NtFlushInstallUILanguage
global _NtFlushInstructionCache
global _NtFlushKey
global _NtFlushProcessWriteBuffers
global _NtFlushVirtualMemory
global _NtFlushWriteBuffer
global _NtFreeUserPhysicalPages
global _NtFreezeRegistry
global _NtFreezeTransactions
global _NtGetCachedSigningLevel
global _NtGetCompleteWnfStateSubscription
global _NtGetContextThread
global _NtGetCurrentProcessorNumber
global _NtGetCurrentProcessorNumberEx
global _NtGetDevicePowerState
global _NtGetMUIRegistryInfo
global _NtGetNextProcess
global _NtGetNextThread
global _NtGetNlsSectionPtr
global _NtGetNotificationResourceManager
global _NtGetWriteWatch
global _NtImpersonateAnonymousToken
global _NtImpersonateThread
global _NtInitializeEnclave
global _NtInitializeNlsFiles
global _NtInitializeRegistry
global _NtInitiatePowerAction
global _NtIsSystemResumeAutomatic
global _NtIsUILanguageComitted
global _NtListenPort
global _NtLoadDriver
global _NtLoadEnclaveData
global _NtLoadHotPatch
global _NtLoadKey
global _NtLoadKey2
global _NtLoadKeyEx
global _NtLockFile
global _NtLockProductActivationKeys
global _NtLockRegistryKey
global _NtLockVirtualMemory
global _NtMakePermanentObject
global _NtMakeTemporaryObject
global _NtManagePartition
global _NtMapCMFModule
global _NtMapUserPhysicalPages
global _NtMapViewOfSectionEx
global _NtModifyBootEntry
global _NtModifyDriverEntry
global _NtNotifyChangeDirectoryFile
global _NtNotifyChangeDirectoryFileEx
global _NtNotifyChangeKey
global _NtNotifyChangeMultipleKeys
global _NtNotifyChangeSession
global _NtOpenEnlistment
global _NtOpenEventPair
global _NtOpenIoCompletion
global _NtOpenJobObject
global _NtOpenKeyEx
global _NtOpenKeyTransacted
global _NtOpenKeyTransactedEx
global _NtOpenKeyedEvent
global _NtOpenMutant
global _NtOpenObjectAuditAlarm
global _NtOpenPartition
global _NtOpenPrivateNamespace
global _NtOpenProcessToken
global _NtOpenRegistryTransaction
global _NtOpenResourceManager
global _NtOpenSemaphore
global _NtOpenSession
global _NtOpenSymbolicLinkObject
global _NtOpenThread
global _NtOpenTimer
global _NtOpenTransaction
global _NtOpenTransactionManager
global _NtPlugPlayControl
global _NtPrePrepareComplete
global _NtPrePrepareEnlistment
global _NtPrepareComplete
global _NtPrepareEnlistment
global _NtPrivilegeCheck
global _NtPrivilegeObjectAuditAlarm
global _NtPrivilegedServiceAuditAlarm
global _NtPropagationComplete
global _NtPropagationFailed
global _NtPulseEvent
global _NtQueryAuxiliaryCounterFrequency
global _NtQueryBootEntryOrder
global _NtQueryBootOptions
global _NtQueryDebugFilterState
global _NtQueryDirectoryFileEx
global _NtQueryDirectoryObject
global _NtQueryDriverEntryOrder
global _NtQueryEaFile
global _NtQueryFullAttributesFile
global _NtQueryInformationAtom
global _NtQueryInformationByName
global _NtQueryInformationEnlistment
global _NtQueryInformationJobObject
global _NtQueryInformationPort
global _NtQueryInformationResourceManager
global _NtQueryInformationTransaction
global _NtQueryInformationTransactionManager
global _NtQueryInformationWorkerFactory
global _NtQueryInstallUILanguage
global _NtQueryIntervalProfile
global _NtQueryIoCompletion
global _NtQueryLicenseValue
global _NtQueryMultipleValueKey
global _NtQueryMutant
global _NtQueryOpenSubKeys
global _NtQueryOpenSubKeysEx
global _NtQueryPortInformationProcess
global _NtQueryQuotaInformationFile
global _NtQuerySecurityAttributesToken
global _NtQuerySecurityObject
global _NtQuerySecurityPolicy
global _NtQuerySemaphore
global _NtQuerySymbolicLinkObject
global _NtQuerySystemEnvironmentValue
global _NtQuerySystemEnvironmentValueEx
global _NtQuerySystemInformationEx
global _NtQueryTimerResolution
global _NtQueryWnfStateData
global _NtQueryWnfStateNameInformation
global _NtQueueApcThreadEx
global _NtRaiseException
global _NtRaiseHardError
global _NtReadOnlyEnlistment
global _NtRecoverEnlistment
global _NtRecoverResourceManager
global _NtRecoverTransactionManager
global _NtRegisterProtocolAddressInformation
global _NtRegisterThreadTerminatePort
global _NtReleaseKeyedEvent
global _NtReleaseWorkerFactoryWorker
global _NtRemoveIoCompletionEx
global _NtRemoveProcessDebug
global _NtRenameKey
global _NtRenameTransactionManager
global _NtReplaceKey
global _NtReplacePartitionUnit
global _NtReplyWaitReplyPort
global _NtRequestPort
global _NtResetEvent
global _NtResetWriteWatch
global _NtRestoreKey
global _NtResumeProcess
global _NtRevertContainerImpersonation
global _NtRollbackComplete
global _NtRollbackEnlistment
global _NtRollbackRegistryTransaction
global _NtRollbackTransaction
global _NtRollforwardTransactionManager
global _NtSaveKey
global _NtSaveKeyEx
global _NtSaveMergedKeys
global _NtSecureConnectPort
global _NtSerializeBoot
global _NtSetBootEntryOrder
global _NtSetBootOptions
global _NtSetCachedSigningLevel
global _NtSetCachedSigningLevel2
global _NtSetContextThread
global _NtSetDebugFilterState
global _NtSetDefaultHardErrorPort
global _NtSetDefaultLocale
global _NtSetDefaultUILanguage
global _NtSetDriverEntryOrder
global _NtSetEaFile
global _NtSetHighEventPair
global _NtSetHighWaitLowEventPair
global _NtSetIRTimer
global _NtSetInformationDebugObject
global _NtSetInformationEnlistment
global _NtSetInformationJobObject
global _NtSetInformationKey
global _NtSetInformationResourceManager
global _NtSetInformationSymbolicLink
global _NtSetInformationToken
global _NtSetInformationTransaction
global _NtSetInformationTransactionManager
global _NtSetInformationVirtualMemory
global _NtSetInformationWorkerFactory
global _NtSetIntervalProfile
global _NtSetIoCompletion
global _NtSetIoCompletionEx
global _NtSetLdtEntries
global _NtSetLowEventPair
global _NtSetLowWaitHighEventPair
global _NtSetQuotaInformationFile
global _NtSetSecurityObject
global _NtSetSystemEnvironmentValue
global _NtSetSystemEnvironmentValueEx
global _NtSetSystemInformation
global _NtSetSystemPowerState
global _NtSetSystemTime
global _NtSetThreadExecutionState
global _NtSetTimer2
global _NtSetTimerEx
global _NtSetTimerResolution
global _NtSetUuidSeed
global _NtSetVolumeInformationFile
global _NtSetWnfProcessNotificationEvent
global _NtShutdownSystem
global _NtShutdownWorkerFactory
global _NtSignalAndWaitForSingleObject
global _NtSinglePhaseReject
global _NtStartProfile
global _NtStopProfile
global _NtSubscribeWnfStateChange
global _NtSuspendProcess
global _NtSuspendThread
global _NtSystemDebugControl
global _NtTerminateEnclave
global _NtTerminateJobObject
global _NtTestAlert
global _NtThawRegistry
global _NtThawTransactions
global _NtTraceControl
global _NtTranslateFilePath
global _NtUmsThreadYield
global _NtUnloadDriver
global _NtUnloadKey
global _NtUnloadKey2
global _NtUnloadKeyEx
global _NtUnlockFile
global _NtUnlockVirtualMemory
global _NtUnmapViewOfSectionEx
global _NtUnsubscribeWnfStateChange
global _NtUpdateWnfStateData
global _NtVdmControl
global _NtWaitForAlertByThreadId
global _NtWaitForDebugEvent
global _NtWaitForKeyedEvent
global _NtWaitForWorkViaWorkerFactory
global _NtWaitHighEventPair
global _NtWaitLowEventPair
global _NtAcquireCMFViewOwnership
global _NtCancelDeviceWakeupRequest
global _NtClearAllSavepointsTransaction
global _NtClearSavepointTransaction
global _NtRollbackSavepointTransaction
global _NtSavepointTransaction
global _NtSavepointComplete
global _NtCreateSectionEx
global _NtCreateCrossVmEvent
global _NtGetPlugPlayEvent
global _NtListTransactions
global _NtMarshallTransaction
global _NtPullTransaction
global _NtReleaseCMFViewOwnership
global _NtWaitForWnfNotifications
global _NtStartTm
global _NtSetInformationProcess
global _NtRequestDeviceWakeup
global _NtRequestWakeupLatency
global _NtQuerySystemTime
global _NtManageHotPatch
global _NtContinueEx

global _WhisperMain
extern _SW2_GetSyscallNumber
extern _SW2_GetRandomSyscallAddress

_WhisperMain:
    pop eax                                  
    mov dword [stubReturn], eax             ; Save the return address to the stub
    push esp
    pop eax
    add eax, 4h
    push dword [eax]
    pop dword [returnAddress]               ; Save original return address
    add eax, 4h
    push eax
    pop dword [espBookmark]                 ; Save original ESP
    call _SW2_GetSyscallNumber              ; Resolve function hash into syscall number
    add esp, 4h                             ; Restore ESP
    mov dword [syscallNumber], eax          ; Save the syscall number
    xor eax, eax
    mov ecx, dword [fs:0c0h]
    test ecx, ecx
    je _x86
    inc eax                                 ; Inc EAX to 1 for Wow64
_x86:
    push eax                                ; Push 0 for x86, 1 for Wow64
    lea edx, dword [esp+4h]
    call _SW2_GetRandomSyscallAddress       ; Get a random 0x02E address
    mov dword [syscallAddress], eax         ; Save the address
    mov esp, dword [espBookmark]            ; Restore ESP
    mov eax, dword [syscallNumber]          ; Restore the syscall number
    call dword [syscallAddress]             ; Call the random syscall location
    mov esp, dword [espBookmark]            ; Restore ESP
    push dword [returnAddress]              ; Restore the return address
    ret
    
_NtAccessCheck:
    push 07EDB3767h
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0822AA280h
    call _WhisperMain

_NtAcceptConnectPort:
    push 01EB83726h
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0A01CF8D6h
    call _WhisperMain

_NtWaitForSingleObject:
    push 004DD6C41h
    call _WhisperMain

_NtCallbackReturn:
    push 021633CECh
    call _WhisperMain

_NtReadFile:
    push 054937C10h
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0B519DD91h
    call _WhisperMain

_NtWriteFile:
    push 00ABB4412h
    call _WhisperMain

_NtRemoveIoCompletion:
    push 01ED61275h
    call _WhisperMain

_NtReleaseSemaphore:
    push 0F8AA2D02h
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 020B34760h
    call _WhisperMain

_NtReplyPort:
    push 02BB1A1AFh
    call _WhisperMain

_NtSetInformationThread:
    push 0AC97AA3Dh
    call _WhisperMain

_NtSetEvent:
    push 000A31324h
    call _WhisperMain

_NtClose:
    push 04295B4C5h
    call _WhisperMain

_NtQueryObject:
    push 06C56C57Ch
    call _WhisperMain

_NtQueryInformationFile:
    push 024313EB6h
    call _WhisperMain

_NtOpenKey:
    push 0A522D2DCh
    call _WhisperMain

_NtEnumerateValueKey:
    push 0398DD6FBh
    call _WhisperMain

_NtFindAtom:
    push 068FF496Eh
    call _WhisperMain

_NtQueryDefaultLocale:
    push 011192390h
    call _WhisperMain

_NtQueryKey:
    push 0320CD316h
    call _WhisperMain

_NtQueryValueKey:
    push 046E45177h
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 007951D07h
    call _WhisperMain

_NtQueryInformationProcess:
    push 08F2C8EB0h
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 090992C57h
    call _WhisperMain

_NtWriteFileGather:
    push 0F3A2F537h
    call _WhisperMain

_NtCreateKey:
    push 06ADF754Ch
    call _WhisperMain

_NtFreeVirtualMemory:
    push 00F503BECh
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0A032C5E0h
    call _WhisperMain

_NtReleaseMutant:
    push 0E38DCA1Bh
    call _WhisperMain

_NtQueryInformationToken:
    push 00396492Eh
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0A4FEA16Eh
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0CE53A6B2h
    call _WhisperMain

_NtOpenThreadToken:
    push 0E8ACE432h
    call _WhisperMain

_NtQueryInformationThread:
    push 0329CADAFh
    call _WhisperMain

_NtOpenProcess:
    push 00FA30E32h
    call _WhisperMain

_NtSetInformationFile:
    push 0393951B9h
    call _WhisperMain

_NtMapViewOfSection:
    push 00C8E0A3Bh
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0F4B2F01Bh
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0F4A5D271h
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 06FD2B3B6h
    call _WhisperMain

_NtTerminateProcess:
    push 0DD863C12h
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0F37A3C2Bh
    call _WhisperMain

_NtReadFileScatter:
    push 08134CBE9h
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0069FCBD9h
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0091E59C7h
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 02B945D15h
    call _WhisperMain

_NtEnumerateKey:
    push 00A1F2D84h
    call _WhisperMain

_NtOpenFile:
    push 0B4829E16h
    call _WhisperMain

_NtDelayExecution:
    push 045107C57h
    call _WhisperMain

_NtQueryDirectoryFile:
    push 03AB8E01Fh
    call _WhisperMain

_NtQuerySystemInformation:
    push 0D847DAD3h
    call _WhisperMain

_NtOpenSection:
    push 09B30FBFEh
    call _WhisperMain

_NtQueryTimer:
    push 0195ADA00h
    call _WhisperMain

_NtFsControlFile:
    push 01CBA4F8Ch
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0C749CDDBh
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 01091F08Ch
    call _WhisperMain

_NtDuplicateObject:
    push 0A880439Ch
    call _WhisperMain

_NtQueryAttributesFile:
    push 0E6DC31EFh
    call _WhisperMain

_NtClearEvent:
    push 02E85D502h
    call _WhisperMain

_NtReadVirtualMemory:
    push 00F93E2F4h
    call _WhisperMain

_NtOpenEvent:
    push 0D1BBD22Ch
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0F5C0E760h
    call _WhisperMain

_NtDuplicateToken:
    push 007910B08h
    call _WhisperMain

_NtContinue:
    push 002A6734Ah
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0FFCC61F5h
    call _WhisperMain

_NtQueueApcThread:
    push 0EB4C665Dh
    call _WhisperMain

_NtYieldExecution:
    push 0089F2A0Fh
    call _WhisperMain

_NtAddAtom:
    push 0B721B2CBh
    call _WhisperMain

_NtCreateEvent:
    push 00A09099Eh
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0F4A4FA30h
    call _WhisperMain

_NtCreateSection:
    push 038EE5A3Fh
    call _WhisperMain

_NtFlushBuffersFile:
    push 06979F640h
    call _WhisperMain

_NtApphelpCacheControl:
    push 07DE25571h
    call _WhisperMain

_NtCreateProcessEx:
    push 0B198C362h
    call _WhisperMain

_NtCreateThread:
    push 08C91B60Fh
    call _WhisperMain

_NtIsProcessInJob:
    push 079C2697Fh
    call _WhisperMain

_NtProtectVirtualMemory:
    push 01F81091Fh
    call _WhisperMain

_NtQuerySection:
    push 00F582D95h
    call _WhisperMain

_NtResumeThread:
    push 08A13C4B9h
    call _WhisperMain

_NtTerminateThread:
    push 0CE6B8849h
    call _WhisperMain

_NtReadRequestData:
    push 018B5020Eh
    call _WhisperMain

_NtCreateFile:
    push 01D7CF73Bh
    call _WhisperMain

_NtQueryEvent:
    push 0C850CDE6h
    call _WhisperMain

_NtWriteRequestData:
    push 064DE9348h
    call _WhisperMain

_NtOpenDirectoryObject:
    push 01CB0CDFDh
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 09A527C02h
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0A12CABB5h
    call _WhisperMain

_NtSetInformationObject:
    push 0BA968629h
    call _WhisperMain

_NtCancelIoFile:
    push 07CEB7240h
    call _WhisperMain

_NtTraceEvent:
    push 0F4AACF0Dh
    call _WhisperMain

_NtPowerInformation:
    push 064826E27h
    call _WhisperMain

_NtSetValueKey:
    push 0991F9880h
    call _WhisperMain

_NtCancelTimer:
    push 07FE47178h
    call _WhisperMain

_NtSetTimer:
    push 025A31D26h
    call _WhisperMain

_NtAccessCheckByType:
    push 09CFB40CCh
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0FEA205AAh
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0D295F4C0h
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 09F33ADAAh
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0EF5B7866h
    call _WhisperMain

_NtAddAtomEx:
    push 009EB792Ch
    call _WhisperMain

_NtAddBootEntry:
    push 00D801510h
    call _WhisperMain

_NtAddDriverEntry:
    push 00F96130Ah
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0079B0B0Ah
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 03FE51ABDh
    call _WhisperMain

_NtAlertResumeThread:
    push 0AE84A83Eh
    call _WhisperMain

_NtAlertThread:
    push 0120D5CA7h
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0B32F1E2Fh
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 00D9D5D20h
    call _WhisperMain

_NtAllocateReserveObject:
    push 00C5638EDh
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 00B1D70EAh
    call _WhisperMain

_NtAllocateUuids:
    push 0FC4B0A01h
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 09C9DC64Fh
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 07EB57F38h
    call _WhisperMain

_NtAlpcCancelMessage:
    push 00D93C13Ah
    call _WhisperMain

_NtAlpcConnectPort:
    push 024B6391Ch
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 065A4531Bh
    call _WhisperMain

_NtAlpcCreatePort:
    push 026B72025h
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 00A96323Dh
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 03E933BF9h
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 066B80343h
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0D5492841h
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0E8CF01D4h
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 08F3F87CCh
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 06EF16D6Bh
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0CE562D06h
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 024B2311Ch
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 060F04D6Eh
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0AC48D9D6h
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0D7B7D605h
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 03561C534h
    call _WhisperMain

_NtAlpcQueryInformation:
    push 034AA17FBh
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 098394519h
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 016CA12BAh
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 022B01F1Eh
    call _WhisperMain

_NtAlpcSetInformation:
    push 0160F149Fh
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0E10AD282h
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 016A93E35h
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0793C7FAEh
    call _WhisperMain

_NtCallEnclave:
    push 0D7B0F77Bh
    call _WhisperMain

_NtCancelIoFileEx:
    push 000AAC2F0h
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0CA5BC2ECh
    call _WhisperMain

_NtCancelTimer2:
    push 0079BE74Dh
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0B9BAC176h
    call _WhisperMain

_NtCommitComplete:
    push 0267BE1D1h
    call _WhisperMain

_NtCommitEnlistment:
    push 09FC2A676h
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0980C9A99h
    call _WhisperMain

_NtCommitTransaction:
    push 09C079AAFh
    call _WhisperMain

_NtCompactKeys:
    push 057E6BAB8h
    call _WhisperMain

_NtCompareObjects:
    push 0871A919Fh
    call _WhisperMain

_NtCompareSigningLevels:
    push 048CA485Eh
    call _WhisperMain

_NtCompareTokens:
    push 004956A4Ch
    call _WhisperMain

_NtCompleteConnectPort:
    push 054B54538h
    call _WhisperMain

_NtCompressKey:
    push 067DB5062h
    call _WhisperMain

_NtConnectPort:
    push 05C0F439Ch
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 003DA2D47h
    call _WhisperMain

_NtCreateDebugObject:
    push 08E34AEA8h
    call _WhisperMain

_NtCreateDirectoryObject:
    push 084B7BCFBh
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0B24DF2F4h
    call _WhisperMain

_NtCreateEnclave:
    push 05E3BB548h
    call _WhisperMain

_NtCreateEnlistment:
    push 0086017F3h
    call _WhisperMain

_NtCreateEventPair:
    push 02B3421ABh
    call _WhisperMain

_NtCreateIRTimer:
    push 09D1E8B9Ah
    call _WhisperMain

_NtCreateIoCompletion:
    push 018161881h
    call _WhisperMain

_NtCreateJobObject:
    push 08AB1822Dh
    call _WhisperMain

_NtCreateJobSet:
    push 0B4BDF26Fh
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0102C5800h
    call _WhisperMain

_NtCreateKeyedEvent:
    push 08AB5CB61h
    call _WhisperMain

_NtCreateLowBoxToken:
    push 035883F2Ch
    call _WhisperMain

_NtCreateMailslotFile:
    push 07D3DB699h
    call _WhisperMain

_NtCreateMutant:
    push 0B2B4D0A2h
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 066C0B87Bh
    call _WhisperMain

_NtCreatePagingFile:
    push 094850EA2h
    call _WhisperMain

_NtCreatePartition:
    push 0DA83D813h
    call _WhisperMain

_NtCreatePort:
    push 021B33C3Bh
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 02E905103h
    call _WhisperMain

_NtCreateProcess:
    push 0952A98B2h
    call _WhisperMain

_NtCreateProfile:
    push 0861D8E7Eh
    call _WhisperMain

_NtCreateProfileEx:
    push 08863C4A7h
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 01E58C114h
    call _WhisperMain

_NtCreateResourceManager:
    push 083A9178Ch
    call _WhisperMain

_NtCreateSemaphore:
    push 0124CCF74h
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 03A940429h
    call _WhisperMain

_NtCreateThreadEx:
    push 09C9FDC26h
    call _WhisperMain

_NtCreateTimer:
    push 00FB8E5C0h
    call _WhisperMain

_NtCreateTimer2:
    push 0CFB70F29h
    call _WhisperMain

_NtCreateToken:
    push 007A29182h
    call _WhisperMain

_NtCreateTokenEx:
    push 0242F6E9Ch
    call _WhisperMain

_NtCreateTransaction:
    push 0CCA8B07Bh
    call _WhisperMain

_NtCreateTransactionManager:
    push 08A349C97h
    call _WhisperMain

_NtCreateUserProcess:
    push 0E5392C64h
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 01B3D63B1h
    call _WhisperMain

_NtCreateWaitablePort:
    push 024BD0B2Eh
    call _WhisperMain

_NtCreateWnfStateName:
    push 02CCD054Fh
    call _WhisperMain

_NtCreateWorkerFactory:
    push 04094085Ah
    call _WhisperMain

_NtDebugActiveProcess:
    push 0862C964Fh
    call _WhisperMain

_NtDebugContinue:
    push 04CC093E4h
    call _WhisperMain

_NtDeleteAtom:
    push 07EEB3332h
    call _WhisperMain

_NtDeleteBootEntry:
    push 00D800D08h
    call _WhisperMain

_NtDeleteDriverEntry:
    push 00B963124h
    call _WhisperMain

_NtDeleteFile:
    push 0B6B82682h
    call _WhisperMain

_NtDeleteKey:
    push 03B8E5A76h
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0D15435C5h
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 01CB62325h
    call _WhisperMain

_NtDeleteValueKey:
    push 0B233D3C9h
    call _WhisperMain

_NtDeleteWnfStateData:
    push 00289E800h
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0349BF1C3h
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0B7872BB0h
    call _WhisperMain

_NtDisplayString:
    push 0069E4C34h
    call _WhisperMain

_NtDrawText:
    push 03ACD255Eh
    call _WhisperMain

_NtEnableLastKnownGood:
    push 015B68084h
    call _WhisperMain

_NtEnumerateBootEntries:
    push 00A523BC9h
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 09C03755Fh
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0B1A4F558h
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0163EC165h
    call _WhisperMain

_NtExtendSection:
    push 0128C3815h
    call _WhisperMain

_NtFilterBootOption:
    push 032AA0A27h
    call _WhisperMain

_NtFilterToken:
    push 039917F3Ah
    call _WhisperMain

_NtFilterTokenEx:
    push 0C6A919EFh
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0EB39DD86h
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0F097F70Bh
    call _WhisperMain

_NtFlushInstructionCache:
    push 02E3BD02Bh
    call _WhisperMain

_NtFlushKey:
    push 07BE1425Eh
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 08A930B85h
    call _WhisperMain

_NtFlushVirtualMemory:
    push 00F99213Fh
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0411C5587h
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 019B1E0DBh
    call _WhisperMain

_NtFreezeRegistry:
    push 04763C063h
    call _WhisperMain

_NtFreezeTransactions:
    push 00B9914F3h
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 033172392h
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0CD4BEDD9h
    call _WhisperMain

_NtGetContextThread:
    push 0309C6235h
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0EE5BC102h
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0A7596104h
    call _WhisperMain

_NtGetDevicePowerState:
    push 0B2296868h
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0A6B15DF8h
    call _WhisperMain

_NtGetNextProcess:
    push 0DF853DE9h
    call _WhisperMain

_NtGetNextThread:
    push 0A892F42Ah
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0E697D758h
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 009BE9396h
    call _WhisperMain

_NtGetWriteWatch:
    push 012AB2BFAh
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 02086F1A5h
    call _WhisperMain

_NtImpersonateThread:
    push 0892F0F0Ch
    call _WhisperMain

_NtInitializeEnclave:
    push 028975004h
    call _WhisperMain

_NtInitializeNlsFiles:
    push 028904B6Eh
    call _WhisperMain

_NtInitializeRegistry:
    push 0069F1A09h
    call _WhisperMain

_NtInitiatePowerAction:
    push 046C22417h
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0E2601736h
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0DB80003Fh
    call _WhisperMain

_NtListenPort:
    push 0C774F4FBh
    call _WhisperMain

_NtLoadDriver:
    push 05CBF3462h
    call _WhisperMain

_NtLoadEnclaveData:
    push 09C03CEB2h
    call _WhisperMain

_NtLoadHotPatch:
    push 070ED3FCAh
    call _WhisperMain

_NtLoadKey:
    push 0B91ED8C6h
    call _WhisperMain

_NtLoadKey2:
    push 07FA79006h
    call _WhisperMain

_NtLoadKeyEx:
    push 05BD8ACA7h
    call _WhisperMain

_NtLockFile:
    push 058C4AA90h
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0E747F8ECh
    call _WhisperMain

_NtLockRegistryKey:
    push 073C0665Ch
    call _WhisperMain

_NtLockVirtualMemory:
    push 03BAFD23Fh
    call _WhisperMain

_NtMakePermanentObject:
    push 0A29ED870h
    call _WhisperMain

_NtMakeTemporaryObject:
    push 00AD3329Fh
    call _WhisperMain

_NtManagePartition:
    push 0C68FC41Fh
    call _WhisperMain

_NtMapCMFModule:
    push 03E981FC6h
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0059C6C06h
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 086B4C00Ah
    call _WhisperMain

_NtModifyBootEntry:
    push 01D9B3728h
    call _WhisperMain

_NtModifyDriverEntry:
    push 001941B16h
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 094039498h
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0009AA3A1h
    call _WhisperMain

_NtNotifyChangeKey:
    push 05B5B7EC4h
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 065FB7192h
    call _WhisperMain

_NtNotifyChangeSession:
    push 0F7A736F5h
    call _WhisperMain

_NtOpenEnlistment:
    push 07BA1064Bh
    call _WhisperMain

_NtOpenEventPair:
    push 0B296D207h
    call _WhisperMain

_NtOpenIoCompletion:
    push 0290F17A4h
    call _WhisperMain

_NtOpenJobObject:
    push 05E92045Fh
    call _WhisperMain

_NtOpenKeyEx:
    push 051FEB285h
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0177F8C40h
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 06B3EAB05h
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0CA810DCAh
    call _WhisperMain

_NtOpenMutant:
    push 0D597B846h
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 00A876C8Eh
    call _WhisperMain

_NtOpenPartition:
    push 0064D669Fh
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 034944B0Fh
    call _WhisperMain

_NtOpenProcessToken:
    push 00396888Fh
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 094CE539Eh
    call _WhisperMain

_NtOpenResourceManager:
    push 001B92EE8h
    call _WhisperMain

_NtOpenSemaphore:
    push 01499E0C8h
    call _WhisperMain

_NtOpenSession:
    push 09201B08Dh
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0069C6031h
    call _WhisperMain

_NtOpenThread:
    push 0AC88A63Eh
    call _WhisperMain

_NtOpenTimer:
    push 087168D8Eh
    call _WhisperMain

_NtOpenTransaction:
    push 01856DDFDh
    call _WhisperMain

_NtOpenTransactionManager:
    push 08520EFDCh
    call _WhisperMain

_NtPlugPlayControl:
    push 0018E7945h
    call _WhisperMain

_NtPrePrepareComplete:
    push 0F89A1710h
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0DA5C190Ah
    call _WhisperMain

_NtPrepareComplete:
    push 056B4723Ah
    call _WhisperMain

_NtPrepareEnlistment:
    push 0D946EAC1h
    call _WhisperMain

_NtPrivilegeCheck:
    push 014B7C60Ah
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0D4B3EA72h
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 00E890E26h
    call _WhisperMain

_NtPropagationComplete:
    push 00A9419FAh
    call _WhisperMain

_NtPropagationFailed:
    push 0F257ECECh
    call _WhisperMain

_NtPulseEvent:
    push 02094CA02h
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0B80DDFF2h
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 01B09F413h
    call _WhisperMain

_NtQueryBootOptions:
    push 05F905903h
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0E749E829h
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0B8A68E18h
    call _WhisperMain

_NtQueryDirectoryObject:
    push 004A03C15h
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0A33C7E6Fh
    call _WhisperMain

_NtQueryEaFile:
    push 0623848BFh
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 052983E0Eh
    call _WhisperMain

_NtQueryInformationAtom:
    push 0D33BCABFh
    call _WhisperMain

_NtQueryInformationByName:
    push 024BA572Dh
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0199F3809h
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0E758ECC7h
    call _WhisperMain

_NtQueryInformationPort:
    push 0AB3AACB1h
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 04F9F9CC2h
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0168C35D1h
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0173773AAh
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 004921BF2h
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 095B6D48Ch
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0C55E33C3h
    call _WhisperMain

_NtQueryIoCompletion:
    push 082AC61BCh
    call _WhisperMain

_NtQueryLicenseValue:
    push 00CBE39E6h
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 05DA55A38h
    call _WhisperMain

_NtQueryMutant:
    push 01C123F85h
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 04F324AB8h
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0038AD3D1h
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0781C9F75h
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 06E3634F6h
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 00C187A9Dh
    call _WhisperMain

_NtQuerySecurityObject:
    push 0049E2DC3h
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0953FEADEh
    call _WhisperMain

_NtQuerySemaphore:
    push 0089B7084h
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 076C48FC9h
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 00E9D710Ah
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 08F96BB2Ah
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 00E94B1A3h
    call _WhisperMain

_NtQueryTimerResolution:
    push 004924441h
    call _WhisperMain

_NtQueryWnfStateData:
    push 060BB4E74h
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 00E942417h
    call _WhisperMain

_NtQueueApcThreadEx:
    push 00311C06Ah
    call _WhisperMain

_NtRaiseException:
    push 09F30B7AAh
    call _WhisperMain

_NtRaiseHardError:
    push 0011071FFh
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0D6BB33D1h
    call _WhisperMain

_NtRecoverEnlistment:
    push 009874C4Dh
    call _WhisperMain

_NtRecoverResourceManager:
    push 0B763E3A6h
    call _WhisperMain

_NtRecoverTransactionManager:
    push 033A30322h
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 00C8E2613h
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0FE73C5FCh
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0F056F5C4h
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0F2DAC678h
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 000A3406Ah
    call _WhisperMain

_NtRemoveProcessDebug:
    push 010AE0720h
    call _WhisperMain

_NtRenameKey:
    push 00B3D109Ch
    call _WhisperMain

_NtRenameTransactionManager:
    push 0093D2361h
    call _WhisperMain

_NtReplaceKey:
    push 096D5A368h
    call _WhisperMain

_NtReplacePartitionUnit:
    push 014BF2816h
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 02CB52B26h
    call _WhisperMain

_NtRequestPort:
    push 020B03914h
    call _WhisperMain

_NtResetEvent:
    push 038A12520h
    call _WhisperMain

_NtResetWriteWatch:
    push 034A10E32h
    call _WhisperMain

_NtRestoreKey:
    push 061EB5848h
    call _WhisperMain

_NtResumeProcess:
    push 05DA2787Ah
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0E649E4D5h
    call _WhisperMain

_NtRollbackComplete:
    push 028B1B28Eh
    call _WhisperMain

_NtRollbackEnlistment:
    push 057956A3Fh
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 07FA05362h
    call _WhisperMain

_NtRollbackTransaction:
    push 018005AADh
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 06DB36122h
    call _WhisperMain

_NtSaveKey:
    push 09BA3FE41h
    call _WhisperMain

_NtSaveKeyEx:
    push 065E5E2A5h
    call _WhisperMain

_NtSaveMergedKeys:
    push 0EB778898h
    call _WhisperMain

_NtSecureConnectPort:
    push 060F14762h
    call _WhisperMain

_NtSerializeBoot:
    push 03EA81C39h
    call _WhisperMain

_NtSetBootEntryOrder:
    push 017358F1Fh
    call _WhisperMain

_NtSetBootOptions:
    push 00D9B0B13h
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 02A9AE1C4h
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0EEB02921h
    call _WhisperMain

_NtSetContextThread:
    push 01033CE81h
    call _WhisperMain

_NtSetDebugFilterState:
    push 0F6699EA6h
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 01CA9EFE6h
    call _WhisperMain

_NtSetDefaultLocale:
    push 03DAFFA8Fh
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 09789EB90h
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0D008F4D2h
    call _WhisperMain

_NtSetEaFile:
    push 07CBF1A7Ch
    call _WhisperMain

_NtSetHighEventPair:
    push 08412BAA3h
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 08A12B095h
    call _WhisperMain

_NtSetIRTimer:
    push 003CB1D48h
    call _WhisperMain

_NtSetInformationDebugObject:
    push 08E34A6A8h
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0096C0AFBh
    call _WhisperMain

_NtSetInformationJobObject:
    push 0735C8152h
    call _WhisperMain

_NtSetInformationKey:
    push 0938DA431h
    call _WhisperMain

_NtSetInformationResourceManager:
    push 09F87C14Fh
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 07CAA5072h
    call _WhisperMain

_NtSetInformationToken:
    push 021807724h
    call _WhisperMain

_NtSetInformationTransaction:
    push 09901F9D0h
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 079209378h
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 01F81090Fh
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 087109F93h
    call _WhisperMain

_NtSetIntervalProfile:
    push 04AA24C1Eh
    call _WhisperMain

_NtSetIoCompletion:
    push 0D44AF519h
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0A1536D06h
    call _WhisperMain

_NtSetLdtEntries:
    push 086AE7EC6h
    call _WhisperMain

_NtSetLowEventPair:
    push 030AFACA1h
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 070CD90BBh
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0EDDEB3EBh
    call _WhisperMain

_NtSetSecurityObject:
    push 0A0BBCC40h
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0C23DEFB4h
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 09788A5FCh
    call _WhisperMain

_NtSetSystemInformation:
    push 054965203h
    call _WhisperMain

_NtSetSystemPowerState:
    push 062D84854h
    call _WhisperMain

_NtSetSystemTime:
    push 01241C901h
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0D614A8C0h
    call _WhisperMain

_NtSetTimer2:
    push 00386ECA7h
    call _WhisperMain

_NtSetTimerEx:
    push 0B886C600h
    call _WhisperMain

_NtSetTimerResolution:
    push 0A731A7A3h
    call _WhisperMain

_NtSetUuidSeed:
    push 0F15D7160h
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 024B1D2A2h
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0802A89B6h
    call _WhisperMain

_NtShutdownSystem:
    push 0149CCDD0h
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 01C8F0802h
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 09A2592B9h
    call _WhisperMain

_NtSinglePhaseReject:
    push 0AA859A39h
    call _WhisperMain

_NtStartProfile:
    push 0CC9AFA09h
    call _WhisperMain

_NtStopProfile:
    push 08139F5ADh
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 01CA1E98Ch
    call _WhisperMain

_NtSuspendProcess:
    push 0F1A41038h
    call _WhisperMain

_NtSuspendThread:
    push 0B41FBEB9h
    call _WhisperMain

_NtSystemDebugControl:
    push 0CC1BC882h
    call _WhisperMain

_NtTerminateEnclave:
    push 0E2131E80h
    call _WhisperMain

_NtTerminateJobObject:
    push 0369D0215h
    call _WhisperMain

_NtTestAlert:
    push 0D13BD8A7h
    call _WhisperMain

_NtThawRegistry:
    push 0CD5121C2h
    call _WhisperMain

_NtThawTransactions:
    push 01F8A351Dh
    call _WhisperMain

_NtTraceControl:
    push 0F5B7F620h
    call _WhisperMain

_NtTranslateFilePath:
    push 0A60E9A5Ah
    call _WhisperMain

_NtUmsThreadYield:
    push 003A11017h
    call _WhisperMain

_NtUnloadDriver:
    push 05E973E66h
    call _WhisperMain

_NtUnloadKey:
    push 0E83A0A46h
    call _WhisperMain

_NtUnloadKey2:
    push 0AED262CCh
    call _WhisperMain

_NtUnloadKeyEx:
    push 07A7C2CA3h
    call _WhisperMain

_NtUnlockFile:
    push 09A1FF414h
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0F595E13Eh
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 006D5E1ABh
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0E0BC976Ch
    call _WhisperMain

_NtUpdateWnfStateData:
    push 01086E314h
    call _WhisperMain

_NtVdmControl:
    push 0CB8BE11Dh
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 07EA34C74h
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0B89844F1h
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 078A33D72h
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 05E926624h
    call _WhisperMain

_NtWaitHighEventPair:
    push 016BF362Dh
    call _WhisperMain

_NtWaitLowEventPair:
    push 0104C34FDh
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 01ACD7E1Ah
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 00FAA3118h
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0E048E6DDh
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0EACE346Eh
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 002E60077h
    call _WhisperMain

_NtSavepointTransaction:
    push 0D70CF7DEh
    call _WhisperMain

_NtSavepointComplete:
    push 048B45638h
    call _WhisperMain

_NtCreateSectionEx:
    push 012D15A10h
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0B0E24384h
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0C853D1DEh
    call _WhisperMain

_NtListTransactions:
    push 027930B25h
    call _WhisperMain

_NtMarshallTransaction:
    push 00254DE1Fh
    call _WhisperMain

_NtPullTransaction:
    push 0D48FD41Dh
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 060A5782Eh
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 075DF6EB9h
    call _WhisperMain

_NtStartTm:
    push 0939E70E3h
    call _WhisperMain

_NtSetInformationProcess:
    push 0EF2CCEB0h
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 03B993D0Eh
    call _WhisperMain

_NtRequestWakeupLatency:
    push 072966906h
    call _WhisperMain

_NtQuerySystemTime:
    push 0A08736ACh
    call _WhisperMain

_NtManageHotPatch:
    push 020BEDDABh
    call _WhisperMain

_NtContinueEx:
    push 06FED9389h
    call _WhisperMain

