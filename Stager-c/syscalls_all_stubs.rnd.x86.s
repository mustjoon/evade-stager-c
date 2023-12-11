.intel_syntax noprefix
.data
.align 4
stubReturn:     .long 0
returnAddress:  .long 0
espBookmark:    .long 0
syscallNumber:  .long 0
syscallAddress: .long 0

.text
.global _NtAccessCheck
.global _NtWorkerFactoryWorkerReady
.global _NtAcceptConnectPort
.global _NtMapUserPhysicalPagesScatter
.global _NtWaitForSingleObject
.global _NtCallbackReturn
.global _NtReadFile
.global _NtDeviceIoControlFile
.global _NtWriteFile
.global _NtRemoveIoCompletion
.global _NtReleaseSemaphore
.global _NtReplyWaitReceivePort
.global _NtReplyPort
.global _NtSetInformationThread
.global _NtSetEvent
.global _NtClose
.global _NtQueryObject
.global _NtQueryInformationFile
.global _NtOpenKey
.global _NtEnumerateValueKey
.global _NtFindAtom
.global _NtQueryDefaultLocale
.global _NtQueryKey
.global _NtQueryValueKey
.global _NtAllocateVirtualMemory
.global _NtQueryInformationProcess
.global _NtWaitForMultipleObjects32
.global _NtWriteFileGather
.global _NtCreateKey
.global _NtFreeVirtualMemory
.global _NtImpersonateClientOfPort
.global _NtReleaseMutant
.global _NtQueryInformationToken
.global _NtRequestWaitReplyPort
.global _NtQueryVirtualMemory
.global _NtOpenThreadToken
.global _NtQueryInformationThread
.global _NtOpenProcess
.global _NtSetInformationFile
.global _NtMapViewOfSection
.global _NtAccessCheckAndAuditAlarm
.global _NtUnmapViewOfSection
.global _NtReplyWaitReceivePortEx
.global _NtTerminateProcess
.global _NtSetEventBoostPriority
.global _NtReadFileScatter
.global _NtOpenThreadTokenEx
.global _NtOpenProcessTokenEx
.global _NtQueryPerformanceCounter
.global _NtEnumerateKey
.global _NtOpenFile
.global _NtDelayExecution
.global _NtQueryDirectoryFile
.global _NtQuerySystemInformation
.global _NtOpenSection
.global _NtQueryTimer
.global _NtFsControlFile
.global _NtWriteVirtualMemory
.global _NtCloseObjectAuditAlarm
.global _NtDuplicateObject
.global _NtQueryAttributesFile
.global _NtClearEvent
.global _NtReadVirtualMemory
.global _NtOpenEvent
.global _NtAdjustPrivilegesToken
.global _NtDuplicateToken
.global _NtContinue
.global _NtQueryDefaultUILanguage
.global _NtQueueApcThread
.global _NtYieldExecution
.global _NtAddAtom
.global _NtCreateEvent
.global _NtQueryVolumeInformationFile
.global _NtCreateSection
.global _NtFlushBuffersFile
.global _NtApphelpCacheControl
.global _NtCreateProcessEx
.global _NtCreateThread
.global _NtIsProcessInJob
.global _NtProtectVirtualMemory
.global _NtQuerySection
.global _NtResumeThread
.global _NtTerminateThread
.global _NtReadRequestData
.global _NtCreateFile
.global _NtQueryEvent
.global _NtWriteRequestData
.global _NtOpenDirectoryObject
.global _NtAccessCheckByTypeAndAuditAlarm
.global _NtWaitForMultipleObjects
.global _NtSetInformationObject
.global _NtCancelIoFile
.global _NtTraceEvent
.global _NtPowerInformation
.global _NtSetValueKey
.global _NtCancelTimer
.global _NtSetTimer
.global _NtAccessCheckByType
.global _NtAccessCheckByTypeResultList
.global _NtAccessCheckByTypeResultListAndAuditAlarm
.global _NtAccessCheckByTypeResultListAndAuditAlarmByHandle
.global _NtAcquireProcessActivityReference
.global _NtAddAtomEx
.global _NtAddBootEntry
.global _NtAddDriverEntry
.global _NtAdjustGroupsToken
.global _NtAdjustTokenClaimsAndDeviceGroups
.global _NtAlertResumeThread
.global _NtAlertThread
.global _NtAlertThreadByThreadId
.global _NtAllocateLocallyUniqueId
.global _NtAllocateReserveObject
.global _NtAllocateUserPhysicalPages
.global _NtAllocateUuids
.global _NtAllocateVirtualMemoryEx
.global _NtAlpcAcceptConnectPort
.global _NtAlpcCancelMessage
.global _NtAlpcConnectPort
.global _NtAlpcConnectPortEx
.global _NtAlpcCreatePort
.global _NtAlpcCreatePortSection
.global _NtAlpcCreateResourceReserve
.global _NtAlpcCreateSectionView
.global _NtAlpcCreateSecurityContext
.global _NtAlpcDeletePortSection
.global _NtAlpcDeleteResourceReserve
.global _NtAlpcDeleteSectionView
.global _NtAlpcDeleteSecurityContext
.global _NtAlpcDisconnectPort
.global _NtAlpcImpersonateClientContainerOfPort
.global _NtAlpcImpersonateClientOfPort
.global _NtAlpcOpenSenderProcess
.global _NtAlpcOpenSenderThread
.global _NtAlpcQueryInformation
.global _NtAlpcQueryInformationMessage
.global _NtAlpcRevokeSecurityContext
.global _NtAlpcSendWaitReceivePort
.global _NtAlpcSetInformation
.global _NtAreMappedFilesTheSame
.global _NtAssignProcessToJobObject
.global _NtAssociateWaitCompletionPacket
.global _NtCallEnclave
.global _NtCancelIoFileEx
.global _NtCancelSynchronousIoFile
.global _NtCancelTimer2
.global _NtCancelWaitCompletionPacket
.global _NtCommitComplete
.global _NtCommitEnlistment
.global _NtCommitRegistryTransaction
.global _NtCommitTransaction
.global _NtCompactKeys
.global _NtCompareObjects
.global _NtCompareSigningLevels
.global _NtCompareTokens
.global _NtCompleteConnectPort
.global _NtCompressKey
.global _NtConnectPort
.global _NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
.global _NtCreateDebugObject
.global _NtCreateDirectoryObject
.global _NtCreateDirectoryObjectEx
.global _NtCreateEnclave
.global _NtCreateEnlistment
.global _NtCreateEventPair
.global _NtCreateIRTimer
.global _NtCreateIoCompletion
.global _NtCreateJobObject
.global _NtCreateJobSet
.global _NtCreateKeyTransacted
.global _NtCreateKeyedEvent
.global _NtCreateLowBoxToken
.global _NtCreateMailslotFile
.global _NtCreateMutant
.global _NtCreateNamedPipeFile
.global _NtCreatePagingFile
.global _NtCreatePartition
.global _NtCreatePort
.global _NtCreatePrivateNamespace
.global _NtCreateProcess
.global _NtCreateProfile
.global _NtCreateProfileEx
.global _NtCreateRegistryTransaction
.global _NtCreateResourceManager
.global _NtCreateSemaphore
.global _NtCreateSymbolicLinkObject
.global _NtCreateThreadEx
.global _NtCreateTimer
.global _NtCreateTimer2
.global _NtCreateToken
.global _NtCreateTokenEx
.global _NtCreateTransaction
.global _NtCreateTransactionManager
.global _NtCreateUserProcess
.global _NtCreateWaitCompletionPacket
.global _NtCreateWaitablePort
.global _NtCreateWnfStateName
.global _NtCreateWorkerFactory
.global _NtDebugActiveProcess
.global _NtDebugContinue
.global _NtDeleteAtom
.global _NtDeleteBootEntry
.global _NtDeleteDriverEntry
.global _NtDeleteFile
.global _NtDeleteKey
.global _NtDeleteObjectAuditAlarm
.global _NtDeletePrivateNamespace
.global _NtDeleteValueKey
.global _NtDeleteWnfStateData
.global _NtDeleteWnfStateName
.global _NtDisableLastKnownGood
.global _NtDisplayString
.global _NtDrawText
.global _NtEnableLastKnownGood
.global _NtEnumerateBootEntries
.global _NtEnumerateDriverEntries
.global _NtEnumerateSystemEnvironmentValuesEx
.global _NtEnumerateTransactionObject
.global _NtExtendSection
.global _NtFilterBootOption
.global _NtFilterToken
.global _NtFilterTokenEx
.global _NtFlushBuffersFileEx
.global _NtFlushInstallUILanguage
.global _NtFlushInstructionCache
.global _NtFlushKey
.global _NtFlushProcessWriteBuffers
.global _NtFlushVirtualMemory
.global _NtFlushWriteBuffer
.global _NtFreeUserPhysicalPages
.global _NtFreezeRegistry
.global _NtFreezeTransactions
.global _NtGetCachedSigningLevel
.global _NtGetCompleteWnfStateSubscription
.global _NtGetContextThread
.global _NtGetCurrentProcessorNumber
.global _NtGetCurrentProcessorNumberEx
.global _NtGetDevicePowerState
.global _NtGetMUIRegistryInfo
.global _NtGetNextProcess
.global _NtGetNextThread
.global _NtGetNlsSectionPtr
.global _NtGetNotificationResourceManager
.global _NtGetWriteWatch
.global _NtImpersonateAnonymousToken
.global _NtImpersonateThread
.global _NtInitializeEnclave
.global _NtInitializeNlsFiles
.global _NtInitializeRegistry
.global _NtInitiatePowerAction
.global _NtIsSystemResumeAutomatic
.global _NtIsUILanguageComitted
.global _NtListenPort
.global _NtLoadDriver
.global _NtLoadEnclaveData
.global _NtLoadHotPatch
.global _NtLoadKey
.global _NtLoadKey2
.global _NtLoadKeyEx
.global _NtLockFile
.global _NtLockProductActivationKeys
.global _NtLockRegistryKey
.global _NtLockVirtualMemory
.global _NtMakePermanentObject
.global _NtMakeTemporaryObject
.global _NtManagePartition
.global _NtMapCMFModule
.global _NtMapUserPhysicalPages
.global _NtMapViewOfSectionEx
.global _NtModifyBootEntry
.global _NtModifyDriverEntry
.global _NtNotifyChangeDirectoryFile
.global _NtNotifyChangeDirectoryFileEx
.global _NtNotifyChangeKey
.global _NtNotifyChangeMultipleKeys
.global _NtNotifyChangeSession
.global _NtOpenEnlistment
.global _NtOpenEventPair
.global _NtOpenIoCompletion
.global _NtOpenJobObject
.global _NtOpenKeyEx
.global _NtOpenKeyTransacted
.global _NtOpenKeyTransactedEx
.global _NtOpenKeyedEvent
.global _NtOpenMutant
.global _NtOpenObjectAuditAlarm
.global _NtOpenPartition
.global _NtOpenPrivateNamespace
.global _NtOpenProcessToken
.global _NtOpenRegistryTransaction
.global _NtOpenResourceManager
.global _NtOpenSemaphore
.global _NtOpenSession
.global _NtOpenSymbolicLinkObject
.global _NtOpenThread
.global _NtOpenTimer
.global _NtOpenTransaction
.global _NtOpenTransactionManager
.global _NtPlugPlayControl
.global _NtPrePrepareComplete
.global _NtPrePrepareEnlistment
.global _NtPrepareComplete
.global _NtPrepareEnlistment
.global _NtPrivilegeCheck
.global _NtPrivilegeObjectAuditAlarm
.global _NtPrivilegedServiceAuditAlarm
.global _NtPropagationComplete
.global _NtPropagationFailed
.global _NtPulseEvent
.global _NtQueryAuxiliaryCounterFrequency
.global _NtQueryBootEntryOrder
.global _NtQueryBootOptions
.global _NtQueryDebugFilterState
.global _NtQueryDirectoryFileEx
.global _NtQueryDirectoryObject
.global _NtQueryDriverEntryOrder
.global _NtQueryEaFile
.global _NtQueryFullAttributesFile
.global _NtQueryInformationAtom
.global _NtQueryInformationByName
.global _NtQueryInformationEnlistment
.global _NtQueryInformationJobObject
.global _NtQueryInformationPort
.global _NtQueryInformationResourceManager
.global _NtQueryInformationTransaction
.global _NtQueryInformationTransactionManager
.global _NtQueryInformationWorkerFactory
.global _NtQueryInstallUILanguage
.global _NtQueryIntervalProfile
.global _NtQueryIoCompletion
.global _NtQueryLicenseValue
.global _NtQueryMultipleValueKey
.global _NtQueryMutant
.global _NtQueryOpenSubKeys
.global _NtQueryOpenSubKeysEx
.global _NtQueryPortInformationProcess
.global _NtQueryQuotaInformationFile
.global _NtQuerySecurityAttributesToken
.global _NtQuerySecurityObject
.global _NtQuerySecurityPolicy
.global _NtQuerySemaphore
.global _NtQuerySymbolicLinkObject
.global _NtQuerySystemEnvironmentValue
.global _NtQuerySystemEnvironmentValueEx
.global _NtQuerySystemInformationEx
.global _NtQueryTimerResolution
.global _NtQueryWnfStateData
.global _NtQueryWnfStateNameInformation
.global _NtQueueApcThreadEx
.global _NtRaiseException
.global _NtRaiseHardError
.global _NtReadOnlyEnlistment
.global _NtRecoverEnlistment
.global _NtRecoverResourceManager
.global _NtRecoverTransactionManager
.global _NtRegisterProtocolAddressInformation
.global _NtRegisterThreadTerminatePort
.global _NtReleaseKeyedEvent
.global _NtReleaseWorkerFactoryWorker
.global _NtRemoveIoCompletionEx
.global _NtRemoveProcessDebug
.global _NtRenameKey
.global _NtRenameTransactionManager
.global _NtReplaceKey
.global _NtReplacePartitionUnit
.global _NtReplyWaitReplyPort
.global _NtRequestPort
.global _NtResetEvent
.global _NtResetWriteWatch
.global _NtRestoreKey
.global _NtResumeProcess
.global _NtRevertContainerImpersonation
.global _NtRollbackComplete
.global _NtRollbackEnlistment
.global _NtRollbackRegistryTransaction
.global _NtRollbackTransaction
.global _NtRollforwardTransactionManager
.global _NtSaveKey
.global _NtSaveKeyEx
.global _NtSaveMergedKeys
.global _NtSecureConnectPort
.global _NtSerializeBoot
.global _NtSetBootEntryOrder
.global _NtSetBootOptions
.global _NtSetCachedSigningLevel
.global _NtSetCachedSigningLevel2
.global _NtSetContextThread
.global _NtSetDebugFilterState
.global _NtSetDefaultHardErrorPort
.global _NtSetDefaultLocale
.global _NtSetDefaultUILanguage
.global _NtSetDriverEntryOrder
.global _NtSetEaFile
.global _NtSetHighEventPair
.global _NtSetHighWaitLowEventPair
.global _NtSetIRTimer
.global _NtSetInformationDebugObject
.global _NtSetInformationEnlistment
.global _NtSetInformationJobObject
.global _NtSetInformationKey
.global _NtSetInformationResourceManager
.global _NtSetInformationSymbolicLink
.global _NtSetInformationToken
.global _NtSetInformationTransaction
.global _NtSetInformationTransactionManager
.global _NtSetInformationVirtualMemory
.global _NtSetInformationWorkerFactory
.global _NtSetIntervalProfile
.global _NtSetIoCompletion
.global _NtSetIoCompletionEx
.global _NtSetLdtEntries
.global _NtSetLowEventPair
.global _NtSetLowWaitHighEventPair
.global _NtSetQuotaInformationFile
.global _NtSetSecurityObject
.global _NtSetSystemEnvironmentValue
.global _NtSetSystemEnvironmentValueEx
.global _NtSetSystemInformation
.global _NtSetSystemPowerState
.global _NtSetSystemTime
.global _NtSetThreadExecutionState
.global _NtSetTimer2
.global _NtSetTimerEx
.global _NtSetTimerResolution
.global _NtSetUuidSeed
.global _NtSetVolumeInformationFile
.global _NtSetWnfProcessNotificationEvent
.global _NtShutdownSystem
.global _NtShutdownWorkerFactory
.global _NtSignalAndWaitForSingleObject
.global _NtSinglePhaseReject
.global _NtStartProfile
.global _NtStopProfile
.global _NtSubscribeWnfStateChange
.global _NtSuspendProcess
.global _NtSuspendThread
.global _NtSystemDebugControl
.global _NtTerminateEnclave
.global _NtTerminateJobObject
.global _NtTestAlert
.global _NtThawRegistry
.global _NtThawTransactions
.global _NtTraceControl
.global _NtTranslateFilePath
.global _NtUmsThreadYield
.global _NtUnloadDriver
.global _NtUnloadKey
.global _NtUnloadKey2
.global _NtUnloadKeyEx
.global _NtUnlockFile
.global _NtUnlockVirtualMemory
.global _NtUnmapViewOfSectionEx
.global _NtUnsubscribeWnfStateChange
.global _NtUpdateWnfStateData
.global _NtVdmControl
.global _NtWaitForAlertByThreadId
.global _NtWaitForDebugEvent
.global _NtWaitForKeyedEvent
.global _NtWaitForWorkViaWorkerFactory
.global _NtWaitHighEventPair
.global _NtWaitLowEventPair
.global _NtAcquireCMFViewOwnership
.global _NtCancelDeviceWakeupRequest
.global _NtClearAllSavepointsTransaction
.global _NtClearSavepointTransaction
.global _NtRollbackSavepointTransaction
.global _NtSavepointTransaction
.global _NtSavepointComplete
.global _NtCreateSectionEx
.global _NtCreateCrossVmEvent
.global _NtGetPlugPlayEvent
.global _NtListTransactions
.global _NtMarshallTransaction
.global _NtPullTransaction
.global _NtReleaseCMFViewOwnership
.global _NtWaitForWnfNotifications
.global _NtStartTm
.global _NtSetInformationProcess
.global _NtRequestDeviceWakeup
.global _NtRequestWakeupLatency
.global _NtQuerySystemTime
.global _NtManageHotPatch
.global _NtContinueEx

.global _WhisperMain

_WhisperMain:
    pop eax                                  
    mov dword ptr [stubReturn], eax         # Save the return address to the stub
    push esp
    pop eax
    add eax, 0x04
    push [eax]
    pop returnAddress                       # Save original return address
    add eax, 0x04
    push eax
    pop espBookmark                         # Save original ESP
    call _SW2_GetSyscallNumber              # Resolve function hash into syscall number
    add esp, 4                              # Restore ESP
    mov dword ptr [syscallNumber], eax      # Save the syscall number
    xor eax, eax
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    je _x86
    inc eax                                 # Inc EAX to 1 for Wow64
_x86:
    push eax                                # Push 0 for x86, 1 for Wow64
    lea edx, dword ptr [esp+0x04]
    call _SW2_GetRandomSyscallAddress       # Get a random 0x02E address
    mov dword ptr [syscallAddress], eax     # Save the address
    mov esp, dword ptr [espBookmark]        # Restore ESP
    mov eax, dword ptr [syscallNumber]      # Restore the syscall number
    call dword ptr syscallAddress           # Call the random syscall location
    mov esp, dword ptr [espBookmark]        # Restore ESP
    push dword ptr [returnAddress]          # Restore the return address
    ret

_NtAccessCheck:
    push 0x7EDB3767
    call _WhisperMain

_NtWorkerFactoryWorkerReady:
    push 0x822AA280
    call _WhisperMain

_NtAcceptConnectPort:
    push 0x1EB83726
    call _WhisperMain

_NtMapUserPhysicalPagesScatter:
    push 0xA01CF8D6
    call _WhisperMain

_NtWaitForSingleObject:
    push 0x04DD6C41
    call _WhisperMain

_NtCallbackReturn:
    push 0x21633CEC
    call _WhisperMain

_NtReadFile:
    push 0x54937C10
    call _WhisperMain

_NtDeviceIoControlFile:
    push 0xB519DD91
    call _WhisperMain

_NtWriteFile:
    push 0x0ABB4412
    call _WhisperMain

_NtRemoveIoCompletion:
    push 0x1ED61275
    call _WhisperMain

_NtReleaseSemaphore:
    push 0xF8AA2D02
    call _WhisperMain

_NtReplyWaitReceivePort:
    push 0x20B34760
    call _WhisperMain

_NtReplyPort:
    push 0x2BB1A1AF
    call _WhisperMain

_NtSetInformationThread:
    push 0xAC97AA3D
    call _WhisperMain

_NtSetEvent:
    push 0x00A31324
    call _WhisperMain

_NtClose:
    push 0x4295B4C5
    call _WhisperMain

_NtQueryObject:
    push 0x6C56C57C
    call _WhisperMain

_NtQueryInformationFile:
    push 0x24313EB6
    call _WhisperMain

_NtOpenKey:
    push 0xA522D2DC
    call _WhisperMain

_NtEnumerateValueKey:
    push 0x398DD6FB
    call _WhisperMain

_NtFindAtom:
    push 0x68FF496E
    call _WhisperMain

_NtQueryDefaultLocale:
    push 0x11192390
    call _WhisperMain

_NtQueryKey:
    push 0x320CD316
    call _WhisperMain

_NtQueryValueKey:
    push 0x46E45177
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x07951D07
    call _WhisperMain

_NtQueryInformationProcess:
    push 0x8F2C8EB0
    call _WhisperMain

_NtWaitForMultipleObjects32:
    push 0x90992C57
    call _WhisperMain

_NtWriteFileGather:
    push 0xF3A2F537
    call _WhisperMain

_NtCreateKey:
    push 0x6ADF754C
    call _WhisperMain

_NtFreeVirtualMemory:
    push 0x0F503BEC
    call _WhisperMain

_NtImpersonateClientOfPort:
    push 0xA032C5E0
    call _WhisperMain

_NtReleaseMutant:
    push 0xE38DCA1B
    call _WhisperMain

_NtQueryInformationToken:
    push 0x0396492E
    call _WhisperMain

_NtRequestWaitReplyPort:
    push 0xA4FEA16E
    call _WhisperMain

_NtQueryVirtualMemory:
    push 0xCE53A6B2
    call _WhisperMain

_NtOpenThreadToken:
    push 0xE8ACE432
    call _WhisperMain

_NtQueryInformationThread:
    push 0x329CADAF
    call _WhisperMain

_NtOpenProcess:
    push 0x0FA30E32
    call _WhisperMain

_NtSetInformationFile:
    push 0x393951B9
    call _WhisperMain

_NtMapViewOfSection:
    push 0x0C8E0A3B
    call _WhisperMain

_NtAccessCheckAndAuditAlarm:
    push 0xF4B2F01B
    call _WhisperMain

_NtUnmapViewOfSection:
    push 0xF4A5D271
    call _WhisperMain

_NtReplyWaitReceivePortEx:
    push 0x6FD2B3B6
    call _WhisperMain

_NtTerminateProcess:
    push 0xDD863C12
    call _WhisperMain

_NtSetEventBoostPriority:
    push 0xF37A3C2B
    call _WhisperMain

_NtReadFileScatter:
    push 0x8134CBE9
    call _WhisperMain

_NtOpenThreadTokenEx:
    push 0x069FCBD9
    call _WhisperMain

_NtOpenProcessTokenEx:
    push 0x091E59C7
    call _WhisperMain

_NtQueryPerformanceCounter:
    push 0x2B945D15
    call _WhisperMain

_NtEnumerateKey:
    push 0x0A1F2D84
    call _WhisperMain

_NtOpenFile:
    push 0xB4829E16
    call _WhisperMain

_NtDelayExecution:
    push 0x45107C57
    call _WhisperMain

_NtQueryDirectoryFile:
    push 0x3AB8E01F
    call _WhisperMain

_NtQuerySystemInformation:
    push 0xD847DAD3
    call _WhisperMain

_NtOpenSection:
    push 0x9B30FBFE
    call _WhisperMain

_NtQueryTimer:
    push 0x195ADA00
    call _WhisperMain

_NtFsControlFile:
    push 0x1CBA4F8C
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0xC749CDDB
    call _WhisperMain

_NtCloseObjectAuditAlarm:
    push 0x1091F08C
    call _WhisperMain

_NtDuplicateObject:
    push 0xA880439C
    call _WhisperMain

_NtQueryAttributesFile:
    push 0xE6DC31EF
    call _WhisperMain

_NtClearEvent:
    push 0x2E85D502
    call _WhisperMain

_NtReadVirtualMemory:
    push 0x0F93E2F4
    call _WhisperMain

_NtOpenEvent:
    push 0xD1BBD22C
    call _WhisperMain

_NtAdjustPrivilegesToken:
    push 0xF5C0E760
    call _WhisperMain

_NtDuplicateToken:
    push 0x07910B08
    call _WhisperMain

_NtContinue:
    push 0x02A6734A
    call _WhisperMain

_NtQueryDefaultUILanguage:
    push 0xFFCC61F5
    call _WhisperMain

_NtQueueApcThread:
    push 0xEB4C665D
    call _WhisperMain

_NtYieldExecution:
    push 0x089F2A0F
    call _WhisperMain

_NtAddAtom:
    push 0xB721B2CB
    call _WhisperMain

_NtCreateEvent:
    push 0x0A09099E
    call _WhisperMain

_NtQueryVolumeInformationFile:
    push 0xF4A4FA30
    call _WhisperMain

_NtCreateSection:
    push 0x38EE5A3F
    call _WhisperMain

_NtFlushBuffersFile:
    push 0x6979F640
    call _WhisperMain

_NtApphelpCacheControl:
    push 0x7DE25571
    call _WhisperMain

_NtCreateProcessEx:
    push 0xB198C362
    call _WhisperMain

_NtCreateThread:
    push 0x8C91B60F
    call _WhisperMain

_NtIsProcessInJob:
    push 0x79C2697F
    call _WhisperMain

_NtProtectVirtualMemory:
    push 0x1F81091F
    call _WhisperMain

_NtQuerySection:
    push 0x0F582D95
    call _WhisperMain

_NtResumeThread:
    push 0x8A13C4B9
    call _WhisperMain

_NtTerminateThread:
    push 0xCE6B8849
    call _WhisperMain

_NtReadRequestData:
    push 0x18B5020E
    call _WhisperMain

_NtCreateFile:
    push 0x1D7CF73B
    call _WhisperMain

_NtQueryEvent:
    push 0xC850CDE6
    call _WhisperMain

_NtWriteRequestData:
    push 0x64DE9348
    call _WhisperMain

_NtOpenDirectoryObject:
    push 0x1CB0CDFD
    call _WhisperMain

_NtAccessCheckByTypeAndAuditAlarm:
    push 0x9A527C02
    call _WhisperMain

_NtWaitForMultipleObjects:
    push 0xA12CABB5
    call _WhisperMain

_NtSetInformationObject:
    push 0xBA968629
    call _WhisperMain

_NtCancelIoFile:
    push 0x7CEB7240
    call _WhisperMain

_NtTraceEvent:
    push 0xF4AACF0D
    call _WhisperMain

_NtPowerInformation:
    push 0x64826E27
    call _WhisperMain

_NtSetValueKey:
    push 0x991F9880
    call _WhisperMain

_NtCancelTimer:
    push 0x7FE47178
    call _WhisperMain

_NtSetTimer:
    push 0x25A31D26
    call _WhisperMain

_NtAccessCheckByType:
    push 0x9CFB40CC
    call _WhisperMain

_NtAccessCheckByTypeResultList:
    push 0xFEA205AA
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarm:
    push 0xD295F4C0
    call _WhisperMain

_NtAccessCheckByTypeResultListAndAuditAlarmByHandle:
    push 0x9F33ADAA
    call _WhisperMain

_NtAcquireProcessActivityReference:
    push 0xEF5B7866
    call _WhisperMain

_NtAddAtomEx:
    push 0x09EB792C
    call _WhisperMain

_NtAddBootEntry:
    push 0x0D801510
    call _WhisperMain

_NtAddDriverEntry:
    push 0x0F96130A
    call _WhisperMain

_NtAdjustGroupsToken:
    push 0x079B0B0A
    call _WhisperMain

_NtAdjustTokenClaimsAndDeviceGroups:
    push 0x3FE51ABD
    call _WhisperMain

_NtAlertResumeThread:
    push 0xAE84A83E
    call _WhisperMain

_NtAlertThread:
    push 0x120D5CA7
    call _WhisperMain

_NtAlertThreadByThreadId:
    push 0xB32F1E2F
    call _WhisperMain

_NtAllocateLocallyUniqueId:
    push 0x0D9D5D20
    call _WhisperMain

_NtAllocateReserveObject:
    push 0x0C5638ED
    call _WhisperMain

_NtAllocateUserPhysicalPages:
    push 0x0B1D70EA
    call _WhisperMain

_NtAllocateUuids:
    push 0xFC4B0A01
    call _WhisperMain

_NtAllocateVirtualMemoryEx:
    push 0x9C9DC64F
    call _WhisperMain

_NtAlpcAcceptConnectPort:
    push 0x7EB57F38
    call _WhisperMain

_NtAlpcCancelMessage:
    push 0x0D93C13A
    call _WhisperMain

_NtAlpcConnectPort:
    push 0x24B6391C
    call _WhisperMain

_NtAlpcConnectPortEx:
    push 0x65A4531B
    call _WhisperMain

_NtAlpcCreatePort:
    push 0x26B72025
    call _WhisperMain

_NtAlpcCreatePortSection:
    push 0x0A96323D
    call _WhisperMain

_NtAlpcCreateResourceReserve:
    push 0x3E933BF9
    call _WhisperMain

_NtAlpcCreateSectionView:
    push 0x66B80343
    call _WhisperMain

_NtAlpcCreateSecurityContext:
    push 0xD5492841
    call _WhisperMain

_NtAlpcDeletePortSection:
    push 0xE8CF01D4
    call _WhisperMain

_NtAlpcDeleteResourceReserve:
    push 0x8F3F87CC
    call _WhisperMain

_NtAlpcDeleteSectionView:
    push 0x6EF16D6B
    call _WhisperMain

_NtAlpcDeleteSecurityContext:
    push 0xCE562D06
    call _WhisperMain

_NtAlpcDisconnectPort:
    push 0x24B2311C
    call _WhisperMain

_NtAlpcImpersonateClientContainerOfPort:
    push 0x60F04D6E
    call _WhisperMain

_NtAlpcImpersonateClientOfPort:
    push 0xAC48D9D6
    call _WhisperMain

_NtAlpcOpenSenderProcess:
    push 0xD7B7D605
    call _WhisperMain

_NtAlpcOpenSenderThread:
    push 0x3561C534
    call _WhisperMain

_NtAlpcQueryInformation:
    push 0x34AA17FB
    call _WhisperMain

_NtAlpcQueryInformationMessage:
    push 0x98394519
    call _WhisperMain

_NtAlpcRevokeSecurityContext:
    push 0x16CA12BA
    call _WhisperMain

_NtAlpcSendWaitReceivePort:
    push 0x22B01F1E
    call _WhisperMain

_NtAlpcSetInformation:
    push 0x160F149F
    call _WhisperMain

_NtAreMappedFilesTheSame:
    push 0xE10AD282
    call _WhisperMain

_NtAssignProcessToJobObject:
    push 0x16A93E35
    call _WhisperMain

_NtAssociateWaitCompletionPacket:
    push 0x793C7FAE
    call _WhisperMain

_NtCallEnclave:
    push 0xD7B0F77B
    call _WhisperMain

_NtCancelIoFileEx:
    push 0x00AAC2F0
    call _WhisperMain

_NtCancelSynchronousIoFile:
    push 0xCA5BC2EC
    call _WhisperMain

_NtCancelTimer2:
    push 0x079BE74D
    call _WhisperMain

_NtCancelWaitCompletionPacket:
    push 0xB9BAC176
    call _WhisperMain

_NtCommitComplete:
    push 0x267BE1D1
    call _WhisperMain

_NtCommitEnlistment:
    push 0x9FC2A676
    call _WhisperMain

_NtCommitRegistryTransaction:
    push 0x980C9A99
    call _WhisperMain

_NtCommitTransaction:
    push 0x9C079AAF
    call _WhisperMain

_NtCompactKeys:
    push 0x57E6BAB8
    call _WhisperMain

_NtCompareObjects:
    push 0x871A919F
    call _WhisperMain

_NtCompareSigningLevels:
    push 0x48CA485E
    call _WhisperMain

_NtCompareTokens:
    push 0x04956A4C
    call _WhisperMain

_NtCompleteConnectPort:
    push 0x54B54538
    call _WhisperMain

_NtCompressKey:
    push 0x67DB5062
    call _WhisperMain

_NtConnectPort:
    push 0x5C0F439C
    call _WhisperMain

_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter:
    push 0x03DA2D47
    call _WhisperMain

_NtCreateDebugObject:
    push 0x8E34AEA8
    call _WhisperMain

_NtCreateDirectoryObject:
    push 0x84B7BCFB
    call _WhisperMain

_NtCreateDirectoryObjectEx:
    push 0xB24DF2F4
    call _WhisperMain

_NtCreateEnclave:
    push 0x5E3BB548
    call _WhisperMain

_NtCreateEnlistment:
    push 0x086017F3
    call _WhisperMain

_NtCreateEventPair:
    push 0x2B3421AB
    call _WhisperMain

_NtCreateIRTimer:
    push 0x9D1E8B9A
    call _WhisperMain

_NtCreateIoCompletion:
    push 0x18161881
    call _WhisperMain

_NtCreateJobObject:
    push 0x8AB1822D
    call _WhisperMain

_NtCreateJobSet:
    push 0xB4BDF26F
    call _WhisperMain

_NtCreateKeyTransacted:
    push 0x102C5800
    call _WhisperMain

_NtCreateKeyedEvent:
    push 0x8AB5CB61
    call _WhisperMain

_NtCreateLowBoxToken:
    push 0x35883F2C
    call _WhisperMain

_NtCreateMailslotFile:
    push 0x7D3DB699
    call _WhisperMain

_NtCreateMutant:
    push 0xB2B4D0A2
    call _WhisperMain

_NtCreateNamedPipeFile:
    push 0x66C0B87B
    call _WhisperMain

_NtCreatePagingFile:
    push 0x94850EA2
    call _WhisperMain

_NtCreatePartition:
    push 0xDA83D813
    call _WhisperMain

_NtCreatePort:
    push 0x21B33C3B
    call _WhisperMain

_NtCreatePrivateNamespace:
    push 0x2E905103
    call _WhisperMain

_NtCreateProcess:
    push 0x952A98B2
    call _WhisperMain

_NtCreateProfile:
    push 0x861D8E7E
    call _WhisperMain

_NtCreateProfileEx:
    push 0x8863C4A7
    call _WhisperMain

_NtCreateRegistryTransaction:
    push 0x1E58C114
    call _WhisperMain

_NtCreateResourceManager:
    push 0x83A9178C
    call _WhisperMain

_NtCreateSemaphore:
    push 0x124CCF74
    call _WhisperMain

_NtCreateSymbolicLinkObject:
    push 0x3A940429
    call _WhisperMain

_NtCreateThreadEx:
    push 0x9C9FDC26
    call _WhisperMain

_NtCreateTimer:
    push 0x0FB8E5C0
    call _WhisperMain

_NtCreateTimer2:
    push 0xCFB70F29
    call _WhisperMain

_NtCreateToken:
    push 0x07A29182
    call _WhisperMain

_NtCreateTokenEx:
    push 0x242F6E9C
    call _WhisperMain

_NtCreateTransaction:
    push 0xCCA8B07B
    call _WhisperMain

_NtCreateTransactionManager:
    push 0x8A349C97
    call _WhisperMain

_NtCreateUserProcess:
    push 0xE5392C64
    call _WhisperMain

_NtCreateWaitCompletionPacket:
    push 0x1B3D63B1
    call _WhisperMain

_NtCreateWaitablePort:
    push 0x24BD0B2E
    call _WhisperMain

_NtCreateWnfStateName:
    push 0x2CCD054F
    call _WhisperMain

_NtCreateWorkerFactory:
    push 0x4094085A
    call _WhisperMain

_NtDebugActiveProcess:
    push 0x862C964F
    call _WhisperMain

_NtDebugContinue:
    push 0x4CC093E4
    call _WhisperMain

_NtDeleteAtom:
    push 0x7EEB3332
    call _WhisperMain

_NtDeleteBootEntry:
    push 0x0D800D08
    call _WhisperMain

_NtDeleteDriverEntry:
    push 0x0B963124
    call _WhisperMain

_NtDeleteFile:
    push 0xB6B82682
    call _WhisperMain

_NtDeleteKey:
    push 0x3B8E5A76
    call _WhisperMain

_NtDeleteObjectAuditAlarm:
    push 0xD15435C5
    call _WhisperMain

_NtDeletePrivateNamespace:
    push 0x1CB62325
    call _WhisperMain

_NtDeleteValueKey:
    push 0xB233D3C9
    call _WhisperMain

_NtDeleteWnfStateData:
    push 0x0289E800
    call _WhisperMain

_NtDeleteWnfStateName:
    push 0x349BF1C3
    call _WhisperMain

_NtDisableLastKnownGood:
    push 0xB7872BB0
    call _WhisperMain

_NtDisplayString:
    push 0x069E4C34
    call _WhisperMain

_NtDrawText:
    push 0x3ACD255E
    call _WhisperMain

_NtEnableLastKnownGood:
    push 0x15B68084
    call _WhisperMain

_NtEnumerateBootEntries:
    push 0x0A523BC9
    call _WhisperMain

_NtEnumerateDriverEntries:
    push 0x9C03755F
    call _WhisperMain

_NtEnumerateSystemEnvironmentValuesEx:
    push 0xB1A4F558
    call _WhisperMain

_NtEnumerateTransactionObject:
    push 0x163EC165
    call _WhisperMain

_NtExtendSection:
    push 0x128C3815
    call _WhisperMain

_NtFilterBootOption:
    push 0x32AA0A27
    call _WhisperMain

_NtFilterToken:
    push 0x39917F3A
    call _WhisperMain

_NtFilterTokenEx:
    push 0xC6A919EF
    call _WhisperMain

_NtFlushBuffersFileEx:
    push 0xEB39DD86
    call _WhisperMain

_NtFlushInstallUILanguage:
    push 0xF097F70B
    call _WhisperMain

_NtFlushInstructionCache:
    push 0x2E3BD02B
    call _WhisperMain

_NtFlushKey:
    push 0x7BE1425E
    call _WhisperMain

_NtFlushProcessWriteBuffers:
    push 0x8A930B85
    call _WhisperMain

_NtFlushVirtualMemory:
    push 0x0F99213F
    call _WhisperMain

_NtFlushWriteBuffer:
    push 0x411C5587
    call _WhisperMain

_NtFreeUserPhysicalPages:
    push 0x19B1E0DB
    call _WhisperMain

_NtFreezeRegistry:
    push 0x4763C063
    call _WhisperMain

_NtFreezeTransactions:
    push 0x0B9914F3
    call _WhisperMain

_NtGetCachedSigningLevel:
    push 0x33172392
    call _WhisperMain

_NtGetCompleteWnfStateSubscription:
    push 0xCD4BEDD9
    call _WhisperMain

_NtGetContextThread:
    push 0x309C6235
    call _WhisperMain

_NtGetCurrentProcessorNumber:
    push 0xEE5BC102
    call _WhisperMain

_NtGetCurrentProcessorNumberEx:
    push 0xA7596104
    call _WhisperMain

_NtGetDevicePowerState:
    push 0xB2296868
    call _WhisperMain

_NtGetMUIRegistryInfo:
    push 0xA6B15DF8
    call _WhisperMain

_NtGetNextProcess:
    push 0xDF853DE9
    call _WhisperMain

_NtGetNextThread:
    push 0xA892F42A
    call _WhisperMain

_NtGetNlsSectionPtr:
    push 0xE697D758
    call _WhisperMain

_NtGetNotificationResourceManager:
    push 0x09BE9396
    call _WhisperMain

_NtGetWriteWatch:
    push 0x12AB2BFA
    call _WhisperMain

_NtImpersonateAnonymousToken:
    push 0x2086F1A5
    call _WhisperMain

_NtImpersonateThread:
    push 0x892F0F0C
    call _WhisperMain

_NtInitializeEnclave:
    push 0x28975004
    call _WhisperMain

_NtInitializeNlsFiles:
    push 0x28904B6E
    call _WhisperMain

_NtInitializeRegistry:
    push 0x069F1A09
    call _WhisperMain

_NtInitiatePowerAction:
    push 0x46C22417
    call _WhisperMain

_NtIsSystemResumeAutomatic:
    push 0xE2601736
    call _WhisperMain

_NtIsUILanguageComitted:
    push 0xDB80003F
    call _WhisperMain

_NtListenPort:
    push 0xC774F4FB
    call _WhisperMain

_NtLoadDriver:
    push 0x5CBF3462
    call _WhisperMain

_NtLoadEnclaveData:
    push 0x9C03CEB2
    call _WhisperMain

_NtLoadHotPatch:
    push 0x70ED3FCA
    call _WhisperMain

_NtLoadKey:
    push 0xB91ED8C6
    call _WhisperMain

_NtLoadKey2:
    push 0x7FA79006
    call _WhisperMain

_NtLoadKeyEx:
    push 0x5BD8ACA7
    call _WhisperMain

_NtLockFile:
    push 0x58C4AA90
    call _WhisperMain

_NtLockProductActivationKeys:
    push 0xE747F8EC
    call _WhisperMain

_NtLockRegistryKey:
    push 0x73C0665C
    call _WhisperMain

_NtLockVirtualMemory:
    push 0x3BAFD23F
    call _WhisperMain

_NtMakePermanentObject:
    push 0xA29ED870
    call _WhisperMain

_NtMakeTemporaryObject:
    push 0x0AD3329F
    call _WhisperMain

_NtManagePartition:
    push 0xC68FC41F
    call _WhisperMain

_NtMapCMFModule:
    push 0x3E981FC6
    call _WhisperMain

_NtMapUserPhysicalPages:
    push 0x059C6C06
    call _WhisperMain

_NtMapViewOfSectionEx:
    push 0x86B4C00A
    call _WhisperMain

_NtModifyBootEntry:
    push 0x1D9B3728
    call _WhisperMain

_NtModifyDriverEntry:
    push 0x01941B16
    call _WhisperMain

_NtNotifyChangeDirectoryFile:
    push 0x94039498
    call _WhisperMain

_NtNotifyChangeDirectoryFileEx:
    push 0x009AA3A1
    call _WhisperMain

_NtNotifyChangeKey:
    push 0x5B5B7EC4
    call _WhisperMain

_NtNotifyChangeMultipleKeys:
    push 0x65FB7192
    call _WhisperMain

_NtNotifyChangeSession:
    push 0xF7A736F5
    call _WhisperMain

_NtOpenEnlistment:
    push 0x7BA1064B
    call _WhisperMain

_NtOpenEventPair:
    push 0xB296D207
    call _WhisperMain

_NtOpenIoCompletion:
    push 0x290F17A4
    call _WhisperMain

_NtOpenJobObject:
    push 0x5E92045F
    call _WhisperMain

_NtOpenKeyEx:
    push 0x51FEB285
    call _WhisperMain

_NtOpenKeyTransacted:
    push 0x177F8C40
    call _WhisperMain

_NtOpenKeyTransactedEx:
    push 0x6B3EAB05
    call _WhisperMain

_NtOpenKeyedEvent:
    push 0xCA810DCA
    call _WhisperMain

_NtOpenMutant:
    push 0xD597B846
    call _WhisperMain

_NtOpenObjectAuditAlarm:
    push 0x0A876C8E
    call _WhisperMain

_NtOpenPartition:
    push 0x064D669F
    call _WhisperMain

_NtOpenPrivateNamespace:
    push 0x34944B0F
    call _WhisperMain

_NtOpenProcessToken:
    push 0x0396888F
    call _WhisperMain

_NtOpenRegistryTransaction:
    push 0x94CE539E
    call _WhisperMain

_NtOpenResourceManager:
    push 0x01B92EE8
    call _WhisperMain

_NtOpenSemaphore:
    push 0x1499E0C8
    call _WhisperMain

_NtOpenSession:
    push 0x9201B08D
    call _WhisperMain

_NtOpenSymbolicLinkObject:
    push 0x069C6031
    call _WhisperMain

_NtOpenThread:
    push 0xAC88A63E
    call _WhisperMain

_NtOpenTimer:
    push 0x87168D8E
    call _WhisperMain

_NtOpenTransaction:
    push 0x1856DDFD
    call _WhisperMain

_NtOpenTransactionManager:
    push 0x8520EFDC
    call _WhisperMain

_NtPlugPlayControl:
    push 0x018E7945
    call _WhisperMain

_NtPrePrepareComplete:
    push 0xF89A1710
    call _WhisperMain

_NtPrePrepareEnlistment:
    push 0xDA5C190A
    call _WhisperMain

_NtPrepareComplete:
    push 0x56B4723A
    call _WhisperMain

_NtPrepareEnlistment:
    push 0xD946EAC1
    call _WhisperMain

_NtPrivilegeCheck:
    push 0x14B7C60A
    call _WhisperMain

_NtPrivilegeObjectAuditAlarm:
    push 0xD4B3EA72
    call _WhisperMain

_NtPrivilegedServiceAuditAlarm:
    push 0x0E890E26
    call _WhisperMain

_NtPropagationComplete:
    push 0x0A9419FA
    call _WhisperMain

_NtPropagationFailed:
    push 0xF257ECEC
    call _WhisperMain

_NtPulseEvent:
    push 0x2094CA02
    call _WhisperMain

_NtQueryAuxiliaryCounterFrequency:
    push 0xB80DDFF2
    call _WhisperMain

_NtQueryBootEntryOrder:
    push 0x1B09F413
    call _WhisperMain

_NtQueryBootOptions:
    push 0x5F905903
    call _WhisperMain

_NtQueryDebugFilterState:
    push 0xE749E829
    call _WhisperMain

_NtQueryDirectoryFileEx:
    push 0xB8A68E18
    call _WhisperMain

_NtQueryDirectoryObject:
    push 0x04A03C15
    call _WhisperMain

_NtQueryDriverEntryOrder:
    push 0xA33C7E6F
    call _WhisperMain

_NtQueryEaFile:
    push 0x623848BF
    call _WhisperMain

_NtQueryFullAttributesFile:
    push 0x52983E0E
    call _WhisperMain

_NtQueryInformationAtom:
    push 0xD33BCABF
    call _WhisperMain

_NtQueryInformationByName:
    push 0x24BA572D
    call _WhisperMain

_NtQueryInformationEnlistment:
    push 0x199F3809
    call _WhisperMain

_NtQueryInformationJobObject:
    push 0xE758ECC7
    call _WhisperMain

_NtQueryInformationPort:
    push 0xAB3AACB1
    call _WhisperMain

_NtQueryInformationResourceManager:
    push 0x4F9F9CC2
    call _WhisperMain

_NtQueryInformationTransaction:
    push 0x168C35D1
    call _WhisperMain

_NtQueryInformationTransactionManager:
    push 0x173773AA
    call _WhisperMain

_NtQueryInformationWorkerFactory:
    push 0x04921BF2
    call _WhisperMain

_NtQueryInstallUILanguage:
    push 0x95B6D48C
    call _WhisperMain

_NtQueryIntervalProfile:
    push 0xC55E33C3
    call _WhisperMain

_NtQueryIoCompletion:
    push 0x82AC61BC
    call _WhisperMain

_NtQueryLicenseValue:
    push 0x0CBE39E6
    call _WhisperMain

_NtQueryMultipleValueKey:
    push 0x5DA55A38
    call _WhisperMain

_NtQueryMutant:
    push 0x1C123F85
    call _WhisperMain

_NtQueryOpenSubKeys:
    push 0x4F324AB8
    call _WhisperMain

_NtQueryOpenSubKeysEx:
    push 0x038AD3D1
    call _WhisperMain

_NtQueryPortInformationProcess:
    push 0x781C9F75
    call _WhisperMain

_NtQueryQuotaInformationFile:
    push 0x6E3634F6
    call _WhisperMain

_NtQuerySecurityAttributesToken:
    push 0x0C187A9D
    call _WhisperMain

_NtQuerySecurityObject:
    push 0x049E2DC3
    call _WhisperMain

_NtQuerySecurityPolicy:
    push 0x953FEADE
    call _WhisperMain

_NtQuerySemaphore:
    push 0x089B7084
    call _WhisperMain

_NtQuerySymbolicLinkObject:
    push 0x76C48FC9
    call _WhisperMain

_NtQuerySystemEnvironmentValue:
    push 0x0E9D710A
    call _WhisperMain

_NtQuerySystemEnvironmentValueEx:
    push 0x8F96BB2A
    call _WhisperMain

_NtQuerySystemInformationEx:
    push 0x0E94B1A3
    call _WhisperMain

_NtQueryTimerResolution:
    push 0x04924441
    call _WhisperMain

_NtQueryWnfStateData:
    push 0x60BB4E74
    call _WhisperMain

_NtQueryWnfStateNameInformation:
    push 0x0E942417
    call _WhisperMain

_NtQueueApcThreadEx:
    push 0x0311C06A
    call _WhisperMain

_NtRaiseException:
    push 0x9F30B7AA
    call _WhisperMain

_NtRaiseHardError:
    push 0x011071FF
    call _WhisperMain

_NtReadOnlyEnlistment:
    push 0xD6BB33D1
    call _WhisperMain

_NtRecoverEnlistment:
    push 0x09874C4D
    call _WhisperMain

_NtRecoverResourceManager:
    push 0xB763E3A6
    call _WhisperMain

_NtRecoverTransactionManager:
    push 0x33A30322
    call _WhisperMain

_NtRegisterProtocolAddressInformation:
    push 0x0C8E2613
    call _WhisperMain

_NtRegisterThreadTerminatePort:
    push 0xFE73C5FC
    call _WhisperMain

_NtReleaseKeyedEvent:
    push 0xF056F5C4
    call _WhisperMain

_NtReleaseWorkerFactoryWorker:
    push 0xF2DAC678
    call _WhisperMain

_NtRemoveIoCompletionEx:
    push 0x00A3406A
    call _WhisperMain

_NtRemoveProcessDebug:
    push 0x10AE0720
    call _WhisperMain

_NtRenameKey:
    push 0x0B3D109C
    call _WhisperMain

_NtRenameTransactionManager:
    push 0x093D2361
    call _WhisperMain

_NtReplaceKey:
    push 0x96D5A368
    call _WhisperMain

_NtReplacePartitionUnit:
    push 0x14BF2816
    call _WhisperMain

_NtReplyWaitReplyPort:
    push 0x2CB52B26
    call _WhisperMain

_NtRequestPort:
    push 0x20B03914
    call _WhisperMain

_NtResetEvent:
    push 0x38A12520
    call _WhisperMain

_NtResetWriteWatch:
    push 0x34A10E32
    call _WhisperMain

_NtRestoreKey:
    push 0x61EB5848
    call _WhisperMain

_NtResumeProcess:
    push 0x5DA2787A
    call _WhisperMain

_NtRevertContainerImpersonation:
    push 0xE649E4D5
    call _WhisperMain

_NtRollbackComplete:
    push 0x28B1B28E
    call _WhisperMain

_NtRollbackEnlistment:
    push 0x57956A3F
    call _WhisperMain

_NtRollbackRegistryTransaction:
    push 0x7FA05362
    call _WhisperMain

_NtRollbackTransaction:
    push 0x18005AAD
    call _WhisperMain

_NtRollforwardTransactionManager:
    push 0x6DB36122
    call _WhisperMain

_NtSaveKey:
    push 0x9BA3FE41
    call _WhisperMain

_NtSaveKeyEx:
    push 0x65E5E2A5
    call _WhisperMain

_NtSaveMergedKeys:
    push 0xEB778898
    call _WhisperMain

_NtSecureConnectPort:
    push 0x60F14762
    call _WhisperMain

_NtSerializeBoot:
    push 0x3EA81C39
    call _WhisperMain

_NtSetBootEntryOrder:
    push 0x17358F1F
    call _WhisperMain

_NtSetBootOptions:
    push 0x0D9B0B13
    call _WhisperMain

_NtSetCachedSigningLevel:
    push 0x2A9AE1C4
    call _WhisperMain

_NtSetCachedSigningLevel2:
    push 0xEEB02921
    call _WhisperMain

_NtSetContextThread:
    push 0x1033CE81
    call _WhisperMain

_NtSetDebugFilterState:
    push 0xF6699EA6
    call _WhisperMain

_NtSetDefaultHardErrorPort:
    push 0x1CA9EFE6
    call _WhisperMain

_NtSetDefaultLocale:
    push 0x3DAFFA8F
    call _WhisperMain

_NtSetDefaultUILanguage:
    push 0x9789EB90
    call _WhisperMain

_NtSetDriverEntryOrder:
    push 0xD008F4D2
    call _WhisperMain

_NtSetEaFile:
    push 0x7CBF1A7C
    call _WhisperMain

_NtSetHighEventPair:
    push 0x8412BAA3
    call _WhisperMain

_NtSetHighWaitLowEventPair:
    push 0x8A12B095
    call _WhisperMain

_NtSetIRTimer:
    push 0x03CB1D48
    call _WhisperMain

_NtSetInformationDebugObject:
    push 0x8E34A6A8
    call _WhisperMain

_NtSetInformationEnlistment:
    push 0x096C0AFB
    call _WhisperMain

_NtSetInformationJobObject:
    push 0x735C8152
    call _WhisperMain

_NtSetInformationKey:
    push 0x938DA431
    call _WhisperMain

_NtSetInformationResourceManager:
    push 0x9F87C14F
    call _WhisperMain

_NtSetInformationSymbolicLink:
    push 0x7CAA5072
    call _WhisperMain

_NtSetInformationToken:
    push 0x21807724
    call _WhisperMain

_NtSetInformationTransaction:
    push 0x9901F9D0
    call _WhisperMain

_NtSetInformationTransactionManager:
    push 0x79209378
    call _WhisperMain

_NtSetInformationVirtualMemory:
    push 0x1F81090F
    call _WhisperMain

_NtSetInformationWorkerFactory:
    push 0x87109F93
    call _WhisperMain

_NtSetIntervalProfile:
    push 0x4AA24C1E
    call _WhisperMain

_NtSetIoCompletion:
    push 0xD44AF519
    call _WhisperMain

_NtSetIoCompletionEx:
    push 0xA1536D06
    call _WhisperMain

_NtSetLdtEntries:
    push 0x86AE7EC6
    call _WhisperMain

_NtSetLowEventPair:
    push 0x30AFACA1
    call _WhisperMain

_NtSetLowWaitHighEventPair:
    push 0x70CD90BB
    call _WhisperMain

_NtSetQuotaInformationFile:
    push 0xEDDEB3EB
    call _WhisperMain

_NtSetSecurityObject:
    push 0xA0BBCC40
    call _WhisperMain

_NtSetSystemEnvironmentValue:
    push 0xC23DEFB4
    call _WhisperMain

_NtSetSystemEnvironmentValueEx:
    push 0x9788A5FC
    call _WhisperMain

_NtSetSystemInformation:
    push 0x54965203
    call _WhisperMain

_NtSetSystemPowerState:
    push 0x62D84854
    call _WhisperMain

_NtSetSystemTime:
    push 0x1241C901
    call _WhisperMain

_NtSetThreadExecutionState:
    push 0xD614A8C0
    call _WhisperMain

_NtSetTimer2:
    push 0x0386ECA7
    call _WhisperMain

_NtSetTimerEx:
    push 0xB886C600
    call _WhisperMain

_NtSetTimerResolution:
    push 0xA731A7A3
    call _WhisperMain

_NtSetUuidSeed:
    push 0xF15D7160
    call _WhisperMain

_NtSetVolumeInformationFile:
    push 0x24B1D2A2
    call _WhisperMain

_NtSetWnfProcessNotificationEvent:
    push 0x802A89B6
    call _WhisperMain

_NtShutdownSystem:
    push 0x149CCDD0
    call _WhisperMain

_NtShutdownWorkerFactory:
    push 0x1C8F0802
    call _WhisperMain

_NtSignalAndWaitForSingleObject:
    push 0x9A2592B9
    call _WhisperMain

_NtSinglePhaseReject:
    push 0xAA859A39
    call _WhisperMain

_NtStartProfile:
    push 0xCC9AFA09
    call _WhisperMain

_NtStopProfile:
    push 0x8139F5AD
    call _WhisperMain

_NtSubscribeWnfStateChange:
    push 0x1CA1E98C
    call _WhisperMain

_NtSuspendProcess:
    push 0xF1A41038
    call _WhisperMain

_NtSuspendThread:
    push 0xB41FBEB9
    call _WhisperMain

_NtSystemDebugControl:
    push 0xCC1BC882
    call _WhisperMain

_NtTerminateEnclave:
    push 0xE2131E80
    call _WhisperMain

_NtTerminateJobObject:
    push 0x369D0215
    call _WhisperMain

_NtTestAlert:
    push 0xD13BD8A7
    call _WhisperMain

_NtThawRegistry:
    push 0xCD5121C2
    call _WhisperMain

_NtThawTransactions:
    push 0x1F8A351D
    call _WhisperMain

_NtTraceControl:
    push 0xF5B7F620
    call _WhisperMain

_NtTranslateFilePath:
    push 0xA60E9A5A
    call _WhisperMain

_NtUmsThreadYield:
    push 0x03A11017
    call _WhisperMain

_NtUnloadDriver:
    push 0x5E973E66
    call _WhisperMain

_NtUnloadKey:
    push 0xE83A0A46
    call _WhisperMain

_NtUnloadKey2:
    push 0xAED262CC
    call _WhisperMain

_NtUnloadKeyEx:
    push 0x7A7C2CA3
    call _WhisperMain

_NtUnlockFile:
    push 0x9A1FF414
    call _WhisperMain

_NtUnlockVirtualMemory:
    push 0xF595E13E
    call _WhisperMain

_NtUnmapViewOfSectionEx:
    push 0x06D5E1AB
    call _WhisperMain

_NtUnsubscribeWnfStateChange:
    push 0xE0BC976C
    call _WhisperMain

_NtUpdateWnfStateData:
    push 0x1086E314
    call _WhisperMain

_NtVdmControl:
    push 0xCB8BE11D
    call _WhisperMain

_NtWaitForAlertByThreadId:
    push 0x7EA34C74
    call _WhisperMain

_NtWaitForDebugEvent:
    push 0xB89844F1
    call _WhisperMain

_NtWaitForKeyedEvent:
    push 0x78A33D72
    call _WhisperMain

_NtWaitForWorkViaWorkerFactory:
    push 0x5E926624
    call _WhisperMain

_NtWaitHighEventPair:
    push 0x16BF362D
    call _WhisperMain

_NtWaitLowEventPair:
    push 0x104C34FD
    call _WhisperMain

_NtAcquireCMFViewOwnership:
    push 0x1ACD7E1A
    call _WhisperMain

_NtCancelDeviceWakeupRequest:
    push 0x0FAA3118
    call _WhisperMain

_NtClearAllSavepointsTransaction:
    push 0xE048E6DD
    call _WhisperMain

_NtClearSavepointTransaction:
    push 0xEACE346E
    call _WhisperMain

_NtRollbackSavepointTransaction:
    push 0x02E60077
    call _WhisperMain

_NtSavepointTransaction:
    push 0xD70CF7DE
    call _WhisperMain

_NtSavepointComplete:
    push 0x48B45638
    call _WhisperMain

_NtCreateSectionEx:
    push 0x12D15A10
    call _WhisperMain

_NtCreateCrossVmEvent:
    push 0xB0E24384
    call _WhisperMain

_NtGetPlugPlayEvent:
    push 0xC853D1DE
    call _WhisperMain

_NtListTransactions:
    push 0x27930B25
    call _WhisperMain

_NtMarshallTransaction:
    push 0x0254DE1F
    call _WhisperMain

_NtPullTransaction:
    push 0xD48FD41D
    call _WhisperMain

_NtReleaseCMFViewOwnership:
    push 0x60A5782E
    call _WhisperMain

_NtWaitForWnfNotifications:
    push 0x75DF6EB9
    call _WhisperMain

_NtStartTm:
    push 0x939E70E3
    call _WhisperMain

_NtSetInformationProcess:
    push 0xEF2CCEB0
    call _WhisperMain

_NtRequestDeviceWakeup:
    push 0x3B993D0E
    call _WhisperMain

_NtRequestWakeupLatency:
    push 0x72966906
    call _WhisperMain

_NtQuerySystemTime:
    push 0xA08736AC
    call _WhisperMain

_NtManageHotPatch:
    push 0x20BEDDAB
    call _WhisperMain

_NtContinueEx:
    push 0x6FED9389
    call _WhisperMain

