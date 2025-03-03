
.MODEL flat

.data
AvatarPlayerNameInLobbyArg1 dword ?
AvatarPlayerNameInLobbyArg2 dword ?
AvatarPlayerNameInLobbyEax dword ?
ConnectionTierIconInLobbyEsp dword ?

.code

; these are defined in AttachDetach.cpp, without the initial _
extrn _hookCounter:dword

extrn _lastPing:dword

extrn _pingToConnectionStrength1:dword  ; pointer to function
extrn _orig_LobbyListRememberPing:dword

extrn _LobbyListDrawConnectionTierCall:dword  ; pointer to function
extrn _orig_LobbyListDrawConnectionTier:dword
extrn _printPingFromLobbyList:proc

extrn _PlayerListCall:dword  ; pointer to function
extrn _orig_PlayerList:dword
extrn _printPingFromPlayerList:proc

extrn _PlayerListGetPing:dword  ; pointer to function
extrn _orig_GetConnectionStrength:dword

extrn _rememberAvatarPlayerNameInLobby:proc
extrn _drawTextWithIcons:dword  ; pointer to function
extrn _orig_AvatarName:dword

extrn _drawIcon:dword  ; pointer to function
extrn _orig_ConnectionTierIconInLobby:dword
extrn _printPingFromAvatarInLobby:proc

; AttachDetach.cpp refers to these functions without the initial _

_LobbyListRememberPing proc
	LOCK INC dword ptr[_hookCounter]
	MOV dword ptr[_lastPing],ECX
	CALL [_pingToConnectionStrength1]
	LOCK DEC dword ptr[_hookCounter]
	JMP [_orig_LobbyListRememberPing]
_LobbyListRememberPing endp

_LobbyListDrawConnectionTier proc
	LOCK INC dword ptr[_hookCounter]
	CALL [_LobbyListDrawConnectionTierCall]
	PUSH dword ptr [ESP+2c8h]
	PUSH dword ptr [ESP+2c8h]
	CALL _printPingFromLobbyList
	ADD ESP,8h
	LOCK DEC dword ptr[_hookCounter]
	JMP [_orig_LobbyListDrawConnectionTier]
_LobbyListDrawConnectionTier endp

_PlayerListDrawConnectionTier proc
	LOCK INC dword ptr[_hookCounter]
	CALL [_PlayerListCall]
	PUSH dword ptr [ESP+210h]
	PUSH dword ptr [ESP+210h]
	CALL _printPingFromPlayerList
	ADD ESP,08h
	LOCK DEC dword ptr[_hookCounter]
	JMP [_orig_PlayerList]
_PlayerListDrawConnectionTier endp

_PlayerListGetPingHook proc
	LOCK INC dword ptr[_hookCounter]
	CALL [_PlayerListGetPing]
	MOV dword ptr [_lastPing],EAX
	LOCK DEC dword ptr[_hookCounter]
	JMP [_orig_GetConnectionStrength]
_PlayerListGetPingHook endp

_AvatarPlayerNameInLobby proc
	LOCK INC dword ptr[_hookCounter]
	MOV [AvatarPlayerNameInLobbyArg1],ESI
	MOV [AvatarPlayerNameInLobbyArg2],EDI
	CALL [_drawTextWithIcons]
	MOV [AvatarPlayerNameInLobbyEax],EAX
	PUSH dword ptr[AvatarPlayerNameInLobbyArg2]
	PUSH dword ptr[AvatarPlayerNameInLobbyArg1]
	CALL _rememberAvatarPlayerNameInLobby
	MOV EAX,[AvatarPlayerNameInLobbyEax]
	ADD ESP,08h
	LOCK DEC dword ptr[_hookCounter]
	JMP [_orig_AvatarName]
_AvatarPlayerNameInLobby endp

_ConnectionTierIconInLobby proc
	LOCK INC dword ptr[_hookCounter]
	CALL [_drawIcon]
	PUSH dword ptr[ESP+4h]
	CALL _printPingFromAvatarInLobby
	ADD ESP,4
	LOCK DEC dword ptr[_hookCounter]
	JMP [_orig_ConnectionTierIconInLobby]
_ConnectionTierIconInLobby endp

end
