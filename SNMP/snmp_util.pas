unit snmp_util;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

type

  {SNMPv2c Message (TSnmpV2Message)
   ├─ Version     : Integer (2)
   ├─ Community   : AnsiString (e.g., 'public')
   └─ PDU
      ├─ PDUType     : Byte (A0..A8)
      ├─ RequestID   : Integer
      ├─ Int0        : Integer (ErrorStatus / nonRepeaters)
      ├─ Int1        : Integer (ErrorIndex / maxRepetitions)
      └─ VarBindList
         ├─ VarBindListPtr : PByte (points to BER SEQUENCE of varbinds)
         └─ VarBindListLen : Integer
            ├─ VarBind 1
            │  ├─ OID   : PByte + Len
            │  └─ Value : PByte + Len
            ├─ VarBind 2
            │  ├─ OID   : PByte + Len
            │  └─ Value : PByte + Len
            └─ ... (remaining VarBinds)}

  PSnmpV2Message = ^TSnmpV2Message;
  TSnmpV2Message = record
    Version        : Byte;
    Community      : AnsiString;
    PDUType        : Byte;
    RequestID      : Integer;
    Int0           : Integer; {ErrorStatus / nonRepeaters  }
    Int1           : Integer; {ErrorIndex  / maxRepetitions}
    VarBindPtr     : PByte; {Points to SEQ Tag of VarBinds}
    VarBindLen     : Integer;
  end;


  {SNMPv3 Message (TSnmpV3Message)                                     {SNMPv3 Encrypted Message (TSnmpV3Message)
   ├─ Version : Integer (3)                                             ├─ Version : Integer (3)
   ├─ Header                                                            ├─ Header
   │  ├─ MsgID : Integer                                                │  ├─ MsgID : Integer
   │  ├─ MsgMaxSize : Integer                                           │  ├─ MsgMaxSize : Integer
   │  ├─ MsgFlags : Byte                                                │  ├─ MsgFlags : Byte
   │  └─ MsgSecurityModel : Integer (Only care for 1 = USM)             │  └─ MsgSecurityModel : Integer
   ├─ Security Parameters (USM)                                         ├─ Security Parameters (USM)
   │  ├─ SecurityEngineID : PByte + Len                                 │  ├─ SecurityEngineID  : PByte + Len
   │  ├─ EngineBoots      : Integer                                     │  ├─ EngineBoots      : Integer
   │  ├─ EngineTime       : Integer                                     │  ├─ EngineTime       : Integer
   │  ├─ SecurityName     : PByte + Len                                 │  ├─ SecurityName      : PByte + Len
   │  ├─ AuthParams       : PByte[12] (HMAC-MD5)                        │  ├─ AuthParams        : PByte[12] (HMAC-MD5)
   │  └─ PrivParams       : PByte[8]  (AES128 salt)                     │  └─ PrivParams        : PByte[8]  (AES128 salt)
   └─ Scoped PDU                                                        └─ Encrypted scoped PDU : Cipher inside Octet String}
      ├─ ScopedPDUType : Byte (A0..A8)
      ├─ RequestID     : Integer
      ├─ Int0          : Integer (error-status / nonRepeaters)
      ├─ Int1          : Integer (error-index / maxRepetitions)
      └─ VarBindList
         ├─ VarBindListPtr : PByte (points to BER SEQUENCE)
         └─ VarBindListLen : Integer
            ├─ VarBind 1
            │  ├─ OID  : PByte + Len
            │  └─ Value: PByte + Len
            ├─ VarBind 2
            │  ├─ OID  : PByte + Len
            │  └─ Value: PByte + Len
            └─ ... (remaining VarBinds)}

  PSnmpV3Message = ^TSnmpV3Message;
  TSnmpV3Message = record
    Version        : Byte;
    //Header
    MsgID          : Integer;
    MsgMaxSize     : Integer;
    MsgFlags       : Byte; {[ x  x  x  x  x  Priv.  Auth.  Reportable]}
    MsgFlagPriv    : Boolean;
    MsgFlagAuth    : Boolean;
    MsgFlagReport  : Boolean;
    MsgSecModel    : Integer; {only care for 1 = USM}
    //Security
    SecEngineID    : PByte;
    SecEngineIDLen : Integer;
    SecEngineBoots : Integer;
    SecEngineTime  : Integer;
    SecName        : PByte;
    SecNameLen     : Integer;
    AuthParams     : PByte; {Len 12 , hmac    }
    PrivParams     : PByte; {Len 8  , aes salt}
    //ScopedPDU
    PDUType        : Byte;
    RequestID      : Integer;
    Int0           : Integer; {ErrorStatus / nonRepeaters  }
    Int1           : Integer; {ErrorIndex  / maxRepetitions}
    VarBindPtr     : PByte; {Points to SEQ Tag of VarBinds}
    VarBindLen     : Integer;
  end;

function BufToHex(p: PByte; len: Integer): string;
function ReadBERLength(var p: PByte): Integer;
function ReadBERInt(var p: PByte; Len: Integer): Int64;
function ParseSnmpV3Message(const PRecvData: PByte; const RecvLen: Integer; out Msg: TSnmpV3Message): Boolean;
function ParseSnmpV2Message(const PRecvData: PByte; const RecvLen: Integer; out Msg: TSnmpV2Message): Boolean;

implementation

{* Interface *}

function BufToHex(p: PByte; len: Integer): string;
const HexChars: array[0..15] of Char = '0123456789ABCDEF';
var i:Integer;
begin
  Result := '';
  for i := 0 to len-1 do
  begin
    Result := Result + HexChars[(p^ shr 4) and $0F] + HexChars[p^ and $0F] + ' ';
    Inc(p);
  end;
  if Result <> '' then
    SetLength(Result, Length(Result)-1);
end;

function ReadBERLength(var p: PByte): Integer;
var
  lenByte, numBytes, i: Integer;
begin
  lenByte := p^;
  Inc(p);
  if (lenByte and $80) = 0 then
    {Short form, length <= 127}
    Result := lenByte
  else
  begin
    {Long form: bit 8 = 1, bits 0-6 = number of subsequent bytes}
    numBytes := lenByte and $7F;
    Result := 0;
    for i := 0 to numBytes-1 do
    begin
      Result := (Result shl 8) or p^;
      Inc(p);
    end;
  end;
end;

function ReadBERInt(var p: PByte; Len: Integer): Int64;
var
  i: Integer;
  ResultInt: Int64;
begin
  ResultInt := 0;
  for i := 0 to Len - 1 do
  begin
    ResultInt := (ResultInt shl 8) or p^;
    Inc(p);
  end;
  Result := ResultInt;
end;

function ParseSnmpV3Message(const PRecvData: PByte; const RecvLen: Integer; out Msg: TSnmpV3Message): Boolean;
var
  p: PByte;
  len: Integer;
begin
  Result := False;
  FillChar(Msg, SizeOf(Msg), 0);

  if (RecvLen<8) or (PRecvData=nil) then
    Exit;

  //SEQ
  p := PRecvData;
  if p^<>$30 then
    Exit;
  Inc(p);
  ReadBERlength(p);

  //Version
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  if p^<>$03 then
    Exit;
  Msg.Version := $03;
  Inc(p);

  //SEQ (Header Data)
  if p^<>$30 then
    Exit;
  Inc(p);
  ReadBERLength(p);

  //MsgID
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  Msg.MsgID := ReadBERInt(p, len);

  //MsgMaxSize
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  Msg.MsgMaxSize := ReadBERInt(p, len);

  //MsgFlags
  if p^<>$04 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);
  if len <> 1 then
    Exit;
  Msg.MsgFlags      := p^;
  Msg.MsgFlagAuth   := (p^ and $01) <> 0;
  Msg.MsgFlagPriv   := (p^ and $02) <> 0;
  Msg.MsgFlagReport := (p^ and $04) <> 0;
  Inc(p);

  //MsgSecurityModel
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  Msg.MsgSecModel := ReadBERInt(p, len);

  //SecurityParams (BER SEQ inside OCTET STRING)
  if p^<>$04 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);

  //SEQ
  if p^<>$30 then
    Exit;
  Inc(p);
  ReadBERLength(p);

  //EngineID
  if p^<>$04 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);
  Msg.SecEngineID := p;
  Msg.SecEngineIDLen := len;
  Inc(p, len);

  //EngineBoots
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);
  Msg.SecEngineBoots := ReadBERInt(p, len);

  //EngineTime
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);
  Msg.SecEngineTime := ReadBERInt(p, len);

  //SecUserName
  if p^ <> $04 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);
  Msg.SecName := p;
  Msg.SecNameLen := len;
  Inc(p, len);

  //AuthParams
  if p^ <> $04 then Exit;
  Inc(p, 2);
  Msg.AuthParams := p;
  Inc(p, 12);

  //PrivParams
  if p^ <> $04 then Exit;
  Inc(p, 2);
  Msg.PrivParams := p;
  Inc(p, 8);

  //p Points to OCT TAG of Scoped PDU

  Result := True;
end;

function ParseSnmpV2Message(const PRecvData: PByte; const RecvLen: Integer; out Msg: TSnmpV2Message): Boolean;
var
  p: PByte;
  len: Integer;
begin
  Result := False;
  FillChar(Msg, SizeOf(Msg), 0);

  if (RecvLen<8) or (PRecvData=nil) then
    Exit;

  //SEQ
  p := PRecvData;
  if p^<>$30 then
    Exit;
  Inc(p);
  ReadBERlength(p);

  //Version
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  if p^<>$01 then
    Exit;
  Msg.Version := $01;
  Inc(p);

  //Community
  if p^<>$04 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  SetString(Msg.Community, PAnsiChar(p), len);
  Inc(p, len);

  //PDU
  if (p^ < $A0) or (p^ > $A8) then
    Exit;
  Msg.PDUType := p^;
  Inc(p);
  ReadBERlength(p);

  //RequestID
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  Msg.RequestID := ReadBERint(p, len);

  //Int0
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  Msg.Int0 := ReadBERint(p, len);

  //Int1
  if p^<>$02 then
    Exit;
  Inc(p);
  len := ReadBERlength(p);
  Msg.Int1 := ReadBERint(p, len);

  //SEQ (VarBind)
  if p^<>$30 then
    Exit;
  Msg.VarBindPtr := p;

  Result := true;
end;

end.

