unit snmp_util;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  md5_hmac, aes128_cipher;

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
    Version           : Byte;
    //Header
    MsgID             : Integer;
    MsgMaxSize        : Integer;
    MsgFlags          : Byte; {[ x  x  x  x  x  Priv.  Auth.  Reportable]}
    MsgFlagPriv       : Boolean;
    MsgFlagAuth       : Boolean;
    MsgFlagReport     : Boolean;
    MsgSecModel       : Integer; {only care for 1 = USM}
    //Security
    SecEngineID       : PByte;
    SecEngineIDLen    : Integer;
    SecEngineBoots    : Integer;
    SecEngineTime     : Integer;
    SecName           : PByte;
    SecNameLen        : Integer;
    AuthParams        : PByte; {Len 12 , hmac    }
    PrivParams        : PByte; {Len 8  , aes salt}
    //ScopedPDU
    scopedPDUStartPtr : PByte;   {start of (encrypted) scoped pdu}
    scopedPDULen      : Integer; {Either Len of OCT or PDU}
  end;

  PSnmpScopedPdu = ^TSnmpScopedPdu;
  TSnmpScopedPdu = record
    ContextEngineID   : PByte;
    ContextEngineIDLen: Integer;
    ContextName       : PByte;
    ContextNameLen    : Integer;
    PDUType           : Byte;
    PDULength         : Integer;
    RequestID         : Integer;
    Int0              : Integer; {ErrorStatus / nonRepeaters  }
    Int1              : Integer; {ErrorIndex  / maxRepetitions}
    VarBindPtr        : PByte; {Points to SEQ Tag of VarBinds}
    VarBindLen        : Integer;
  end;


function  BufToHex(p: PByte; len: Cardinal): string;

function  ReadBERLength(var p: PByte): Cardinal;
function  EncodeBERLength(len: Cardinal): TBytes;
function  ReadBERInt(var p: PByte; Len: Cardinal): Integer;

function  ParseSnmpV3Message(const PRecvData: PByte; const RecvLen: Cardinal; out Msg: TSnmpV3Message): Boolean;
function  ParseSnmpV2Message(const PRecvData: PByte; const RecvLen: Cardinal; out Msg: TSnmpV2Message): Boolean;

procedure InsertHmacSnmpV3Message(PData: PByte; const DataLen: Cardinal; const AuthPass, EngineID: TBytes; PAuthParams: PByte);
function  CheckHmacSnmpV3Message(PData: PByte; const DataLen: Cardinal; const AuthPass, EngineID: TBytes; PAuthParams: PByte): Boolean;

function  WriteBERIntRev(var p: PByte; value: Integer): Cardinal;
function  WriteBEROctRev(var p: PByte; DataPtr: PByte; DataLen: Cardinal): Cardinal;
function  WriteBERTagRev(var p: PByte; Tag: Byte; len: Cardinal): Cardinal;
function  WriteBEROidRev(var p: PByte; oid: Array of Cardinal): Cardinal;

implementation

{* Interface *}

function BufToHex(p: PByte; len: Cardinal): string;
const HexChars: array[0..15] of Char = '0123456789ABCDEF';
var i:Integer;
begin
  Result := '_';
  if (len > 0) and (p<>nil) then
  begin
    for i := 0 to len-1 do
    begin
      Result := Result + HexChars[(p^ shr 4) and $0F] + HexChars[p^ and $0F] + ' ';
      Inc(p);
    end;
    if Result <> '' then
      SetLength(Result, Length(Result)-1);
  end;
end;

function ReadBERLength(var p: PByte): Cardinal;
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

function ReadBERInt(var p: PByte; Len: Cardinal): Integer;
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

function EncodeBERLength(len: Cardinal): TBytes;
var
  tmp: array[0..4] of Byte;
  n, i: Integer;
begin
  if len < 128 then
  begin
    setLength(Result, 1);
    Result[0] := Byte(len);
    Exit;
  end;

  n := 0;
  while len > 0 do
  begin
    tmp[n] := Byte(len and $FF);
    len := len shr 8;
    Inc(n);
  end;

  SetLength(Result, n+1);
  Result[0] := $80 or Byte(n);
  for i := 0 to n-1 do
    Result[i+1] := tmp[n-1-i];
end;

function WriteBERIntRev(var p: PByte; value: Integer): Cardinal;
var
  pEnd: PByte;
  v,i: Integer;
  l  : TBytes;
begin
  pEnd := P;

  if value=0 then
  begin
    p^ := 0;   Dec(p);
    p^ := 1;   Dec(p);
    p^ := $02; Dec(p);
    Result := 3;
    Exit;
  end;

  {value}
  v := value;
  i := 0;
  while v <> 0 do
  begin
    p^ := Byte(v and $FF);
    v := v shr 8;
    Dec(p);
    Inc(i);
  end;
  if ((p+1)^ and $80)<>0 then
  begin
    {prepend 0x00 if HI of first byte is 1 (for psoitive)}
    p^:=0;
    Dec(p);
    Inc(i);
  end;

  {length}
  l := EncodeBERLength(i);
  for i := Length(l)-1 downto 0 do
  begin
    p^ := l[i];
    Dec(p);
  end;

  {tag}
  p^ := $02;
  Dec(p);

  Result := PtrUInt(pEnd) - PtrUInt(p);
end;

function WriteBEROctRev(var p: PByte; DataPtr: PByte; DataLen: Cardinal): Cardinal;
var
  d, pEnd: PByte;
  i:  Integer;
  l:  TBytes;
begin
  pEnd := P;

  if (DataPtr=nil) or (DataLen=0) then
  begin
    p^ := 0;   Dec(p);
    p^ := $04; Dec(p);
    Result := 2;
    Exit;
  end;

  {value}
  d := DataPtr+(DataLen-1);
  for i := DataLen-1 downto 0 do
  begin
    p^ := d^;
    Dec(d);
    Dec(p);
  end;

  {length}
  l := EncodeBERLength(DataLen);
  for i := Length(l)-1 downto 0 do
  begin
    p^ := l[i];
    Dec(p);
  end;

  {tag}
  p^ := $04;
  Dec(p);

  Result := PtrUInt(pEnd) - PtrUInt(p);
end;

function WriteBERTagRev(var p: PByte; Tag: Byte; len: Cardinal): Cardinal;
var
  pEnd: PByte;
  l: TBytes;
  i: Integer;
begin
  pEnd := P;

  if (len=0) then
  begin
    p^ := $0;  Dec(p);
    p^ := Tag; Dec(p);
    Result := 2;
    Exit;
  end;

  {length}
  l := EncodeBERLength(len);
  for i := Length(l)-1 downto 0 do
  begin
    p^ := l[i];
    Dec(p);
  end;

  {tag}
  p^ := Tag;
  Dec(p);

  Result := NativeUInt(pEnd) - NativeUInt(p);
end;

function WriteBEROidRev(var p: PByte; oid: Array of Cardinal): Cardinal;
var
  pEnd: PByte;
  l: TBytes;
  i,n: Integer;
  subid: Cardinal;
begin
  pEnd := P;
  n := 0;

  {value}
  for i := Length(oid)-1 downto 2 do
  begin
    subid := oid[i];
    repeat
      p^ := Byte(subid and $7F);
      Inc(n);
      subid := subid shr 7;
      if subid<>0 then
        p^ := p^ or $80;
      Dec(p);
    until subid=0;
  end;
  {value (first two cardinals)}
  p^ := Byte(oid[0]*40 + oid[1]);
  Inc(n);
  Dec(p);

  {length}
  l := EncodeBERLength(n);
  for i := Length(l)-1 downto 0 do
  begin
    p^ := l[i];
    Dec(p);
  end;

  {tag}
  p^ := $06;
  Dec(p);

  Result := PtrUInt(pEnd) - PtrUInt(p);
end;

function CheckHmacSnmpV3Message(PData: PByte; const DataLen: Cardinal; const AuthPass, EngineID: TBytes; PAuthParams: PByte): Boolean;
var
  recvHmac: TMD5HMAC;
  calcHmac: TMD5HMAC;
begin
  move(PAuthParams^, recvHmac[0], 12);
  fillchar(PAuthParams^, 12, 0);
  calcHmac := computeMD5Hmac(PData, DataLen, AuthPass, EngineID);
  Result := CompareMem(@recvHmac[0], @calcHmac[0], 12);
end;

procedure InsertHmacSnmpV3Message(PData: PByte; const DataLen: Cardinal; const AuthPass, EngineID: TBytes; PAuthParams: PByte);
var
  calcHmac: TMD5HMAC;
begin
  calcHmac := computeMD5Hmac(PData, DataLen, AuthPass, EngineID);
  move(calcHmac[0], PAuthParams^, 12);
end;

function ParseSnmpV3Message(const PRecvData: PByte; const RecvLen: Cardinal; out Msg: TSnmpV3Message): Boolean;
var
  p: PByte;
  len: Cardinal;
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
  if len = 0 then
    Msg.SecEngineID := nil
  else
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
  if p^ <> $04 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);
  if (len=0) then
    Msg.AuthParams := nil
  else
    Msg.AuthParams := p;
  Inc(p, len);

  //PrivParams
  if p^ <> $04 then
    Exit;
  Inc(p);
  len := ReadBERLength(p);
  if (len=0) then
    Msg.PrivParams := nil
  else
    Msg.PrivParams := p;
  Inc(p, len);


  //SEQ or OCT
  if (p^<>$30) and (p^<>$04) then
    Exit;
  if (p^=$30) and (Msg.MsgFlagPriv) then
    Exit;
  if (p^=$04) and (not Msg.MsgFlagPriv) then
    Exit;
  Inc(p);
  len := ReadBERLength(p);

  Msg.scopedPDULen := len;
  Msg.scopedPDUStartPtr := p;

  Result := True;
end;

function ParseSnmpV2Message(const PRecvData: PByte; const RecvLen: Cardinal; out Msg: TSnmpV2Message): Boolean;
var
  p: PByte;
  len: Cardinal;
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

