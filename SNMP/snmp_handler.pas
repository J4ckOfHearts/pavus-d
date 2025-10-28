unit snmp_handler;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  snmp_util;

{Returns the length of content written to RespData-Buffer}
function handleRequest(const RecvData: PByte; const RecvLen: Integer; RespData: PByte; const MibData: PByte): Integer;

implementation

(* Local *)

function handleV3Request(const RecvData: PByte; const RecvLen: Integer; RespData: PByte; MibData: PByte): Integer;
var
  v3Msg : TSnmpV3Message;
begin
  WriteLn('[*] Handeling a v3 packet now');
  Result := -1;
  if not ParseSnmpV3Message(RecvData, RecvLen, v3Msg) then
    Exit;
  WriteLn('[+] (v:0x',inttohex(v3Msg.Version),' msgID:',v3Msg.MsgID,' msgMaxSize:',v3Msg.MsgMaxSize,' msgFlags:',inttohex(v3Msg.MsgFlags),'[A=',v3Msg.MsgFlagAuth,',P=',v3Msg.MsgFlagPriv,',R=',v3Msg.MsgFlagReport,'] msgSecModel:',v3Msg.MsgSecModel,' engineID:',BufToHex(v3Msg.SecEngineID, v3Msg.SecEngineIDLen),' boots:',v3Msg.SecEngineBoots,' time:', v3Msg.SecEngineTime,' secName:',BufToHex(v3Msg.SecName, v3Msg.SecNameLen),' authParams:',BufToHex(v3Msg.AuthParams, 12),' privParams:', BufToHex(v3Msg.PrivParams, 8),')');
end;

function handleV2Request(const RecvData: PByte; const RecvLen: Integer; RespData: PByte): Integer;
var
  v2Msg : TSnmpV2Message;
begin
  WriteLn('[*] Handeling a v2 packet now');
  Result := -1;
  if not ParseSnmpV2Message(RecvData, RecvLen, v2Msg) then
    Exit;
  WriteLn('[+] (v:0x',inttohex(v2Msg.Version),' c:',v2Msg.Community,' pdu:0x',inttohex(v2Msg.PDUType),' id:',v2Msg.RequestID,' i0:',v2Msg.Int0,' i1:',v2Msg.Int1,')');
end;

(* Interface *)

function handleRequest(const RecvData: PByte; const RecvLen: Integer; RespData: PByte; const MibData: PByte): Integer;
var
  p: PByte;
begin

  {Neg. Result = no valid v2/v3 snmp message (Drop packet)}
  Result := -1;
  p := RecvData;
  {First Byte must be SEQ <=> 0x30}
  if p^ <> $30 then
    Exit;
  Inc(p);
  {increase p until after len}
  ReadBERLength(p);
  {Integer should be next, expect INT <=> 0x02}
  if p^ <> $02 then
    Exit;
  Inc(p);
  {Length should be next, expect 1}
  if p^ <> $01 then
    Exit;
  Inc(p);
  {Read the Version}
  case p^ of
    {v1=0x00/ v2=0x01 /v3=0x03}
    $01: Result := handleV2Request(RecvData, RecvLen, RespData);
    $03: Result := handleV3Request(RecvData, RecvLen, RespData, MibData);
    else Exit;
  end;

end;

end.

