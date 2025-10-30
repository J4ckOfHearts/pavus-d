unit snmp_handler;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  snmp_util, aes128_cipher;

{Returns the length of content written to RespData-Buffer}
function handleRequest(const RecvData: PByte; const RecvLen: Integer; RespData: PByte; const MibData: PByte; out SendStart:PByte): Integer;

implementation

(* Local *)

const
  BUFFER_SEND_SIZE = 12288; {12288b = 12kb}
  BUFFER_RECV_SIZE = 8192 ; {8192b  = 8 kb}
  BUFFER_MIB_SIZE  = 4096 ; {4096b  = 4 kb}

function craftV3ProbeReport(EndOfReplyBuf: PByte; out SendStart: PByte): Integer;

begin

end;

function handleV3Request(RecvData: PByte; const RecvLen: Integer; RespData: PByte; MibData: PByte; out SendStart: PByte): Integer;
const
  exAuthPass: Array[0..5] of Byte
    = (Ord('a'),Ord('w'),Ord('a'),Ord('w'),Ord('a'),Ord('w'));
  exPrivPass: Array[0..7] of Byte
    = (Ord('a'),Ord('d'),Ord('m'),Ord('i'),Ord('n'),Ord('k'),Ord('e'),Ord('y'));
  exEngineID: Array[0..4] of Byte
    = ($FF,$69,$69,$69,$FF);
var
  v3Msg : TSnmpV3Message;
  RecvDataDec : PByte;
begin
  WriteLn('[*] Handeling a v3 packet now');
  Result := -1;

  if not ParseSnmpV3Message(RecvData, RecvLen, v3Msg) then
    Exit;

  //check if user is known
  // TODO

  WriteLn('[+] (v:0x',inttohex(v3Msg.Version),' msgID:',v3Msg.MsgID,' msgMaxSize:',v3Msg.MsgMaxSize,' msgFlags:',inttohex(v3Msg.MsgFlags),'[A=',v3Msg.MsgFlagAuth,',P=',v3Msg.MsgFlagPriv,',R=',v3Msg.MsgFlagReport,'] msgSecModel:',v3Msg.MsgSecModel,' engineID:',BufToHex(v3Msg.SecEngineID, v3Msg.SecEngineIDLen),' boots:',v3Msg.SecEngineBoots,' time:', v3Msg.SecEngineTime,' secName:',BufToHex(v3Msg.SecName, v3Msg.SecNameLen),' authParams:',BufToHex(v3Msg.AuthParams, 12),' privParams:', BufToHex(v3Msg.PrivParams, 8),')');

  {Check if this is a discovery probe}
  if ((v3Msg.SecEngineIDLen=0) and (v3Msg.SecEngineID=nil)) then
  begin
    {Send a Report}
    Result := craftV3ProbeReport(RespData+2*BUFFER_SEND_SIZE, SendStart);
    Exit;
  end;

  if v3Msg.MsgFlagAuth then
    if not CheckHmacSnmpV3Message(RecvData, RecvLen, exAuthPass, exEngineID, v3Msg.AuthParams) then
      if v3Msg.MsgFlagReport then
      begin
        //report auth-error
        //TODO
        Exit;
      end else
        Exit; {no report, drop silently}

  if not v3Msg.MsgFlagPriv then
  begin
    {We don't allow Plaintext v3}
    if v3Msg.MsgFlagReport then
    begin
      // report some error TODO

      Exit;
    end else
      Exit; {no report, drop silently}
  end;

  RecvDataDec := RecvData + BUFFER_RECV_SIZE;
  decryptAES128(localizeAES128Key(exPrivPass, exEngineID), 0, 0, v3Msg.PrivParams, RecvData, RecvLen, RecvDataDec);

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

function handleRequest(const RecvData: PByte; const RecvLen: Integer; RespData: PByte; const MibData: PByte;  out SendStart: PByte): Integer;
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
    $03: Result := handleV3Request(RecvData, RecvLen, RespData, MibData, SendStart);
    else Exit;
  end;

end;

end.

