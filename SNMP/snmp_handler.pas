unit snmp_handler;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  snmp_util, aes128_cipher, md5_hmac;

{Returns the length of content written to RespData-Buffer}
function handleRequest(const RecvData: PByte; const RecvLen: Integer; RespData: PByte; const MibData: PByte; out SendStart:PByte): Integer;

implementation

(* Local *)

const
  BUFFER_SEND_SIZE = 12288; {12288b = 12kb}
  BUFFER_RECV_SIZE = 8192 ; {8192b  = 8 kb}
  BUFFER_MIB_SIZE  = 4096 ; {4096b  = 4 kb}

function craftV3TimeSyncReport(EndOfReplyBuf: PByte; RecvData: PByte; RecvDataLen: Integer; v3Msg: TSnmpV3Message; out SendStart: PByte): Integer;
const
  ex12Zero: Array[0..11] of Byte
    = ($0,$0,$0,$0,$0,$0,$0,$0,$0,$0,$0,$0);
  exAuthPass: Array[0..5] of Byte
    = (Ord('a'),Ord('w'),Ord('a'),Ord('w'),Ord('a'),Ord('w'));
  exEngineID: Array[0..4] of Byte
    = ($FF,$69,$69,$69,$FF);
var
  recvHmac: TMD5HMAC;
  calcHmac: TMD5HMAC;

  p, pAuth: PByte;
  lenVarbind, lenVarBinds, lenScopedPDU, lenSecParams, lenGlobParams, lenMsg : Cardinal;
begin
  move(v3Msg.AuthParams^, recvHmac[0], 12);
  fillchar(v3Msg.AuthParams^, 12, 0);
  calcHmac := computeMD5Hmac(RecvData, RecvDataLen, exAuthPass, exEngineID);
  if not comparemem(@recvHmac[0], @calcHmac[0], 12) then
  begin
    Result := -1;
    Exit;
  end;

  p := EndOfReplyBuf;
  lenVarbind   := 0;
  lenVarBinds  := 0;
  lenScopedPDU := 0;
  lenSecParams := 0;
  lenGlobParams:= 0;
  lenMsg       := 0;

  lenVarbind    += WriteBERIntRev(p, 1);
  lenVarbind    += WriteBEROidRev(p, [1,3,6,1,6,3,15,1,1,2,0]);
  lenVarbind    += WriteBERTagRev(p, $30, lenVarbind);          {varbind0}
  lenVarBinds   += lenVarBind;

  lenScopedPDU  += WriteBERTagRev(p, $30, lenVarbinds)+lenVarBinds;         {varbinds}

  lenScopedPDU  += WriteBERIntRev(p, 0);                        {error-index}
  lenScopedPDU  += WriteBERIntRev(p, 0);                        {error-status}
  lenScopedPDU  += WriteBERIntRev(p, v3Msg.RequestID);          {request-id}
  lenScopedPDU  += WriteBERTagRev(p, $A8, lenScopedPDU);        {report-pdu}

  lenScopedPDU  += WriteBEROctRev(p, nil, 0);                   {context-name}
  lenScopedPDU  += WriteBEROctRev(p, nil, 0);                   {context-EngineID}
  lenScopedPDU  += WriteBERTagRev(p, $30, lenScopedPDU);        {scoped-pdu}

  lenSecParams  += WriteBEROctRev(p, nil, 0);                  {priv}
  pAuth := p-11;
  lenSecParams  += WriteBEROctRev(p, @ex12Zero[0], 12);        {auth}
  lenSecParams  += WriteBEROctRev(p, v3Msg.SecName, v3Msg.SecNameLen);  {userName}
  lenSecParams  += WriteBERIntRev(p, 2);                       {!time}
  lenSecParams  += WriteBERIntRev(p, 2);                       {!boots}
  lenSecParams  += WriteBEROctRev(p, @exEngineID[0], 5);       {engineID}
  lenSecParams  += WriteBERTagRev(p, $30, lenSecParams);
  lenSecParams  += WriteBERTagRev(p, $04, lenSecParams);

  lenGlobParams += WriteBERIntRev(p, 3);                       {msgSecModel}
  lenGlobParams += WriteBEROctRev(p, @[$05][0], 1);            {msgFlags}
  lenGlobParams += WriteBERIntRev(p, 65535);                   {msgMaxSize}
  lenGlobParams += WriteBERIntRev(p, v3Msg.MsgID);             {msgID}
  lenGlobParams += WriteBERTagRev(p, $30, lenGlobParams);

  lenMsg        += WriteBERIntRev(p, 3);

  lenMsg += lenGlobParams + lenSecParams + lenScopedPDU;

  Result := WriteBERTagRev(p, $30, lenMsg) + lenMsg;

  Inc(p);
  SendStart := p;

  {authenticate}
  calcHmac := computeMD5Hmac(p, Result, exAuthPass, exEngineID);
  move(calcHmac[0], pAuth^, 12);

end;

function craftV3DiscoverReport(EndOfReplyBuf: PByte; const v3Msg: TSnmpV3Message;  out SendStart: PByte): Integer;
const
  exEngineID: Array[0..4] of Byte
    = ($FF,$69,$69,$69,$FF);
var
  p  : PByte;
  lenVarbind, lenVarBinds, lenScopedPDU, lenSecParams, lenGlobParams, lenMsg : Cardinal;
begin
  p := EndOfReplyBuf;
  lenVarbind   := 0;
  lenVarBinds  := 0;
  lenScopedPDU := 0;
  lenSecParams := 0;
  lenGlobParams:= 0;
  lenMsg       := 0;

  lenVarbind    += WriteBERIntRev(p, 1);
  lenVarbind    += WriteBEROidRev(p, [1,3,6,1,6,3,15,1,1,4,0]);
  lenVarbind    += WriteBERTagRev(p, $30, lenVarbind);          {varbind0}
  lenVarBinds   += lenVarBind;

  lenScopedPDU  += WriteBERTagRev(p, $30, lenVarbinds)+lenVarBinds;         {varbinds}

  lenScopedPDU  += WriteBERIntRev(p, 0);                        {error-index}
  lenScopedPDU  += WriteBERIntRev(p, 0);                        {error-status}
  lenScopedPDU  += WriteBERIntRev(p, v3Msg.RequestID);          {request-id}
  lenScopedPDU  += WriteBERTagRev(p, $A8, lenScopedPDU);        {report-pdu}

  lenScopedPDU  += WriteBEROctRev(p, nil, 0);                   {context-name}
  lenScopedPDU  += WriteBEROctRev(p, nil, 0);                   {context-EngineID}
  lenScopedPDU  += WriteBERTagRev(p, $30, lenScopedPDU);        {scoped-pdu}

  lenSecParams  += WriteBEROctRev(p, nil, 0);                  {priv}
  lenSecParams  += WriteBEROctRev(p, nil, 0);                  {auth}
  lenSecParams  += WriteBEROctRev(p, nil, 0);                  {userName}
  lenSecParams  += WriteBERIntRev(p, 0);                       {time}
  lenSecParams  += WriteBERIntRev(p, 0);                       {boots}
  lenSecParams  += WriteBEROctRev(p, @exEngineID[0], 5);       {engineID}
  lenSecParams  += WriteBERTagRev(p, $30, lenSecParams);
  lenSecParams  += WriteBERTagRev(p, $04, lenSecParams);

  lenGlobParams += WriteBERIntRev(p, 3);                       {msgSecModel}
  lenGlobParams += WriteBEROctRev(p, @[$04][0], 1);            {msgFlags}
  lenGlobParams += WriteBERIntRev(p, 65535);                   {msgMaxSize}
  lenGlobParams += WriteBERIntRev(p, v3Msg.MsgID);             {msgID}
  lenGlobParams += WriteBERTagRev(p, $30, lenGlobParams);

  lenMsg        += WriteBERIntRev(p, 3);

  lenMsg += lenGlobParams + lenSecParams + lenScopedPDU;

  Result := WriteBERTagRev(p, $30, lenMsg) + lenMsg;

  Inc(p);
  SendStart := p;
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
    WriteLn('[+] Sending discovery report');
    Result := craftV3DiscoverReport(RespData+2*BUFFER_SEND_SIZE, v3Msg, SendStart);
    Exit;
  end;

  {Check if this is a time-sync probe}
  if ((v3Msg.PrivParams=nil) {}) then
  begin
    {Send Report}
    WriteLn('[+] Sending time-sync report');
    Result := craftV3TimeSyncReport(RespData+2*BUFFER_SEND_SIZE, RecvData, RecvLen, v3Msg, SendStart);
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
  decryptAES128(localizeAES128Key(exPrivPass, exEngineID), v3Msg.SecEngineBoots, v3Msg.SecEngineTime, v3Msg.PrivParams, v3Msg.scopedPDUStartPtr, v3Msg.scopedPDULen, RecvDataDec);

  {read scoped PDU and reply accordingly}


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

