program pavusd;

{$mode objfpc}{$H+}
                             
uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils,
  udp_daemon, snmp_handler, md5_hmac, aes128_cipher, snmp_util;

const
  SNMP_MAIN_PORT  = 161;
  SNMP_SIDE_PORT  = 162;
  BUFFER_SEND_SIZE = 12288; {12288b = 12kb}
  BUFFER_RECV_SIZE = 8192 ; {8192b  = 8 kb}
  BUFFER_MIB_SIZE  = 4096 ; {4096b  = 4 kb}

type
  TServer = class
    UDPDaemon : TUDPDaemon;
    procedure OnRecv(RecvData: PByte; const RecvLen: Integer; RespData: PByte; MibData: PByte; const FromIP: string; FromPort: Word);
  end;

(* TServer *)

procedure TServer.OnRecv(RecvData: PByte; const RecvLen: Integer; RespData: PByte; MibData: PByte; const FromIP: string; FromPort: Word);
var
  RespLen: Integer;
  SendStart: PByte;
begin

  {Log Connection}
  WriteLn('[*] Got ', RecvLen, ' bytes from ', FromIP, ':', FromPort);

  {Handle Message}
  RespLen := handleRequest(RecvData, RecvLen, RespData, MibData, SendStart);

  if (RespLen>0) then
  begin
    {We have handled a v2/v3 packet and want to reply}
    FillChar(RecvData^, BUFFER_RECV_SIZE*2, 0);
    {Send response}
    UDPDaemon.SendTo(SendStart, RespLen, FromIP, FromPort);
    FillChar(RespData^, BUFFER_SEND_SIZE*2, 0);
  end else
  begin
    {We drop the packet and dont respond}
    FillChar(RecvData^, BUFFER_RECV_SIZE*2, 0);
    FillChar(RespData^, BUFFER_SEND_SIZE*2, 0);
    WriteLn('[-] Dropping packet of ', RecvLen, ' bytes from ', FromIP, ':', FromPort);
  end;

end;

(* Main *)

var

  ReusableBuffer, RespBuf, RecvBuf, MibBuf : PByte;

  Server                   : TServer;
  inp                      : String;

procedure doTests();
var
  // Test Crypt
  Request, EngineID: TBytes;
  PrivParams, localAESKey: TBytes;
  Encrypt, Decrypt: TBytes;
  Hmac: TMD5HMAC;
  AW, PW: string;
  i, etime, eboots: Integer;
  //
begin

  // Test HMAC

  AW := 'authpass';
  EngineID := TEncoding.UTF8.GetBytes('engine-123');
  Request  := TEncoding.UTF8.GetBytes('This is a test SNMP packet.');

  Write('AW      :  ');
  for i := 0 to Length(TEncoding.UTF8.GetBytes(AW))-1 do
    Write(IntToHex(TEncoding.UTF8.GetBytes(AW)[i], 2),' ');
  Writeln;

  Write('engineID:  ');
  for i := 0 to Length(EngineID)-1 do
    Write(IntToHex(EngineID[i], 2),' ');
  Writeln;

  Write('Request :  ');
  for i := 0 to Length(Request)-1 do
    Write(IntToHex(Request[i], 2),' ');
  Writeln;
  WriteLn;

  Hmac := computeMD5Hmac(@Request[0], Length(Request), @TEncoding.UTF8.GetBytes(AW)[0], @EngineID[0]);

  Writeln('HMAC-MD5 (12 bytes, hex):');
  for i := 0 to Length(Hmac)-1 do
    Write(IntToHex(Hmac[i], 2),' ');
    {Expected: D9 40 E7 CD 16 30 72 10 B9 DF EE A0}
  Writeln;
  WriteLn;

  // Test AES-localize-key

  PW := 'privpass';
  setlength(PrivParams, 8);
  PrivParams[0] := $0; PrivParams[1] := $1; PrivParams[2] := $2; PrivParams[3] := $3;
  PrivParams[4] := $4; PrivParams[5] := $5; PrivParams[6] := $6; PrivParams[7] := $7;

  Write('PW      :  ');
  for i := 0 to Length(TEncoding.UTF8.GetBytes(PW))-1 do
    Write(IntToHex(TEncoding.UTF8.GetBytes(PW)[i], 2),' ');
  Writeln;

  Write('PrivP   :  ');
  for i := 0 to Length(PrivParams)-1 do
    Write(IntToHex(PrivParams[i], 2),' ');
  Writeln;
  WriteLn;

  localAESKey := localizeAES128Key(@TEncoding.UTF8.GetBytes(PW)[0], @EngineID[0]);

  Writeln('AES localized key:');
  for i := 0 to Length(localAESKey)-1 do
    Write(IntToHex(localAESKey[i], 2),' ');
    {Expected: 55 CE 1A 90 73 1B 25 2F D5 25 A3 E1 FC 94 CB 7A}
  Writeln;
  WriteLn;

  // Test AES crypt

  etime := 0;
  eboots := 0;

  setLength(Encrypt, length(Request));
  encryptAES128(localAESKey, eboots, etime, @PrivParams[0], @Request[0], Length(Request), @Encrypt[0]);

  Writeln('AES encrypted:');
  for i := 0 to Length(Encrypt)-1 do
    Write(IntToHex(Encrypt[i], 2),' ');
    {Expected: 3D D6 74 C2 80 2E 41 23 7F 60 F0 FD E7 9A 8A F2 6D B2 3B 6A C9 23 E6 F9 F1 9A E2}
  Writeln;
  WriteLn;

  setLength(Decrypt, length(Request));
  decryptAES128(localAESKey, eboots, etime, @PrivParams[0], @Request[0], Length(Request), @Decrypt[0]);

  Writeln('AES decrypted:');
  for i := 0 to Length(Decrypt)-1 do
    Write(IntToHex(Decrypt[i], 2),' ');
    {Expected: 3D D6 74 C2 80 2E 41 23 7F 60 F0 FD E7 9A 8A F2 F5 AB 15 EA F3 2A 9A 7A 7C 0C 71}
  Writeln;
  WriteLn;

  // Test ...

  ReadLn();
  halt();
end;

begin
  //doTests();

  {__________
  |          |  <- RespBuf
  |  OUT     |
  | (12kb)   |
  |----------|
  |          |
  |  OUT-x   |
  | (12kb)   |
  |----------|  <- RecvBuf
  |  IN-x    |
  | (8kb)    |
  |----------|
  |  IN      |
  | (8kb)    |
  |----------|  <- MibBuf
  | MIB (4kb)|
  |__________}

  GetMem(ReusableBuffer, (BUFFER_SEND_SIZE*2)+(BUFFER_RECV_SIZE*2)+BUFFER_MIB_SIZE);
  RespBuf    := ReusableBuffer;
  RecvBuf    := ReusableBuffer + (BUFFER_SEND_SIZE*2);
  MibBuf     := ReusableBuffer + (BUFFER_SEND_SIZE*2) + (BUFFER_RECV_SIZE*2);
  FillChar(RespBuf^, BUFFER_SEND_SIZE*2, 0);
  FillChar(RecvBuf^, BUFFER_RECV_SIZE*2, 0);
  FillChar(MibBuf^ , BUFFER_MIB_SIZE   , 0);

  Server := TServer.Create;
  Server.UDPDaemon := TUDPDaemon.Create(SNMP_MAIN_PORT, true, RespBuf, RecvBuf, MibBuf);
  Server.UDPDaemon.OnReceive := @Server.OnRecv;
  Server.UDPDaemon.Start;

  while True do
  begin
    ReadLn(inp);
    if lowercase(inp)='stop' then
    begin
      Server.UDPDaemon.Terminate;
      Break;
    end;
    sleep(50);
  end;

  Server.Free; {waits for UDPDaemon internally}
end.

