program pavusd;

{$mode objfpc}{$H+}
                             
uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils,
  udp_daemon, snmp_handler, md5_hmac, aes128_cipher;

const
  SNMP_MAIN_PORT  = 161;
  SNMP_SIDE_PORT  = 162;
  BUFFER_MSG_SIZE = 8192; {8192b = 8kb}
  BUFFER_MIB_SIZE = 8192; {8192b = 8kb}

type
  TServer = class
    UDPDaemon : TUDPDaemon;
    procedure OnRecv(const RecvData: PByte; const RecvLen: Integer; const RespData: PByte; const FromIP: string; FromPort: Word);
  end;

(* TServer *)

procedure TServer.OnRecv(const RecvData: PByte; const RecvLen: Integer; const RespData: PByte; const FromIP: string; FromPort: Word);
var
  RespLen: Integer;
begin
  // Log Connection
  WriteLn('[*] Got ', RecvLen, ' bytes from ', FromIP, ':', FromPort);
  // Handle Message
  RespLen := handleRequest(RecvData, RecvLen, RespData);
  // Send Response
  UDPDaemon.SendTo(RespData, RespLen, FromIP, FromPort);
end;

(* Main *)

var
  ReusableBuffer           : PByte;
  RecvBuf, RespBuf, MibBuf : PByte;
  Server                   : TServer;
  StopRequested            : Boolean;

procedure HandleStdIn();
var
  inp : String;
begin
  while True do
  begin
    ReadLn(inp);
    if lowercase(inp)='stop' then
    begin
      Server.UDPDaemon.Terminate;
      StopRequested := True;
      Break;
    end;
  end;
end;

procedure doTests();
var
  Request, EngineID: TBytes;
  Hmac: TMD5HMAC;
  AW: UniCodeString;
  i: Integer;
begin

  // Start Test HMAC

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

  Hmac := computeMD5Hmac(@Request[0], Length(Request), @TEncoding.UTF8.GetBytes(AW)[0], @EngineID[0]);

  Writeln('HMAC-MD5 (12 bytes, hex):');
  for i := 0 to Length(Hmac)-1 do
    Write(IntToHex(Hmac[i], 2),' ');
    {Expected: D9 40 E7 CD 16 30 72 10 B9 DF EE A0}
  Writeln;

  // End Test HMAC

  ReadLn();
  halt();
end;

begin
  doTests();

  GetMem(ReusableBuffer, (BUFFER_MSG_SIZE*2)+BUFFER_MIB_SIZE);
  RespBuf := ReusableBuffer;
  RecvBuf := ReusableBuffer +  BUFFER_MSG_SIZE;
  MibBuf  := ReusableBuffer + (BUFFER_MSG_SIZE*2);

  Server := TServer.Create;
  Server.UDPDaemon := TUDPDaemon.Create(SNMP_MAIN_PORT, true, RespBuf, RecvBuf, MibBuf);
  Server.UDPDaemon.OnReceive := @Server.OnRecv;
  Server.UDPDaemon.Start;

  StopRequested := False;
  TThread.CreateAnonymousThread(@HandleStdIn).Start;

  while not StopRequested do
    Sleep(50);

  Server.Free; {waits for UDPDaemon internally}
end.

