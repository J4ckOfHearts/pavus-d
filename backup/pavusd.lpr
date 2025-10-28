program pavusd;

{$mode objfpc}{$H+}
                             
uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils,
  udp_daemon, snmp_handler;

const
  SNMP_MAIN_PORT = 161;

type
  TServer = class
    UDPDaemon : TUDPDaemon;
    procedure OnRecv(const RecvData: TBytes; const FromIP: string; FromPort: Word);
  end;

(* TServer *)

procedure TServer.OnRecv(const RecvData: TBytes; const FromIP: string; FromPort: Word);
var
  RespData : TBytes;
begin

  WriteLn('[*] Got ', Length(RecvData), ' bytes from ', FromIP, ':', FromPort);

  // Handle Message
  RespData := handleRequest(RecvData);

  // Send Response
  UDPDaemon.SendTo(RespData, FromIP, FromPort);

end;

(* Main *)
var
  Server  : TServer;
  StopRequested : Boolean;

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

begin
  Server := TServer.Create;
  Server.UDPDaemon := TUDPDaemon.Create(SNMP_MAIN_PORT, true);
  Server.UDPDaemon.OnReceive := @Server.OnRecv;
  Server.UDPDaemon.Start;

  StopRequested := False;
  TThread.CreateAnonymousThread(@HandleStdIn).Start;

  while not StopRequested do
    Sleep(50);

  Server.Free; {waits for UDPDaemon internally}
end.

