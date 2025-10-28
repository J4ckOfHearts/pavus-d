unit udp_daemon;

{$mode ObjFPC}{$H+}

interface

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils,
  blcksock, synsock;

const
  UDP_RECV_BUF_SIZE = 8192; {8192b = 8kb}

type
  TUDPReceiveEvent = procedure(const RecvData: PByte; const RecvLen: Integer; const RespData: PByte; const FromIP: string; FromPort: Word) of object;

  TUDPDaemon = class(TThread)

  private
    FSocket    : TUDPBlockSocket;
    FPort      : Word;
    FOnReceive : TUDPReceiveEvent;
    FClosed    : Boolean;

    FRespBuf   : PByte;
    FRecvBuf   : PByte;
    FMibBuf    : PByte;

  protected
    procedure Execute; override;

  public
    constructor Create(Port: Word; CreateSuspended: Boolean = False; const RespBuf: PByte = nil; const RecvBuf: PByte = nil; const MibBuf: PByte = nil);
    destructor Destroy; override;

    procedure StopAndWait;
    procedure SendTo(const Data: PByte; const DataLen: Integer; const Host: string; Port: Word);
    property  OnReceive: TUDPReceiveEvent read FOnReceive write FOnReceive;
  end;

implementation

(* TUDPDaemon *)

constructor TUDPDaemon.Create(Port: Word; CreateSuspended: Boolean = False; const RespBuf: PByte = nil; const RecvBuf: PByte = nil;  const MibBuf: PByte = nil);
begin
  inherited Create(True);
  FreeOnTerminate := False; {we need to clean up Object after it terminated, so don't allow immediate free}
  FRespBuf := RespBuf;
  FRecvBuf := RecvBuf;
  FMibBuf  := MibBuf;
  FPort := Port;
  FSocket := TUDPBlockSocket.Create;
  FSocket.CreateSocket;
  FSocket.Bind('0.0.0.0', IntToStr(Port));
  if not CreateSuspended then
    Start;
end;

destructor TUDPDaemon.Destroy;
begin
  StopAndWait;
  FreeAndNil(FSocket);
  inherited Destroy;
end;

procedure TUDPDaemon.Execute;
var
  DataStr: RawByteString;
  FromIP: string;
  FromPort: Integer;
begin
  WriteLn('[+] TUDPDaemon is now running on port '+IntToStr(FPort));
  while not Terminated do
  begin
    if FSocket.CanRead(100) then
    begin
      DataStr := FSocket.RecvPacket(UDP_RECV_BUF_SIZE);
      if FSocket.LastError = 0 then
      begin
        FromIP := FSocket.GetRemoteSinIP;
        FromPort := FSocket.GetRemoteSinPort;
        if Length(DataStr) > 0 then
          Move(DataStr[1], FRecvBuf, Length(DataStr));
        if Assigned(FOnReceive) then
          try
            FOnReceive(FRecvBuf, Length(DataStr), FRespBuf, FromIP, FromPort);
          except
            {ignore user exceptions}
          end;
      end;
    end;
  end;
  FClosed := True;
end;

procedure TUDPDaemon.StopAndWait;
begin
  if Terminated then Exit;
  Terminate;
  FSocket.CloseSocket;
  while not FClosed do Sleep(10);
end;

procedure TUDPDaemon.SendTo(const Data: PByte; const DataLen: Integer; const Host: string; Port: Word);
begin
  if DataLen <= 0 then Exit;
  FSocket.Connect(Host, IntToStr(Port));
  FSocket.SendBufferTo(Data, DataLen);
end;

end.

