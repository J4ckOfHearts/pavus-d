unit udp_daemon;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  blcksock, synsock;

const
  UDP_RECV_BUF_SIZE = 8192; {8192b = 8kb}

type
  TUDPReceiveEvent = procedure(const RecvData: TBytes; const FromIP: string; FromPort: Word) of object;

  TUDPDaemon = class(TThread)

  private
    FSocket    : TUDPBlockSocket;
    FPort      : Word;
    FOnReceive : TUDPReceiveEvent;
    FClosed    : Boolean;

  protected
    procedure Execute; override;

  public
    constructor Create(Port: Word; CreateSuspended: Boolean = False);
    destructor Destroy; override;

    procedure StopAndWait;
    procedure SendTo(const Data: TBytes; const Host: string; Port: Word);
    property  OnReceive: TUDPReceiveEvent read FOnReceive write FOnReceive;
  end;

implementation

(* TUDPDaemon *)

constructor TUDPDaemon.Create(Port: Word; CreateSuspended: Boolean);
begin
  inherited Create(True);
  FreeOnTerminate := False; {we need to clean up Object after it terminated, so don't allow immediate free}
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
  Buf: TBytes;
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
        SetLength(Buf, Length(DataStr));
        if Length(Buf) > 0 then
          Move(DataStr[1], Buf[0], Length(Buf));
        if Assigned(FOnReceive) then
          try
            FOnReceive(Buf, FromIP, FromPort);
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

procedure TUDPDaemon.SendTo(const Data: TBytes; const Host: string; Port: Word);
begin
  if Length(Data) = 0 then Exit;
  FSocket.Connect(Host, IntToStr(Port));
  FSocket.SendBufferTo(@Data[0], Length(Data));
end;

end.

