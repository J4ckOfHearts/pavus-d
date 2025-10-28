unit snmp_handler;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

{Returns the length of content written to RespData-Buffer}
function handleRequest(const RecvData: PByte; const RecvLen: Integer; const RespData: PByte): Integer;



implementation

function handleRequest(const RecvData: PByte; const RecvLen: Integer; const RespData: PByte): Integer;
begin

end;

end.

