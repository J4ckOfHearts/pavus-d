unit aes128_cipher;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  DCPmd5;

implementation

(* local *)

function localizeAES128Key(const PrivPass: TBytes; const EngineID: TBytes): TBytes;
var
  MD : TDCP_md5;
  Ku : array[0..15{MD5 Digest Length}] of Byte;
  Kul: array[0..15{MD5 Digest Length}] of Byte;
  Repetitions, i: Integer;
begin
  MD := TDCP_md5.Create(nil);
  try

    MD.Init;

    Repetitions := (1024 * 1024 + Length(PrivPass) - 1) div Length(PrivPass);
    for i := 0 to Repetitions-1 do
    begin
      if Length(PrivPass) > 0 then
        MD.Update(PrivPass[0], Length(PrivPass));
    end;
    MD.Final(Ku[0]);

    MD.Init;
    MD.Update(Ku[0], SizeOf(Ku));
    if Length(EngineID) > 0 then
      MD.Update(EngineID[0], Length(EngineID));
    MD.Update(Ku[0], SizeOf(Ku));
    MD.Final(Kul[0]);

    SetLength(Result, SizeOf(Kul));
    Move(Kul[0], Result[0], SizeOf(Kul));

  finally
    MD.Free;
  end;
end;

(* interface *)



end.

