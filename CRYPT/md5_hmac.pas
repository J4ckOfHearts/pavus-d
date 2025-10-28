unit md5_hmac;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  DCPmd5;

type
  TMD5HMAC = Array[0..11] of Byte;

{Excpects the SNMP Message to be "zeroed out" already!}
function computeMD5Hmac(const Data: PByte; const DataLen: Integer; const AuthPass: TBytes; const EngineID: TBytes): TMD5HMAC;

implementation

(* local *)

function localizeMD5HmacKey(const AuthPass: TBytes; const EngineID: TBytes): TBytes;
const
  HMAC_BLOCK_SIZE = 64;
  REPEAT_SIZE = 1024 * 1024; {=1mb}
var
  MD:  TDCP_md5;
  Buf: TBytes;
  PasswordIndex, Count, i : Integer;
  Digest: Array[0..15{MD5 Digest Length}] of Byte;
begin
  MD := TDCP_md5.Create(nil);
  try

    SetLength(Buf, REPEAT_SIZE);
    PasswordIndex := 0;
    Count := 0;

    while Count < REPEAT_SIZE do
    begin
      for i := 0 to HMAC_BLOCK_SIZE-1 do
      begin
        if Count + i >= REPEAT_SIZE then Break;
        Buf[Count+i] := AuthPass[PasswordIndex];
        Inc(PasswordIndex);
        if PasswordIndex >= Length(AuthPass) then
          PasswordIndex := 0;
      end;
      Inc(Count, HMAC_BLOCK_SIZE);
    end;

    MD.Init;
    MD.Update(Buf[0], Length(Buf));
    MD.Final(Digest[0]);

    MD.Init;
    MD.Update(Digest, SizeOf(Digest));
    if Length(EngineID) > 0 then
      MD.Update(EngineID[0], Length(EngineID));
    MD.Update(Digest, SizeOf(Digest));
    MD.Final(Digest[0]);

    SetLength(Result, SizeOf(Digest));
    Move(Digest[0], Result[0], SizeOf(Digest));

  finally
    MD.Free;
  end;
end;

(* interface *)

function computeMD5Hmac(const Data: PByte{<- sec params zeroed out}; const DataLen: Integer; const AuthPass: TBytes; const EngineID: TBytes): TMD5HMAC;
const
  HMAC_BLOCK_SIZE = 64;
  HMAC_AUTH_CODE_LEN = 12;
var
  MD: TDCP_md5;
  localizedKey: TBytes;
  k_ipad, k_opad: Array[0..HMAC_BLOCK_SIZE-1] of Byte;
  i: Integer;
  NewDigest: array[0..15{MD5 Digest Length}] of Byte;
begin
  MD := TDCP_md5.Create(nil);
  try

    localizedKey := localizeMD5HmacKey(AuthPass, EngineID);

    if (Length(localizedKey) > HMAC_BLOCK_SIZE) then
    begin
      MD.Init;
      MD.Update(localizedKey[0], Length(localizedKey));
      MD.Final(localizedKey[0]);
    end;

    for i := 0 to Length(localizedKey)-1 do
    begin
      k_ipad[i] := localizedKey[i] xor $36;
      k_opad[i] := localizedKey[i] xor $5C;
    end;

    for i := Length(localizedKey) to HMAC_BLOCK_SIZE-1 do
    begin
      k_ipad[i] := $36;
      k_opad[i] := $5C;
    end;

    FillChar(NewDigest, SizeOf(NewDigest), 0);

    MD.Init;
    MD.Update(k_ipad, HMAC_BLOCK_SIZE);
    if DataLen > 0 then
      MD.Update(Data^, DataLen);
    MD.Final(NewDigest[0]);

    MD.Init;
    MD.Update(k_opad, HMAC_BLOCK_SIZE);
    MD.Update(NewDigest[0], SizeOf(NewDigest));
    MD.Final(NewDigest[0]);

    for i := 0 to HMAC_AUTH_CODE_LEN-1 do
      Result[i] := NewDigest[i];

  finally
    MD.Free;
  end;
end;

end.

