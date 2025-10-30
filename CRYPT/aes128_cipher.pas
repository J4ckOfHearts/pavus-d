unit aes128_cipher;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  DCPmd5, DCPrijndael;

procedure encryptAES128(const LocalizedKey: TBytes; EngineBoots, EngineTime: Integer; const PrivParameters: PByte; const PlainTextPtr: PByte; const PlainTextLen: Integer; CipherTextPtr: PByte);
procedure decryptAES128(const LocalizedKey: TBytes; EngineBoots, EngineTime: Integer; const PrivParameters: PByte; const CipherTextPtr: PByte; const CipherTextLen: Integer; PlainTextPtr: PByte);
function  localizeAES128Key(const PrivPass: TBytes; const EngineID: TBytes): TBytes;

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

procedure decryptAES128(const LocalizedKey: TBytes; EngineBoots, EngineTime: Integer; const PrivParameters: PByte; const CipherTextPtr: PByte; const CipherTextLen: Integer; PlainTextPtr: PByte);
var
  AES    : TDCP_rijndael;
  AESkey : TBytes;
  IV     : Array[0..15] of Byte;
begin
  if Length(LocalizedKey) < 16 then
    raise Exception.Create('[decryptAES128] LocalizedKey must be at least 16 bytes');

  SetLength(AESKey, 16);
  Move(LocalizedKey[0], AESKey[0], 16);

  IV[0] := (EngineBoots shr 24) and $FF;
  IV[1] := (EngineBoots shr 16) and $FF;
  IV[2] := (EngineBoots shr 8)  and $FF;
  IV[3] := EngineBoots and $FF;
  IV[4] := (EngineTime shr 24) and $FF;
  IV[5] := (EngineTime shr 16) and $FF;
  IV[6] := (EngineTime shr 8)  and $FF;
  IV[7] := EngineTime and $FF;

  Move(PrivParameters^, IV[8], 8);

  AES := TDCP_rijndael.Create(nil);
  try
    AES.Init(AESKey[0], 128, @IV[0]);
    AES.DecryptCFBblock(CipherTextPtr^, PlainTextPtr^, CipherTextLen);
  finally
    AES.Burn;
    AES.Free;
  end;

end;

procedure encryptAES128(const LocalizedKey: TBytes; EngineBoots, EngineTime: Integer; const PrivParameters: PByte; const PlainTextPtr: PByte; const PlainTextLen: Integer; CipherTextPtr: PByte);
var
  AES    : TDCP_rijndael;
  AESkey : TBytes;
  IV     : Array[0..15] of Byte;
begin
  SetLength(AESKey, 16);
  Move(LocalizedKey[0], AESKey[0], 16);

  IV[0] := (EngineBoots shr 24) and $FF;
  IV[1] := (EngineBoots shr 16) and $FF;
  IV[2] := (EngineBoots shr 8)  and $FF;
  IV[3] := EngineBoots and $FF;
  IV[4] := (EngineTime shr 24) and $FF;
  IV[5] := (EngineTime shr 16) and $FF;
  IV[6] := (EngineTime shr 8)  and $FF;
  IV[7] := EngineTime and $FF;

  Move(PrivParameters^, IV[8], 8);

  AES := TDCP_rijndael.Create(nil);
  try
    AES.Init(AESKey[0], 128, @IV[0]);
    AES.EncryptCFBblock(PlainTextPtr^, CipherTextPtr^, PlainTextLen);
  finally
    AES.Burn;
    AES.Free;
  end;

end;

end.

