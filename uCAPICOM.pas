unit uCAPICOM;

interface



uses
  SysUtils, Variants, Classes, CAPICOM_TLB, StdCtrls, ExtCtrls, Windows,
  uBase64;


const
   EMITIDO_POR = 'Autoridad Certificante de Firma Digital';


type

  TCAPICOM  = class
  private
    FFileStream: TFileStream;
  public
    NroCertificadoLogueado:String;
    UsuarioFirmo: String;
    function GetTempFile(const Extension: string): string;
    function verificarFirmaCadena(aCadena,aArchFirma: String):Boolean;
    function firmarCadena(aCadena,aArchFirma:String):Boolean;

    function firmarArchivo(aOriginal, aFirmado: String): Boolean;
    function verificarFirmaArchivo(aFirmado,aOriginal: String): Boolean;
    function InformacionTarjeta(var aTarSerial:String):Boolean;
    function NroSerieCertificado:String;
    function ExisteUsuario(aUsuario: String;SalvarCer:String=''): Boolean;
    function certificadoPFX: String;
  end;

implementation
uses dialogs, pkcs11_library,pkcs11_slot, math, StrUtils;


Const
  CAPICOM_MY_STORE = 'My';
  MAX_PATH = 255;
{ TCAPICOM }


function TCAPICOM.firmarArchivo(aOriginal, aFirmado: String): Boolean;
var
  FileSaveStream: TFileStream;
  MemoryStream: TMemoryStream;

  SignedString: WideString;
  P: PByteArray;
  VarArray: Variant;
  oUtilities: CAPICOM_TLB.IUtilities;

  Store: CAPICOM_TLB.IStore;
  SignedData: CAPICOM_TLB.ISignedData;
  Signer: CAPICOM_TLB.ISigner;
  Signer2: ISigner2;
  Attribute: IAttribute;

  Certs: ICertificates2;
  i: Integer;
  Email:String;
begin
  Result := False;
  UsuarioFirmo := '';

  if Assigned(FFileStream) then
    FreeAndNil(FFileStream);


  FFileStream := TFileStream.Create(aOriginal, fmOpenRead or fmShareExclusive);
  try
    if (FFileStream.Size = 0) then
      Exit;

    MemoryStream := TMemoryStream.Create;
    try
      FFileStream.Position := 0;
      MemoryStream.CopyFrom(FFileStream, FFileStream.Size);
      MemoryStream.Position := 0;

      VarArray := VarArrayCreate([0, MemoryStream.Size - 1], VarByte);
      P := VarArrayLock(VarArray);

      try
        Move(MemoryStream.Memory^, P^, MemoryStream.Size);
      finally
        VarArrayUnlock(VarArray);
      end;

      oUtilities := CoUtilities.Create;

      Store := CoStore.Create;
      Store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE,
        CAPICOM_STORE_OPEN_READ_ONLY);

      Certs := Store.Certificates;

      SignedData := CoSignedData.Create;
      SignedData.Content := oUtilities.ByteArrayToBinaryString(VarArray);

      Signer := CoSigner.Create;
      Attribute := CoAttribute.Create;
      Attribute.Name := CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME;
      Attribute.Value := Now;

      Signer.AuthenticatedAttributes.Add(Attribute);

      for i := 1 to Certs.count do
      begin
        if NroCertificadoLogueado = (IInterface( Certs.Item[i] ) as  ICertificate2).SerialNumber then
          if trim(UpperCase((IInterface( Certs.Item[i] ) as  ICertificate2).GetInfo(CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME))) = UpperCase(EMITIDO_POR) then
          begin
            Signer.Certificate := IInterface( Certs.Item[i] ) as  ICertificate2;

            Email := Signer.Certificate.GetInfo (CAPICOM_CERT_INFO_SUBJECT_EMAIL_NAME);
            UsuarioFirmo := copy(Email,1,Pos('@',Email)-1);

            break;
          end;
      end;



      Signer2 := Signer as ISigner2;

      MemoryStream.Clear;
      MemoryStream.Position := 0;


      SignedString := SignedData.Sign(Signer2, True, CAPICOM_ENCODE_BASE64);


      MemoryStream.Write(SignedString[1], Length(SignedString) * 2);

      MemoryStream.Position := 0;
      FileSaveStream := TFileStream.Create(aFirmado,  fmCreate or fmShareExclusive);
      try
        FileSaveStream.CopyFrom(MemoryStream, MemoryStream.Size);
      finally
        FreeAndNil(FileSaveStream);
      end;
      Result := True;
    finally
      FreeAndNil(MemoryStream);
    end;
  finally
    FreeAndNil(FFileStream);
  end;
end;

function TCAPICOM.GetTempFile(const Extension: string): string;
var
  Buffer: array[0..MAX_PATH] of Char;
begin
  repeat
    GetTempPath(SizeOf(Buffer) - 1, Buffer);
    GetTempFileName(Buffer, '~', 0, Buffer);
    Result := ChangeFileExt(Buffer, Extension);
  until not FileExists(Result);
end;

function TCAPICOM.firmarCadena(aCadena,aArchFirma:String):Boolean;
var
  ArcTmp:AnsiString;
  s : String;
  strL : TFileStream;
  rdm:String;
begin
  Randomize;
  rdm := IntTOStr(RandomRange(10,9999999));

  ArcTmp := GetTempFile('cad-'+rdm);

  strL := TFileStream.Create(ArcTmp,fmCreate );
  try
    s := aCadena;
    strL.Write( s[1], length(s));
  finally
    FreeAndNil(strL);
  end;

  try
    Result := firmarArchivo(ArcTmp,aArchFirma);
  finally
    DeleteFile(PAnsiChar(ArcTmp));
  end;

end;

function TCAPICOM.InformacionTarjeta(var aTarSerial: String): Boolean;
var
  allOK: boolean;
  i:integer;
  PKCS11Slot: TPKCS11Slot;
  pkcs11: TPKCS11Library;

begin
  aTarSerial := '';

  try
  // Shutdown any existing...
    pkcs11:= TPKCS11Library.Create('asepkcs.dll');

    allOK := pkcs11.Initialize();
    if not(allOK) then
    begin
      pkcs11.Finalize();
      allOK := pkcs11.Initialize();
    end;


    if not(allOK) then
    begin
      raise Exception.Create('Error:' + pkcs11.RVToString(pkcs11.LastRV));
    end;


    for i:=0 to (pkcs11.CountSlots - 1) do
    begin
      PKCS11Slot := pkcs11.Slot[i];
      try
        aTarSerial := PKCS11Slot.Token.SerialNumber;
        break;
      except
        on E:Exception do
        begin
          raise Exception.Create('Error al leer la tarjeta. - '+E.Message);
        end;
      end;
    end;

    Result := True;
  except
     Result := False;
  end;


end;

function TCAPICOM.verificarFirmaArchivo(aFirmado,aOriginal: String): Boolean;
var
  FSignedData:TFileStream;
  MemoryStream:TMemoryStream;
  SignedData:CAPICOM_TLB.ISignedData;
  strBase64EncodedMessage:WideString;
  oUtilities:CAPICOM_TLB.IUtilities;
  Signedfile:TMemoryStream;
  VarArray:Variant;
  P:PByteArray;
  FCert:CAPICOM_TLB.ICertificate;
begin
  FSignedData:=TFileStream.Create(aFirmado, fmOpenRead or fmShareExclusive);
  try
    FSignedData.Position:=0;

    MemoryStream:=TMemoryStream.Create;
    try
      MemoryStream.CopyFrom(FSignedData, FSignedData.Size);
      MemoryStream.Position:=0;

      SetLength(strBase64EncodedMessage, MemoryStream.Size);
      FillChar(strBase64EncodedMessage[1], MemoryStream.Size, 0);
      MemoryStream.Read (strBase64EncodedMessage[1], MemoryStream.Size);

      oUtilities:=CoUtilities.Create;
      SignedData:=CoSignedData.Create;

      Signedfile:=TMemoryStream.Create;
      try
        Signedfile.LoadFromFile(aOriginal);
        Signedfile.Position:=0;

        VarArray:=VarArrayCreate([0, Signedfile.Size-1], VarByte);
        P:=VarArrayLock(VarArray);
        try
          Move(Signedfile.Memory^, P^, Signedfile.Size);
        finally
          VarArrayUnlock(VarArray);
          FreeAndNil(Signedfile);
        end;

        SignedData.Content:=oUtilities.ByteArrayToBinaryString(VarArray);
        SignedData.Verify(oUtilities.BinaryStringToByteArray(strBase64EncodedMessage), True, CAPICOM_VERIFY_SIGNATURE_AND_CERTIFICATE);

        If SignedData.Certificates.Count > 0 Then
           FCert:=ICertificate(IDispatch(SignedData.Certificates.Item[1]))
        else
           FCert:=nil;


        Result := assigned(FCert);
      finally
        MemoryStream.Free;
      end;
    finally
      Signedfile.Free;
    end;
  finally
    FSignedData.free
  end;
end;

function TCAPICOM.verificarFirmaCadena(aCadena,aArchFirma: String):Boolean;
var
  ArcTmp:AnsiString;
  s : String;
  strL : TFileStream;
  rdm:String;
begin
  Randomize;
  rdm := IntTOStr(RandomRange(10,9999999));

  ArcTmp := GetTempFile('cad-'+rdm);

  strL := TFileStream.Create(ArcTmp,fmCreate );
  try
    s := aCadena;
    strL.Write( s[1], length(s));
  finally
    FreeAndNil(strL);
  end;

  try
    Result := verificarFirmaArchivo(aArchFirma,ArcTmp);
  finally
    DeleteFile(PAnsiChar(ArcTmp));
  end;
end;



function TCAPICOM.NroSerieCertificado: String;
var
  Store: CAPICOM_TLB.IStore;
  CertStore : ICertificates;
  Cert:ICertificate2;
  ArchCer:String;
begin
  Result := '';
  try
    Store := CoStore.Create;
    Store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE,
         CAPICOM_STORE_OPEN_READ_ONLY);

    CertStore := Store.Certificates ;
    Cert :=  IInterface(CertStore.Item[1]) as ICertificate2;


    ArchCer := GetTempFile('Arch_Cer');
    DeleteFile(PChar(archCer));

    Cert.Save(ArchCer, '', CAPICOM_CERTIFICATE_SAVE_AS_CER, CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY);

    Result := Cert.SerialNumber;
  except
    on E:Exception do
    begin
      Result := '';
      raise Exception.Create('Error no se puede obtener el certificado. - '+E.Message);
    end;
  end;
end;

function TCAPICOM.ExisteUsuario(aUsuario: String;SalvarCer:String=''): Boolean;
var
  Store: CAPICOM_TLB.IStore;
  CertStore : ICertificates;
  Cert:ICertificate2;
  i:integer;
  Email,Usr:String;
  entreFechas:Boolean;
begin
  NroCertificadoLogueado := '';
  UsuarioFirmo := '';
  Result := False;
  try
    Store := CoStore.Create;
    Store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE,
         CAPICOM_STORE_OPEN_READ_ONLY);

    CertStore := Store.Certificates ;

    for i := 1 to CertStore.Count do
    begin
      Cert :=  IInterface(CertStore.Item[i]) as ICertificate2;

      if Trim(UpperCase(Cert.GetInfo(CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME))) <> UpperCase(EMITIDO_POR) then
      begin
        Continue;
      end;


      Email := Cert.GetInfo (CAPICOM_CERT_INFO_SUBJECT_EMAIL_NAME);
      Usr := copy(Email,1,Pos('@',Email)-1);

      if UpperCase(Usr)=UpperCase(aUsuario) then
      begin
        entreFechas :=  (Trunc(Cert.ValidFromDate)<=Trunc(Now))and(Trunc(Now)<= Trunc(Cert.ValidToDate));
        Result := entreFechas and Cert.IsValid.Result;
        if Result then
        begin
          NroCertificadoLogueado := Cert.SerialNumber;

          if Trim(SalvarCer)<>'' then
            Cert.Save(SalvarCer, '', CAPICOM_CERTIFICATE_SAVE_AS_CER, CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY);
          Exit;
        end else begin

{          if not entreFechas then
            ShowMessage('Certificado Vencido')
          else
            ShowMessage('Certificado Revocado');
}
          if not entreFechas then
            raise Exception.Create('Certificado Vencido')
          else
            raise Exception.Create('Certificado Revocado')
        end;
      end;
    end;
  except
    on E:Exception do
    begin
      raise Exception.Create('Error no se puede obtener el usuario del certificado. - '+E.Message);
    end;
  end;
end;

function TCAPICOM.CertificadoPFX: String;
var
  Store: CAPICOM_TLB.IStore;
//  exp: CAPICOM_TLB.
  CertStore : ICertificates;
  Cert:ICertificate2;
  ArchCer:String;
  archivoStr: string;
  filestring: TFileStream;
begin
  Result := '';
  try
    Store := CoStore.Create;
    Store.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_READ_ONLY);

    CertStore := Store.Certificates ;
    Cert :=  IInterface(CertStore.Item[1]) as ICertificate2;


    ArchCer := GetTempFile('Arch_Cer');
    DeleteFile(PChar(archCer));

    Cert.Save(ArchCer, '123123123', CAPICOM_CERTIFICATE_SAVE_AS_PFX, CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY);
    archivoStr := cert.Export(CAPICOM_ENCODE_BINARY);
    ShowMessage(archivoStr);
    archivoStr := Decode64(archivoStr);
    filestring := TFileStream.Create('.\certificado.algo', fmCreate);
    filestring.write(archivoStr[1], length(archivoStr));
    filestring.Free;
    Result := Cert.SerialNumber;
  except
    on E:Exception do
    begin
      Result := '';
      raise Exception.Create('Error no se puede obtener el certificado. - '+E.Message);
    end;
  end;
end;

end.
