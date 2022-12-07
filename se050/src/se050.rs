use crate::types::*;
use core::convert::{From, TryFrom};
use byteorder::{ByteOrder, BE};

use cortex_m_semihosting::{debug, heprintln, hprint};

#[derive(Debug, PartialEq, Eq)]
pub enum Se050Error {
    UnknownError,
    T1Error(T1Error),
}

//SEE AN12413 P. 34 - Table 17. Instruction mask constants
#[allow(dead_code)]
pub const INS_MASK_INS_CHAR : u8 = 0xE0;
#[allow(dead_code)]
pub const INS_MASK_INSTRUCTION : u8 = 0x1F;

//SEE AN12413 P. 34 - Table 18. Instruction characteristics constants

pub const APDU_INSTRUCTION_TRANSIENT: u8 = 0x80;

#[allow(dead_code)]
pub const APDU_INSTRUCTION_AUTH_OBJECT: u8 = 0x40; 
#[allow(dead_code)]
pub const APDU_INSTRUCTION_ATTEST: u8 = 0x20;




//See AN12413,- Table 19. Instruction constants P. 35 
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduInstruction {
    /* mask:0x1f */
    Write = 0x01,
    Read = 0x02,
    Crypto = 0x03,
    Mgmt = 0x04,
    Process = 0x05,
    ImportExternal = 0x06,    
    InstructECKSIA = 0x88,
    InstructECKSGECKAPK = 0xCA,
}



// See AN12413,  Table 20. P1Mask constants P. 35
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduP1Maskconstants {
    P1Unused = 0x80,
    P1MaskKeyType = 0x60,
    P1MaskCredType = 0x1F,

}


// See AN12413,  Table 21. P1KeyType constants P. 35
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduP1KeyType {
    /* mask:0x60 */
    KeyPair = 0x60,
    PrivateKey = 0x40,
    PublicKey = 0x20,
}

// See  AN12413, Table 22. P1Cred constants P. 35 - 36
#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Se050ApduP1CredType {
    Default = 0x00,
    EC = 0x01,
    RSA = 0x02,
    AES = 0x03,
    DES = 0x04,
    HMAC = 0x05,
    Binary = 0x06,
    UserID = 0x07,
    Counter = 0x08,
    PCR = 0x09,
    Curve = 0x0b,
    Signature = 0x0c,
    MAC = 0x0d,
    Cipher = 0x0e,
    TLS = 0x0f,
    CryptoObj = 0x10,
    EcksgeckapkP1 = 0xBF,
}

// See AN12413, 4.3.5 P2 parameter Table 23. P2 constants -P. 36 - 37
#[allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Se050ApduP2 {
    Default = 0x00,
    Generate = 0x03,
    Create = 0x04,
    Size = 0x07,
    Sign = 0x09,
    Verify = 0x0a,
    Init = 0x0b,
    Update = 0x0c,
    Final = 0x0d,
    Oneshot = 0x0e,
    DH = 0x0f,
    Diversify = 0x10,
    AuthFirstPart2 = 0x12,
    AuthNonfirstPart2 = 0x13,
    DumpKey = 0x14,
    ChangeKeyPart1 = 0x15,
    ChangeKeyPart2 = 0x16,
    KillAuth = 0x17,
    Import = 0x18,
    Export = 0x19,
    SessionCreate = 0x1b,
    SessionClose = 0x1c,
    SessionRefresh = 0x1e,
    SessionPolicy = 0x1f,
    Version = 0x20,
    Memory = 0x22,
    List = 0x25,
    Type = 0x26,
    Exist = 0x27,
    DeleteObject = 0x28,
    DeleteAll = 0x2a,
    SessionUserID = 0x2c,
    HKDF = 0x2d,
    PBKDF = 0x2e,
    I2CM = 0x30,
    I2CMAttested = 0x31,
    MAC = 0x32,
    UnlockChallenge = 0x33,
    CurveList = 0x34,
    SignECDAA = 0x35,
    ID = 0x36,
    EncryptOneshot = 0x37,
    DecryptOneshot = 0x38,
    Attest = 0x3a,
    Attributes = 0x3b,
    CPLC = 0x3c,
    Time = 0x3d,
    Transport = 0x3e,
    Variant = 0x3f,
    Param = 0x40,
    DeleteCurve = 0x41,
    Encrypt = 0x42,
    Decrypt = 0x43,
    Validate = 0x44,
    GenerateOneshot = 0x45,
    ValidateOneshot = 0x46,
    CryptoList = 0x47,
    Random = 0x49,
    TLS_PMS = 0x4a,
    TLS_PRF_CLI_Hello = 0x4b,
    TLS_PRF_SRV_Hello = 0x4c,
    TLS_PRF_CLI_RND = 0x4d,
    TLS_PRF_SRV_RND = 0x4e,
    RAW = 0x4f,
    ImportExt = 0x51,
    SCP = 0x52,
    AuthFirstPart1 = 0x53,
    AuthNonfirstPart1 = 0x54,
    ECKSGECKAPK_P2 = 0x21,
}

// See AN12413, 4.3.6 SecureObject type Table 24. SecureObjectType constants   P. 38
#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
pub enum Se050ApduSecObjType {
    ECKeyPair = 0x01,
    ECPrivKey = 0x02,
    ECPubKey = 0x03,
    RSAKeyPair = 0x04,
    RSAKeyPairCRT = 0x05,
    RSAPrivKey = 0x06,
    RSAPrivKeyCRT = 0x07,
    RSAPubKey = 0x08,
    AESKey = 0x09,
    DESKey = 0x0a,
    BinaryFile = 0x0b,
    UserID = 0x0c,
    Counter = 0x0d,
    PCR = 0x0f,
    Curve = 0x10,
    HMACKey = 0x11,
}

// See AN12413,  4.3.7 Memory Table 25. Memory constants  P.38
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduMemoryType {
    Persistent = 1,
    TransientReset = 2,
    TransientDeselect = 3,
}

// See AN12413, 4.3.8 Origin Table 26. Origin constants  P. 38
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ApduObjectOrigin {
    External = 1,
    Internal = 2,
    Provisioned = 3,
}

// See AN12413,4.3.9 TLV tags Table 27. Tags P.39
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050TlvTag {
    SessionID = 0x10,
    Policy = 0x11,
    MaxAttempts = 0x12,
    ImportAuthData = 0x13,
    ImportAuthKeyID = 0x14,
    Tag1 = 0x41,
    Tag2 = 0x42,
    Tag3 = 0x43,
    Tag4 = 0x44,
    Tag5 = 0x45,
    Tag6 = 0x46,
    Tag7 = 0x47,
    Tag8 = 0x48,
    Tag9 = 0x49,
    Tag10 = 0x4a,
}

// See AN12413,4.3.10 ECSignatureAlgo Table 28. ECSignatureAlgo P.39
//(See AN12413, 4.3.22 AttestationAlgo AttestationAlgo is either ECSignatureAlgo or RSASignatureAlgo. P.43)
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ECSignatureAlgo {
SigEcdsaPlain = 0x09,
SigEcdsaSha = 0x11,
SigEcdsaSha224 = 0x25,
SigEcdsaSha256 = 0x21,
SigEcdsaSha384 = 0x22,
SigEcdsaSha512 = 0x26,

}

// See AN12413, 4.3.11 EDSignatureAlgo Table 29. EDSignatureAlgo P.39
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050EDSignatureAlgo {

    SigEd25519pure = 0xA3,

}

// See AN12413, 4.3.12 ECDAASignatureAlgo Table 30. ECDAASignatureAlgo P.40
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ECDAASignatureAlgo {

    SigEcdaa= 0xF4,

}

// See AN12413, 4.3.13 RSASignatureAlgo Table 31. RSASignatureAlgo P.40
//See AN12413, 4.3.22 AttestationAlgo AttestationAlgo is either ECSignatureAlgo or RSASignatureAlgo. P.43
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050RSASignatureAlgo {
    
RsaSha1Pkcs1Pss  = 0x15 ,
RsaSha224Pkcs1Pss = 0x2B ,
RsaSha256Pkcs1Pss= 0x2C ,
RsaSha384Pkcs1Pss = 0x2D ,
RsaSha512Pkcs1Pss = 0x2E,
RsaSha1Pkcs1 = 0x0A ,
RsaSha224Pkcs1 = 0x27 ,
RsaSha256Pkcs1 = 0x28 ,
RsaSha384Pkcs1 =  0x29 ,
RsaSha512Pkcs1 = 0x2A ,

}


 // See AN12413, 4.3.14 RSAEncryptionAlgo Table 32. RSAEncryptionAlgo P.40
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050RSAEncryptionAlgo {

    RsaNoPad = 0x0C,
    RsaPkcs1 = 0x0A,
    RsaPkcs10aep = 0x0F,

}

 // See AN12413, 4.3.15 RSABitLength Table 33. RSABitLength P.40
 #[allow(dead_code)]
 #[repr(u16)]
 pub enum Se050RSABitLength {

     Rsa512 = 512,
     Rsa1024 = 1024,
     Rsa1152 = 1152,
     Rsa2048 = 2048,
     Rsa3072 = 3072,
     Rsa4096 = 4096,
 
 }
  

// See AN12413, 4.3.16 RSAKeyComponent Table 34. RSAKeyComponentP.41
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050RSAKeyComponent {    
    
    RsaCompMod = 0x00 ,
    RsaCompPubExp = 0x01 ,
    RsaCompPrivExp = 0x02 ,
    RsaCompP = 0x03 ,
    RsaCompQ  = 0x04 ,
    RsaCompDp = 0x05 ,
    RsaCompDq = 0x06 ,
    RsaCompInvq = 0x07 ,

 
}
 

    // See AN12413, 4.3.17 DigestMode Table 35. DigestMode constants P.41
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050DigestModeconstants {
  
        DigestNoHash = 0x00,
        DigestSha = 0x01,
        DigestSha224 = 0x07,
        DigestSha256 = 0x04,
        DigestSha384 = 0x05,
        DigestSha512 =  0x06,

}

    // See AN12413, 4.3.18 MACAlgo Table 36. MACAlgo constants P.41- 42
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050MACAlgoconstants {
      
        HmacSha = 0x18,
        HmacSha256 = 0x19,
        HmacSha384 = 0x1A,
        HmacSha512 = 0x1B,
        Cmac128  = 0x31,
        DesMac4Iso9797M2 = 0x05,
        DesMac4Iso9797_1M2Alg3 = 0x13,
        DesMac4Iso9797M1 = 0x03,
        DesMac4Iso9797_1M1Alg3 = 0x2F,
        DesMac8Iso9797M2 = 0x06,
        DesMac8Iso9797_1M2Alg3 = 0x14,
        DesMac8Iso9797_1M1Alg3 = 0x04,
        // DES_MAC8_ISO9797_1_M1_ALG3 = 0x30,
        //CMAC128 = 0x31,
        DesCmac8 = 0x7A,
        AesCmac16 = 0x66,

}
 

    // See AN12413,4.3.19 ECCurve Table 37. ECCurve constants   P.42
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050ECCurveconstants  {
    
    NistP192 = 0x01,
    NistP224 = 0x02,    
    NistP256 = 0x03,
    NistP384 = 0x04,
    NistP521 = 0x05,

    Brainpool160 = 0x06,
    Brainpool192 = 0x07,
    Brainpool224 = 0x08,
    Brainpool256 = 0x09,
    Brainpool320 = 0x0A,
    Brainpool384 = 0x0B,
    Brainpool512 = 0x0C,
 
    Secp160k1=0x0D,
    Secp192k1=0x0E,
    Secp224k1=0x0F,
    Secp256k1=0x10,
  
    TpmEccBnP256=0x11,
    IdEccEd25519= 0x40, 
    IdEccMontDh25519=0x41
 
}


    // See AN12413, 4.3.20 ECCurveParam  Table 38. ECCurveParam constants P 42
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum Se050ECCurveParamconstants {     
    
    CurveParamA = 0x01,
    CurveParamB = 0x02,
    CurveParamG = 0x04,
    CurveParamN = 0x08,
    CurveParamPrime = 0x10,

}
 
    // See AN12413,4.3.21 CipherMode Table 39. CipherMode constants   P.43
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050CipherModeconstants {
         
    DesCbcNopad = 0x01,  
    DesCbcIso9797M1 = 0x02,
    DesCbcIso9797M2=0x03,
    DesCbcPkcs5=0x04,
    DesEcbNopad= 0x05,
    DesEcbIso9797M1= 0x06,
    DesEcbIso9797M2= 0x07,
    DesEcbPkcs5 =0x08,
    AesEcbNopad =0x0E,
    AesCbcNopad =0x0D,
    AesCbcIso9797M1 =0x16,
    AesCbcIso9797M2 =0x17,
    AesCbcPkcs5= 0x18,
    AesCtr =0xF0,

 
}

// See AN12413,4.3.23 // 4.3.22 AttestationAlgo // AttestationAlgo is either ECSignatureAlgo or RSASignatureAlgo.


    // See AN12413,4.3.23 AppletConfig Table 40. Applet configurations   P.43-44
    #[allow(dead_code)]
    #[repr(u16)]
    pub enum  Se050AppletConfig {

     ConfigEcdaa = 0x0001,
     ConfigEcdsaEcdhEcdhe = 0x0002,
     ConfigEddsaA = 0x0004,
     ConfigDhMont = 0x0008,
     ConfigHmac = 0x0010,
     ConfigRsaPlain = 0x0020,
     ConfigRsaCrt =  0x0040,
     ConfigAes = 0x0080,
  
     ConfigDes = 0x0100,
     ConfigPbkdf= 0x0200,
     ConfigTls = 0x0400,
     ConfigMifare = 0x0800,
     ConfigFipsModeDisabled = 0x1000,
     ConfigI2cm = 0x2000,

     ConfigEccAll = 0x000F,
     ConfigRsaAll = 0x0060,
     ConfigAll = 0x3FFF,

     }


    // See AN12413, 4.3.24 LockIndicator ,Table 41. LockIndicator constants  P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050LockIndicatorconstants { 

    TransientLock = 0x01,
    PersistentLock = 0x02,
 
}
 
    // See AN12413,  4.3.25 ,   Table 42. LockState constants   P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050LockStateconstants {   

    LOCKED = 0x01,
    UNLOCKED = 0x02,
 
}


    // See AN12413,   4.3.26 CryptoContext , Table 43. P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050CryptoContextconstants { 

        CcDigest = 0x01, 
        CcCipher = 0x02,
        CcSignature = 0x03,
    }
     
    // See AN12413,  4.3.27 Result  Table 44. Result constants P.44
    #[allow(dead_code)]
    #[repr(u8)]
    pub enum  Se050Resultconstants {     
 
     ResultSuccess= 0x01,
     ResultFailure = 0x02,
    }


     // See AN12413,4.3.28  TransientIndicator, Table 45. TransientIndicator constants P.44   
     #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050TransientIndicatorconstants {     

     PERSISTENT =0x01,
     TRANSIENT =0x02,

     }
 
   // See AN12413,4.3.28, 4.3.29 SetIndicator  Table 46. SetIndicator constants P.45     
     #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050SetIndicatorconstants {     

      NotSet = 0x01,
      SET = 0x02,

     }
 
     // See AN12413,4.3.28, 4.3.30 MoreIndicator   Table 47. MoreIndicator constants   P.45  
     #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050MoreIndicatorconstants {    

     NoMore = 0x01,
     MORE = 0x02,

     }

 

     // See AN12413,4.3.28, 4.3.31 PlatformSCPRequest , Table 48. PlatformSCPRequest constants P.45
    #[allow(dead_code)]
     #[repr(u8)]
     pub enum  Se050PlatformSCPRequestconstants {    

     ScpRequired = 0x01 ,
     ScpNotRequired = 0x02,

     }
 


     // See AN12413,// 4.3.34 Policy constants // 4.3.34.1 Session policy P.46
    //  A notation will be used to identify specific bits: 
    // the most significant Byte is 1 and the most significant bit is 8; 
    // so if B2b7 is set, this would be coded as 0x00 0x40.
     //Position in Header:
    //B1b8 = 1000 0000 =0x80 ,  
    //B1b7 = 0100 0000 = 0x40,,  
    //B1b6 = 0010 0000 = 0x20 ;
    //B1b5 = 0001 0000 = 0x10 ;
    //B1b4 = 0000 1000 =0x08 ,  
    //B1b3 = 0000 0100 = 0x04,,  
    //B1b2 = 0000 0010 = 0x02 ;
    //B1b1 = 0000 0001 = 0x01;

    #[allow(dead_code)]
    #[repr(u32)]
    pub enum  Se050Sessionpolicies {    
        //RFU = 0x80 ,
        //RFU = 0x40 ,
        PolicySessionMaxApdu= 0x80,        
        PolicySessionAllowRefresh = 0x20,        
   
        }
    
 // See AN12413,// 4.3.34 Policy constants // 4.3.34.1 Session policy P.47
    //  A notation will be used to identify specific bits: 
    // the most significant Byte is 1 and the most significant bit is 8; 
    // so if B2b7 is set, this would be coded as 0x00 0x40.
    //Position in Header 
    //B1b8 = 1000 0000 =0x80 ,  
    //B1b7 = 0100 0000 = 0x40,,  
    //B1b6 = 0010 0000 = 0x20 ;
    //B1b5 = 0001 0000 = 0x10 ;
    //B1b4 = 0000 1000 =0x08 ,  
    //B1b3 = 0000 0100 = 0x04,,  
    //B1b2 = 0000 0010 = 0x02 ;
    //B1b1 = 0000 0001 = 0x01;

    //B2b8 = 1000 0000 0000 0000 =0x8000 ,  
    //B2b7 = 0100 0000 0000 0000 = 0x4000,  
    //B2b6 = 0010 0000 0000 0000= 0x2000 ;
    //B2b5 = 0001 0000 0000 0000= 0x1000 ;
    //B2b4 = 0000 1000 0000 0000=0x0800 ,  
    //B2b3 = 0000 0100 0000 0000= 0x0400,,  
    //B2b2 = 0000 0010 0000 0000= 0x0200 ;
    //B2b1 = 0000 0001 0000 0000= 0x0100;

    //B3b8 = 1000 0000 0000 0000 0000 0000 =0x800000 ,  
    //B3b7 = 0100 0000 0000 0000 0000 0000= 0x400000,  
    //B3b6 = 0010 0000 0000 0000 0000 0000= 0x200000 ;
    //B3b5 = 0001 0000 0000 0000 0000 0000= 0x100000 ;
    //B3b4 = 0000 1000 0000 0000 0000 0000= 0x080000 ,  
    //B3b3 = 0000 0100 0000 0000 0000 0000= 0x040000,  
    //B3b2 = 0000 0010 0000 0000 0000 0000= 0x020000 ;
    //B3b1 = 0000 0001 0000 0000 0000 0000= 0x010000;




    #[allow(dead_code)]  
  
         #[repr(u32)]
    pub enum Se050Objectpolicies {    

        //RFU = 0x80 ,
        //RFU = 0x40 ,
        PolicyObjForbidAll= 0x20,
        PolicyObjAllowSign = 0x10,

        PolicyObjAllowVerify = 0x08,
        PolicyObjAllowKa = 0x04,
        PolicyObjAllowEnc = 0x02,
        PolicyObjAllowDec = 0x01,

        PolicyObjAllowKdf = 0x8000,
        PolicyObjAllowWrap =  0x4000,
        PolicyObjAllowRead =  0x2000,
        PolicyObjAllowWrite = 0x1000,

        PolicyObjAllowGen = 0x0800,
        PolicyObjAllowDelete = 0x0400,  
        PolicyObjRequireSm  = 0x0200,
        PolicyObjRequirePcrValue =  0x0100,

        PolicyObjAllowAttestation = 0x800000 , 
        PolicyObjAllowDesfireAuthentication = 0x400000 ,  
        PolicyObjAllowDesfireDumpSessionKeys  = 0x200000 , 
        PolicyObjAllowImportExport = 0x100000 ,        

        //RFU = 0x080000 ,
        //RFU = 0x040000 ,
        //RFU = 0x020000 ,
        //RFU = 0x010000 ,      

        }
    


include!("se050_convs.rs");

//////////////////////////////////////////////////////////////////////////////
//trait-Se050Device ->  struct Se050
pub trait Se050Device {
    
    fn enable(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    fn disable(&mut self, _delay: &mut DelayWrapper);

    //See AN12413,4.5 Session management // 4.5.1 Generic session commands //4.5.1.1 CreateSession P.48
    fn create_session(&mut self,  authobjid: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

    //See AN12413,4.5 Session management // 4.5.1 Generic session commands //4.5.1.2 ExchangeSessionData P.49
    fn exchange_session_data(&mut self, session_policies: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands /4.5.1.3 process_session_cmd P.49-50
    fn process_session_cmd(&mut self,apducommand : &[u8], session_id : &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 RefreshSession P.50
    fn refresh_session(&mut self,policy: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 RefreshSession P.50
    fn close_session(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> ;


    //See AN12413 , 4.5 Session management //4.5.2 UserID session operations // 4.5.2.1 VerifySessionUserID P.51-52    
    fn verify_session_user_id(&mut self, user_idvalue: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413 , 4.5.4 ECKey session operations //  4.5.4.1 ECKeySessionInternalAuthenticate P.52    
    fn eckey_session_internal_authenticate(&mut self, input_data: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413 ,  4.5.4 ECKey session operations //   4.5.4.2 eckey_session_get_eckapublic_key P.53-54
    fn eckey_session_get_eckapublic_key(&mut self, input_data: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;


       
    //AN12413 // 4.6 Module management  //4.6.3 set_applet_features  P.56 -57
    fn set_applet_features(&mut self,applet_config: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

   // See AN12413, // 4.7 Secure Object management // P57-58

    // See AN12413,  4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey //P1_EC ///P.58-59
 
   // fn generate_eccurve_key(&mut self, eccurve: &[u8], delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>; //ERWEITERT
   fn generate_eccurve_key(&mut self, objectid: &[u8;4] ,eccurve: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

   // fn generate_p256_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error //DEFAULT CONFIGURATION OF SE050
    fn generate_p256_key(&mut self, objectid: &[u8;4],delay: &mut DelayWrapper) -> Result<(), Se050Error>;
     
    // See AN12413,  4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.2 WriteRSAKey  //P.59-60

    /*
    TO-DO  ->FUNCTIONS TO GENERATE RSA-KEY


    */

    // See AN12413 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey //AES key, DES key or HMAC key // P 60/ P.61

    fn write_aes_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    fn write_des_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;
    
    fn write_hmac_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;


    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.4 WriteBinary  //P.61

    /*
    TO-DO  ->FUNCTIONS  FOR Creating or writimg to a binary file object

    */

    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject P.57 //4.7.1.5 write_user_id  //P.62    
    fn write_user_id(&mut self, user_identifier_value : &[u8], delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>;
    
     /*
    TO-DO  ->FUNCTIONS  FOR Creating or writing  a UserID object, setting the user identifier value.  
    VerifySessionUserID 0x80 0x04 0x00 0x2C
    WriteUserID 0x80 0x01 0x07 0x00

    */
  
    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.6 WriteCounter  //P.62

     /*
    TO-DO  ->FUNCTIONS  FOR Creating or writing to a counter object.

    */
 
    //4.12 Crypto operations AES/DES  //4.12.4 CipherOneShot - Encrypt or decrypt data in one shot mode //P.87

    /* 
        fn encrypt_aes_oneshot(
            &mut self,
            data: &[u8],
            enc: &mut [u8],
            delay: &mut DelayWrapper,
        ) -> Result<(), Se050Error>;
    */

    //fn encrypt_aes_oneshot( &mut self,   data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    fn encrypt_aes_oneshot( &mut self,   cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    fn decrypt_aes_oneshot( &mut self,   cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    
    fn encrypt_des_oneshot( &mut self,   cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
    fn decrypt_des_oneshot( &mut self,   cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper,) -> Result<(), Se050Error>;
         

    // See AN12413, //4.19 Generic management commands // P110-11
    fn get_random(&mut self, buf: &mut [u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //AN12413, // 4.19 Generic management commands //4.19.1 GetVersion  P.108 -109  
    fn get_version(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> ;
    
    //AN12413, // 4.19 Generic management commands //4.19.2 get_timestamp P.109
    fn get_timestamp(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> ;
    
    //AN12413, // 4.19 Generic management commands //4.19.2 GetTimestamp P.109 
    fn get_free_memory(&mut self, memoryconstant: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> ;


    //AN12413, // 4.19 Generic management commands //44.19.5 delete_all P.112
    fn delete_all(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> ;
 
    }
 
//struct Se050AppInfo ->no further Implementation 20221026
#[allow(dead_code)]
#[derive(Debug)]
pub struct Se050AppInfo {
    applet_version: u32,
    features: u16,
    securebox_version: u16,
}
//STRUCT SE050
pub struct Se050<T>
where
    T: T1Proto,
{
    t1_proto: T,
    atr_info: Option<AnswerToReset>,
    app_info: Option<Se050AppInfo>,
}
 
//impl- > for struct SE050 ->new function
impl<T> Se050<T>
where
    T: T1Proto,
{
    pub fn new(t1: T) -> Se050<T> {
        Se050 {
            t1_proto: t1,
            atr_info: None,
            app_info: None,
        }
    }
}
//impl- > for struct SE050 ->functions
impl<T> Se050Device for Se050<T>
where
    T: T1Proto,
{
    fn enable(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        hprint!("Enable 1");
        /* Step 1: perform interface soft reset, parse ATR */
        let r = self.t1_proto.interface_soft_reset(delay);
        hprint!("Enable 2");
        if r.is_err() {
            error!("SE050 Interface Reset Error");
            return Err(Se050Error::UnknownError);
        }
        hprint!("Enable 3");
        self.atr_info = r.ok();
        debug!("SE050 ATR: {:?}", self.atr_info.as_ref().unwrap());
        hprint!("Enable 4");
        /* Step 2: send GP SELECT to choose SE050 JCOP APP, parse APP version */
        let app_id: [u8; 16] = [
            0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00,
            0x00, 0x00,
        ];
        let app_select_apdu = RawCApdu {
            cla: ApduClass::StandardPlain,
            ins: ApduStandardInstruction::SelectFile.into(),
            p1: 0x04,
            p2: 0x00,
            data: &app_id,
            le: Some(0),
        };
        hprint!("Enable 5");
        self.t1_proto.send_apdu_raw(&app_select_apdu, delay).map_err(|_| Se050Error::UnknownError)?;
        hprint!("Enable 6");
        let mut appid_data: [u8; 11] = [0; 11];
        let appid_apdu = self.t1_proto
            .receive_apdu_raw(&mut appid_data, delay)
            .map_err(|_| Se050Error::UnknownError)?;
            hprint!("Enable 7");
        let adata = appid_apdu.data;
        let asw = appid_apdu.sw;
        if asw != 0x9000 || adata.len() != 7 {
            error!("SE050 GP SELECT Err: {:?} {:x}", delog::hex_str!(adata), asw);
            return Err(Se050Error::UnknownError);
        }
        hprint!("Enable 8");
        self.app_info = Some(Se050AppInfo {
            applet_version: BE::read_uint(&adata[0..3], 3) as u32,
            features: BE::read_u16(&adata[3..5]),
            securebox_version: BE::read_u16(&adata[5..7]),
        });
        hprint!("Enable 9");
        debug!("SE050 App: {:?}", self.app_info.as_ref().unwrap());

        Ok(())
    }

    fn disable(&mut self, _delay: &mut DelayWrapper) {
        // send S:EndApduSession
        // receive ACK
        // power down
    }

//###########################################################################
//See AN12413, 4.5 Session management // 4.5.1 Generic session commands //4.5.1.1 create_session P.48
// Creates a session on SE050.
//Depending on the authentication object being referenced, a specific method of authentication applies. 
//The response needs to adhere to this authentication method.

// authentication object identifier -> authobjid


#[inline(never)]
fn create_session(&mut self,  authobjid: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &authobjid);
   
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt ) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::SessionCreate.into(),
        Some(0x0C)
    );
    capdu.push(tlv1);
   
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 create_session Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 create_session OK");
    Ok(())
}


//###########################################################################
//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.2 exchange_session_data P.49
// Sets session policies for the current session.
 // Session policies ->session_policies

#[inline(never)]
fn exchange_session_data(&mut self, session_policies: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &session_policies);
   
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt ) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::SessionPolicy.into(),
        Some(0)
    );
    capdu.push(tlv1);
   
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 exchange_session_data Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 exchange_session_data OK");
    Ok(())
}


     //###########################################################################
    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands /4.5.1.3 process_session_cmd P.49-50
    //Requests a command to be processed within a specific session. 
    //Note that the applet does not check the validity of the CLA byte of the TLV[TAG_1] payload.

     #[inline(never)]
     
     fn process_session_cmd(&mut self,apducommand : &[u8], session_id : &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

         let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &apducommand);

         let tlv = SimpleTlv::new(Se050TlvTag::SessionID.into(), &session_id);	

        
         let mut capdu = CApdu::new(
             ApduClass::ProprietaryPlain,
             Into::<u8>::into(Se050ApduInstruction::Process) | APDU_INSTRUCTION_TRANSIENT,
             Se050ApduP1CredType::Default.into(),
             Se050ApduP2::Default.into(),
             Some(0)
         );
         capdu.push(tlv1);
         capdu.push(tlv);
     
         self.t1_proto
             .send_apdu(&capdu, delay)
             .map_err(|_| Se050Error::UnknownError)?;
 
         let mut rapdu_buf: [u8; 16] = [0; 16];
         let rapdu = self.t1_proto
             .receive_apdu(&mut rapdu_buf, delay)
             .map_err(|_| Se050Error::UnknownError)?;
 
         if rapdu.sw != 0x9000 {
             error!("SE050 process_session_cmd: {:x}", rapdu.sw);
             return Err(Se050Error::UnknownError);
         }
 
         debug!("SE050 process_session_cmd OK");
         Ok(())
     }
 
 //###########################################################################

//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 refresh_session P.50

#[inline(never)]
     
fn refresh_session(&mut self,policy: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

    let tlv = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
 
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2:: SessionRefresh.into(),
        None
    );
    capdu.push(tlv);
    

    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 refresh_session: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 refresh_session OK");
    Ok(())
}

 //###########################################################################

//See AN12413 , 4.5 Session management // 4.5.1 Generic session commands 4.5.1.5 CloseSession P.50
//Closes a running session.
//When a session is closed, it cannot be reopened.
//All session parameters are transient.
//If CloseSession returns a Status Word different from SW_NO_ERROR, the applet immediately needs to be reselected as further APDUs would not be handled successfully.
 

#[inline(never)]
#[allow(unused_mut)]
fn close_session(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
   
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::SessionClose.into(),
        None
    );
    
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 close_session: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050close_session OK");
    Ok(())
}


 //###########################################################################

 //See AN12413 , 4.5 Session management //4.5.2 UserID session operations // 4.5.2.1 VerifySessionUserID P.51-52

 #[inline(never)]
 
 fn verify_session_user_id(&mut self, user_idvalue: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
     let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &user_idvalue);
      
     let mut capdu = CApdu::new(
         ApduClass::ProprietaryPlain,
         Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
         Se050ApduP1CredType::Default.into(),
         Se050ApduP2::SessionUserID.into(),
         None
     );
     capdu.push(tlv1);
      
     self.t1_proto
         .send_apdu(&capdu, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     let mut rapdu_buf: [u8; 16] = [0; 16];
     let rapdu = self.t1_proto
         .receive_apdu(&mut rapdu_buf, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     if rapdu.sw != 0x9000 {
         error!("SE050 verify_session_user_id Failed: {:x}", rapdu.sw);
         return Err(Se050Error::UnknownError);
     }

     debug!("SE050 verify_session_user_id OK");
     Ok(())
 }


 //4.5.3 AESKey session operations // 4.5.3.1 SCPInitializeUpdate  P.52
  //[SCP03] Section 7.1.1 shall be applied.
// The user shall always set the P1 parameter to ‘00’ (KVN = ‘00’).


 //4.5.3.2 SCPExternalAuthenticate  P.52
 //[SCP03] Section 7.1.2 shall be applied.


 // 4.5.4 ECKey session operations // 4.5.4.1 ECKeySessionInternalAuthenticate P.52
 
 //Initiates an authentication based on an ECKey Authentication Object. 
 //See  Section 3.6.3.3 for more information.
 //The user shall always use key version number = ‘00’ and key identifier = ‘00’.


 //###########################################################################
  //See AN12413 , 4.5.4 ECKey session operations //  4.5.4.1 ECKeySessionInternalAuthenticate P.52-53
 // Initiates an authentication based on an ECKey Authentication Object. e
 //See  Section 3.6.3.3 for more information.
// The user shall always use key version number = ‘00’ and key identifier = ‘00’.
//Payload TLV[TAG_1] Input data (see Table 73) P.53.
//InstructECKSIA = 0x88

#[inline(never)]
 
    fn eckey_session_internal_authenticate(&mut self, input_data: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &input_data);
        
        let mut capdu = CApdu::new(
            ApduClass::ProprietarySecure,
            Into::<u8>::into(Se050ApduInstruction::InstructECKSIA) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),   
            Some(0)
        );

        capdu.push(tlv1);
        
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 eckey_session_internal_authenticate Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 eckey_session_internal_authenticate OK");
        Ok(())
    }


//###########################################################################
  //See AN12413 ,  4.5.4 ECKey session operations //   4.5.4.2 eckey_session_get_eckapublic_key P.53-54
  //  Gets the public key of the static device key pair (either     RESERVED_ID_ECKEY_SESSION or RESERVED_ID_EXTERNAL_IMPORT).
  //  The key identifier used in subTag 0x83 must be either:
  //  • 0x00 for user authentication.
 //   • 0x02 for ImportExternalObject (i.e., single side import) only.
  //  Note that any key identifier value different from 0x02 or 0x00 is RFU, but if passed, it is  treated as user authentication (so equal to 0x00).
//InstructECKSGECKAPK=0xCA 

  #[inline(never)]
 
  fn eckey_session_get_eckapublic_key(&mut self, input_data: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

      let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &input_data);
             
      let mut capdu = CApdu::new(
          ApduClass::ProprietarySecure,
          Into::<u8>::into(Se050ApduInstruction:: InstructECKSGECKAPK) | APDU_INSTRUCTION_TRANSIENT,
          Se050ApduP1CredType::EcksgeckapkP1.into(),
          Se050ApduP2::ECKSGECKAPK_P2.into(),
          Some(0)
      );

      capdu.push(tlv1);
      
      self.t1_proto
          .send_apdu(&capdu, delay)
          .map_err(|_| Se050Error::UnknownError)?;

      let mut rapdu_buf: [u8; 16] = [0; 16];
      let rapdu = self.t1_proto
          .receive_apdu(&mut rapdu_buf, delay)
          .map_err(|_| Se050Error::UnknownError)?;

      if rapdu.sw != 0x9000 {
          error!("SE050 eckey_session_get_eckapublic_key Failed: {:x}", rapdu.sw);
          return Err(Se050Error::UnknownError);
      }

      debug!("SE050 eckey_session_get_eckapublic_key OK");
      Ok(())
  }

 
 //###########################################################################
 /*  
 #[inline(never)]
 /* ASSUMPTION: SE050 is provisioned with an instantiated ECC curve object; */
        /* NOTE: hardcoded Object ID 0xae51ae51! */
  //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey    P.58
 //P1_EC 4.3.19 ECCurve P.42
 fn generate_eccurve_key(&mut self,  eccurve: &[u8],delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
     let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
     let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &eccurve );	// Se050ECCurveconstants
     let mut capdu = CApdu::new(
         ApduClass::ProprietaryPlain,
         Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
         Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
         Se050ApduP2::Default.into(),
         None
     );
     capdu.push(tlv1);
     capdu.push(tlv2);
     self.t1_proto
         .send_apdu(&capdu, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     let mut rapdu_buf: [u8; 16] = [0; 16];
     let rapdu = self.t1_proto
         .receive_apdu(&mut rapdu_buf, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     if rapdu.sw != 0x9000 {
         error!("SE050 GenECCurve {:x} Failed: {:x}", eccurve, rapdu.sw);
         return Err(Se050Error::UnknownError);
     }

     debug!("SE050 GenEccurve {:x} : OK",eccurve);
     Ok(ObjectId([0xae, 0x51, 0xae, 0x51]))
 }
 */




 //###########################################################################
 #[inline(never)]
 /* ASSUMPTION: SE050 is provisioned with an instantiated ECC curve object; */
        /* NOTE: hardcoded Object ID 0xae51ae51! */
  //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey    P.58
 //P1_EC 4.3.19 ECCurve P.42
 fn generate_eccurve_key(&mut self, objectid: &[u8;4], eccurve: &[u8],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
     let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
     let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &eccurve );	// Se050ECCurveconstants
     let mut capdu = CApdu::new(
         ApduClass::ProprietaryPlain,
         Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
         Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
         Se050ApduP2::Default.into(),
         None
     );
     capdu.push(tlv1);
     capdu.push(tlv2);
     self.t1_proto
         .send_apdu(&capdu, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     let mut rapdu_buf: [u8; 16] = [0; 16];
     let rapdu = self.t1_proto
         .receive_apdu(&mut rapdu_buf, delay)
         .map_err(|_| Se050Error::UnknownError)?;

     if rapdu.sw != 0x9000 {
         error!("SE050 GenECCurve {:x} Failed: {:x}", eccurve, rapdu.sw);
         return Err(Se050Error::UnknownError);
     }

     debug!("SE050 GenEccurve {:x} : OK",eccurve);
     Ok(())
 }





  
/*  

     //###########################################################################
    #[inline(never)]
    /* ASSUMPTION: SE050 is provisioned with an instantiated P-256 curve object;
        see NXP AN12413 -> Secure Objects -> Default Configuration */
    /* NOTE: hardcoded Object ID 0xae51ae51! */
     //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey   P.58
      //P1_EC //  4.3.19 ECCurve NIST_P256 P.42
    fn generate_p256_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x03]);	// NIST P-256
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
            Se050ApduP2::Default.into(),
            None
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 GenP256 Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 GenP256 OK");
        Ok(ObjectId([0xae, 0x51, 0xae, 0x51]))
    }

*/

   //###########################################################################
   #[inline(never)]
   /* ASSUMPTION: SE050 is provisioned with an instantiated P-256 curve object;
       see NXP AN12413 -> Secure Objects -> Default Configuration */
   /* NOTE: hardcoded Object ID 0xae51ae51! */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey   P.58
     //P1_EC //  4.3.19 ECCurve NIST_P256 P.42
   fn generate_p256_key(&mut self, objectid: &[u8;4],delay: &mut DelayWrapper) -> Result<(), Se050Error> {
       let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
       let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x03]);	// NIST P-256
       let mut capdu = CApdu::new(
           ApduClass::ProprietaryPlain,
           Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
           Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
           Se050ApduP2::Default.into(),
           None
       );
       capdu.push(tlv1);
       capdu.push(tlv2);
       self.t1_proto
           .send_apdu(&capdu, delay)
           .map_err(|_| Se050Error::UnknownError)?;

       let mut rapdu_buf: [u8; 16] = [0; 16];
       let rapdu = self.t1_proto
           .receive_apdu(&mut rapdu_buf, delay)
           .map_err(|_| Se050Error::UnknownError)?;

       if rapdu.sw != 0x9000 {
           error!("SE050 GenP256 Failed: {:x}", rapdu.sw);
           return Err(Se050Error::UnknownError);
       }

       debug!("SE050 GenP256 OK");
       Ok(())
   }

 



//###########################################################################

    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
      //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60 
      //P1_AES //template for 
    fn write_aes_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        if key.len() != 16 {
            todo!();
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::AES.into(),
            Se050ApduP2::Default.into(),
            Some(0)
        );
        capdu.push(tlv1);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 WriteAESKey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }


    //##################################################

    //ERWEITERT
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60 
    //P1_DES
    fn write_des_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        if key.len() != 16 {
            todo!();
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::DES.into(),
            Se050ApduP2::Default.into(),
            Some(0)
        );
        capdu.push(tlv1);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 WriteDESKey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //##################################################   

    //ERWEITERT
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60 
    //P1_HMAC
    fn write_hmac_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
    if key.len() != 16 {
        todo!();
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::HMAC.into(),
        Se050ApduP2::Default.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 WriteHMACKey Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    Ok(())
    }

 
/*  
  //###########################################################################
  
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    //4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT//  4.3.21 CipherMode // AES CBC NOPAD
    fn encrypt_aes_oneshot(&mut self, data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
    {
        if data.len() > 240 || (data.len() % 16 != 0) {
            error!("Input data too long or unaligned");
            return Err(Se050Error::UnknownError);
        }
        if enc.len() != data.len() {
            error!("Insufficient output buffer");
            return Err(Se050Error::UnknownError);
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x0d]);	// AES CBC NOPAD
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Crypto.into(),
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::EncryptOneshot.into(),
            Some(0)
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 EncryptAESOneshot Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 EncryptAESOneshot Return TLV Missing");
            Se050Error::UnknownError })?;

        if tlv1_ret.get_data().len() != enc.len() {
            error!("SE050 EncryptAESOneshot Length Mismatch");
            return Err(Se050Error::UnknownError);
        }
        enc.copy_from_slice(tlv1_ret.get_data());
        debug!("SE050 EncryptAESOneshot OK");
        Ok(())
    }
 */

// VerifySessionUserID 0x80 0x04 0x00 0x2C


#[inline(never)]
//WriteUserID 0x80 0x01 0x07 0x00
/* NOTE: hardcoded Object ID 0xae51ae51! */
// See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject P.57 //4.7.1.5 WriteUserID  //P.62
fn write_user_id(&mut self, user_identifier_value : &[u8], delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &user_identifier_value );	 
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::UserID.into(),
        Se050ApduP2::Default.into(),
        None
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 write_user_id  Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 write_user_id OK");
    Ok(ObjectId([0xae, 0x51, 0xae, 0x51]))
}


//###########################################################################
  
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT P.87
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn encrypt_aes_oneshot(&mut self,  cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), & cipher_mode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::EncryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 EncryptAESOneshot {:x} Failed: {:x}",  cipher_mode, rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 EncryptAESOneshot Return TLV Missing");
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 EncryptAESOneshot Length Mismatch");
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 EncryptAESOneshot {:x} OK",  cipher_mode );
    Ok(())
}


//###########################################################################
//ERWEITERT
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // DECRYPT P.87
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn decrypt_aes_oneshot(&mut self,  cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(),  & cipher_mode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::DecryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 DecryptAESOneshot {:x}, Failed: {:x}",  cipher_mode,rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 DecryptAESOneshot_{:x} Return TLV Missing",   cipher_mode);
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 DecryptAESOneshot {:x} Length Mismatch",  cipher_mode );
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 DecryptAESOneshot {:x} OK", cipher_mode );
    Ok(())
}


//###########################################################################
  
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT  P.87
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn encrypt_des_oneshot(&mut self,  cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), & cipher_mode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::EncryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 EncryptDESOneshot {:x} Failed: {:x}",  cipher_mode, rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 EncryptDESOneshot Return TLV Missing");
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 EncryptDESOneshot Length Mismatch");
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 EncryptDESOneshot {:x} OK",  cipher_mode );
    Ok(())
}


//###########################################################################
//ERWEITERT
#[inline(never)]
/* NOTE: hardcoded Object ID 0xae50ae50! */
//4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // DECRYPT P.87 
//  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
fn decrypt_des_oneshot(&mut self,  cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> 
{
    if data.len() > 240 || (data.len() % 16 != 0) {
        error!("Input data too long or unaligned");
        return Err(Se050Error::UnknownError);
    }
    if enc.len() != data.len() {
        error!("Insufficient output buffer");
        return Err(Se050Error::UnknownError);
    }
    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
    let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(),  & cipher_mode);	// 4.3.21 CipherMode Table 39. CipherMode constants
    let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Se050ApduInstruction::Crypto.into(),
        Se050ApduP1CredType::Cipher.into(),
        Se050ApduP2::DecryptOneshot.into(),
        Some(0)
    );
    capdu.push(tlv1);
    capdu.push(tlv2);
    capdu.push(tlv3);
    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 260] = [0; 260];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 DecryptDESOneshot {:x}, Failed: {:x}",  cipher_mode,rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
        error!("SE050 DecryptDESOneshot_{:x} Return TLV Missing",   cipher_mode);
        Se050Error::UnknownError })?;

    if tlv1_ret.get_data().len() != enc.len() {
        error!("SE050 DecryptDESOneshot {:x} Length Mismatch",  cipher_mode );
        return Err(Se050Error::UnknownError);
    }
    enc.copy_from_slice(tlv1_ret.get_data());
    debug!("SE050 DecryptDESOneshot {:x} OK", cipher_mode );
    Ok(())
}

//###########################################################################
 //AN12413 // 4.6 Module management  //4.6.3 SetAppletFeatures  P.56 -57
 // Sets the applet features that are supported. 
 // To successfully execute this command, the session must be authenticated using the RESERVED_ID_FEATURE.
//The 2-byte input value is a pre-defined AppletConfig value.


     #[inline(never)]    
    fn set_applet_features(&mut self,applet_config: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &applet_config);
       
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),
            None
        );
        capdu.push(tlv1);
         
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050  set_applet_features Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050  set_applet_features OK");
        Ok(())
    }




//###########################################################################
    //AN12413, // 4.19 Generic management commands //4.19.1 GetVersion  P.108 -109
   // Gets the applet version information.
   // This will return 7-byte VersionInfo (including major, minor and patch version of the applet,  supported applet features and secure box version).
//Le 0x0B Expecting TLV with 7-byte data

#[inline(never)]
#[allow(unused_mut)]
fn get_version(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {

    
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2:: Version.into(),
        Some(0x0B)
    );

    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 get_version Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 get_version OK");
    Ok(())
}


 //###########################################################################
 //AN12413, // 4.19 Generic management commands //4.19.2 GetTimestamp P.109
//Gets a monotonic counter value (time stamp) from the operating system of the device (both persistent and transient part). 
//See TimestampFunctionality for details on the timestamps.


#[inline(never)]
#[allow(unused_mut)]
fn get_timestamp(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {

    
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::Time.into(),
        Some(0x14)
    );

    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 get_timestamp Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 get_timestamp OK");
    Ok(())
}

 //###########################################################################
 //AN12413, // 4.19 Generic management commands //4.19.2 GetTimestamp P.109
//Gets the amount of free memory. 
//MemoryType indicates the type of memory.

//The result indicates the amount of free memory. 
//Note that behavior of the function might not be fully linear
//and can have a granularity of 16 bytes since the applet will typically report the “worst case” amount. 
//For example, when allocating 2 bytes at a time, the first report will show 16 bytes being allocated, which remains the same for the next 7 allocations of 2 bytes.

//  memoryconstant      Persistent = 1,   TransientReset = 2,    TransientDeselect = 3,
 

#[inline(never)]

fn get_free_memory(&mut self, memoryconstant: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

    let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &memoryconstant);

    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::Memory.into(),
        Some(0x06)
    );

    capdu.push(tlv1);

    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 get_free_memory Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 get_free_memory OK");
    Ok(())
}


 
 //###########################################################################
    //AN12413, Pages 110/111 -> 4.19 Generic management commands //4.19.4 GetRandom (Gets random data from the SE050.) p.110
    #[inline(never)]
    fn get_random(&mut self, buf: &mut [u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut buflen: [u8; 2] = [0, 0];
        BE::write_u16(&mut buflen, buf.len() as u16);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &buflen);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Mgmt.into(),
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Random.into(),
            Some(0)
        );
        capdu.push(tlv1);
        self.t1_proto.send_apdu(&capdu, delay).map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self.t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 GetRandom Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 GetRandom Return TLV Missing");
            Se050Error::UnknownError })?;

        if tlv1_ret.get_data().len() != buf.len() {
            error!("SE050 GetRandom Length Mismatch");
            return Err(Se050Error::UnknownError);
        }
        buf.copy_from_slice(tlv1_ret.get_data());
        debug!("SE050 GetRandom OK");
        Ok(())
    }
 


 //###########################################################################
 //AN12413, // 4.19 Generic management commands //44.19.5 DeleteAll P.112
 /* 
 Delete all Secure Objects, delete all curves and Crypto Objects. 
 Secure Objects that are trust provisioned by NXP are not deleted 
 (i.e., all objects that have Origin set to ORIGIN_PROVISIONED, 
 including the objects with reserved object identifiers listed in Object attributes).
 This command can only be used from sessions that are authenticated using the credential with index RESERVED_ID_FACTORY_RESET.
 Important: if a secure messaging session is up & running (e.g., AESKey or ECKey session) 
 and the command is sent within this session, 
 the response of the DeleteAll command will not be wrapped 
 (i.e., not encrypted and no R-MAC), 
 so this will also break down the secure channel protocol 
 (as the session is closed by the delete_all command itself).
 */

#[inline(never)]
#[allow(unused_mut)]
fn delete_all(&mut self,  delay: &mut DelayWrapper) -> Result<(), Se050Error> {

    
    let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::DeleteAll.into(),
        Some(0x00)
    );

    self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    let mut rapdu_buf: [u8; 16] = [0; 16];
    let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

    if rapdu.sw != 0x9000 {
        error!("SE050 delete_all Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
    }

    debug!("SE050 delete_all OK");
    Ok(())
}

}
