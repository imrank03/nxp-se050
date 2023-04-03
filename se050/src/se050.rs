use crate::types::*;
use byteorder::{ByteOrder, BE};
use core::convert::{From, TryFrom};

#[derive(Debug, PartialEq, Eq)]
pub enum Se050Error {
    UnknownError,
    T1Error(T1Error),
}

//SEE AN12413 P. 34 - Table 15. Error codes
#[allow(dead_code)]
#[repr(u16)]

pub enum Se050ApduError {
    SwNoError = 0x9000,
    SwConditionsNotSatisfied = 0x6985,

    SwSecurityStatus = 0x6982,
    SwWrongData = 0x6A80,
    SwDataInvalid = 0x6984,
    SwCommandNotAllowed = 0x6986,
}

//SEE AN12413 P. 34 - Table 17. Instruction mask constants
#[allow(dead_code)]
pub const INS_MASK_INS_CHAR: u8 = 0xE0;
#[allow(dead_code)]
pub const INS_MASK_INSTRUCTION: u8 = 0x1F;

//SEE AN12413 P. 34 - Table 18. Instruction characteristics constants

pub const APDU_INSTRUCTION_TRANSIENT: u8 = 0x80;

#[allow(dead_code)]
pub const APDU_INSTRUCTION_AUTH_OBJECT: u8 = 0x40;
#[allow(dead_code)]
pub const APDU_INSTRUCTION_ATTEST: u8 = 0x20;

//See AN12413,- 4.3.3 Instruction - Table 19. Instruction constants P. 35
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
    InstructApplet = 0xA4,
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
    SigEcdaa = 0xF4,
}

// See AN12413, 4.3.13 RSASignatureAlgo Table 31. RSASignatureAlgo P.40
//See AN12413, 4.3.22 AttestationAlgo AttestationAlgo is either ECSignatureAlgo or RSASignatureAlgo. P.43
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050RSASignatureAlgo {
    RsaSha1Pkcs1Pss = 0x15,
    RsaSha224Pkcs1Pss = 0x2B,
    RsaSha256Pkcs1Pss = 0x2C,
    RsaSha384Pkcs1Pss = 0x2D,
    RsaSha512Pkcs1Pss = 0x2E,
    RsaSha1Pkcs1 = 0x0A,
    RsaSha224Pkcs1 = 0x27,
    RsaSha256Pkcs1 = 0x28,
    RsaSha384Pkcs1 = 0x29,
    RsaSha512Pkcs1 = 0x2A,
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
    RsaCompMod = 0x00,
    RsaCompPubExp = 0x01,
    RsaCompPrivExp = 0x02,
    RsaCompP = 0x03,
    RsaCompQ = 0x04,
    RsaCompDp = 0x05,
    RsaCompDq = 0x06,
    RsaCompInvq = 0x07,
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
    DigestSha512 = 0x06,
}

// See AN12413, 4.3.18 MACAlgo Table 36. MACAlgo constants P.41- 42
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050MACAlgoconstants {
    HmacSha = 0x18,
    HmacSha256 = 0x19,
    HmacSha384 = 0x1A,
    HmacSha512 = 0x1B,
    Cmac128 = 0x31, //CMAC128 = 0x31,
    DesMac4Iso9797M2 = 0x05,
    DesMac4Iso9797_1M2Alg3 = 0x13,
    DesMac4Iso9797M1 = 0x03,
    DesMac4Iso9797_1M1Alg3 = 0x2F,
    DesMac8Iso9797M2 = 0x06,
    DesMac8Iso9797_1M2Alg3 = 0x14,
    DesMac8Iso9797_1M1Alg3 = 0x04, // DES_MAC8_ISO9797_1_M1_ALG3 = 0x30,
    DesCmac8 = 0x7A,
    AesCmac16 = 0x66,
}

// See AN12413,4.3.19 ECCurve Table 37. ECCurve constants   P.42
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050ECCurveconstants {
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

    Secp160k1 = 0x0D,
    Secp192k1 = 0x0E,
    Secp224k1 = 0x0F,
    Secp256k1 = 0x10,

    TpmEccBnP256 = 0x11,
    IdEccEd25519 = 0x40,
    IdEccMontDh25519 = 0x41,
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
pub enum Se050CipherModeconstants {
    DesCbcNopad = 0x01,
    DesCbcIso9797M1 = 0x02,
    DesCbcIso9797M2 = 0x03,
    DesCbcPkcs5 = 0x04,
    DesEcbNopad = 0x05,
    DesEcbIso9797M1 = 0x06,
    DesEcbIso9797M2 = 0x07,
    DesEcbPkcs5 = 0x08,
    AesEcbNopad = 0x0E,
    AesCbcNopad = 0x0D,
    AesCbcIso9797M1 = 0x16,
    AesCbcIso9797M2 = 0x17,
    AesCbcPkcs5 = 0x18,
    AesCtr = 0xF0,
}

// See AN12413,4.3.23 // 4.3.22 AttestationAlgo // AttestationAlgo is either ECSignatureAlgo or RSASignatureAlgo.

// See AN12413,4.3.23 AppletConfig Table 40. Applet configurations   P.43-44
#[allow(dead_code)]
#[repr(u16)]
pub enum Se050AppletConfig {
    ConfigEcdaa = 0x0001,
    ConfigEcdsaEcdhEcdhe = 0x0002,
    ConfigEddsaA = 0x0004,
    ConfigDhMont = 0x0008,
    ConfigHmac = 0x0010,
    ConfigRsaPlain = 0x0020,
    ConfigRsaCrt = 0x0040,
    ConfigAes = 0x0080,

    ConfigDes = 0x0100,
    ConfigPbkdf = 0x0200,
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
pub enum Se050LockIndicatorconstants {
    TransientLock = 0x01,
    PersistentLock = 0x02,
}

// See AN12413,  4.3.25 ,   Table 42. LockState constants   P.44
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050LockStateconstants {
    LOCKED = 0x01,
    UNLOCKED = 0x02,
}

// See AN12413,   4.3.26 CryptoContext , Table 43. P.44
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050CryptoContextconstants {
    CcDigest = 0x01,
    CcCipher = 0x02,
    CcSignature = 0x03,
}

// See AN12413,  4.3.27 Result  Table 44. Result constants P.44
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050Resultconstants {
    ResultSuccess = 0x01,
    ResultFailure = 0x02,
}

// See AN12413,4.3.28  TransientIndicator, Table 45. TransientIndicator constants P.44
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050TransientIndicatorconstants {
    PERSISTENT = 0x01,
    TRANSIENT = 0x02,
}

// See AN12413,4.3.28, 4.3.29 SetIndicator  Table 46. SetIndicator constants P.45
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050SetIndicatorconstants {
    NotSet = 0x01,
    SET = 0x02,
}

// See AN12413,4.3.28, 4.3.30 MoreIndicator   Table 47. MoreIndicator constants   P.45
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050MoreIndicatorconstants {
    NoMore = 0x01,
    MORE = 0x02,
}

// See AN12413,4.3.28, 4.3.31 PlatformSCPRequest , Table 48. PlatformSCPRequest constants P.45
#[allow(dead_code)]
#[repr(u8)]
pub enum Se050PlatformSCPRequestconstants {
    ScpRequired = 0x01,
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
pub enum Se050Sessionpolicies {
    //RFU = 0x80 ,
    //RFU = 0x40 ,
    PolicySessionMaxApdu = 0x80,

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
    PolicyObjForbidAll = 0x20,
    PolicyObjAllowSign = 0x10,

    PolicyObjAllowVerify = 0x08,
    PolicyObjAllowKa = 0x04,
    PolicyObjAllowEnc = 0x02,
    PolicyObjAllowDec = 0x01,

    PolicyObjAllowKdf = 0x8000,
    PolicyObjAllowWrap = 0x4000,
    PolicyObjAllowRead = 0x2000,
    PolicyObjAllowWrite = 0x1000,

    PolicyObjAllowGen = 0x0800,
    PolicyObjAllowDelete = 0x0400,
    PolicyObjRequireSm = 0x0200,
    PolicyObjRequirePcrValue = 0x0100,

    PolicyObjAllowAttestation = 0x800000,
    PolicyObjAllowDesfireAuthentication = 0x400000,
    PolicyObjAllowDesfireDumpSessionKeys = 0x200000,
    PolicyObjAllowImportExport = 0x100000,
    //RFU = 0x080000 ,
    //RFU = 0x040000 ,
    //RFU = 0x020000 ,
    //RFU = 0x010000 ,
}

#[allow(dead_code)]
#[repr(u8)]
pub enum Se050keyversionnumber {
    KeyVersionNumber00 = 0x00,
}

include!("se050_convs.rs");

//////////////////////////////////////////////////////////////////////////////
//trait-Se050Device ->  struct Se050
pub trait Se050Device {
    //OLD VERSION
    fn enable(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;
    //OLD VERSION
    fn disable(&mut self, _delay: &mut DelayWrapper);

    //See AN12413, //  4.4 Applet selection P.47-48
    /*
    TO DO
    */

    //See AN12413,4.5 Session management

    //See AN12413,4.5 Session management // 4.5.1 Generic session commands //4.5.1.1 CreateSession P.48
    fn create_session(
        &mut self,
        authobjectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,4.5 Session management // 4.5.1 Generic session commands //4.5.1.2 ExchangeSessionData P.49
    fn exchange_session_data(
        &mut self,
        session_policies: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands /4.5.1.3 process_session_cmd P.49-50
    fn process_session_cmd(
        &mut self,
        apducommand: &[u8],
        session_id: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 RefreshSession P.50
    fn refresh_session(
        &mut self,
        policy: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 , 4.5 Session management // 4.5.1 Generic session commands //4.5.1.4 RefreshSession P.50
    fn close_session(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413 , 4.5 Session management //4.5.2 UserID session operations // 4.5.2.1 VerifySessionUserID P.51-52
    fn verify_session_user_id(
        &mut self,
        user_idvalue: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 , 4.5.4 ECKey session operations //  4.5.4.1 ECKeySessionInternalAuthenticate P.52
    fn eckey_session_internal_authenticate(
        &mut self,
        input_data: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 ,  4.5.4 ECKey session operations //   4.5.4.2 eckey_session_get_eckapublic_key P.53-54
    fn eckey_session_get_eckapublic_key(
        &mut self,
        input_data: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 , 4.6 Module management

    //See AN12413 , 4.6 Module management //   4.6.1 SetLockState P.54-55
    fn set_lock_state(
        &mut self,
        lockindicator: &[u8],
        lockstate: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 , 4.6 Module management //   4.6.2 SetPlatformSCPRequest P.55-56
    fn set_platform_scp_request(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //AN12413 // 4.6 Module management  //4.6.3 set_applet_features  P.56 -57
    fn set_applet_features(
        &mut self,
        applet_config: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413,  4.7 Secure Object management

    // See AN12413,  4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey //P1_EC ///P.58-59
    // fn generate_eccurve_key(&mut self, eccurve: &[u8], delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>; //ERWEITERT
    fn write_ec_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        eccurve: &[u8],
        private_key_value: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //OLD VERSION
    fn generate_p256_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>;
    //DEFAULT CONFIGURATION OF SE050

    //NEW VERSION
    // fn generate_p256_key(&mut self,policy: &[u8],  objectid: &[u8;4],  private_key_value: &[u8],  delay: &mut DelayWrapper) -> Result<(), Se050Error> ;

    fn generate_ed255_key_pair(&mut self, delay: &mut DelayWrapper)
        -> Result<ObjectId, Se050Error>;

    //AN12413 //4.7 Secure Object management //4.7.1 WriteSecureObject// 4.7.1.2 WriteRSAKey //P.59-60
    fn write_rsa_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        keysize: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey //AES key, DES key or HMAC key // P 60/ P.61

    //OLD VERSION
    fn write_aes_key(&mut self, key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //NEW VERSION
    //  fn write_aes_key(&mut self,policy: &[u8], objectid: &[u8;4],kekid: &[u8;4],key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    fn generate_aes_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error>;

    fn write_des_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        kekid: &[u8; 4],
        key: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    fn write_hmac_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        kekid: &[u8; 4],
        key: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.4 WriteBinary  //P.61
    fn write_binary(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        file_offset: &[u8; 2],
        file_length: &[u8; 2],
        data1: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject P.57 //4.7.1.5 write_user_id  //P.62
    fn write_user_id(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        user_identifier_value: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.6 WriteCounter  //P.62
    fn write_counter(
        &mut self,
        policy: &[u8],
        counterid: &[u8; 4],
        countersize: &[u8; 2],
        counterfile: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject // 4.7.1.7 WritePCR  P.63
    fn write_pcr(
        &mut self,
        policy: &[u8],
        pcrid: &[u8; 4],
        initial_hash_value: &[u8],
        ext: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management // 4.7.1.8  ImportObject P.63-64

    fn import_object(
        &mut self,
        identifier: &[u8; 4],
        rsakeycomponent: &[u8],
        serializedobjectencrypted: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject // 4.7.1.7 WritePCR  P.64
    fn import_external_object(
        &mut self,
        authdata: &[u8],
        hostpublickeyidentifier: &[u8],
        writesecureobjectcommand: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management // 4.7.3 ReadSecureObject //4.7.3.1 ReadObject // P.65-66
    fn read_secure_object(
        &mut self,
        objectidentifier: &[u8; 4],
        offset: &[u8; 2],
        length: &[u8; 2],
        rsakeycomponent: &[u8],
        attobjectidentifier: &[u8; 4],
        attlogo: &[u8],
        freshnessrandom: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.7 Secure Object management // 4.7.3 ReadSecureObject //4.7.3.2 ExportObject // P.67
    fn export_secure_object(
        &mut self,
        objectidentifier: &[u8; 4],
        rsakeycomponent: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.1 ReadType P.67-68
    fn read_type(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject 4.7.4.2 ReadSize P.68
    fn read_size(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.3 ReadIDList P.69
    fn read_id_list(
        &mut self,
        offset: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.4 CheckObjectExists P.70
    fn check_object_exists(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //fn check_object_exists_p256(&mut self, buf: &mut [u8],  delay: &mut DelayWrapper) -> Result< (), Se050Error>;

    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.5 DeleteSecureObject P.70
    fn delete_secure_object(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413//   4.8 EC curve management

    // See AN12413//   4.8 EC curve management // 4.8.1 CreateECCurve -Create an EC curve listed in ECCurve P.71-72
    fn create_eccurve(
        &mut self,
        eccurve: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413//   4.8 EC curve management //  4.8.2 SetECCurveParam -Set a curve parameter. The curve must have been created first by CreateEcCurve. P.72
    fn set_eccurve_param(
        &mut self,
        eccurve: &[u8],
        eccurveptaram: &[u8],
        curveparametervalue: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413//   4.8 EC curve management //  4.8.3 GetECCurveID Get the curve associated with an EC key.. P.72-73
    fn get_eccurve_id(
        &mut self,
        identifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413//   4.8 EC curve management //  4.8.3 GetECCurveID Get the curve associated with an EC key.. P.73
    fn read_eccurve_list(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    // See AN12413//   4.8 EC curve management // 4.8.5 DeleteECCurve - Deletes an EC curve P.74
    fn delete_eccurve(
        &mut self,
        eccurve: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413// 4.9 Crypto Object management

    // See AN12413// 4.9 Crypto Object management // 4.9.1 CreateCryptoObject - Creates a Crypto Object on the SE050. P74-75
    fn create_crypto_object(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        cryptocontext: &[u8],
        cryptoobjectsubtype: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413// 4.9 Crypto Object management // 4.9.2 ReadCryptoObjectList. P.75
    fn read_crypto_object_list(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    // See AN12413// 4.9 Crypto Object management // 4.9.3 DeleteCryptoObject P.75 - 76
    fn delete_crypto_object(
        &mut self,
        cryptoobjectidentifier: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.10 Crypto operations EC // 4.10.1 Signature generation // 4.10.1.1 ECDSASign P.76-77
    fn ecdsa_sign(
        &mut self,
        eckeyidentifier: &[u8; 4],
        ecsignaturealgo: &[u8],
        inputdata: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.10 Crypto operations EC

    // See AN12413 // 4.10 Crypto operations EC // 4.10.1 Signature generation // 4.10.1.2 EdDSASign P.77
    fn eddsa_sign(
        &mut self,
        eckeyidentifier: &[u8; 4],
        edsignaturealgo: &[u8],
        inputdata: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.10 Crypto operations EC // 4.10.1 Signature generation // 4.10.1.3 ECDAASign P.78
    fn ecdaa_sign(
        &mut self,
        eckeyidentifier: &[u8; 4],
        ecdaasignaturealgo: &[u8],
        hashedinputdata: &[u8; 32],
        randomdata: &[u8; 32],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.10 Crypto operations EC // 4.10.2 Signature verification // 4.10.2.1 ECDSAVerify P.79
    fn ecdsa_verify(
        &mut self,
        eckeyidentifier: &[u8; 4],
        ecsignaturealgo: &[u8],
        hashedcomparedata: &[u8],
        asn1signaturedata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.10 Crypto operations EC // 4.10.2 Signature verification // 4.10.2.2 EdDSAVerify P.80
    fn eddsa_verify(
        &mut self,
        eckeyidentifier: &[u8; 4],
        edsignaturealgo: &[u8],
        plaincomparedata: &[u8],
        signaturedata: &[u8; 64],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.10 Crypto operations EC //  4.10.3 Shared secret generation //  4.10.3.1 ECDHGenerateSharedSecret P.81
    fn ecdh_generate_shared_secret(
        &mut self,
        eckeyidentifier: &[u8; 4],
        eckey: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.11 Crypto operations RSA

    // See AN12413 // 4.11 Crypto operations RSA // 4.11.1 Signature Generation //4.11.1.1 RSASign P.82
    fn rsa_sign(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsasignaturealgo: &[u8],
        inputdata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.11 Crypto operations RSA // 4.11.2 Signature Verification  //4.11.2.1 RSAVerify P.82-83
    fn rsa_verify(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsasignaturealgo: &[u8],
        datatobeverified: &[u8],
        asn1signature: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.11 Crypto operations RSA // 4.11.3 Encryption // 4.11.3.1 RSAEncrypt P.83-84
    fn rsa_encrypt(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsaencryptionalgo: &[u8],
        datatobeencrypted: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413 // 4.11 Crypto operations RSA // 4.11.3 Encryption // 4.11.3.2 RSADecrypt P.84
    fn rsa_decrypt(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsaencryptionalgo: &[u8],
        datatobedecrypted: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.12 Crypto operations AES/DES

    //See AN12413 //4.12 Crypto operations AES/DES //4.12.1 CipherInit P.84-85
    fn cipher_init_encrypt(
        &mut self,
        keyobjectidentifier: &[u8; 4],
        cryptoobjectidentifier: &[u8; 2],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;
    fn cipher_init_decrypt(
        &mut self,
        keyobjectidentifier: &[u8; 4],
        cryptoobjectidentifier: &[u8; 2],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.12 Crypto operations AES/DES //4.12.2 CipherUpdate P.85-86
    fn cipher_update(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        inputdata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.12 Crypto operations AES/DES //4.12.3 CipherFinal P.86-87
    fn cipher_final(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        inputdata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.12 Crypto operations AES/DES //4.12.4 CipherOneShot P.87
    fn cipher_one_shot_encrypt(
        &mut self,
        keybjectidentifier: &[u8; 4],
        ciphermode: &[u8],
        inputdata: &[u8],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;
    fn cipher_one_shot_decrypt(
        &mut self,
        keybjectidentifier: &[u8; 4],
        ciphermode: &[u8],
        inputdata: &[u8],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //4.12 Crypto operations AES/DES  //4.12.4 CipherOneShot - Encrypt or decrypt data in one shot mode //P.87
    /*
    //OLD VERSION
        fn encrypt_aes_oneshot(
            &mut self,
            data: &[u8],
            enc: &mut [u8],
            delay: &mut DelayWrapper,
        ) -> Result<(), Se050Error>;
    */
    //OLD VERSION
    fn encrypt_aes_oneshot(
        &mut self,
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //NEW VERSION
    //fn encrypt_aes_oneshot(&mut self, objectid: &[u8;4], cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error> ;
    fn decrypt_aes_oneshot(
        &mut self,
        objectid: &[u8; 4],
        cipher_mode: &[u8],
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    fn encrypt_des_oneshot(
        &mut self,
        objectid: &[u8; 4],
        cipher_mode: &[u8],
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;
    fn decrypt_des_oneshot(
        &mut self,
        objectid: &[u8; 4],
        cipher_mode: &[u8],
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.13 Message Authentication Codes

    //See AN12413 //4.13 Message Authentication Codes //4.13.1 MACInit P.87-88
    fn mac_init(
        &mut self,
        mackeybjectidentifier: &[u8; 4],
        cryptobjectidentifier: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.13 Message Authentication Codes //4.13.1 MACInit P.87-88
    fn mac_update(
        &mut self,
        macdatainput: &[u8],
        cryptobjectidentifier: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.13 Message Authentication Codes //4.13.3 MACFinal P.89
    fn mac_final(
        &mut self,
        macdatainput: &[u8],
        cryptobjectidentifier: &[u8; 2],
        mactovalidate: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.13 Message Authentication Codes //4.13.4 MACOneShot P.90
    fn mac_one_shot(
        &mut self,
        keyobjectidentifier: &[u8; 4],
        macalgo: &[u8],
        datainputtomac: &[u8],
        mactoverify: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.14 Key Derivation Functions

    //See AN12413 //4.14 Key Derivation Functions //4.14.1 HKDF P.90-91
    fn hkdf(
        &mut self,
        hmackeyidentifier: &[u8; 4],
        digestmode: &[u8],
        salt: &[u8; 64],
        info: &[u8; 64],
        requestedlength: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413 //4.14 Key Derivation Functions //4.14.2 PBKDF2 P.91-92
    fn pbkdf2derivekey(
        &mut self,
        passwordidentifier: &[u8; 4],
        salt: &[u8; 64],
        iterationcount: &[u8; 2],
        requestedlength: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.1 DFDiversifyKey P92-95
    fn dfdiversifykey(
        &mut self,
        masterkeyidentifier: &[u8; 4],
        diversifiedkeyidentifier: &[u8; 4],
        divinput: &[u8; 31],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.2 DFAuthenticateFirst  //4.15.2.1 DFAuthenticateFirstPart1 // P.95-96
    fn dfauthenticatefirstpart1(
        &mut self,
        keyidentifier: &[u8; 4],
        diversifiedkeyidentifier: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.2 DFAuthenticateFirst  //4.15.2.2 DFAuthenticateFirstPart2 // P.95-96
    fn dfauthenticatefirstpart2(
        &mut self,
        input: &[u8; 32],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.3 DFAuthenticateNonFirst  //4.15.3.1 DFAuthenticateNonFirstPart1// P.96-97
    fn dfauthenticatenonfirstpart1(
        &mut self,
        keyidentifier: &[u8; 4],
        encryptedcardchallenge: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.3 DFAuthenticateNonFirst  //4.15.3.2 DFAuthenticateNonFirstPart2// P.97
    fn dfauthenticatenonfirstpart2(
        &mut self,
        edata: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.3 DFAuthenticateNonFirst  //4.15.4 DFDumpSessionKeys// P.97-98
    fn dfdumpdsessionkeys(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.5 DFChangeKey// 4.15.5.1 DFChangeKeyPart1 P.98-99
    fn dfchangekeypart1(
        &mut self,
        oldkey: &[u8; 4],
        newkey: &[u8; 4],
        setnumber: &[u8],
        desfirekeynumber: &[u8],
        keyversion: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.5 DFChangeKey// 4.15.5.2 DFChangeKeyPart2 P.99
    fn dfchangekeypart2(&mut self, mac: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413,// 4.15 MIFARE DESFire support //4.15.6 DFKillAuthentication  P.99-100
    fn dfkillauthentication(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413, //4.16 TLS handshake support

    //See AN12413, //4.16 TLS handshake support //  4.16.1 TLSGenerateRandom P.100
    fn tls_generate_random(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //See AN12413, //4.16 TLS handshake support //  4.16.2 TLSCalculatePreMasterSecret P.101
    fn tls_calculate_pre_master_secret(
        &mut self,
        pskidentifier: &[u8; 4],
        keypairidentifier: &[u8; 4],
        hmackeyidentifier: &[u8; 4],
        inputdata: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413, //4.16 TLS handshake support //  4.16.3 TLSPerformPRF P.101-102
    fn tls_perform_prf(
        &mut self,
        hmackeyidentifier: &[u8; 4],
        digestmode: &[u8],
        label: &[u8; 64],
        random: &[u8; 32],
        requestlenght: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413, //4.17 I2C controller support

    //See AN12413, //4.17 I2C controller support //4.17.1 I2CM_ExecuteCommandSet //P.103-106
    fn i2cm_execute_command_set(
        &mut self,
        i2ccommand: &[u8],
        attestationobjectidentifier: &[u8],
        attestationalgo: &[u8],
        freshnessrandom: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413, //4.18 Digest operations

    //AN12413, //4.18 Digest operations 4.18.1 DigestInit // P.106
    fn digest_init(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //AN12413, //4.18 Digest operations //4.18.2 DigestUpdate // P.106-107
    fn digest_update(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        datatobehashed: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //AN12413, //4.18 Digest operations //4.18.3 DigestFinal // P. 107-108
    fn digest_final(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        datatobehashed: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //AN12413, //4.18 Digest operations //4.18.3 DigestFinal // P. 107-108
    fn digest_one_shot(
        &mut self,
        digestmode: &[u8],
        datatobehashed: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    //See AN12413, // 4.19 Generic management commands

    //AN12413, // 4.19 Generic management commands //4.19.1 GetVersion  P.108 -109
    fn get_version(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //AN12413, // 4.19 Generic management commands //4.19.2 get_timestamp P.109
    fn get_timestamp(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //AN12413, // 4.19 Generic management commands //4.19.2 GetTimestamp P.109
    fn get_free_memory(
        &mut self,
        memoryconstant: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error>;

    // See AN12413, //4.19 Generic management commands // P110-11
    //OLD VERSION
    fn get_random(&mut self, buf: &mut [u8], delay: &mut DelayWrapper) -> Result<(), Se050Error>;

    //AN12413, // 4.19 Generic management commands //44.19.5 delete_all P.112
    fn delete_all(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error>;
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
    //###########################################################################
    //###########################################################################
    //OLD VERSION
    fn enable(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        /* Step 1: perform interface soft reset, parse ATR */
        let r = self.t1_proto.interface_soft_reset(delay);
        if r.is_err() {
            error!("SE050 Interface Reset Error");
            return Err(Se050Error::UnknownError);
        }
        self.atr_info = r.ok();
        debug!("SE050 ATR: {:?}", self.atr_info.as_ref().unwrap());

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
        self.t1_proto
            .send_apdu_raw(&app_select_apdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut appid_data: [u8; 11] = [0; 11];
        let appid_apdu = self
            .t1_proto
            .receive_apdu_raw(&mut appid_data, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let adata = appid_apdu.data;
        let asw = appid_apdu.sw;
        if asw != 0x9000 || adata.len() != 7 {
            error!(
                "SE050 GP SELECT Err: {:?} {:x}",
                delog::hex_str!(adata),
                asw
            );
            return Err(Se050Error::UnknownError);
        }

        self.app_info = Some(Se050AppInfo {
            applet_version: BE::read_uint(&adata[0..3], 3) as u32,
            features: BE::read_u16(&adata[3..5]),
            securebox_version: BE::read_u16(&adata[5..7]),
        });
        debug!("SE050 App: {:?}", self.app_info.as_ref().unwrap());

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //TO-DO

    fn disable(&mut self, _delay: &mut DelayWrapper) {
        // send S:EndApduSession
        // receive ACK
        // power down
    }

    //###########################################################################
    //###########################################################################
    //See AN12413, //  4.4 Applet selection P.47-48
    // The applet can be selected by sending a GP SELECT command.
    //This command     interacts with the JCOP Card Manager and will result in the selection of the SE050 IoT     applet.

    /*
    TO DO
    */

    //###########################################################################
    //###########################################################################
    //See AN12413, 4.5 Session management
    /*
    CreateSession
    ExchangeSessionData
    ProcessSessionCmd
    RefreshSession
    CloseSession
    */

    //###########################################################################
    //See AN12413, 4.5 Session management // 4.5.1 Generic session commands //4.5.1.1 create_session P.48
    // Creates a session on SE050.
    //Depending on the authentication object being referenced, a specific method of authentication applies.
    //The response needs to adhere to this authentication method.

    // authentication object identifier -> authobjectidentifier

    #[inline(never)]
    fn create_session(
        &mut self,
        authobjectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), authobjectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::SessionCreate.into(),
            Some(0x0C),
        );
        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    fn exchange_session_data(
        &mut self,
        session_policies: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &session_policies);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::SessionPolicy.into(),
            Some(0),
        );
        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    fn process_session_cmd(
        &mut self,
        apducommand: &[u8],
        session_id: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvtgsid = SimpleTlv::new(Se050TlvTag::SessionID.into(), &session_id);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &apducommand);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Process) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );

        capdu.push(tlvtgsid);
        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    fn refresh_session(
        &mut self,
        policy: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvtgsid = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::SessionRefresh.into(),
            None,
        );
        capdu.push(tlvtgsid);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
            None,
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    //###########################################################################
    //See AN12413 , 4.5 Session management //4.5.2 UserID session operations // 4.5.2.1 VerifySessionUserID P.51-52

    #[inline(never)]
    fn verify_session_user_id(
        &mut self,
        user_idvalue: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &user_idvalue);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::SessionUserID.into(),
            None,
        );
        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 verify_session_user_id Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 verify_session_user_id OK");
        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //4.5.3 AESKey session operations
    /*
    SCPInitializeUpdate
    SCPExternalAuthenticate
    */

    //###########################################################################
    //4.5.3 AESKey session operations // 4.5.3.1 SCPInitializeUpdate  P.52
    //[SCP03] Section 7.1.1 shall be applied.
    // The user shall always set the P1 parameter to ‘00’ (KVN = ‘00’).

    /*
    TO-DO
    CLA 0x80
    INS 0x50

    */

    //###########################################################################
    //4.5.3.2 SCPExternalAuthenticate  P.52
    //[SCP03] Section 7.1.2 shall be applied

    /*
    TO-DO

    CLA 0x80
    INS 0x82

    */

    //###########################################################################
    //###########################################################################
    //See AN12413 , 4.5.4 ECKey session operations
    /*
    ECKeySessionInternalAuthenticate
    ECKeySessionGetECKAPublicKey
    */

    //###########################################################################
    //See AN12413 , 4.5.4 ECKey session operations //  4.5.4.1 ECKeySessionInternalAuthenticate P.52-53
    // Initiates an authentication based on an ECKey Authentication Object. e
    //See  Section 3.6.3.3 for more information.
    // The user shall always use key version number = ‘00’ and key identifier = ‘00’.
    //Payload TLV[TAG_1] Input data (see Table 73) P.53.
    //InstructECKSIA = 0x88

    #[inline(never)]
    fn eckey_session_internal_authenticate(
        &mut self,
        input_data: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), input_data);

        let mut capdu = CApdu::new(
            ApduClass::ProprietarySecure,
            Into::<u8>::into(Se050ApduInstruction::InstructECKSIA) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!(
                "SE050 eckey_session_internal_authenticate Failed: {:x}",
                rapdu.sw
            );
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 eckey_session_internal_authenticate OK");
        Ok(())
    }

    //###########################################################################
    //See AN12413 ,  4.5.4 ECKey session operations //   4.5.4.2 eckey_session_get_eckapublic_key P.53-54
    //Gets the public key of the static device key pair (either     RESERVED_ID_ECKEY_SESSION or RESERVED_ID_EXTERNAL_IMPORT).
    //The key identifier used in subTag 0x83 must be either:
    //• 0x00 for user authentication.
    //• 0x02 for ImportExternalObject (i.e., single side import) only.
    //Note that any key identifier value different from 0x02 or 0x00 is RFU, but if passed, it is  treated as user authentication (so equal to 0x00).
    //InstructECKSGECKAPK=0xCA

    #[inline(never)]

    fn eckey_session_get_eckapublic_key(
        &mut self,
        input_data: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), input_data);

        let mut capdu = CApdu::new(
            ApduClass::ProprietarySecure,
            Into::<u8>::into(Se050ApduInstruction::InstructECKSGECKAPK)
                | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::EcksgeckapkP1.into(),
            Se050ApduP2::ECKSGECKAPK_P2.into(),
            Some(0),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!(
                "SE050 eckey_session_get_eckapublic_key Failed: {:x}",
                rapdu.sw
            );
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 eckey_session_get_eckapublic_key OK");
        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413 , 4.6 Module management
    /*
    SetLockState
    SetPlatformSCPRequest
    SetAppletFeatures
    */

    //###########################################################################
    //See AN12413 , 4.6 Module management //   4.6.1 SetLockState P.54-55
    /*
    Sets the applet transport lock (locked or unlocked).
    There is a Persistent lock and a   Transient Lock.
    If the Persistent lock is UNLOCKED, the device is unlocked (regardless   of the Transient lock).
    If the Persistent lock is LOCKED, the device is only unlocked when   the Transient lock is UNLOCKED and the device will be locked again after deselect of the
    applet.
    Note that regardless of the lock state, the credential RESERVED_ID_TRANSPORT  allows access to all features.
    For example, it is possible to write/update objects within the   session opened by RESERVED_ID_TRANSPORT, even if the applet is locked.
    The default TRANSIENT_LOCK state is LOCKED; there is no default PERSISTENT_LOCK state (depends on product configuration).
    */

    #[inline(never)]
    fn set_lock_state(
        &mut self,
        lockindicator: &[u8],
        lockstate: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &lockindicator);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &lockstate);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Transport.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 set_lock_state Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 set_lock_state OK");
        Ok(())
    }

    //###########################################################################
    //See AN12413 , 4.6 Module management //   4.6.2 SetPlatformSCPRequest P.55-56
    /*
    Sets the required state for platform SCP (required or not required). This is a persistent
    state.
    If platform SCP is set to SCP_REQUIRED, any applet APDU command will be refused
    by the applet when platform SCP is not enabled. Enabled means full encryption and
    MAC, both on C-APDU and R-APDU. Any other level is not sufficient and will not be
    accepted. SCP02 will not be accepted (as there is no response MAC and encryption).
    If platform SCP is set to “not required,” any applet APDU command will be accepted by
    the applet.

    his command can only be used in a session that used the credential with identifier
    RESERVED_ID_PLATFORM_SCP as authentication object.
    Note that the default state is SCP_NOT_REQUIRED.
    */

    #[inline(never)]
    #[allow(unused_mut)]
    fn set_platform_scp_request(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::SCP.into(),
            None,
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 set_platform_scp_request Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 set_platform_scp_request OK");
        Ok(())
    }

    //###########################################################################
    //AN12413 // 4.6 Module management  //4.6.3 SetAppletFeatures  P.56 -57
    // Sets the applet features that are supported.
    // To successfully execute this command, the session must be authenticated using the RESERVED_ID_FEATURE.
    //The 2-byte input value is a pre-defined AppletConfig value.

    #[inline(never)]
    fn set_applet_features(
        &mut self,
        applet_config: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &applet_config);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),
            None,
        );
        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    //###########################################################################
    //AN12413 //4.7 Secure Object management

    /*
    WriteECKey
    WriteRSAKey
    WriteSymmKey
    WriteBinary
    WriteUserID
    WriteCounter
    WritePCR

    ImportObject
    */

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
    /* ASSUMPTION: SE050 is provisioned with an instantiated ECC curve object; */
    /* NOTE: hardcoded Object ID 0xae51ae51! */
    //AN12413 //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey    P.58
    //P1_EC 4.3.19 ECCurve P.42
    #[inline(never)]
    fn write_ec_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        eccurve: &[u8],
        private_key_value: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &eccurve); // Se050ECCurveconstants
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &private_key_value);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
            Se050ApduP2::Default.into(),
            None,
        );

        capdu.push(tlvp);
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            //  error!("SE050 write_ec_key {:x} Failed: {:x}", eccurve, rapdu.sw);
            //error!("SE050 write_ec_key   Failed: {:x}",  rapdu.sw);
            error!("SE050 write_ec_key {:x?} Failed: {:x}", eccurve, rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        //debug!("SE050 write_ec_key {:x} : OK",eccurve);

        //debug!("SE050 write_ec_key   : OK" );
        debug!("SE050 write_ec_key {:x?} : OK", eccurve);

        Ok(())
    }

    //###########################################################################
    //OLD VERSION
    #[inline(never)]
    /* ASSUMPTION: SE050 is provisioned with an instantiated P-256 curve object;
    see NXP AN12413 -> Secure Objects -> Default Configuration */
    /* NOTE: hardcoded Object ID 0xae51ae51! */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey   P.58
    //P1_EC //  4.3.19 ECCurve NIST_P256 P.42

    //20E8A001
    //&[0x20, 0xE8, 0xA0, 0x01]

    fn generate_p256_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
        //let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
        //let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x51, 0xae, 0x51]);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0x20, 0xE8, 0xA0, 0x01]);

        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x03]); // NIST P-256
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
            Se050ApduP2::Default.into(),
            None,
        );
        capdu.push(tlv1);

        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        // let mut rapdu_buf: [u8; 16] = [0; 16];

        let mut rapdu_buf: [u8; 260] = [0; 260];

        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 GenP256 Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 GenP256 OK");
        Ok(ObjectId([0xae, 0x51, 0xae, 0x51]))
    }

    //###########################################################################
    /* ASSUMPTION: SE050 is provisioned with an instantiated ECC curve object; */

    //AN12413 //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey    P.58
    //P1_EC 4.3.19 ECCurve P.42

    /* NOTE: hardcoded Object ID 0xae51ae51! */
    //  &[0xae, 0x51, 0xae, 0x51]
    //20E8A002
    //&[0x20, 0xE8, 0xA0, 0x02]

    #[inline(never)]
    //fn write_ec_key(&mut self,policy: &[u8],  objectid: &[u8;4], eccurve: &[u8], private_key_value: &[u8],  delay: &mut DelayWrapper) -> Result<(), Se050Error>
    fn generate_ed255_key_pair(
        &mut self,
        delay: &mut DelayWrapper,
    ) -> Result<ObjectId, Se050Error> {
        {
            //  let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);

            //   let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
            let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x52, 0xae, 0x52]);

            // let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), & eccurve);	// Se050ECCurveconstants
            //let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &ID_ECC_ED_25519  );	// Se050ECCurveconstants
            let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x40]); // Se050ECCurveconstants
                                                                          //let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &private_key_value );

            let mut capdu = CApdu::new(
                ApduClass::ProprietaryPlain,
                Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
                Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
                Se050ApduP2::Default.into(),
                None,
            );
            //  capdu.push(tlvp);
            capdu.push(tlv1);
            capdu.push(tlv2);
            //     capdu.push(tlv3);

            self.t1_proto
                .send_apdu(&capdu, delay)
                .map_err(|_| Se050Error::UnknownError)?;

            //  let mut rapdu_buf: [u8; 16] = [0; 16];
            let mut rapdu_buf: [u8; 260] = [0; 260];

            let rapdu = self
                .t1_proto
                .receive_apdu(&mut rapdu_buf, delay)
                .map_err(|_| Se050Error::UnknownError)?;

            if rapdu.sw != 0x9000 {
                //  error!("SE050 write_ec_key {:x} Failed: {:x}", eccurve, rapdu.sw);
                //error!("SE050 write_ec_key   Failed: {:x}",  rapdu.sw);
                // error!("SE050 generate_ed255_key_pair {:x?} Failed: {:x}", eccurve, rapdu.sw);

                error!("SE050 generate_ed255_key_pair   Failed: {:x}", rapdu.sw);

                return Err(Se050Error::UnknownError);
            }

            //debug!("SE050 write_ec_key {:x} : OK",eccurve);

            //debug!("SE050 write_ec_key   : OK" );
            // debug!("SE050 generate_ed255_key_pair {:x?} : OK",eccurve);
            // Ok(())

            debug!("SE050 generate_ed255_key_pair OK");
            //Ok(ObjectId([0xae, 0x52, 0xae, 0x52]))
            Ok(ObjectId([0xae, 0x52, 0xae, 0x52]))
        }
    }

    //###########################################################################
    /* ASSUMPTION: SE050 is provisioned with an instantiated P-256 curve object;
    see NXP AN12413 -> Secure Objects -> Default Configuration */
    //NEW VERSION
    //AN12413 //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.1 WriteECKey   P.58
    //P1_EC //  4.3.19 ECCurve NIST_P256 P.42
    /*    #[inline(never)]

       fn generate_p256_key(&mut self,policy: &[u8],  objectid: &[u8;4],   private_key_value: &[u8],  delay: &mut DelayWrapper) -> Result<(), Se050Error>
       {

           let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
           let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
           let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x03]);	// NIST P-256
           let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &private_key_value );

           let mut capdu = CApdu::new(
               ApduClass::ProprietaryPlain,
               Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
               Se050ApduP1CredType::EC | Se050ApduP1KeyType::KeyPair,
               Se050ApduP2::Default.into(),
               None
           );

           capdu.push(tlvp);
           capdu.push(tlv1);
           capdu.push(tlv2);
           capdu.push(tlv3);

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
    */
    //###########################################################################
    //AN12413 //4.7 Secure Object management //4.7.1 WriteSecureObject// 4.7.1.2 WriteRSAKey
    /*
    Creates or writes an RSA key or a key component.
    Supported key sizes are listed in RSABitLength. Other values are not supported.
    An RSA key creation requires multiple ADPUs to be sent:
    • The first APDU must contain:
    – Policy (optional, so only if non-default applies)
    – Object identifier
    – Key size
    – 1 of the key components.
    • Each next APDU must contain 1 of the key components.
    The policy applies only once all key components are set.
    Once an RSAKey object has been created, its format remains fixed and cannot be
    updated (so CRT or raw mode, no switch possible).
    If the object already exists, P1KeyType is ignored.
    For key pairs, if no component is present (TAG_3 until TAG_9), the key pair will be
    generated on chip; otherwise the key pair will be constructed starting with the given
    component.
    For private keys or public keys, there should always be exactly one of the tags TAG_3
    until TAG_10.
    Warning: writing transient RSAkey Secure Objects in CRT mode causes NVM write
    accesses.

    • TLV[TAG_8] and TLV[TAG_10] must only contain a value if the key pair is to be set to
    a known value and P1KeyType is either P1_KEY_PAIR or P1_PUBLIC; otherwise the
    value must be absent and the length must be equal to 0.
    • TLV[TAG_9] must only contain a value it the key is to be set in raw mode to a known
    value and P1KeyType is either P1_KEY_PAIR or P1_PRIVATE; otherwise the value
    must be absent and the length must be equal to 0.
    • If TLV[TAG_3] up to TLV[TAG_10] are absent (except TLV[TAG_8]), the RSA key
    will be generated on chip in case the object does not yet exist; otherwise it will be
    regenerated. This only applies to RSA key pairs.
    • Keys can be set by setting the different components of a key; only 1 component can be
    set at a time in this case
    */

    /*
    P2_RAW only in case
    P1KeyType = P1_KEY_PAIR
    and TLV[TAG_3] until TLV[TAG_10] is empty
    and the SE050 must generate a raw RSA key pair;
    */

    #[inline(never)]
    fn write_rsa_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        keysize: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);

        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), keysize);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::RSA | Se050ApduP1KeyType::KeyPair,
            Se050ApduP2::RAW.into(),
            None,
        );

        capdu.push(tlvp);
        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            //  error!("SE050 write_rsa_key {:x} Failed: {:x}", eccurve, rapdu.sw);
            error!("SE050 write_rsa_key  Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        //debug!("SE050 write_rsa_key {:x} : OK",eccurve);
        debug!("SE050 write_rsa_key : OK");

        Ok(())
    }
    /*
        //NEW VERSION

        //###########################################################################
        /* NOTE: hardcoded Object ID 0xae50ae50! */
        /* no support yet for rfc3394 key wrappings, policies or max attempts */
        //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60
        //P1_AES //template for
        #[inline(never)]
        fn write_aes_key(&mut self,policy: &[u8], objectid: &[u8;4],kekid: &[u8;4],key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
            if key.len() != 16 {
                todo!();
            }

            let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
            let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
            let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), kekid);
            let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);

            let mut capdu = CApdu::new(
                ApduClass::ProprietaryPlain,
                Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
                Se050ApduP1CredType::AES.into(),
                Se050ApduP2::Default.into(),
                Some(0)
            );
            capdu.push(tlvp);
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
                error!("SE050 WriteAESKey Failed: {:x}", rapdu.sw);
                return Err(Se050Error::UnknownError);
            }

            Ok(())
        }
    */
    //OLD VERSION

    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
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
            Some(0),
        );
        capdu.push(tlv1);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 WriteAESKey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //NEW VERSION

    //###########################################################################
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60
    //P1_AES //template for
    #[inline(never)]
    //fn write_aes_key(&mut self,policy: &[u8], objectid: &[u8;4],kekid: &[u8;4],key: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {

    //fn generate_aes_key(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
    fn generate_aes_key(&mut self, delay: &mut DelayWrapper) -> Result<ObjectId, Se050Error> {
        /*   if key.len() != 16 {
                    todo!();
                }
        */
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0x20, 0xE8, 0xA0, 0x02]);
        // let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
        // let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        // let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), kekid);
        // let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::AES.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );
        //  capdu.push(tlvp);
        capdu.push(tlv1);
        //     capdu.push(tlv2);
        //   capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];

        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 WriteAESKey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        //  Ok(())

        debug!("SE050 GenAES OK");
        Ok(ObjectId([0x20, 0xE8, 0xA0, 0x02]))
    }

    //##################################################
    //ERWEITERT
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    /* no support yet for rfc3394 key wrappings, policies or max attempts */
    //4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.3 WriteSymmKey P.60
    //P1_DES
    fn write_des_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        kekid: &[u8; 4],
        key: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        if key.len() != 16 {
            todo!();
        }

        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), kekid);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::DES.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );

        capdu.push(tlvp);
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
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
    fn write_hmac_key(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        kekid: &[u8; 4],
        key: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        if key.len() != 16 {
            todo!();
        }

        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), kekid);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), key);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::HMAC.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );
        capdu.push(tlvp);
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 WriteHMACKey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.4 WriteBinary  //P.61
    fn write_binary(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        file_offset: &[u8; 2],
        file_length: &[u8; 2],
        data1: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), file_offset);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), file_length);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), &data1);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Binary.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );
        capdu.push(tlvp);
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 write_binary Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //OLD VERSION
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    //4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT//  4.3.21 CipherMode // AES CBC NOPAD
    fn encrypt_aes_oneshot(
        &mut self,
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        if data.len() > 240 || (data.len() % 16 != 0) {
            error!("Input data too long or unaligned");
            return Err(Se050Error::UnknownError);
        }
        if enc.len() != data.len() {
            error!("Insufficient output buffer");
            return Err(Se050Error::UnknownError);
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xae, 0x50, 0xae, 0x50]);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &[0x0d]); // AES CBC NOPAD
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Crypto.into(),
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::EncryptOneshot.into(),
            Some(0),
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 EncryptAESOneshot Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 EncryptAESOneshot Return TLV Missing");
            Se050Error::UnknownError
        })?;

        if tlv1_ret.get_data().len() != enc.len() {
            error!("SE050 EncryptAESOneshot Length Mismatch");
            return Err(Se050Error::UnknownError);
        }
        enc.copy_from_slice(tlv1_ret.get_data());
        debug!("SE050 EncryptAESOneshot OK");
        Ok(())
    }

    // VerifySessionUserID 0x80 0x04 0x00 0x2C

    //###########################################################################
    #[inline(never)]
    //WriteUserID 0x80 0x01 0x07 0x00
    /* NOTE: hardcoded Object ID 0xae51ae51! */
    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject P.57 //4.7.1.5 WriteUserID  //P.62
    fn write_user_id(
        &mut self,
        policy: &[u8],
        objectid: &[u8; 4],
        user_identifier_value: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);

        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), user_identifier_value);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::UserID.into(),
            Se050ApduP2::Default.into(),
            None,
        );
        capdu.push(tlvp);

        capdu.push(tlv1);

        capdu.push(tlv2);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 write_user_id  Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 write_user_id OK");
        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject //4.7.1.6 WriteCounter P.62

    /*
    Creates or writes to a counter object.
    Counters can only be incremented, not decremented.
    When a counter reaches its maximum value (e.g., 0xFFFFFFFF for a 4-byte counter), it
    cannot be incremented again.
    An input value (TAG_3) must always have the same length as the existing counter (if it
    exists); otherwise the command will return an error.
    */

    #[inline(never)]
    fn write_counter(
        &mut self,
        policy: &[u8],
        counterid: &[u8; 4],
        countersize: &[u8; 2],
        counterfile: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), counterid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), countersize);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &counterfile);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Counter.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );
        capdu.push(tlvp);
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 write_counter Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.7 Secure Object management //4.7.1 WriteSecureObject // 4.7.1.7 WritePCR  P.63-64

    /*
    Creates or writes to a PCR object.
    A PCR is a hash to which data can be appended; i.e., writing data to a PCR will update
    the value of the PCR to be the hash of all previously inserted data concatenated with the
    new input data.
    A PCR will always use DigestMode = DIGEST_SHA256; no other configuration possible.
    If TAG_2 and TAG_3 are not passed, the PCR is reset to its initial value (i.e., the value
    set when the PCR was created).
    This reset is controlled under the POLICY_OBJ_ALLOW_DELETE policy, so users that
    can delete the PCR can also reset the PCR to initial value.
    */

    #[inline(never)]
    fn write_pcr(
        &mut self,
        policy: &[u8],
        pcrid: &[u8; 4],
        initial_hash_value: &[u8],
        ext: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlvp = SimpleTlv::new(Se050TlvTag::Policy.into(), &policy);
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), pcrid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), initial_hash_value);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &ext);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Counter.into(),
            Se050ApduP2::Default.into(),
            Some(0),
        );
        capdu.push(tlvp);
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 write_pcr Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413 // 4.7 Secure Object management // 4.7.1.8  ImportObject P.63-64
    /*4.7.1.8 ImportObject
    Writes a serialized Secure Object to the SE050 (i.e., “import”). See
    SecureObjectImportExport for details on the import/export mechanism.
    */
    /*
        To-DO

        TLV[TAG_1] 4-byte identifier.
        TLV[TAG_2] 1-byte RSAKeyComponent
        TLV[TAG_3] Serialized object (encrypted).

    */

    #[inline(never)]
    fn import_object(
        &mut self,
        identifier: &[u8; 4],
        rsakeycomponent: &[u8],
        serializedobjectencrypted: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), identifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &rsakeycomponent);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &serializedobjectencrypted);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Import.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 import_object Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413 // 4.7 Secure Object management //4.7.2 ImportExternalObject P.64
    /*
    Note: The APDU “ImportExternalObject” must not be used without first contacting
    NXP to avoid potential problems. If you have used or plan to use the APDU
    “ImportExternalObject,” please make sure you contact your NXP representative.
    Combined with the INS_IMPORT_EXTERNAL mask, enables users to send a
    WriteSecureObject APDU (WriteECKey until WritePCR) protected by the same security
    mechanisms as an ECKey session. See Secure Object external import for details on the
    flow of the external import mechanism

    TLV[TAG_IMPORT_AUTH_DATA]     Authentication data
    TLV[TAG_IMPORT_AUTH_KEY_ID] Host public key Identifier

    TLV[TAG_1]… Wraps a complete WriteSecureObject command,
    protected by ECKey session secure messaging

    */

    #[inline(never)]
    fn import_external_object(
        &mut self,
        authdata: &[u8],
        hostpublickeyidentifier: &[u8],
        writesecureobjectcommand: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlva = SimpleTlv::new(Se050TlvTag::ImportAuthData.into(), &authdata);
        let tlvb = SimpleTlv::new(
            Se050TlvTag::ImportAuthKeyID.into(),
            &hostpublickeyidentifier,
        );
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &writesecureobjectcommand);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::ImportExternal) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),
            Some(0x08),
        );

        capdu.push(tlva);
        capdu.push(tlvb);
        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 import_external_object Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413 // 4.7 Secure Object management // 4.7.3 ReadSecureObject
    /*
    ReadObject
    ExportObject
    */

    //###########################################################################
    // See AN12413 // 4.7 Secure Object management // 4.7.3 ReadSecureObject //4.7.3.1 ReadObject // P.65-66
    #[inline(never)]
    fn read_secure_object(
        &mut self,
        objectidentifier: &[u8; 4],
        offset: &[u8; 2],
        length: &[u8; 2],
        rsakeycomponent: &[u8],
        attobjectidentifier: &[u8; 4],
        attlogo: &[u8],
        freshnessrandom: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), offset);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), length);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), &rsakeycomponent);

        let tlv5 = SimpleTlv::new(Se050TlvTag::Tag1.into(), attobjectidentifier);
        let tlv6 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &attlogo);
        let tlv7 = SimpleTlv::new(Se050TlvTag::Tag3.into(), freshnessrandom);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Default.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);
        capdu.push(tlv5);
        capdu.push(tlv6);
        capdu.push(tlv7);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 read_secure_object Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.7 Secure Object management // 4.7.3 ReadSecureObject //4.7.3.2 ExportObject // P.67
    #[inline(never)]
    fn export_secure_object(
        &mut self,
        objectidentifier: &[u8; 4],
        rsakeycomponent: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &rsakeycomponent);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Export.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 export_secure_object Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject

    /*
    ReadType
    ReadSize
    ReadIDList

    CheckObjectExists
    DeleteSecureObject
    */

    //###########################################################################
    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.1 ReadType P.67-68
    #[inline(never)]
    fn read_type(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Type.into(),
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 read_type Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject 4.7.4.2 ReadSize P.68
    #[inline(never)]
    fn read_size(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Size.into(),
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 read_size Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.3 ReadIDList P.69
    #[inline(never)]
    fn read_id_list(
        &mut self,
        offset: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), offset);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0xFF]);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::List.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 read_id_list Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.4 CheckObjectExists P.70
    #[inline(never)]
    fn check_object_exists(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Exist.into(),
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 check_object_exists Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    /*
     //###########################################################################
       //###########################################################################
        // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.4 CheckObjectExists P.70
        #[inline(never)]
        fn check_object_exists_p256(&mut self, buf: &mut [u8],  delay: &mut DelayWrapper) -> Result< (), Se050Error>
        {

            //let mut buflen: [u8; 2] = [0, 0];
           // BE::write_u16(&mut buflen, buf.len() as u16);

           let a : [u8; 1] = [0x00];

           let b : [u8; 1] = [0x01];


        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &[0x20, 0xE8, 0xA0, 0x01]);

        let mut capdu = CApdu::new(
        ApduClass::ProprietaryPlain,
        Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
        Se050ApduP1CredType::Default.into(),
        Se050ApduP2::Exist.into(),
        Some(0x00)
        );

        capdu.push(tlv1);

        self.t1_proto
        .send_apdu(&capdu, delay)
        .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];

        let rapdu = self.t1_proto
        .receive_apdu(&mut rapdu_buf, delay)
        .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
        error!("SE050 check_object_exists_p256 Failed: {:x}", rapdu.sw);
        return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 check_object_exists_p256 Return TLV Missing");
            Se050Error::UnknownError })?;
    /*
        if tlv1_ret.get_data().len() != buf.len() {
            error!("SE050 check_object_exists_p256 Length Mismatch");
            return Err(Se050Error::UnknownError);
        }
    */

    //Ok(());

    //Ok(buf.copy_from_slice(tlv1_ret.get_data()))



       buf.copy_from_slice(tlv1_ret.get_data());





     Ok(buf.copy_from_slice(tlv1_ret.get_data()))




        }

    */

    //###########################################################################
    // See AN12413// 4.7 Secure Object management  //4.7.4 ManageSecureObject // 4.7.4.5 DeleteSecureObject P.70
    #[inline(never)]
    fn delete_secure_object(
        &mut self,
        objectidentifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::DeleteObject.into(),
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 delete_secure_object Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413// 4.8 EC curve management

    /*
    CreateECCurve
    SetECCurveParam
    GetECCurveId
    ReadECCurveList
    DeleteECCurve
    */

    //###########################################################################
    // See AN12413// 4.8 EC curve management //4.8.1 CreateECCurve -Create an EC curve listed in ECCurve P.71-72
    //TLV[TAG_1] 1-byte curve identifier (from ECCurve)

    #[inline(never)]
    fn create_eccurve(
        &mut self,
        eccurve: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &eccurve);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Curve.into(),
            Se050ApduP2::Create.into(),
            None,
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 create_eccurve Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413//   4.8 EC curve management //  4.8.2 SetECCurveParam -Set a curve parameter. The curve must have been created first by CreateEcCurve. P.72
    //TLV[TAG_1] 1-byte curve identifier (from ECCurve)
    //TLV[TAG_2] 1-byte ECCurveParam
    //TLV[TAG_3] Bytestring containing curve parameter value.

    #[inline(never)]
    fn set_eccurve_param(
        &mut self,
        eccurve: &[u8],
        eccurveparam: &[u8],
        curveparametervalue: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &eccurve);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &eccurveparam);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &curveparametervalue);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Curve.into(),
            Se050ApduP2::Param.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 set_eccurve_param Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413//   4.8 EC curve management //  4.8.3 GetECCurveID Get the curve associated with an EC key.. P.72-73
    //TLV[TAG_1] 4-byte identifier

    #[inline(never)]
    fn get_eccurve_id(
        &mut self,
        identifier: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), identifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Curve.into(),
            Se050ApduP2::ID.into(),
            None,
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 get_eccurve_id Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413//   4.8 EC curve management //  4.8.3 GetECCurveID Get the curve associated with an EC key.. P. 73
    //TLV[TAG_1] Byte array listing all curve identifiers in ECCurve (excluding UNUSED)
    //where the curve identifier < 0x40; for each curve, a 1-byte SetIndicator is returned.

    #[inline(never)]
    #[allow(unused_mut)]
    fn read_eccurve_list(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Curve.into(),
            Se050ApduP2::List.into(),
            Some(0x00),
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 read_eccurve_list Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413//   4.8 EC curve management // 4.8.5 DeleteECCurve - Deletes an EC curve P.74
    //TLV[TAG_1]  1-byte curve identifier (from ECCurve))

    #[inline(never)]

    fn delete_eccurve(
        &mut self,
        eccurve: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &eccurve);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Curve.into(),
            Se050ApduP2::DeleteObject.into(),
            None,
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 delete_eccurve Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413// 4.9 Crypto Object management
    /*
    CreateCryptoObject
    ReadCryptoObjectList
    DeleteCryptoObject
    */

    //###########################################################################
    // See AN12413// 4.9 Crypto Object management // 4.9.1 CreateCryptoObject - Creates a Crypto Object on the SE050. P74-75
    /* Once the Crypto Object is created, it is bound to     the user who created the Crypto Object.
    For valid combinations of CryptoObject and the CryptoObject subtype, see CryptoObject.*/

    //TLV[TAG_1] 2-byte Crypto Object identifier
    //TLV[TAG_2] 1-byte CryptoContext
    //TLV[TAG_3] 1-byte Crypto Object subtype, either from DigestMode, CipherMode or MACAlgo (depending on TAG_2).

    #[inline(never)]
    fn create_crypto_object(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        cryptocontext: &[u8],
        cryptoobjectsubtype: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), cryptoobjectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &cryptocontext);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &cryptoobjectsubtype);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Write) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::CryptoObj.into(),
            Se050ApduP2::Default.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 create_crypto_object Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413// 4.9 Crypto Object management // 4.9.2 ReadCryptoObjectList. P.75
    // Get the list of allocated Crypto Objects indicating the identifier, the CryptoContext and the sub type of the CryptoContext.

    #[inline(never)]
    #[allow(unused_mut)]
    fn read_crypto_object_list(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Read) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::CryptoObj.into(),
            Se050ApduP2::List.into(),
            Some(0x00),
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 read_crypto_object_list Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413// 4.9 Crypto Object management // 4.9.3 DeleteCryptoObject P.75 - 76
    // Deletes a Crypto Object on the SE050.
    // Note: when a Crypto Object is deleted, the memory (as mentioned in Crypto Objects) is   de-allocated and will be freed up on the next incoming APDU.
    // TLV[TAG_1] 2-byte Crypto Object identifier

    #[inline(never)]

    fn delete_crypto_object(
        &mut self,
        cryptoobjectidentifier: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), cryptoobjectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::CryptoObj.into(),
            Se050ApduP2::DeleteObject.into(),
            None,
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 read_crypto_object_list Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413 // 4.10 Crypto operations EC

    /*
    ##Signature generation
    ECDSASign
    EdDSASign
    ECDAASign

    ##Signature verification
    ECDSAVerify
    EdDSAVerify

    ##Shared secret generation
    ECDHGenerateSharedSecret
     */

    //###########################################################################
    // See AN12413 // 4.10 Crypto operations EC // 4.10.1 Signature generation // 4.10.1.1 ECDSASign P.76-77
    //Elliptic Curve Crypto operations are supported and tested for all curves listed in    ECCurve.

    //TLV[TAG_1]  4-byte identifier of EC key pair or private key.
    //TLV[TAG_2] 1-byte ECSignatureAlgo.
    //TLV[TAG_3] Byte array containing input data.

    #[inline(never)]
    fn ecdsa_sign(
        &mut self,
        eckeyidentifier: &[u8; 4],
        ecsignaturealgo: &[u8],
        inputdata: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), eckeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &ecsignaturealgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), inputdata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Signature.into(),
            Se050ApduP2::Sign.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 ecdsa_sign Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.10 Crypto operations EC // 4.10.1 Signature generation // 4.10.1.2 EdDSASign P.77-78
    //The EdDSASign command signs external data using the indicated key pair or private key (using a Twisted Edwards curve).
    // This is performed according to the EdDSA algorithm as specified in [RFC8032].

    //TLV[TAG_1]  4-byte identifier of EC key pair or private key.
    //TLV[TAG_2] 1-byte EDSignatureAlgo.
    //TLV[TAG_3] Byte array containing plain input data.

    #[inline(never)]
    fn eddsa_sign(
        &mut self,
        eckeyidentifier: &[u8; 4],
        edsignaturealgo: &[u8],
        inputdata: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), eckeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &edsignaturealgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), inputdata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Signature.into(),
            Se050ApduP2::Sign.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 eddsa_sign Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.10 Crypto operations EC // 4.10.1 Signature generation // 4.10.1.3 ECDAASign P.78-79
    //The ECDAASign command signs external data using the indicated key pair or private key.
    //This is performed according to ECDAA.

    //TLV[TAG_1]  4-byte identifier of EC key pair or private key.
    //TLV[TAG_2] 1-byte ECDAASignatureAlgo
    //TLV[TAG_3] T = 32-byte array containing hashed input data.
    //TLV[TAG_4] r = 32-byte array containing random data, must be in the interval [1, n-1] where n is the order of the curve.

    #[inline(never)]

    fn ecdaa_sign(
        &mut self,
        eckeyidentifier: &[u8; 4],
        ecdaasignaturealgo: &[u8],
        hashedinputdata: &[u8; 32],
        randomdata: &[u8; 32],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), eckeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &ecdaasignaturealgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), hashedinputdata);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), randomdata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Signature.into(),
            Se050ApduP2::Sign.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 ecdaa_sign Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.10 Crypto operations EC // 4.10.2 Signature verification // 4.10.2.1 ECDSAVerify P.79
    //The ECDSAVerify command verifies whether the signature is correct for a given (hashed) data input using an EC public key or EC key pair’s public key.

    //TLV[TAG_1]  4-byte identifier of EC key pair or private key.
    //TLV[TAG_2] 1-byte ECSignatureAlgo
    //TLV[TAG_3] Byte array containing hashed data to compare.
    //TLV[TAG_5]  Byte array containing ASN.1 signature

    #[inline(never)]

    fn ecdsa_verify(
        &mut self,
        eckeyidentifier: &[u8; 4],
        ecsignaturealgo: &[u8],
        hashedcomparedata: &[u8],
        asn1signaturedata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), eckeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &ecsignaturealgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &hashedcomparedata);
        let tlv5 = SimpleTlv::new(Se050TlvTag::Tag5.into(), &asn1signaturedata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Signature.into(),
            Se050ApduP2::Verify.into(),
            Some(0x03),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv5);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 ecdsa_verify Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.10 Crypto operations EC // 4.10.2 Signature verification // 4.10.2.2 EdDSAVerify P.80

    /*
    The EdDSAVerify command verifies whether the signature is correct for a given data  input (hashed using SHA512),
     using an EC public key or EC key pair’s public key.
     The     signature needs to be given as concatenation of r and s.
    */

    //TLV[TAG_1]  4-byte identifier of EC key pair or private key.
    //TLV[TAG_2]  1-byte EDSignatureAlgo.
    //TLV[TAG_3] Byte array containing plain data to compare
    //TLV[TAG_5] 64-byte array containing the signature (concatenation of r and s).

    #[inline(never)]

    fn eddsa_verify(
        &mut self,
        eckeyidentifier: &[u8; 4],
        edsignaturealgo: &[u8],
        plaincomparedata: &[u8],
        signaturedata: &[u8; 64],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), eckeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &edsignaturealgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &plaincomparedata);
        let tlv5 = SimpleTlv::new(Se050TlvTag::Tag5.into(), signaturedata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Signature.into(),
            Se050ApduP2::Verify.into(),
            Some(0x03),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv5);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 eddsa_verify Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.10 Crypto operations EC //  4.10.3 Shared secret generation //  4.10.3.1 ECDHGenerateSharedSecret P.81

    /*
    The ECDHGenerateSharedSecret command generates a shared secret ECC point on
    the curve using an EC private key on SE050 and an external public key provided by the caller.
    The output shared secret is returned to the caller.
    All curves from ECCurve are supported, except ID_ECC_ED_25519.
    */

    //TLV[TAG_1]  4-byte identifier of EC key pair or private key.
    //TLV[TAG_2]  External public key (see ECKey).

    #[inline(never)]

    fn ecdh_generate_shared_secret(
        &mut self,
        eckeyidentifier: &[u8; 4],
        eckey: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), eckeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &eckey);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::EC.into(),
            Se050ApduP2::DH.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 ecdh_generate_shared_secret Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    // See AN12413 // 4.11 Crypto operations RSA

    /*
    ##Signature Generation
    RSASign

    ##Signature Verification
    RSAVerify

    ##Signature Encryption
    RSAEncrypt
    RSADecrypt
    */

    //###########################################################################
    // See AN12413 // 4.11 Crypto operations RSA // 4.11.1 Signature Generation //4.11.1.1 RSASign P.82

    //TLV[TAG_1] 4-byte identifier of the key pair or private key.
    //TLV[TAG_2] 1-byte RSASignatureAlgo
    //TLV[TAG_3] Byte array containing input data.

    #[inline(never)]

    fn rsa_sign(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsasignaturealgo: &[u8],
        inputdata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), rsakeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &rsasignaturealgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &inputdata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Signature.into(),
            Se050ApduP2::Sign.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 rsa_sign Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.11 Crypto operations RSA // 4.11.2 Signature Verification  //4.11.2.1 RSAVerify P.82-83

    //TLV[TAG_1] 4-byte identifier of the key pair or public key.
    //TLV[TAG_2] 1-byte RSASignatureAlgo
    //TLV[TAG_3] Byte array containing data to be verified.
    //TLV[TAG_5] Byte array containing ASN.1 signature.

    #[inline(never)]

    fn rsa_verify(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsasignaturealgo: &[u8],
        datatobeverified: &[u8],
        asn1signature: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), rsakeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &rsasignaturealgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &datatobeverified);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &asn1signature);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Signature.into(),
            Se050ApduP2::Verify.into(),
            Some(0x03),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 rsa_verify Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.11 Crypto operations RSA // 4.11.3 Encryption // 4.11.3.1 RSAEncrypt P.83-84
    //TLV[TAG_1] 4-byte identifier of the key pair or public key.
    //TLV[TAG_2] 1-byte RSAEncryptionAlgo
    //TLV[TAG_3] Byte array containing data to be encrypted.

    #[inline(never)]
    fn rsa_encrypt(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsaencryptionalgo: &[u8],
        datatobeencrypted: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), rsakeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &rsaencryptionalgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &datatobeencrypted);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::RSA.into(),
            Se050ApduP2::EncryptOneshot.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 rsa_encrypt Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    // See AN12413 // 4.11 Crypto operations RSA // 4.11.3 Encryption // 4.11.3.2 RSADecrypt P.84
    //TLV[TAG_1] 4-byte identifier of the key pair or public key.
    //TLV[TAG_2] 1-byte RSAEncryptionAlgo
    //TLV[TAG_3] Byte array containing data to be decrypted.

    #[inline(never)]
    fn rsa_decrypt(
        &mut self,
        rsakeyidentifier: &[u8; 4],
        rsaencryptionalgo: &[u8],
        datatobedecrypted: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), rsakeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &rsaencryptionalgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &datatobedecrypted);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::RSA.into(),
            Se050ApduP2::DecryptOneshot.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 rsa_decrypt Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413 //4.12 Crypto operations AES/DES

    /*
    ##multiple steps: init/update/final – multiple calls to process data.
    CipherInit
    CipherUpdate
    CipherFinal

    ##in one shot mode – 1 call to process data:
    CipherOneShot
     */

    //###########################################################################
    //See AN12413 //4.12 Crypto operations AES/DES //4.12.1 CipherInit P.84-85
    /*
    Cipher operations can be done either using Secure Object of type AESKey or DESKey.
    CipherMode indicates the algorithm to be applied.
    Cipher operations can be done in one shot mode or in multiple steps. Users are
    recommended to opt for one shot mode as much as possible as there is no NVM write
    access in that case, while an AES operation in multiple steps involves NVM write access.
    There are 2 options to use AES crypto modes:

    SE050 APDU Specification
    • in multiple steps: init/update/final – multiple calls to process data.
    • in one shot mode – 1 call to process data
    Note: If the Crypto Object is using AES in
    */

    //TLV[TAG_1] 4-byte identifier of the key object.
    //TLV[TAG_2] 2-byte Crypto Object identifier
    //TLV[TAG_4] Initialization Vector
    //[Optional]
    //[Conditional: only when the Crypto Object type equals CC_CIPHER and subtype is not including ECB]

    #[inline(never)]
    fn cipher_init_encrypt(
        &mut self,
        keyobjectidentifier: &[u8; 4],
        cryptoobjectidentifier: &[u8; 2],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), keyobjectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptoobjectidentifier);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), &initializationvector);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::Encrypt.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 cipher_init_encrypt Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    #[inline(never)]
    fn cipher_init_decrypt(
        &mut self,
        keyobjectidentifier: &[u8; 4],
        cryptoobjectidentifier: &[u8; 2],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), keyobjectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptoobjectidentifier);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), &initializationvector);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::Decrypt.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 cipher_init_encrypt Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413 //4.12 Crypto operations AES/DES //4.12.2 CipherUpdate P.85-86
    //TLV[TAG_2] 2-byte Crypto Object identifier
    //TLV[TAG_3] Byte array containing input data

    #[inline(never)]
    fn cipher_update(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        inputdata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptoobjectidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &inputdata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::Update.into(),
            Some(0x00),
        );

        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 cipher_update Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413 //4.12 Crypto operations AES/DES //4.12.3 CipherFinal P.86-87
    //TLV[TAG_2] 2-byte Crypto Object identifier
    //TLV[TAG_3] Byte array containing input data

    #[inline(never)]
    fn cipher_final(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        inputdata: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptoobjectidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &inputdata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::AuthFirstPart1.into(),
            Some(0x00),
        );

        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 cipher_final Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413 //4.12 Crypto operations AES/DES //4.12.4 CipherOneShot P.87

    /*
    TLV[TAG_1] 4-byte identifier of the key object.
    TLV[TAG_2] 1-byte CipherMode
    TLV[TAG_3] Byte array containing input data.
    TLV[TAG_4] Byte array containing an initialization vector.
    [Optional]
    [Conditional: only when the Crypto Object type
    equals CC_CIPHER and subtype is not including     ECB]
    */
    #[inline(never)]
    fn cipher_one_shot_encrypt(
        &mut self,
        keybjectidentifier: &[u8; 4],
        ciphermode: &[u8],
        inputdata: &[u8],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), keybjectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &ciphermode); // 4.3.21 CipherMode Table 39. CipherMode constants
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &inputdata);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), &initializationvector);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::Encrypt.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 cipher_one_shot_encrypt Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    #[inline(never)]
    fn cipher_one_shot_decrypt(
        &mut self,
        keybjectidentifier: &[u8; 4],
        ciphermode: &[u8],
        inputdata: &[u8],
        initializationvector: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), keybjectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &ciphermode); // 4.3.21 CipherMode Table 39. CipherMode constants
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &inputdata);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), &initializationvector);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::Decrypt.into(),
            Some(0x00),
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 cipher_one_shot_decrypt Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }
    /*
    //NEW VERSION
        //###########################################################################
        #[inline(never)]
        /* NOTE: hardcoded Object ID 0xae50ae50! */
        //4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT P.87
        //  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
        fn encrypt_aes_oneshot(&mut self, objectid: &[u8;4], cipher_mode: &[u8], data: &[u8],  enc: &mut [u8], delay: &mut DelayWrapper, ) -> Result<(), Se050Error>
        {
            if data.len() > 240 || (data.len() % 16 != 0) {
                error!("Input data too long or unaligned");
                return Err(Se050Error::UnknownError);
            }
            if enc.len() != data.len() {
                error!("Insufficient output buffer");
                return Err(Se050Error::UnknownError);
            }
            let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
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
                //error!("SE050 EncryptAESOneshot {:x} Failed: {:x}",  cipher_mode, rapdu.sw);
                //error!("SE050 EncryptAESOneshot   Failed: {:x}",  c  rapdu.sw);
                error!("SE050 EncryptAESOneshot {:x?} Failed: {:x}",  cipher_mode, rapdu.sw);

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
          //  debug!("SE050 EncryptAESOneshot {:x} OK",  cipher_mode );
           // debug!("SE050 EncryptAESOneshot   OK",  cipher_mode );
           debug!("SE050 EncryptAESOneshot {:x?} OK",  cipher_mode );



            Ok(())
        }
    */
    //###########################################################################
    //ERWEITERT
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    //4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // DECRYPT P.87
    //  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
    fn decrypt_aes_oneshot(
        &mut self,
        objectid: &[u8; 4],
        cipher_mode: &[u8],
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        if data.len() > 240 || (data.len() % 16 != 0) {
            error!("Input data too long or unaligned");
            return Err(Se050Error::UnknownError);
        }
        if enc.len() != data.len() {
            error!("Insufficient output buffer");
            return Err(Se050Error::UnknownError);
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &cipher_mode); // 4.3.21 CipherMode Table 39. CipherMode constants
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Crypto.into(),
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::DecryptOneshot.into(),
            Some(0),
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            //error!("SE050 DecryptAESOneshot {:x}, Failed: {:x}",  cipher_mode,rapdu.sw);
            //error!("SE050 DecryptAESOneshot   Failed: {:x}",  rapdu.sw);
            error!(
                "SE050 DecryptAESOneshot {:x?}, Failed: {:x}",
                cipher_mode, rapdu.sw
            );
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            //   error!("SE050 DecryptAESOneshot {:x} Return TLV Missing",   cipher_mode);
            //  error!("SE050 DecryptAESOneshot   Return TLV Missing",   );
            error!(
                "SE050 DecryptAESOneshot {:x?} Return TLV Missing",
                cipher_mode
            );

            Se050Error::UnknownError
        })?;

        if tlv1_ret.get_data().len() != enc.len() {
            //  error!("SE050 DecryptAESOneshot {:x} Length Mismatch",  cipher_mode );
            //error!("SE050 DecryptAESOneshot  Length Mismatch" );
            error!("SE050 DecryptAESOneshot {:x?} Length Mismatch", cipher_mode);

            return Err(Se050Error::UnknownError);
        }
        enc.copy_from_slice(tlv1_ret.get_data());
        // debug!("SE050 DecryptAESOneshot {:x} OK", cipher_mode );
        //debug!("SE050 DecryptAESOneshot  OK",   );
        debug!("SE050 DecryptAESOneshot {:x?} OK", cipher_mode);

        Ok(())
    }

    //###########################################################################
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    //4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // ENCRYPT  P.87
    //  4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
    fn encrypt_des_oneshot(
        &mut self,
        objectid: &[u8; 4],
        cipher_mode: &[u8],
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        if data.len() > 240 || (data.len() % 16 != 0) {
            error!("Input data too long or unaligned");
            return Err(Se050Error::UnknownError);
        }
        if enc.len() != data.len() {
            error!("Insufficient output buffer");
            return Err(Se050Error::UnknownError);
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &cipher_mode); // 4.3.21 CipherMode Table 39. CipherMode constants
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Crypto.into(),
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::EncryptOneshot.into(),
            Some(0),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            //  error!("SE050 EncryptDESOneshot {:x} Failed: {:x}",  cipher_mode, rapdu.sw);
            // error!("SE050 EncryptDESOneshot   Failed: {:x}",  rapdu.sw);
            error!(
                "SE050 EncryptDESOneshot {:x?} Failed: {:x}",
                cipher_mode, rapdu.sw
            );
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 EncryptDESOneshot Return TLV Missing");
            Se050Error::UnknownError
        })?;

        if tlv1_ret.get_data().len() != enc.len() {
            error!("SE050 EncryptDESOneshot Length Mismatch");
            return Err(Se050Error::UnknownError);
        }
        enc.copy_from_slice(tlv1_ret.get_data());
        // debug!("SE050 EncryptDESOneshot {:x} OK",  cipher_mode );
        //   debug!("SE050 EncryptDESOneshot   OK",   );
        debug!("SE050 EncryptDESOneshot {:x?} OK", cipher_mode);
        Ok(())
    }

    //###########################################################################
    //ERWEITERT
    #[inline(never)]
    /* NOTE: hardcoded Object ID 0xae50ae50! */
    //4.12 Crypto operations AES/DES // 4.12.4 CipherOneShot // DECRYPT P.87
    //4.3.21 CipherMode // 4.3.21 CipherMode Table 39. CipherMode constants P.43
    fn decrypt_des_oneshot(
        &mut self,
        objectid: &[u8; 4],
        cipher_mode: &[u8],
        data: &[u8],
        enc: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        if data.len() > 240 || (data.len() % 16 != 0) {
            error!("Input data too long or unaligned");
            return Err(Se050Error::UnknownError);
        }
        if enc.len() != data.len() {
            error!("Insufficient output buffer");
            return Err(Se050Error::UnknownError);
        }
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), objectid);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &cipher_mode); // 4.3.21 CipherMode Table 39. CipherMode constants
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), data);
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Se050ApduInstruction::Crypto.into(),
            Se050ApduP1CredType::Cipher.into(),
            Se050ApduP2::DecryptOneshot.into(),
            Some(0),
        );
        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            //error!("SE050 DecryptDESOneshot {:x}, Failed: {:x}",  cipher_mode,rapdu.sw);
            // error!("SE050 DecryptDESOneshot  Failed: {:x}",   rapdu.sw);
            error!(
                "SE050 DecryptDESOneshot {:x?}, Failed: {:x}",
                cipher_mode, rapdu.sw
            );

            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            //  error!("SE050 DecryptDESOneshot_{:x} Return TLV Missing",   cipher_mode);
            //  error!("SE050 DecryptDESOneshot    Return TLV Missing",   );
            error!(
                "SE050 DecryptDESOneshot {:x?} Return TLV Missing",
                cipher_mode
            );

            Se050Error::UnknownError
        })?;

        if tlv1_ret.get_data().len() != enc.len() {
            //error!("SE050 DecryptDESOneshot {:x} Length Mismatch",  cipher_mode );
            //error!("SE050 DecryptDESOneshot   Length Mismatch" );
            error!("SE050 DecryptDESOneshot {:x?} Length Mismatch", cipher_mode);

            return Err(Se050Error::UnknownError);
        }
        enc.copy_from_slice(tlv1_ret.get_data());
        //  debug!("SE050 DecryptDESOneshot {:x} OK", cipher_mode );
        // debug!("SE050 DecryptDESOneshot   OK"    );
        debug!("SE050 DecryptDESOneshot {:x?} OK", cipher_mode);

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413 //4.13 Message Authentication Codes
    /*
    ##multiple steps: init/update/final – multiple calls to process data.

    MACInit
    MACUpdate
    MACFinal

    ##in one shot mode – 1 call to process data:
    MACOneShot
    */

    //###########################################################################
    //See AN12413 //4.13 Message Authentication Codes //4.13.1 MACInit P.87-88
    /*

     Initiate a MAC operation. The state of the MAC operation is kept in the Crypto Object  until it’s finalized or deleted.
     The 4-byte identifier of the key must refer to an AESKey, DESKey or HMACKey.

         TLV[TAG_1] 4-byte identifier of the MAC key object.
         TLV[TAG_2] 2-byte Crypto Object identifier
    */

    #[inline(never)]
    fn mac_init(
        &mut self,
        mackeybjectidentifier: &[u8; 4],
        cryptobjectidentifier: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), mackeybjectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptobjectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::MAC.into(),
            Se050ApduP2::Generate.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 mac_init Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413 //4.13 Message Authentication Codes //4.13.2 MACUpdate P.88-89
    /*
            TLV[TAG_1] Byte array containing data to be taken as input to MAC.
            TLV[TAG_2] 2-byte Crypto Object identifier
    */
    #[inline(never)]

    fn mac_update(
        &mut self,
        macdatainput: &[u8],
        cryptobjectidentifier: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &macdatainput);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptobjectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::MAC.into(),
            Se050ApduP2::Update.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 mac_update Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413 //4.13 Message Authentication Codes //4.13.3 MACFinal P.89
    /*
            TLV[TAG_1] Byte array containing data to be taken as input to MAC.
            TLV[TAG_2] 2-byte Crypto Object identifier
            TLV[TAG_3] Byte array containing MAC to validate.
            [Conditional: only applicable if the crypto object is set for validating (MACInit P2 = P2_VALIDATE)]
    */

    #[inline(never)]
    fn mac_final(
        &mut self,
        macdatainput: &[u8],
        cryptobjectidentifier: &[u8; 2],
        mactovalidate: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &macdatainput);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptobjectidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &mactovalidate);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::MAC.into(),
            Se050ApduP2::Final.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 mac_final Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413 //4.13 Message Authentication Codes //4.13.4 MACOneShot P.90

    /*
            Performs a MAC operation in one shot (without keeping state).
            The 4-byte identifier of the key must refer to an AESKey, DESKey or HMACKey.

            TLV[TAG_1] 4-byte identifier of the key object.
            TLV[TAG_2] 1-byte MACAlgo
            TLV[TAG_3] Byte array containing data to be taken as input to MAC.
            TLV[TAG_5] MAC to verify (when P2=P2_VALIDATE_ONESHOT)
    */

    #[inline(never)]
    fn mac_one_shot(
        &mut self,
        keyobjectidentifier: &[u8; 4],
        macalgo: &[u8],
        datainputtomac: &[u8],
        mactoverify: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), keyobjectidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &macalgo);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &datainputtomac);
        let tlv5 = SimpleTlv::new(Se050TlvTag::Tag5.into(), &mactoverify);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::MAC.into(),
            Se050ApduP2::GenerateOneshot.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv5);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 mac_one_shot Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413 //4.14 Key Derivation Functions
    /*
    HKDF
    PBKDF2
    */

    //###########################################################################
    //See AN12413 //4.14 Key Derivation Functions //4.14.1 HKDF P.90-91

    /*
            Perform HMAC Key Derivation Function according to [RFC5869].
            The HKDF can only be used in Extract-And-Expand mode. In this mode, the full algorithm
            is executed. The caller must provide a salt length (0 up to 64 bytes). If salt length equals
            0 or salt is not provided as input, the default salt will be used. Expand-only mode is not
            supported.
            Note that this KDF is equal to the KDF in Feedback Mode described in [NIST SP800-108]
            with the PRF being HMAC with SHA256 and with an 8-bit counter at the end of the
            iteration variable.

            TLV[TAG_1] 4-byte HMACKey identifier (= IKM)
            TLV[TAG_2] 1-byte DigestMode (except DIGEST_NO_HASH and DIGEST_SHA224)
            TLV[TAG_3] [Optional] Salt. (0 to 64 bytes)
            TLV[TAG_4] [Optional] Info: The context and information to apply (1 to 448  bytes).
            TLV[TAG_5] 2-byte requested length (L): 1 up to   MAX_APDU_PAYLOAD_LENGTH
    */

    #[inline(never)]

    fn hkdf(
        &mut self,
        hmackeyidentifier: &[u8; 4],
        digestmode: &[u8],
        salt: &[u8; 64],
        info: &[u8; 64],
        requestedlength: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), hmackeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &digestmode);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), salt);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), info);
        let tlv5 = SimpleTlv::new(Se050TlvTag::Tag5.into(), requestedlength);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::HKDF.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);
        capdu.push(tlv5);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 hkdf Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413 //4.14 Key Derivation Functions //4.14.2 PBKDF2 P.91-92
    /*
            Password Based Key Derivation Function 2 (PBKDF2) according to [RFC8018] with HMAC SHA1 as underlying pseudorandom function.
            The password is an input to the KDF and must be stored inside the SE050.
            The output is returned to the host.

            TLV[TAG_1] 4-byte password identifier (object type must be HMACKey)

            TLV[TAG_2] Salt (0 to 64 bytes)
            [Optional]

            TLV[TAG_3] 2-byte Iteration count: 1 up to 0x7FFF.
            TLV[TAG_4] 2-byte Requested length: 1 up to 512 bytes.
    */

    #[inline(never)]
    fn pbkdf2derivekey(
        &mut self,
        passwordidentifier: &[u8; 4],
        salt: &[u8; 64],
        iterationcount: &[u8; 2],
        requestedlength: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), passwordidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), salt);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), iterationcount);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), requestedlength);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::PBKDF.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 pbkdf2derivekey Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support

    /*
    (MIFARE DESFire EV2 Key derivation (S-mode). This is limited to AES128 keys only.)

    DFDiversifyKey

    DFAuthenticateFirstPart1
    DFAuthenticateFirstPart2

    DFAuthenticateNonFirstPart1
    DFAuthenticateNonFirstPart2

    DFDumpSessionKeys

    DFChangeKeyPart1
    DFChangeKeyPart2

    DFKillAuthentication
    */

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.1 DFDiversifyKey P92-95
    /*
    MIFARE DESFire EV2 Key derivation (S-mode). This is limited to AES128 keys only.
    The SE050 can be used by a card reader to setup a session
    where the SE050 stores the  master key(s) and the session keys are generated and passed to the host.
    The SE050 keeps an internal state of MIFARE DESFire authentication data during authentication setup.
    This state is fully transient, so it is lost on deselect of the applet.
    The MIFARE DESFire state is owned by 1 user at a time; i.e., the user who
    calls DFAuthenticateFirstPart1 owns the MIFARE DESFire context until
    DFAuthenticateFirstPart1 is called again or until DFKillAuthentication is called.

    The SE050 can also be used to support a ChangeKey command, either supporting
    ChangeKey or ChangeKeyEV2. To establish a correct use case, policies need to be
    applied to the keys to indicate keys can be used for ChangeKey or not, etc..

    TLV[TAG_1] 4-byte master key identifier.
    TLV[TAG_2] 4-byte diversified key identifier.
    TLV[TAG_3] Byte array containing divInput (up to 31 bytes).
    */

    #[inline(never)]
    fn dfdiversifykey(
        &mut self,
        masterkeyidentifier: &[u8; 4],
        diversifiedkeyidentifier: &[u8; 4],
        divinput: &[u8; 31],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), masterkeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), diversifiedkeyidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), divinput);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Diversify.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050  dfdiversifykeyFailed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.2 DFAuthenticateFirst  //4.15.2.1 DFAuthenticateFirstPart1 // P.95

    /*
    Mutual authentication between the reader and the card, part 1.

    TLV[TAG_1] 4-byte key identifier.
    TLV[TAG_2] 16-byte encrypted card challenge: E(Kx,RndB)
    */

    #[inline(never)]

    fn dfauthenticatefirstpart1(
        &mut self,
        keyidentifier: &[u8; 4],
        diversifiedkeyidentifier: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), keyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), diversifiedkeyidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::AuthFirstPart1.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050  dfauthenticateFirstpart1 Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.2 DFAuthenticateFirst  //4.15.2.2 DFAuthenticateFirstPart2 // P.95-96

    /*
        For First part 2, the key identifier is implicitly set to the identifier used for the First authentication.
        DFAuthenticateFirstPart1 needs to be called before; otherwise an error is returned.
        TLV[TAG_1] 32 byte input: E(Kx,TI||RndA’||PDcap2||PCDcap2)
    */

    #[inline(never)]

    fn dfauthenticatefirstpart2(
        &mut self,
        input: &[u8; 32],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), input);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::AuthFirstPart2.into(),
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050  dfauthenticateFirstpart2 Failed: {:x}", rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.3 DFAuthenticateNonFirst  //4.15.3.1 DFAuthenticateNonFirstPart1// P.96-97
    /*
        Mutual authentication between the reader and the card, part 2.
        TLV[TAG_1] 4-byte key identifier
        TLV[TAG_2] 16-byte encrypted card challenge: E(Kx,RndB)

    */

    #[inline(never)]
    fn dfauthenticatenonfirstpart1(
        &mut self,
        keyidentifier: &[u8; 4],
        encryptedcardchallenge: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), keyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), encryptedcardchallenge);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::AuthNonfirstPart1.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 dfauthenticatenonfirstpart1 Failed: {:x}", rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.3 DFAuthenticateNonFirst  //4.15.3.2 DFAuthenticateNonFirstPart2// P.97
    /*
        For NonFirst part 2, the key identifier is implicitly set to the identifier used for the NonFirst
        part 1 authentication. DFAuthenticateNonFirstPart1 needs to be called before; otherwise
        an error is returned.
        If authentication fails, SW_WRONG_DATA will be returned.

        TLV[TAG_1] 16-byte E(Kx, RndA’)
    */

    #[inline(never)]
    fn dfauthenticatenonfirstpart2(
        &mut self,
        edata: &[u8; 16],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), edata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::AuthNonfirstPart2.into(),
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 dfauthenticatenonfirstpart2 Failed: {:x}", rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.4 DFDumpSessionKeys// P.97-98
    /*
        Dump the Transaction Identifier and the session keys to the host.
    */

    #[inline(never)]
    #[allow(unused_mut)]
    fn dfdumpdsessionkeys(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::DumpKey.into(),
            Some(0x2A),
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 dfdumpdsessionkeys Failed: {:x}", rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.5 DFChangeKey// 4.15.5.1 DFChangeKeyPart1 P.98-99
    /*
        The DFChangeKeyPart1 command is supporting the function to change keys on the
        DESFire PICC. The command generates the cryptogram required to perform such
        operation.
        The new key and, if used, the current (or old) key must be stored in the SE050 and have
        the POLICY_OBJ_ALLOW_DESFIRE_AUTHENTICATION associated to execute this
        command. This means the new PICC key must have been loaded into the SE050 prior to
        issuing this command.
        The 1-byte key set number indicates whether DESFire ChangeKey or DESFire
        ChangeKeyEV2 is used. When key set equals 0xFF, ChangeKey is used.

        TLV[TAG_1] 4-byte identifier of the old key.
        [Optional: if the authentication key is the same as
        the key to be replaced, this TAG should not be
        present].
        TLV[TAG_2] 4-byte identifier of the new key.
        TLV[TAG_3] 1-byte key set number
        [Optional: default = 0xC6]
        TLV[TAG_4] 1-byte DESFire key number to be targeted.
        TLV[TAG_5] 1-byte key version
    */

    #[inline(never)]
    fn dfchangekeypart1(
        &mut self,
        oldkey: &[u8; 4],
        newkey: &[u8; 4],
        setnumber: &[u8],
        desfirekeynumber: &[u8],
        keyversion: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), oldkey);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), newkey);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &setnumber);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), &desfirekeynumber);
        let tlv5 = SimpleTlv::new(Se050TlvTag::Tag5.into(), &keyversion);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::ChangeKeyPart1.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);
        capdu.push(tlv5);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 dfchangekeypart1 Failed: {:x}", rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.5 DFChangeKey// 4.15.5.2 DFChangeKeyPart2 P.99
    /*
        The DFChangeKeyPart2 command verifies the MAC returned by ChangeKey or
        ChangeKeyEV2. Note that this function only needs to be called if a MAC is returned
        (which is not the case if the currently authenticated key is changed on the DESFire card).

        TLV[TAG_1] MAC
    */

    #[inline(never)]
    fn dfchangekeypart2(&mut self, mac: &[u8], delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &mac);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::ChangeKeyPart2.into(),
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 dfchangekeypart2 Failed: {:x}", rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //See AN12413,// 4.15 MIFARE DESFire support //4.15.6 DFKillAuthentication  P.99-100
    /*
      DFKillAuthentication invalidates any authentication and clears the internal DESFire state.
    Keys used as input (master keys or diversified keys) are not touched.
        TLV[TAG_1] MAC
    */

    #[inline(never)]
    #[allow(unused_mut)]
    fn dfkillauthentication(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::KillAuth.into(),
            None,
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 dfkillauthentication Failed: {:x}", rapdu.sw);

            return Err(Se050Error::UnknownError);
        }

        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413, //4.16 TLS handshake support
    /*
    TLSGenerateRandom
    TLSCalculatePreMasterSecret
    TLSPerformPRF
    */

    //###########################################################################
    //See AN12413, //4.16 TLS handshake support //  4.16.1 TLSGenerateRandom P.100

    #[inline(never)]
    #[allow(unused_mut)]
    fn tls_generate_random(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::TLS.into(),
            Se050ApduP2::Random.into(),
            Some(0x24),
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 tls_generate_random  Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 tls_generate_random OK");
        Ok(())
    }

    //###########################################################################
    //See AN12413, //4.16 TLS handshake support //  4.16.2 TLSCalculatePreMasterSecret P.101 -102
    /*
        TLV[TAG_1] 4-byte PSK identifier referring to a 16, 32, 48 or 64-byte Pre Shared Key.
        [Optional]
        pskidentifier

        TLV[TAG_2] 4-byte key pair identifier.
        [Optional]
        keypairidentifier.

        TLV[TAG_3] 4-byte target HMACKey identifier.

        hmackeyidentifier.

        TLV[TAG_4] Byte array containing input data.
        inputdata

    */

    #[inline(never)]
    #[allow(unused_mut)]
    fn tls_calculate_pre_master_secret(
        &mut self,
        pskidentifier: &[u8; 4],
        keypairidentifier: &[u8; 4],
        hmackeyidentifier: &[u8; 4],
        inputdata: &[u8; 4],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), pskidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), keypairidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), hmackeyidentifier);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), inputdata);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::TLS.into(),
            Se050ApduP2::TLS_PMS.into(),
            None,
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!(
                "SE050 tls_calculate_pre_master_secret Failed: {:x}",
                rapdu.sw
            );
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 tls_calculate_pre_master_secret OK");
        Ok(())
    }

    //###########################################################################
    //See AN12413, //4.16 TLS handshake support //  4.16.3 TLSPerformPRF P.101-102
    /*
    The command TLSPerformPRF will compute either:
    • the master secret for TLS according to [RFC5246], section 8.1
    • key expansion data from a master secret for TLS according to [RFC5246], section 6.3.
    Each time before calling this function, TLSGenerateRandom must be called. Executing
    this function will clear the random that is stored in the SE050.
    The function can be called as client or as server and either using the pre-master secret or
    master secret as input, stored in an HMACKey. The input length must be either 16, 32, 48
    or 64 bytes.
    This results in P2 having 4 possibilities:
    • P2_TLS_PRF_CLI_HELLO: pass the clientHelloRandom to calculate a master secret,
    the serverHelloRandom is in SE050, generated by TLSGenerateRandom.
    • P2_TLS_PRF_SRV_HELLO: pass the serverHelloRandom to calculate a master
    secret, the clientHelloRandom is in SE050, generated by TLSGenerateRandom.
    • P2_TLS_PRF_CLI_RANDOM: pass the clientRandom to generate key expansion data,
    the serverRandom is in SE050, generated by TLSGenerateRandom.
    • P2_TLS_PRF_SRV_RANDOM: pass the serverRandom to generate key expansion
    data, the clientRandom is in SE050
    */

    /*
    TLV[TAG_1] 4-byte HMACKey identifier.
    TLV[TAG_2] 1-byte DigestMode, except DIGEST_NO_HASH and     DIGEST_SHA224
    TLV[TAG_3] Label (1 to 64 bytes)
    TLV[TAG_4] 32-byte random
    TLV[TAG_5] 2-byte requested length (1 up to 512 bytes)

    */

    #[inline(never)]
    fn tls_perform_prf(
        &mut self,
        hmackeyidentifier: &[u8; 4],
        digestmode: &[u8],
        label: &[u8; 64],
        random: &[u8; 32],
        requestlenght: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), hmackeyidentifier);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &digestmode);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), label);
        let tlv4 = SimpleTlv::new(Se050TlvTag::Tag4.into(), random);
        let tlv5 = SimpleTlv::new(Se050TlvTag::Tag5.into(), requestlenght);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::TLS.into(),
            Se050ApduP2::TLS_PRF_CLI_Hello.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv4);
        capdu.push(tlv5);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 tls_perform_prf Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 tls_perform_prf OK");
        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413, //4.17 I2C controller support

    /*
    I2CM_ExecuteCommandSet
    */

    //###########################################################################
    //See AN12413, //4.17 I2C controller support //4.17.1 I2CM_ExecuteCommandSet //P.103-106
    /*
    TLV[TAG_1] Byte array containing I2C Command set as TLV array.
    i2ccommand

    TLV[TAG_2] 4-byte attestation object identifier.
    [Optional]
    [Conditional: only when INS_ATTEST is set]
    attestationobjectidentifier

    TLV[TAG_3] 1-byte AttestationAlgo
    [Optional]
    [Conditional: only when INS_ATTEST is set]

    attestationobjectidentifier

    TLV[TAG_7] 16-byte freshness random
    [Optional]
    [Conditional: only when INS_ATTEST is set]

    attestationalgo

     */

    #[inline(never)]
    fn i2cm_execute_command_set(
        &mut self,
        i2ccommand: &[u8],
        attestationobjectidentifier: &[u8],
        attestationalgo: &[u8],
        freshnessrandom: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &i2ccommand);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &attestationobjectidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &attestationalgo);
        let tlv7 = SimpleTlv::new(Se050TlvTag::Tag7.into(), &freshnessrandom);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::I2CM.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);
        capdu.push(tlv3);
        capdu.push(tlv7);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 i2cm_execute_command_set Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 i2cm_execute_command_set OK");
        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413, //4.18 Digest operations
    /*
    DigestInit
    DigestUpdate
    DigestFinal
    DigestOneShot
    */

    //###########################################################################
    //See AN12413, //4.18 Digest operations //4.18.1 DigestInit // P.106

    /*
    4.18 Digest operations
    There are 2 options to use Digest operations on SE050:
    • in multiple steps: init/update/final – multiple calls to process data.
    • in one shot mode – 1 call to process data
    Users are recommended to opt for one shot mode as much as possible.
    */
    /*
    4.18.1 DigestInit
    Open a digest operation. The state of the digest operation is kept in the Crypto Object
    until the Crypto Object is finalized or deleted.
    */

    //TLV[TAG_2] 2-byte Crypto Object identifier

    #[inline(never)]
    fn digest_init(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptoobjectidentifier);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Init.into(),
            None,
        );

        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 digest_init Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 digest_init OK");
        Ok(())
    }

    //###########################################################################
    //See AN12413, //4.18 Digest operations //4.18.2 DigestUpdate // P.106-107
    /*
    Update a digest operation.
    */

    //TLV[TAG_2] 2-byte Crypto Object identifier
    // TLV[TAG_3] Data to be hashed.

    #[inline(never)]
    fn digest_update(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        datatobehashed: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptoobjectidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &datatobehashed);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Update.into(),
            None,
        );

        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 digest_update Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 digest_update OK");
        Ok(())
    }

    //###########################################################################
    //See AN12413, //4.18 Digest operations //4.18.3 DigestFinal // P. 107-108
    /*
    Finalize a digest operation.
    */

    //TLV[TAG_2] 2-byte Crypto Object identifier
    // TLV[TAG_3] Data to be hashed.

    #[inline(never)]
    fn digest_final(
        &mut self,
        cryptoobjectidentifier: &[u8; 2],
        datatobehashed: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), cryptoobjectidentifier);
        let tlv3 = SimpleTlv::new(Se050TlvTag::Tag3.into(), &datatobehashed);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Final.into(),
            Some(0x00),
        );

        capdu.push(tlv2);
        capdu.push(tlv3);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 digest_final Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 digest_final OK");
        Ok(())
    }

    //###########################################################################
    //See AN12413, //4.18 Digest operations //4.18.3 DigestFinal // P. 107-108
    /*
    Finalize a digest operation.
    */

    //TLV[TAG_1] 1-byte DigestMode (except DIGEST_NO_HASH)
    // TLV[TAG_2] Data to be hashed.

    #[inline(never)]
    fn digest_one_shot(
        &mut self,
        digestmode: &[u8],
        datatobehashed: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &digestmode);
        let tlv2 = SimpleTlv::new(Se050TlvTag::Tag2.into(), &datatobehashed);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Crypto) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Oneshot.into(),
            Some(0x00),
        );

        capdu.push(tlv1);
        capdu.push(tlv2);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 digest_one_shotl Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        debug!("SE050 digest_one_shot OK");
        Ok(())
    }

    //###########################################################################
    //###########################################################################
    //See AN12413, // 4.19 Generic management commands

    /*
    GetVersion
    GetTimestamp
    GetFreeMemory
    GetRandom
    GetCryptoObjectList
    DeleteAll
    DeleteCrypto
    */

    //###########################################################################
    //See AN12413, // 4.19 Generic management commands //4.19.1 GetVersion  P.108 -109
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
            Se050ApduP2::Version.into(),
            Some(0x0B),
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    //See AN12413, // 4.19 Generic management commands //4.19.2 GetTimestamp P.109
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
            Some(0x14),
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    //See AN12413, // 4.19 Generic management commands //4.19.2 GetTimestamp P.109
    //Gets the amount of free memory.
    //MemoryType indicates the type of memory.

    //The result indicates the amount of free memory.
    //Note that behavior of the function might not be fully linear,
    //and can have a granularity of 16 bytes since the applet will typically report the “worst case” amount.
    //For example, when allocating 2 bytes at a time, the first report will show 16 bytes being allocated, which remains the same for the next 7 allocations of 2 bytes.
    //  memoryconstant      Persistent = 1,   TransientReset = 2,    TransientDeselect = 3,
    // TLV[TAG_1] Memory

    #[inline(never)]
    fn get_free_memory(
        &mut self,
        memoryconstant: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), Se050Error> {
        let tlv1 = SimpleTlv::new(Se050TlvTag::Tag1.into(), &memoryconstant);

        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::Memory.into(),
            Some(0x06),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
    //See AN12413, Pages 110/111 -> 4.19 Generic management commands //4.19.4 GetRandom (Gets random data from the SE050.) p.110
    //TLV[TAG_1] 2-byte requested size.
    //OLD VERSION
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
            Some(0x00),
        );

        capdu.push(tlv1);

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 260] = [0; 260];
        let rapdu = self
            .t1_proto
            .receive_apdu(&mut rapdu_buf, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        if rapdu.sw != 0x9000 {
            error!("SE050 GetRandom Failed: {:x}", rapdu.sw);
            return Err(Se050Error::UnknownError);
        }

        let tlv1_ret = rapdu.get_tlv(Se050TlvTag::Tag1.into()).ok_or_else(|| {
            error!("SE050 GetRandom Return TLV Missing");
            Se050Error::UnknownError
        })?;

        if tlv1_ret.get_data().len() != buf.len() {
            error!("SE050 GetRandom Length Mismatch");
            return Err(Se050Error::UnknownError);
        }

        buf.copy_from_slice(tlv1_ret.get_data());

        debug!("SE050 GetRandom OK bla bla");

        Ok(())
    }

    //###########################################################################
    //See AN12413, // 4.19 Generic management commands //44.19.5 DeleteAll P.112
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
    fn delete_all(&mut self, delay: &mut DelayWrapper) -> Result<(), Se050Error> {
        let mut capdu = CApdu::new(
            ApduClass::ProprietaryPlain,
            Into::<u8>::into(Se050ApduInstruction::Mgmt) | APDU_INSTRUCTION_TRANSIENT,
            Se050ApduP1CredType::Default.into(),
            Se050ApduP2::DeleteAll.into(),
            Some(0x00),
        );

        self.t1_proto
            .send_apdu(&capdu, delay)
            .map_err(|_| Se050Error::UnknownError)?;

        let mut rapdu_buf: [u8; 16] = [0; 16];
        let rapdu = self
            .t1_proto
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
