use crate::types::*;
use crate::{Se050, Se050Device, T1overI2C};

extern crate std;

mod test_twi;

#[test]
fn test_capdu() {
    let mut c = CApdu::new(ApduClass::ProprietaryPlain, 0x20, 0x40, 0x60, Some(0));
    let t1 = SimpleTlv::new(0x41, &[0,1,2,3,0,1,2,3,0,1,2,3]);
    c.push(t1);
    let v: heapless::Vec<u8, 256> = c.byte_iter().collect();
    // APDU header, Lc (1B), TLV (1B size), Le (1B)
    assert_eq!(v.len(), 4+1+(1+1+12)+1);
    assert_eq!(v.as_slice(), &[0x80,0x20,0x40,0x60,0x0e,
                               0x41,0x0c,0,1,2,3,0,1,2,3,0,1,2,3,
                               0x00]);
}

#[test]
fn test_crc16_ccitt() {
    assert_eq!(0x78a1, Se050CRC::calculate(&[0,48,95,111,242]));
}

const T1FC_S_INTF_RESET: &[u8] = &[0x5a, 0xcf, 0x00, 0x37, 0x7f];
const T1FRH_S_INTF_RESET: &[u8] = &[0xa5, 0xef, 0x23];
const T1F_ATR: &[u8] =
       &[0x00, 0xA0, 0x00, 0x00, 0x03, 0x96, 0x04, 0x03,
       0xE8, 0x00, 0xFE, 0x02, 0x0B, 0x03, 0xE8, 0x08,
       0x01, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00,
       0x0A, 0x4A, 0x43, 0x4F, 0x50, 0x34, 0x20, 0x41,
       0x54, 0x50, 0x4F, 0x87, 0x77];

#[test]
fn test_soft_reset() {
    let mut delay = test_twi::get_delay_wrapper();
    let mut xtwi = test_twi::TWI::new();
    xtwi.push_in(T1FC_S_INTF_RESET);
    xtwi.push_out(T1FRH_S_INTF_RESET);
    xtwi.push_out(T1F_ATR);
    let mut t1 = T1overI2C::new(xtwi, 0x48, 0x5a);

    let atr = t1.interface_soft_reset(&mut delay);
    assert!(atr.as_ref().map_err(|e| std::println!("ATR Fail: {:?}", e)).is_ok());
    let atr = atr.unwrap();
    assert_eq!(atr.dllp.ifsc, 254);
}

const T1FC_GP_SELECT_SE050: &[u8] = &[0x5a, 0x00, 0x16,
       0x00, 0xa4, 0x04, 0x00, 0x10,
       0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
       0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
       0x00, 0xa8, 0xc8];
const T1FRH_GP_SELECT_SE050: &[u8] = &[0xa5, 0x00, 0x09];
const T1F_APP_VERSION: &[u8] =
       &[0x03, 0x01, 0x01, 0x6f, 0xff, 0x01, 0x0b, 0x90, 0x00, 0xcc, 0x8b];

#[test]
fn test_se050_init() {
    let mut delay = test_twi::get_delay_wrapper();
    let mut xtwi = test_twi::TWI::new();
    xtwi.push_in(T1FC_S_INTF_RESET);
    xtwi.push_out(T1FRH_S_INTF_RESET);
    xtwi.push_out(T1F_ATR);
    xtwi.push_in(T1FC_GP_SELECT_SE050);
    xtwi.push_out(T1FRH_GP_SELECT_SE050);
    xtwi.push_out(T1F_APP_VERSION);
    let t1 = T1overI2C::new(xtwi, 0x48, 0x5a);
    let mut se050 = Se050::new(t1);
    let r = se050.enable(&mut delay);
    assert!(r.is_ok());
}
