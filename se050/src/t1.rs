use crate::types::*;
use core::convert::{Into, TryInto};
use byteorder::{ByteOrder, LE, BE};

pub struct T1overI2C<TWI>
where
    TWI: embedded_hal::blocking::i2c::Read + embedded_hal::blocking::i2c::Write,
{
    twi: TWI,
    se_address: u16,
    nad_hd2se: u8,
    nad_se2hd: u8,
    iseq_snd: u8,
    iseq_rcv: u8,
}

const TWI_RETRIES: usize = 128;
const TWI_RETRY_DELAY_MS: u32 = 2;

#[allow(unused_variables)]
fn maybe_debug(label: &str, data: &[u8]) {
    if data.len() > 32 {
        let (dh, dt) = data.split_at(16);
        debug!("{} {:?}...{:?}", label, dh, &dt[dt.len()-16..dt.len()]);
    } else {
        debug!("{} {:?}", label, data);
    }
}

impl<TWI> T1overI2C<TWI>
where
    TWI: embedded_hal::blocking::i2c::Read + embedded_hal::blocking::i2c::Write,
{
    pub fn new(twi: TWI, address: u16, nad: u8) -> Self {
        let nad_r: u8 = ((nad & 0xf0) >> 4) | ((nad & 0x0f) << 4);
        T1overI2C {
            twi,
            se_address: address,
            nad_hd2se: nad,
            nad_se2hd: nad_r,
            iseq_snd: 0,
            iseq_rcv: 0,
        }
    }

    fn twi_write(&mut self, data: &[u8], delay: &mut DelayWrapper) -> Result<(), T1Error> {
        maybe_debug("T1 W", data);
        for _i in 0..TWI_RETRIES {
            let e = self.twi.write(self.se_address as u8, data);
            if e.is_ok() {
                trace!("t1w ok({})", i);
                return Ok(());
            }
            delay.inner.delay_ms(TWI_RETRY_DELAY_MS);
            // TODO: we should only loop on AddressNack errors
            // but the existing traits don't provide an API for that
        }
        trace!("t1w err");
        Err(T1Error::TransmitError)
    }

    fn twi_read(&mut self, data: &mut [u8], delay: &mut DelayWrapper) -> Result<(), T1Error> {
        for _i in 0..TWI_RETRIES {
            let e = self.twi.read(self.se_address as u8, data);
            if e.is_ok() {
                maybe_debug("T1 R", data);
                trace!("t1r ok({})", i);
                return Ok(());
            }
            delay.inner.delay_ms(TWI_RETRY_DELAY_MS);
            // TODO: we should only loop on AddressNack errors
            // but the existing traits don't provide an API for that
        }
        trace!("t1r err");
        Err(T1Error::ReceiveError)
    }

    #[inline(never)]
    fn receive_frame(
        &mut self,
        buf: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<T1Header, T1Error> {
        if 3 > buf.len() {
            return Err(T1Error::BufferOverrunError(3));
        }
        // read T1 frame header
        self.twi_read(&mut buf[0..3], delay)?;
        let pcb = buf[1].try_into().map_err(|_| T1Error::ProtocolError)?;
        let mut header = T1Header { nad: buf[0], pcb, len: buf[2], crc: 0 };
        if header.nad != self.nad_se2hd {
            return Err(T1Error::ProtocolError);
        }
        let dlen = header.len as usize;
        if dlen + 2 > buf.len() {
            return Err(T1Error::BufferOverrunError(dlen+2));
        }
        let mut crc_state = Se050CRC::new();
        crc_state.update(&buf[0..3]);

        // read T1 frame payload
        self.twi_read(&mut buf[0..dlen + 2], delay)?;
        header.crc = LE::read_u16(&buf[dlen..dlen + 2]);

        crc_state.update(&buf[0..dlen]);
        let calculated_crc = crc_state.get();

        if calculated_crc != header.crc {
            return Err(T1Error::ChecksumError);
        }

        Ok(header)
    }

    #[inline(never)]
    fn send_frame(&mut self, pcb: T1PCB, data: &[u8], delay: &mut DelayWrapper) -> Result<(), T1Error> {
        if data.len() > MAX_IFSC {
            return Err(T1Error::BufferOverrunError(data.len()));
        }

        let mut buf = heapless::Vec::<u8, MAX_T1_FRAME_SIZE>::new();
        buf.extend_from_slice(&[self.nad_hd2se, pcb.into(), data.len() as u8]).unwrap();
        buf.extend_from_slice(data).unwrap();
        let crc = Se050CRC::calculate(buf.as_slice());
        let mut crcbuf: [u8; 2] = [0, 0];
        LE::write_u16(&mut crcbuf, crc);
        buf.extend_from_slice(&crcbuf).unwrap();
        self.twi_write(buf.as_slice(), delay)
    }

    fn send_s(
        &mut self,
        code: T1SCode,
        data: &[u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), T1Error> {
        self.send_frame(T1PCB::S(code, false), data, delay)
    }

    fn receive_s(
        &mut self,
        code: T1SCode,
        data: &mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<(), T1Error> {
        let header = self.receive_frame(data, delay)?;
        match header.pcb {
        T1PCB::S(scode, true) if code == scode => { Ok(()) },
        T1PCB::S(_, _) => { Err(T1Error::ProtocolError) },
        T1PCB::R(_, r) => { Err(T1Error::RCodeReceived(r)) },
        _ => { Err(T1Error::ProtocolError) }
        }
    }

    fn send_apdu_from_iter(&mut self, apdu_iter: &mut CApduByteIterator, delay: &mut DelayWrapper) -> Result<(), T1Error> {
        let mut peek: Option<u8> = None;
        let mut buf: heapless::Vec<u8, MAX_IFSC> = heapless::Vec::new();

        loop {
            buf.clear();
            loop {
                let v = apdu_iter.next();
                if v.is_none() { break; }
                buf.push(v.unwrap()).ok();
                if buf.len() == MAX_IFSC {
                    peek = apdu_iter.next();
                    break;
                }
            }
            self.send_frame(T1PCB::I(self.iseq_snd, peek.is_some()), buf.as_slice(), delay)?;
            self.iseq_snd ^= 1;
            if peek.is_none() { break; }
            // receive R(N(R))
            todo!();
        }

        Ok(())
    }
}

impl<TWI> T1Proto for T1overI2C<TWI>
where
    TWI: embedded_hal::blocking::i2c::Read + embedded_hal::blocking::i2c::Write,
{
    #[inline(never)]
    fn send_apdu(&mut self, apdu: &CApdu, delay: &mut DelayWrapper) -> Result<(), T1Error> {
        self.send_apdu_from_iter(&mut apdu.byte_iter(), delay)
    }

    #[inline(never)]
    fn send_apdu_raw(&mut self, apdu: &RawCApdu, delay: &mut DelayWrapper) -> Result<(), T1Error> {
        self.send_apdu_from_iter(&mut apdu.byte_iter(), delay)
    }

    #[inline(never)]
    fn receive_apdu<'a>(
        &mut self,
        buf: &'a mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<RApdu<'a>, T1Error> {
        let rapdu = self.receive_apdu_raw(buf, delay)?;

        let mut tlvs = heapless::Vec::new();
        let mut buf_offset: usize = 0;

        loop {
            if buf_offset == rapdu.data.len() { break; }
            let tag = rapdu.data[buf_offset];
            let len: usize;
            if buf_offset+1 >= rapdu.data.len() { return Err(T1Error::TlvParseError); }
            if rapdu.data[buf_offset+1] == 0x82 {
                if buf_offset+4 > rapdu.data.len() { return Err(T1Error::TlvParseError); }
                len = BE::read_u16(&rapdu.data[buf_offset+2..buf_offset+4]) as usize;
                if buf_offset+4+len > rapdu.data.len() { return Err(T1Error::TlvParseError); }
                tlvs.push(SimpleTlv::new(tag, &rapdu.data[buf_offset+4..buf_offset+4+len])).map_err(|_| T1Error::TlvParseError)?;
                buf_offset += 4 + len;
            } else if rapdu.data[buf_offset+1] < 0x80 {
                len = rapdu.data[buf_offset+1] as usize;
                if buf_offset+2+len > rapdu.data.len() { return Err(T1Error::TlvParseError); }
                tlvs.push(SimpleTlv::new(tag, &rapdu.data[buf_offset+2..buf_offset+2+len])).map_err(|_| T1Error::TlvParseError)?;
                buf_offset += 2 + len;
            }
        }

        Ok(RApdu { sw: rapdu.sw, tlvs })
    }

    #[inline(never)]
    fn receive_apdu_raw<'a>(
        &mut self,
        buf: &'a mut [u8],
        delay: &mut DelayWrapper,
    ) -> Result<RawRApdu<'a>, T1Error> {
        let buf_len: usize = buf.len();
        let mut buf_offset: usize = 0;
        loop {
            let header = self.receive_frame(&mut buf[buf_offset..buf_len], delay)?;
            if let T1PCB::I(seq, multi) = header.pcb {
                if seq != self.iseq_rcv {
                    return Err(T1Error::ProtocolError);
                }
                self.iseq_rcv ^= 1;
                buf_offset += header.len as usize;
                if !multi { break; }
                self.send_frame(T1PCB::R(self.iseq_rcv, 0), &[], delay)?;
            }
        }

        if buf_offset < 2 { return Err(T1Error::ProtocolError); }
        let sw = BE::read_u16(&buf[buf_offset-2..buf_offset]);
        Ok(RawRApdu { sw, data: &buf[0..buf_offset-2] })
    }

    #[inline(never)]
    fn interface_soft_reset(&mut self, delay: &mut DelayWrapper) -> Result<AnswerToReset, T1Error> {
        let mut atrbuf: [u8; 64] = [0u8; 64];
        self.send_s(T1SCode::InterfaceSoftReset, &[], delay)?;
        self.receive_s(T1SCode::InterfaceSoftReset, &mut atrbuf, delay)?;

        let atr_pv = atrbuf[0];
        let dllp_len = atrbuf[6];
        if dllp_len != 4 {
            return Err(T1Error::ProtocolError);
        }
        let plp_type = atrbuf[11];
        let plp_len = atrbuf[12];
        if plp_type != 2 /* I2C */ || plp_len != 11 {
            return Err(T1Error::ProtocolError);
        }
        let _hb_len = atrbuf[24];
        /* TODO: check/use length of historical bytes */
        Ok(AnswerToReset {
            protocol_version: atr_pv,
            vendor_id: atrbuf[1..6].try_into().unwrap(),
            dllp: DataLinkLayerParameters {
                bwt_ms: BE::read_u16(&atrbuf[7..9]),
                ifsc: BE::read_u16(&atrbuf[9..11]),
            },
            plp: PhysicalLayerParameters::I2C(I2CParameters {
                mcf: BE::read_u16(&atrbuf[13..15]),
                configuration: atrbuf[15],
                mpot_ms: atrbuf[16],
                rfu: atrbuf[17..20].try_into().unwrap(),
                segt_us: BE::read_u16(&atrbuf[20..22]),
                wut_us: BE::read_u16(&atrbuf[22..24]),
            }),
            historical_bytes: atrbuf[25..40].try_into().unwrap(),
        })
    }
}
