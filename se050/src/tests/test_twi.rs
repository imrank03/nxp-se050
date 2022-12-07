use heapless::{Deque, Vec};

extern crate std;

type Msg = Vec<u8, 261>;

pub struct TWI {
    pub next_in: Deque<Msg, 32>,
    pub next_out: Deque<Msg, 32>,
    pub seen_in: Deque<Msg, 32>,
}

impl TWI {
    pub fn new() -> Self {
        Self { next_in: Deque::new(), next_out: Deque::new(), seen_in: Deque::new() }
    }

    pub fn push_in(&mut self, slice: &[u8]) {
        let vec = Vec::from_slice(slice).unwrap();
        self.next_in.push_back(vec).unwrap();
    }

    pub fn push_out(&mut self, slice: &[u8]) {
        let vec = Vec::from_slice(slice).unwrap();
        self.next_out.push_back(vec).unwrap();
    }
}

pub enum TestError {
    Mismatch,
    BufferOverflow,
    DequeUnderflow,
    DequeOverflow,
}

impl embedded_hal::blocking::i2c::Read for TWI {
    type Error = TestError;

    fn read(&mut self, _addr: u8, buf: &mut [u8]) -> Result<(), Self::Error> {
        let output = self.next_out.pop_front().ok_or_else(|| {
            std::println!("READ: Empty");
            TestError::DequeUnderflow })?;

        if output.len() > buf.len() {
            std::println!("READ: Size Overflow ({} > {})", output.len(), buf.len());
            return Err(TestError::BufferOverflow);
        }
        buf[0..output.len()].copy_from_slice(output.as_slice());
        Ok(())
    }
}

impl embedded_hal::blocking::i2c::Write for TWI {
    type Error = TestError;

    fn write(&mut self, _addr: u8, buf: &[u8]) -> Result<(), Self::Error> {
        let expected = self.next_in.pop_front().ok_or_else(|| {
            std::println!("WRITE: Empty");
            TestError::DequeUnderflow })?;

        if expected.as_slice() != buf {
            std::println!("WRITE: Expectation Mismatch ({:?} != {:?})", expected.as_slice(), buf);
            return Err(TestError::Mismatch);
        }
        self.seen_in.push_back(expected).map_err(|_| {
            std::println!("WRITE: Log Deque Full");
            TestError::DequeOverflow })?;
        Ok(())
    }
}

//////////////////////////////////////////////////////////////////////////////

pub struct DummyDelay {}

static mut GLOBAL_DUMMY_DELAY: Option<DummyDelay> = Some(DummyDelay {});

impl embedded_hal::blocking::delay::DelayMs<u32> for DummyDelay {
    fn delay_ms(&mut self, _ms: u32) {}
}

pub fn get_delay_wrapper() -> crate::types::DelayWrapper {
    crate::types::DelayWrapper { inner: unsafe { GLOBAL_DUMMY_DELAY.as_mut().unwrap() } }
}
