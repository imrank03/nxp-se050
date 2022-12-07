// src/main.rs
#![allow(warnings)]
#![no_std]
#![no_main]

// use cortex_m::delay::Delay;
use cortex_m_rt::entry; // The runtime
use cortex_m_semihosting::{debug, heprintln, hprint};
use se050::{DelayWrapper, Se050, Se050Device, T1overI2C};
use stm32h7xx_hal::{pac, prelude::*, delay::Delay, timer};

// use defmt_rtt as _; // global logger

// static mut G_DELAY : stm32h7xx_hal::delay::Delay 

#[entry]
fn main() -> ! {
    heprintln!("Hello world");
    let cp = cortex_m::Peripherals::take().unwrap();
    let dp = pac::Peripherals::take().unwrap();
    heprintln!("Hello world 2");
    // Constrain and Freeze power
    let pwr = dp.PWR.constrain();
    let pwrcfg = pwr.freeze();
    heprintln!("Hello world 3");
    // Constrain and Freeze clock
    let rcc = dp.RCC.constrain();
    let ccdr = rcc.sys_ck(100.MHz()).freeze(pwrcfg, &dp.SYSCFG);
    let gpiob = dp.GPIOB.split(ccdr.peripheral.GPIOB);
    heprintln!("Hello world 4");
    // Configure the SCL and the SDA pin for our I2C bus
    let scl = gpiob.pb8.into_alternate_open_drain();
    let sda = gpiob.pb9.into_alternate_open_drain();

    // Get the delay provider.
    // Get the delay provider.

    // let mut d = AsmDelay::new(asm_delay::bitrate::U32BitrateExt::mhz(64));
    heprintln!("Hello world 11");
    // let mut test_delay = Delay::new(cp.SYST, ccdr.clocks);
    heprintln!("Hello world 12");
    let mut test_delay = cp.SYST.delay(ccdr.clocks);
    // static mut delay: Option<&mut Delay> = None;
    // let syst_delay = Delay::new(cp.SYST, ccdr.clocks);
    heprintln!("Hello world 13");

    heprintln!("Hello world 5");
    let i2c = dp
        .I2C1
        .i2c((scl, sda), 100.kHz(), ccdr.peripheral.I2C1, &ccdr.clocks);
        heprintln!("Hello world 6");
    let se = T1overI2C::new(i2c, 0x00, 0x1);
    heprintln!("Hello world 7");

    let mut se05 = Se050::new(se);
    heprintln!("Hello world 8");
    // let mut delay = get_delay_wrapper();
    heprintln!("Hello world 9");

    // let mut timer = dp.TIM2.timer(1.Hz(), ccdr.peripheral.TIM2, &ccdr.clocks);
    // let delay = timer.start(MilliSeconds::from_ticks(20).into_rate());
    let mut delay_wrapper = DelayWrapper{
        inner: unsafe {&mut test_delay},
    };
 

    heprintln!("Hello world 10");

    let _r = se05.enable(unsafe {&mut delay_wrapper});
    hprint!("Hello world 11");
    let version = Se050Device::get_version(&mut se05, &mut delay_wrapper).unwrap();

    heprintln!("version {:?}", version);

    loop {}
}

#[panic_handler] // panicking behavior
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        cortex_m::asm::bkpt();
        heprintln!("panic");
    }
}

// type RealDelay = stm32h7xx_hal::delay::Delay;

// pub struct DummyDelay<'a>(&'a mut RealDelay);

// impl embedded_hal::blocking::delay::DelayMs<u16> for DummyDelay<'_> {
//    fn delay_ms(&mut self, ms: u16) {
//         Delay::delay_ms(&mut self.0, ms);
//     }
// }


// pub fn get_delay() -> DelayWrapper {
//     DelayWrapper {
//         inner: unsafe { GLOBAL_DUMMY_DELAY.as_mut().unwrap() 
//     }
// }

// pub struct DummyDelay {}

// static mut GLOBAL_DUMMY_DELAY: Option<DummyDelay> = Some(DummyDelay {});

// impl embedded_hal::blocking::delay::DelayMs<u32> for DummyDelay<'_> {
//     fn delay_ms(&mut self, ms: u32) {
//         cortex_m::asm::delay((ms).into());
//     }
// }

// pub fn get_delay_wrapper() -> DelayWrapper {
//     DelayWrapper {
//         inner: unsafe { GLOBAL_DUMMY_DELAY.as_mut().unwrap() },
//     }
// }
