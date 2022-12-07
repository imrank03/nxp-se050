use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/types.rs");
    println!("cargo:rerun-if-changed=src/se050.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let conv1 = Command::new("python3")
        .arg("conv.py")
        .args(&["src/types.rs", "src/types_convs.rs"])
        .status()
        .expect("failed to run converter for types.rs");
    let conv2 = Command::new("python3")
        .arg("conv.py")
        .args(&["src/se050.rs", "src/se050_convs.rs"])
        .status()
        .expect("failed to run converter for se050.rs");

    assert!(conv1.success());
    assert!(conv2.success());
}
