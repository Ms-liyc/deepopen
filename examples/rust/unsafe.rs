use std::process::Command;

fn run() {
    Command::new("sh").arg("-c").arg("echo hi");
}
