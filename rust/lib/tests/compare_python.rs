use std::path::Path;

const TEST_KEY: &[u8; 32] = b"whats the Elvish word for friend";

fn test_input(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    buf
}

fn run_python_script(script: &str, args: Vec<String>, input: &[u8]) -> Vec<u8> {
    let mut python_args = vec!["-c", script];
    for arg in &args {
        python_args.push(arg);
    }
    let cargo_toml_path = env!("CARGO_MANIFEST_DIR");
    let python_dir = Path::new(&cargo_toml_path).join("../../python");
    let output = duct::cmd("python3", python_args)
        .stdin_bytes(input)
        .stdout_capture()
        .stderr_capture()
        .dir(python_dir)
        .unchecked()
        .run()
        .expect("child process error");
    if !output.stderr.is_empty() {
        println!("===== Python stderr =====");
        let stderr = String::from_utf8_lossy(&output.stderr);
        print!("{stderr}");
    }
    assert!(output.status.success());
    output.stdout
}

#[test]
fn test_compare_python() {
    const PYTHON_SCRIPT: &str = r#"
import bessie
import sys

assert len(sys.argv) == 2, "one arg expected"
key = sys.argv[1].encode("ascii")
plaintext = sys.stdin.buffer.read()
output = bessie.encrypt(key, plaintext)
sys.stdout.buffer.write(output)
"#;
    for msg_len in [0, 1, 64, 1000] {
        dbg!(msg_len);
        let input = test_input(msg_len);
        let args = vec![String::from_utf8(TEST_KEY.to_vec()).unwrap()];
        let ciphertext = run_python_script(PYTHON_SCRIPT, args, &input);
        let plaintext = bessie::decrypt(&TEST_KEY, &ciphertext).expect("invalid ciphertext");
        assert_eq!(input, plaintext);
    }
}
