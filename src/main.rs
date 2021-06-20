use safetydump::in_memory_dump;

fn main() {
    let test = vec!["safetydump", "0"];
    let buf_b64 = in_memory_dump(test);
    println!("{}", buf_b64);
}
