extern crate prost_build;

fn main() {
    prost_build::compile_protos(&["protos/googleplay.proto"],
                                &["protos/"]).unwrap();
}
