extern crate protobuf_codegen_pure;
use std::path::Path;

fn main() {
    if !Path::new("src/protos/googleplay.rs").exists() {
        protobuf_codegen_pure::Codegen::new()
            .out_dir("src/protos")
            .inputs(&["protos/googleplay.proto"])
            .include("protos")
            .customize(protobuf_codegen_pure::Customize {
                expose_fields: Some(true),
                generate_accessors: Some(false),
                serde_derive: Some(true),
                // singular_field_option: Some(true),
                ..Default::default()
            })
            .run()
            .expect("protoc");
    }
}
