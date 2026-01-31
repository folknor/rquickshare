fn main() {
    // Protobuf compilation
    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    config
        .compile_protos(
            &[
                "src/proto_src/device_to_device_messages.proto",
                "src/proto_src/offline_wire_formats.proto",
                "src/proto_src/securegcm.proto",
                "src/proto_src/securemessage.proto",
                "src/proto_src/ukey.proto",
                "src/proto_src/wire_format.proto",
            ],
            &["src/proto_src"],
        )
        .expect("Failed to compile protobuf files");
}
