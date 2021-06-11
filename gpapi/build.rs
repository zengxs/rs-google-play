use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use configparser::ini::Ini;
use protobuf::RepeatedField;

use googleplay_protobuf::DeviceConfigurationProto;

fn main() {
    if !Path::new("src/device_properties.bin").exists() {
        let mut config = Ini::new();
        config.read(fs::read_to_string("device.properties").unwrap()).unwrap();
        
        let mut device_configurations = HashMap::new();
        for section in config.sections() {
            eprintln!("{:?}", section);
            let mut device_configuration = DeviceConfigurationProto::new();
            device_configuration.touchScreen = config.getint(&section, "TouchScreen").unwrap().map(|v| v as i32);
            device_configuration.keyboard = config.getint(&section, "Keyboard").unwrap().map(|v| v as i32);
            device_configuration.navigation = config.getint(&section, "Navigation").unwrap().map(|v| v as i32);
            device_configuration.screenLayout = config.getint(&section, "ScreenLayout").unwrap().map(|v| v as i32);
            device_configuration.hasHardKeyboard = config.getbool(&section, "HasHardKeyboard").unwrap();
            device_configuration.hasFiveWayNavigation = config.getbool(&section, "HasFiveWayNavigation").unwrap();
            device_configuration.screenDensity = config.getint(&section, "Screen.Density").unwrap().map(|v| v as i32);
            device_configuration.glEsVersion = config.getint(&section, "GL.Version").unwrap().map(|v| v as i32);
            device_configuration.systemSharedLibrary = RepeatedField::from_vec(config.get(&section, "SharedLibraries").unwrap().split(",").map(|s| String::from(s)).collect());
            device_configuration.systemAvailableFeature = RepeatedField::from_vec(config.get(&section, "Features").unwrap().split(",").map(|s| String::from(s)).collect());
            device_configuration.nativePlatform = RepeatedField::from_vec(config.get(&section, "Platforms").unwrap().split(",").map(|s| String::from(s)).collect());
            device_configuration.screenWidth = config.getint(&section, "Screen.Width").unwrap().map(|v| v as i32);
            device_configuration.systemSupportedLocale = RepeatedField::from_vec(config.get(&section, "Locales").unwrap().split(",").map(|s| String::from(s)).collect());
            device_configuration.glExtension = RepeatedField::from_vec(config.get(&section, "GL.Extensions").unwrap().split(",").map(|s| String::from(s)).collect());
            device_configurations.insert(section, device_configuration);
        }
        let devices_encoded: Vec<u8> = bincode::serialize(&device_configurations).unwrap();
        let mut file = File::create("src/device_properties.bin").unwrap();
        file.write_all(&devices_encoded).unwrap();
    }
}
