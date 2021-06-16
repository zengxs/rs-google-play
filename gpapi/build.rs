use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use configparser::ini::Ini;
use protobuf::{RepeatedField, SingularField, SingularPtrField};

use googleplay_protobuf::{AndroidBuildProto, AndroidCheckinProto, DeviceConfigurationProto};

fn main() {
    if !Path::new("src/device_properties.bin").exists() || !Path::new("src/android_checkins.bin").exists() {
        let mut config = Ini::new();
        config.read(fs::read_to_string("device.properties").unwrap()).unwrap();
        
        let mut device_configurations = HashMap::new();
        let mut android_checkins = HashMap::new();
        for section in config.sections() {
            let mut android_build = AndroidBuildProto::new();
            android_build.id = SingularField::from(config.get(&section, "Build.FINGERPRINT"));
            android_build.product = SingularField::from(config.get(&section, "Build.HARDWARE"));
            android_build.carrier = SingularField::from(config.get(&section, "Build.BRAND"));
            android_build.radio = SingularField::from(config.get(&section, "Build.RADIO"));
            android_build.bootloader = SingularField::from(config.get(&section, "Build.BOOTLOADER"));
            android_build.device = SingularField::from(config.get(&section, "Build.DEVICE"));
            android_build.sdkVersion = config.getint(&section, "Build.VERSION.SDK_INT").unwrap().map(|v| v as i32);
            android_build.model = SingularField::from(config.get(&section, "Build.MODEL"));
            android_build.manufacturer = SingularField::from(config.get(&section, "Build.MANUFACTURER"));
            android_build.buildProduct = SingularField::from(config.get(&section, "Build.PRODUCT"));
            android_build.client = SingularField::from(config.get(&section, "Client"));
            android_build.otaInstalled = Some(false);
            android_build.googleServices = config.getint(&section, "GSF.version").unwrap().map(|v| v as i32);
            let mut android_checkin = AndroidCheckinProto::new();
            android_checkin.build = SingularPtrField::from(Some(android_build));
            android_checkin.lastCheckinMsec = Some(0);
            android_checkin.cellOperator = SingularField::from(config.get(&section, "CellOperator"));
            android_checkin.simOperator = SingularField::from(config.get(&section, "SimOperator"));
            android_checkin.roaming = SingularField::from(config.get(&section, "Roaming"));
            android_checkin.userNumber = Some(0);
            android_checkins.insert(section.clone(), android_checkin);

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

        let checkins_encoded: Vec<u8> = bincode::serialize(&android_checkins).unwrap();
        let mut file = File::create("src/android_checkins.bin").unwrap();
        file.write_all(&checkins_encoded).unwrap();

    }
}
