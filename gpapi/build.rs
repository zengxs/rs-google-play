use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use configparser::ini::Ini;
use prost::Message;

use googleplay_protobuf::{AndroidBuildProto, AndroidCheckinProto, DeviceConfigurationProto};

fn main() {
    if !Path::new("src/device_properties.bin").exists()
        || !Path::new("src/android_checkins.bin").exists()
    {
        let mut config = Ini::new();
        config
            .read(fs::read_to_string("device.properties").unwrap())
            .unwrap();

        let mut device_configurations = HashMap::new();
        let mut android_checkins = HashMap::new();
        for section in config.sections() {
            let mut android_build = AndroidBuildProto::default();
            android_build.id = config.get(&section, "Build.FINGERPRINT");
            android_build.product = config.get(&section, "Build.HARDWARE");
            android_build.carrier = config.get(&section, "Build.BRAND");
            android_build.radio = config.get(&section, "Build.RADIO");
            android_build.bootloader = config.get(&section, "Build.BOOTLOADER");
            android_build.device = config.get(&section, "Build.DEVICE");
            android_build.sdk_version = config
                .getint(&section, "Build.VERSION.SDK_INT")
                .unwrap()
                .map(|v| v as i32);
            android_build.model = config.get(&section, "Build.MODEL");
            android_build.manufacturer = config.get(&section, "Build.MANUFACTURER");
            android_build.build_product = config.get(&section, "Build.PRODUCT");
            android_build.client = config.get(&section, "Client");
            android_build.ota_installed = Some(false);
            android_build.google_services = config
                .getint(&section, "GSF.version")
                .unwrap()
                .map(|v| v as i32);
            let mut android_checkin = AndroidCheckinProto::default();
            android_checkin.build = Some(android_build);
            android_checkin.last_checkin_msec = Some(0);
            android_checkin.cell_operator =
                config.get(&section, "CellOperator");
            android_checkin.sim_operator = config.get(&section, "SimOperator");
            android_checkin.roaming = config.get(&section, "Roaming");
            android_checkin.user_number = Some(0);
            let mut android_checkin_encoded = Vec::new();
            android_checkin_encoded.reserve(android_checkin.encoded_len());
            android_checkin.encode(&mut android_checkin_encoded).unwrap();
            android_checkins.insert(section.clone(), android_checkin_encoded);

            let mut device_configuration = DeviceConfigurationProto::default();
            device_configuration.touch_screen = config
                .getint(&section, "TouchScreen")
                .unwrap()
                .map(|v| v as i32);
            device_configuration.keyboard = config
                .getint(&section, "Keyboard")
                .unwrap()
                .map(|v| v as i32);
            device_configuration.navigation = config
                .getint(&section, "Navigation")
                .unwrap()
                .map(|v| v as i32);
            device_configuration.screen_layout = config
                .getint(&section, "ScreenLayout")
                .unwrap()
                .map(|v| v as i32);
            device_configuration.has_hard_keyboard =
                config.getbool(&section, "HasHardKeyboard").unwrap();
            device_configuration.has_five_way_navigation =
                config.getbool(&section, "HasFiveWayNavigation").unwrap();
            device_configuration.screen_density = config
                .getint(&section, "Screen.Density")
                .unwrap()
                .map(|v| v as i32);
            device_configuration.gl_es_version = config
                .getint(&section, "GL.Version")
                .unwrap()
                .map(|v| v as i32);
            device_configuration.system_shared_library = config
                .get(&section, "SharedLibraries")
                .unwrap()
                .split(",")
                .map(|s| String::from(s))
                .collect();
            device_configuration.system_available_feature = config
                .get(&section, "Features")
                .unwrap()
                .split(",")
                .map(|s| String::from(s))
                .collect();
            device_configuration.native_platform = config
                .get(&section, "Platforms")
                .unwrap()
                .split(",")
                .map(|s| String::from(s))
                .collect();
            device_configuration.screen_width = config
                .getint(&section, "Screen.Width")
                .unwrap()
                .map(|v| v as i32);
            device_configuration.system_supported_locale = config
                .get(&section, "Locales")
                .unwrap()
                .split(",")
                .map(|s| String::from(s))
                .collect();
            device_configuration.gl_extension = config
                .get(&section, "GL.Extensions")
                .unwrap()
                .split(",")
                .map(|s| String::from(s))
                .collect();
            let mut device_encoded = Vec::new();
            device_encoded.reserve(device_configuration.encoded_len());
            device_configuration.encode(&mut device_encoded).unwrap();
            device_configurations.insert(section, device_encoded);
        }

        let checkins_encoded: Vec<u8> = bincode::serialize(&android_checkins).unwrap();
        let devices_encoded: Vec<u8> = bincode::serialize(&device_configurations).unwrap();

        let mut file = File::create("src/device_properties.bin").unwrap();
        file.write_all(&devices_encoded).unwrap();

        let mut file = File::create("src/android_checkins.bin").unwrap();
        file.write_all(&checkins_encoded).unwrap();
    }
}
