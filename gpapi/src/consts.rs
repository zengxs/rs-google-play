// These are obtained from reversing the Play Store and extracting the public key components from the pem
/// Google Play Public Key (base64 encoded)
pub const GOOGLE_PUB_KEY_B64: &'static str = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==";
/// Google Play Public modulus (hexstr encoded)
pub const GOOGLE_PUB_MODULUS_HEXSTR: &'static str = "ca26ff56bfbf495b94ed946ebb7ad09da072e5d296318541781cc995af7962c4c28ea9af0822de224865da1dca129942b356a799ca277b2b4577145be175043ddb684546726120a9a2d950d0639b4e7ba4a448d7a901d18a69786c79a884394232b3b11f044d06ca2cd5a0458d1044d573df890c251dcffcb8076b1ffaae67f9";
/// Google Play Public exponent
pub const GOOGLE_PUB_EXP: u32 = 65537;
/// Exact ciphersuite specification is needed, see:
/// https://stackoverflow.com/questions/22832104/how-can-i-see-hidden-app-data-in-google-drive
pub const GOOGLE_ACCEPTED_CIPHERS: &'static str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:ECDH+AES:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!eNULL:!MD5:!DSS";

pub mod defaults {
    pub const DEFAULT_LANGUAGE: &str = "en_US";
    pub const DEFAULT_CLIENT_SIG: &str = "38918a453d07199354f8b19af05ec6562ced5788";
    pub const DEFAULT_CALLER_SIG: &str = "38918a453d07199354f8b19af05ec6562ced5788";
    pub const DEFAULT_USE_CACHE: bool = false;
    pub const DEFAULT_DEBUG: bool = false;
    pub const DEFAULT_COUNTRY_CODE: &str = "us";
    pub const DEFAULT_AUTH_USER_AGENT: &str = "GoogleAuth/1.4";
    pub mod api_user_agent {
        pub const DEFAULT_API: &str = "3";
        pub const DEFAULT_VERSION_CODE: &str = "81053300";
        pub const DEFAULT_SDK: &str = "27";
        pub const DEFAULT_DEVICE: &str = "hero2lte";
        pub const DEFAULT_HARDWARE: &str = "samsungexynos8890";
        pub const DEFAULT_PRODUCT: &str = "hero2ltexx";
        pub const DEFAULT_PLATFORM_VERSION_RELEASE: &str = "8.1.0";
        pub const DEFAULT_MODEL: &str = "SM-G935F";
        pub const DEFAULT_BUILD_ID: &str = "OPM2.171019.029.B1";
        pub const DEFAULT_IS_WIDE_SCREEN: &str = "0";
        pub const DEFAULT_SUPPORTED_ABIS: &str = "arm64-v8a;armeabi-v7a;armeabi";
    }
    pub const DEFAULT_FINSKY_AGENT: &str = "Android-Finsky";
    pub const DEFAULT_FINSKY_VERSION: &str = "10.5.33-all [0] [PR] 201016072";
    pub const DEFAULT_DFE_TARGETS: &str = "CAEScFfqlIEG6gUYogFWrAISK1WDAg+hAZoCDgIU1gYEOIACFkLMAeQBnASLATlASUuyAyqCAjY5igOMBQzfA/IClwFbApUC4ANbtgKVAS7OAX8YswHFBhgDwAOPAmGEBt4OfKkB5weSB5AFASkiN68akgMaxAMSAQEBA9kBO7UBFE1KVwIDBGs3go6BBgEBAgMECQgJAQIEAQMEAQMBBQEBBAUEFQYCBgUEAwMBDwIBAgOrARwBEwMEAg0mrwESfTEcAQEKG4EBMxghChMBDwYGASI3hAEODEwXCVh/EREZA4sBYwEdFAgIIwkQcGQRDzQ2fTC2AjfVAQIBAYoBGRg2FhYFBwEqNzACJShzFFblAo0CFxpFNBzaAd0DHjIRI4sBJZcBPdwBCQGhAUd2A7kBLBVPngEECHl0UEUMtQETigHMAgUFCc0BBUUlTywdHDgBiAJ+vgKhAU0uAcYCAWQ/5ALUAw1UwQHUBpIBCdQDhgL4AY4CBQICjARbGFBGWzA1CAEMOQH+BRAOCAZywAIDyQZ2MgM3BxsoAgUEBwcHFia3AgcGTBwHBYwBAlcBggFxSGgIrAEEBw4QEqUCASsWadsHCgUCBQMD7QICA3tXCUw7ugJZAwGyAUwpIwM5AwkDBQMJA5sBCw8BNxBVVBwVKhebARkBAwsQEAgEAhESAgQJEBCZATMdzgEBBwG8AQQYKSMUkAEDAwY/CTs4/wEaAUt1AwEDAQUBAgIEAwYEDx1dB2wGeBFgTQ";
    pub const DEFAULT_DOWNLOAD_USER_AGENT: &str =
        "AndroidDownloadManager/6.0.1 (Linux; U; Android 6.0.1; Nexus 7 Build/MOB30X)";
    pub const DEFAULT_PRE_FETCH: bool = false;
    pub const DEFAULT_DEVICE_COUNTRY: &str = "en";
    pub const DEFAULT_ANDROID_VENDING: &str = "com.google.android.gms";
    pub const DEFAULT_ACCOUNT_TYPE: &str = "HOSTED_OR_GOOGLE";
    pub const DEFAULT_GOOGLE_PLAY_SERVICES_VERSION: &str = "12866025";
    pub const DEFAULT_SERVICE: &str = "ac2dm";
    pub const DEFAULT_BASE_URL: &str = "https://android.clients.google.com";
}
