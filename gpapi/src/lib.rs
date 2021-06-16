pub mod consts;

use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use hyper_openssl::HttpsConnector;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Method, Request};
use hyper::header::{HeaderValue as HyperHeaderValue, HeaderName as HyperHeaderName};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Url;
use openssl::ssl::{SslConnector, SslMethod};
use protobuf::{Message, SingularField, SingularPtrField};

use googleplay_protobuf::{
    AndroidCheckinProto, AndroidCheckinRequest, AndroidCheckinResponse, BulkDetailsRequest,
    BulkDetailsResponse, BuyResponse, DeliveryResponse, DetailsResponse, DeviceConfigurationProto,
    ResponseWrapper, UploadDeviceConfigRequest, UploadDeviceConfigResponse,
};

#[macro_use]
extern crate lazy_static;

static DEVICES_ENCODED: &[u8] = include_bytes!("device_properties.bin");
static CHECKINS_ENCODED: &[u8] = include_bytes!("android_checkins.bin");
lazy_static! {
    static ref DEVICE_CONFIGURATIONS: HashMap<String, DeviceConfigurationProto> = bincode::deserialize(DEVICES_ENCODED).unwrap();
    static ref ANDROID_CHECKINS: HashMap<String, AndroidCheckinProto> = bincode::deserialize(CHECKINS_ENCODED).unwrap();
}

pub const STATUS_PURCHASE_UNAVAIL: i32 = 2;
pub const STATUS_PURCHASE_REQD: i32 = 3;
pub const STATUS_PURCHASE_ERR: i32 = 5;

#[derive(Debug)]
pub struct Gpapi {
    locale: String,
    timezone: String,
    device_codename: String,
    auth_subtoken: Option<String>,
    device_config_token: Option<String>,
    device_checkin_consistency_token: Option<String>,
    dfe_cookie: Option<String>,
    gsf_id: Option<i64>,
    client: Box<reqwest::Client>,
    hyper_client: Box<hyper::Client<HttpsConnector<HttpConnector>>>,
}

impl Gpapi {
    pub fn new<S: Into<String>>(locale: S, timezone: S, device_codename: S) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_cipher_list(consts::GOOGLE_ACCEPTED_CIPHERS).unwrap();
        let https = HttpsConnector::with_connector(http, connector).unwrap();
        let hyper_client = Client::builder().build::<_, hyper::Body>(https);

        Gpapi {
            locale: locale.into(),
            timezone: timezone.into(),
            device_codename: device_codename.into(),
            auth_subtoken: None,
            device_config_token: None,
            device_checkin_consistency_token: None,
            dfe_cookie: None,
            gsf_id: None,
            client: Box::new(reqwest::Client::new()),
            hyper_client: Box::new(hyper_client),
        }
    }

    pub fn checkin(&mut self, username: &str, ac2dm_token: &str) -> Result<Option<i64>, Box<dyn Error>> {
        let mut checkin = ANDROID_CHECKINS.get(&self.device_codename).map(|c| c.clone())
            .expect("Invalid device codename");

        checkin.build.as_mut().map(|mut b| b.timestamp = Some(
            (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 1000) as i64));

        let mut req = AndroidCheckinRequest::new();
        req.id = Some(0);
        req.checkin = SingularPtrField::from(Some(checkin));
        req.locale = SingularField::from(Some(self.locale.clone()));
        req.timeZone = SingularField::from(Some(self.timezone.clone()));
        req.version = Some(3);
        req.deviceConfiguration = SingularPtrField::from(DEVICE_CONFIGURATIONS.get(&self.device_codename).map(|c| c.clone()));
        req.fragment = Some(0);
        let mut req_followup = req.clone();
        let bytes = req.write_to_bytes()?;
        let resp = self.execute_checkin_request(&bytes)?;
        self.device_checkin_consistency_token = resp.deviceCheckinConsistencyToken.into_option();

        // checkin again to upload gfsid
        req_followup.id = resp.androidId.map(|id| id as i64);
        req_followup.securityToken = resp.securityToken;
        req_followup.accountCookie.push(format!("[{}]", username));
        req_followup.accountCookie.push(ac2dm_token.to_string());
        let bytes = req_followup.write_to_bytes()?;
        let resp = self.execute_checkin_request(&bytes)?;
        Ok(resp.androidId.map(|id| id as i64))
    }

    pub fn upload_device_config(&self) -> Result<Option<UploadDeviceConfigResponse>, Box<dyn Error>> {
        let mut req = UploadDeviceConfigRequest::new();
        req.deviceConfiguration = SingularPtrField::from(DEVICE_CONFIGURATIONS.get(&self.device_codename).map(|c| c.clone()));
        //let headers = self.get_headers();
        let bytes = req.write_to_bytes()?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-DFE-Enabled-Experiments",
            HeaderValue::from_static("cl:billing.select_add_instrument_by_default"));
        headers.insert(
            "X-DFE-Unsupported-Experiments",
            HeaderValue::from_static("nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes"));
        headers.insert(
            "X-DFE-SmallestScreenWidthDp",
            HeaderValue::from_static("320"));
        headers.insert(
            "X-DFE-Filter-Level",
            HeaderValue::from_static("3"));
        let resp = self.execute_request_v2(
            "uploadDeviceConfig", None, Some(&bytes), headers)?;
        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.uploadDeviceConfigResponse.into_option())
        } else {
            Ok(None)
        }
    }

    /// Play Store package detail request (provides more detail than bulk requests).
    pub fn details(&self, pkg_name: &str) -> Result<Option<DetailsResponse>, Box<dyn Error>> {
        let mut req = HashMap::new();
        req.insert("doc", pkg_name);
        let resp = self.execute_request_v2("details", Some(req), None, HeaderMap::new())?;
        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.detailsResponse.into_option())
        } else {
            Ok(None)
        }
    }

    pub fn bulk_details(
        &self,
        pkg_names: &[&str],
    ) -> Result<Option<BulkDetailsResponse>, Box<dyn Error>> {
        let mut req = BulkDetailsRequest::new();
        req.docid = pkg_names.into_iter().cloned().map(String::from).collect();
        req.includeChildDocs = Some(false);
        let bytes = req.write_to_bytes()?;
        let resp = self.execute_request_v2(
            "bulkDetails",
            None,
            Some(&bytes),
            HeaderMap::new(),
        )?;
        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.bulkDetailsResponse.into_option())
        } else {
            Ok(None)
        }
    }

    pub fn get_download_url(&self, pkg_name: &str, vc: u64) -> Result<Option<String>, Box<dyn Error>> {
        if let Ok(Some(ref app_delivery_resp)) = self.app_delivery_data(pkg_name, vc) {
            match app_delivery_resp {
                DeliveryResponse {
                    appDeliveryData: app_delivery_data,
                    ..
                } => Ok(app_delivery_data.clone().unwrap().downloadUrl.into_option()),
            }
        } else {
            if let Ok(Some(purchase_resp)) = self.purchase(pkg_name, vc) {
                Ok(purchase_resp
                    .purchaseStatusResponse
                    .unwrap()
                    .appDeliveryData
                    .unwrap()
                    .downloadUrl
                    .into_option())
            } else {
                Err("didn't get purchase data".into())
            }
        }
    }

    pub fn app_delivery_data(
        &self,
        pkg_name: &str,
        vc: u64,
    ) -> Result<Option<DeliveryResponse>, Box<dyn Error>> {
        let vc = vc.to_string();

        let mut req = HashMap::new();

        req.insert("doc", pkg_name);
        req.insert("vc", &vc);
        req.insert("ot", "1");

        let delivery_resp = self.execute_request_v2(
            "delivery",
            Some(req),
            None,
            HeaderMap::new(),
        )?;
        if let Some(payload) = delivery_resp.payload.into_option() {
            Ok(payload.deliveryResponse.into_option())
        } else {
            Ok(None)
        }
    }

    pub fn purchase(&self, pkg_name: &str, vc: u64) -> Result<Option<BuyResponse>, Box<dyn Error>> {
        let vc = vc.to_string();
        let body = format!("ot=1&doc={}&vc={}", pkg_name, vc);
        let body_bytes = body.into_bytes();

        let resp = self.execute_request_v2(
            "purchase",
            None,
            Some(&body_bytes),
            HeaderMap::new(),
        )?;
        match resp {
            ResponseWrapper {
                commands, payload, ..
            } => match (commands.into_option(), payload.into_option()) {
                (_, Some(payload)) => Ok(payload.buyResponse.into_option()),
                (Some(commands), _) => Err(commands.displayErrorMessage.unwrap().into()),
                _ => unimplemented!(),
            }, // ResponseWrapper { commands: SingularPtrField<ServerCommands>::some(commands), .. } => Err(commands.displayErrorMessage)
        }
        // if let Some(payload) = resp.payload.into_option() {
        //     Ok(payload.buyResponse.into_option())
        // } else {
        //     Ok(None)
        // }
    }

    pub async fn authenticate<S: Into<String> + Clone>(&mut self, username: S, password: S) -> Result<(), Box<dyn Error>> {
        let username = username.into();
        let login = encrypt_login(&username, &password.into()).unwrap();
        let encrypted_password = base64_urlsafe(&login);
        let form = self.login(&username, &encrypted_password).await?;
        if let Some(token) = form.get("auth") {
            let token = token.to_string();
            self.gsf_id = self.checkin(&username, &token)?;
            self.get_auth_subtoken(&username, &encrypted_password).await?;
            if let Some(upload_device_config_token) = self.upload_device_config()? {
                self.device_config_token = Some(upload_device_config_token.uploadDeviceConfigToken.unwrap());
                Ok(())
            } else {
                Err("No device config token".into())
            }
        } else {
            Err("No GSF auth token".into())
        }
    }

    pub async fn get_auth_subtoken(&mut self, username: &str, encrypted_password: &str) -> Result<(), Box<dyn Error>> {
        let mut login_req = build_login_request(username, encrypted_password);
        login_req.params.insert(String::from("service"), String::from("androidmarket"));
        login_req.params.insert(String::from("app"), String::from("com.android.vending"));
        let second_login_req = login_req.clone();

        let reply = self.login_helper(&login_req).await?;
        if let Some(master_token) = reply.get("token") {
            self.auth_subtoken = self.get_second_round_token(master_token, second_login_req).await?;
        }
        Ok(())
    }

    pub async fn get_second_round_token(&self, master_token: &str, mut login_req: LoginRequest) -> Result<Option<String>, Box<dyn Error>> {
        if let Some(gsf_id) = self.gsf_id {
            login_req.params.insert(String::from("androidId"), format!("{:x}", gsf_id));
        }
        login_req.params.insert(String::from("Token"), String::from(master_token));
        login_req.params.insert(String::from("check_email"), String::from("1"));
        login_req.params.insert(String::from("token_request_options"), String::from("CAA4AQ=="));
        login_req.params.insert(String::from("system_partition"), String::from("1"));
        login_req.params.insert(String::from("_opt_is_called_from_account_manager"), String::from("1"));
        login_req.params.remove("Email");
        login_req.params.remove("EncryptedPasswd");
        let reply = self.login_helper(&login_req).await?;
        Ok(reply.get("auth").map(|a| String::from(a)))
    }

    /// Handles logging into Google Play Store, retrieving a set of tokens from
    /// the server that can be used for future requests.
    pub async fn login(&self, username: &str, encrypted_password: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let login_req = build_login_request(username, encrypted_password);

        self.login_helper(&login_req).await
    }

    pub async fn login_helper(&self, login_req: &LoginRequest) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let form_body = login_req.form_post();

        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/{}", consts::defaults::DEFAULT_BASE_URL, "auth"))
            .body(Body::from(form_body)).unwrap();
        let headers = req.headers_mut();
        headers.insert(
            hyper::header::USER_AGENT,
            HyperHeaderValue::from_str(&consts::defaults::DEFAULT_AUTH_USER_AGENT)?);
        headers.insert(
            hyper::header::CONTENT_TYPE,
            HyperHeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"));
        if let Some(gsf_id) = &self.gsf_id {
            headers.insert(
                HyperHeaderName::from_static("device"),
                HyperHeaderValue::from_str(&format!("{:x}", gsf_id))?);
            headers.insert(
                HyperHeaderName::from_static("app"),
                HyperHeaderValue::from_static("com.android.vending"));
        }

        let res = self.hyper_client.request(req).await?;

	let body_bytes = hyper::body::to_bytes(res.into_body()).await?;
        let reply = parse_form_reply(&std::str::from_utf8(&body_bytes.to_vec()).unwrap());
        Ok(reply)
    }

    /// Lower level Play Store request, used by APIs but exposed for specialized
    /// requests. Returns a `ResponseWrapper` which depending on the request
    /// populates different fields/values.
    pub fn execute_request_v2(
        &self,
        endpoint: &str,
        query: Option<HashMap<&str, &str>>,
        msg: Option<&[u8]>,
        headers: HeaderMap,
    ) -> Result<ResponseWrapper, Box<dyn Error>> {
        let bytes = self.execute_request_helper(endpoint, query, msg, headers, true)?;
        let mut resp = ResponseWrapper::new();
        resp.merge_from_bytes(&bytes)?;
        Ok(resp)
    }

    pub fn execute_checkin_request(&self, msg: &[u8]) -> Result<AndroidCheckinResponse, Box<dyn Error>> {
        let bytes = self.execute_request_helper("checkin", None, Some(msg), HeaderMap::new(), false)?;
        let mut resp = AndroidCheckinResponse::new();
        resp.merge_from_bytes(&bytes)?;
        Ok(resp)
    }

    pub fn execute_request_helper(
        &self,
        endpoint: &str,
        query: Option<HashMap<&str, &str>>,
        msg: Option<&[u8]>,
        mut headers: HeaderMap,
        fdfe: bool,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut url = if fdfe {
            Url::parse(&format!(
                "{}/fdfe/{}",
                consts::defaults::DEFAULT_BASE_URL, endpoint
            ))?
        } else {
            Url::parse(&format!(
                "{}/{}",
                consts::defaults::DEFAULT_BASE_URL, endpoint
            ))?
        };

        let config = BuildConfiguration {
            ..Default::default()
        };

        headers.insert(
            reqwest::header::ACCEPT_LANGUAGE,
            HeaderValue::from_str(&self.locale.replace("_", "-"))?);
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&config.user_agent())?);
        headers.insert(
            "X-DFE-Encoded-Targets",
            HeaderValue::from_static(consts::defaults::DEFAULT_DFE_TARGETS));
        headers.insert(
            "X-DFE-Client-Id",
            HeaderValue::from_static("am-android-google"));
        headers.insert(
            "X-DFE-MCCMCN",
            HeaderValue::from_str(
                &ANDROID_CHECKINS.get(&self.device_codename).map(
                    |d| d.cellOperator.clone().unwrap()
                ).unwrap())?);
        headers.insert(
            "X-DFE-Network-Type",
            HeaderValue::from_static("4"));
        headers.insert(
            "X-DFE-Content-Filters",
            HeaderValue::from_static(""));
        headers.insert(
            "X-DFE-Request-Params",
            HeaderValue::from_static("timeoutMs=4000"));
        if let Some(gsf_id) = &self.gsf_id {
            headers.insert(
                "X-DFE-Device-Id",
                HeaderValue::from_str(&format!("{:x}", gsf_id))?);
        }
        if let Some(auth_subtoken) = &self.auth_subtoken {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("GoogleLogin auth={}", auth_subtoken))?);
        }
        if let Some(device_config_token) = &self.device_config_token {
            headers.insert(
                "X-DFE-Device-Config-Token",
                HeaderValue::from_str(&device_config_token)?);
        }
        if let Some(device_checkin_consistency_token) = &self.device_checkin_consistency_token {
            headers.insert(
                "X-DFE-Device-Checkin-Consistency-Token",
                HeaderValue::from_str(&device_checkin_consistency_token)?);
        }
        if let Some(dfe_cookie) = &self.dfe_cookie{
            headers.insert(
                "X-DFE-Cookie",
                HeaderValue::from_str(&dfe_cookie)?);
        }

        if let Some(query) = query {
            let mut queries = url.query_pairs_mut();
            for (key, val) in query {
                queries.append_pair(key, val);
            }
        }

        let mut res = if let Some(msg) = msg {
            (*self.client)
                .post(url)
                .headers(headers)
                .body(msg.to_owned())
                .send()?
        } else {
            (*self.client).get(url).headers(headers).send()?
        };

        let mut buf = Vec::new();
        res.copy_to(&mut buf)?;

        Ok(buf)
    }
}

/// Play Store API endpoints supported
#[derive(Debug)]
pub enum Endpoint {
    Details,
    BulkDetails,
}

impl Endpoint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Endpoint::Details => "details",
            Endpoint::BulkDetails => "bulkDetails",
        }
    }
}

#[derive(Debug)]
pub struct PubKey {
    pub modulus: Vec<u8>,
    pub exp: Vec<u8>,
}

pub fn parse_form_reply(data: &str) -> HashMap<String, String> {
    let mut form_resp = HashMap::new();
    let lines: Vec<&str> = data.split_terminator('\n').collect();
    for line in lines.iter() {
        let kv: Vec<&str> = line.split_terminator('=').collect();
        form_resp.insert(String::from(kv[0]).to_lowercase(), String::from(kv[1]));
    }
    form_resp
}

/// Handles encrypting your login/password using Google's public key
/// Produces something of the format:
/// |00|4 bytes of sha1(publicKey)|rsaEncrypt(publicKeyPem, "login\x00password")|
pub fn encrypt_login(login: &str, password: &str) -> Option<Vec<u8>> {
    let raw = base64::decode(consts::GOOGLE_PUB_KEY_B64).unwrap();
    if let Ok(Some(pubkey)) = extract_pubkey(&raw) {
        let rsa = build_openssl_rsa(&pubkey);

        let data = format!("{login}\x00{password}", login = login, password = password);
        let mut to = vec![0u8; rsa.size() as usize];
        let padding = openssl::rsa::Padding::PKCS1_OAEP;

        if let Ok(_sz) = rsa.public_encrypt(data.as_bytes(), &mut to, padding) {
            let sha1 = openssl::sha::sha1(&raw);
            let mut res = vec![];
            res.push(0x00);
            res.extend(&sha1[0..4]);
            res.extend(&to);
            Some(res)
        } else {
            None
        }
    } else {
        None
    }
}

///
/// Base64 encode w/ URL safe characters.
///
pub fn base64_urlsafe(input: &[u8]) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

///
/// Gen up an `openssl::rsa::Rsa` from a `PubKey`.
///
pub fn build_openssl_rsa(p: &PubKey) -> openssl::rsa::Rsa<openssl::pkey::Public> {
    use openssl::bn::BigNum;
    use openssl::rsa::Rsa;

    let modulus = BigNum::from_hex_str(&hex::encode(&p.modulus)).unwrap();
    let exp = BigNum::from_hex_str(&hex::encode(&p.exp)).unwrap();
    let rsa = Rsa::from_public_components(modulus, exp).unwrap();

    rsa
}

///
/// Extract public key (PEM) from a raw buffer.
///
fn extract_pubkey(buf: &[u8]) -> Result<Option<PubKey>, Box<dyn Error>> {
    use byteorder::{NetworkEndian, ReadBytesExt};
    use std::io::{Cursor, Read};
    let mut cur = Cursor::new(&buf);

    let sz = cur.read_u32::<NetworkEndian>()?;
    let mut modulus = vec![0u8; sz as usize];
    cur.read_exact(&mut modulus)?;

    let sz = cur.read_u32::<NetworkEndian>()?;
    let mut exp = vec![0u8; sz as usize];
    cur.read_exact(&mut exp)?;

    Ok(Some(PubKey { modulus, exp }))
}

#[derive(Debug, Clone)]
pub struct LoginRequest {
    params: HashMap<String, String>,
    build_config: Option<BuildConfiguration>,
}

impl LoginRequest {
    pub fn form_post(&self) -> String {
        self.params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join("&")
    }
}

#[derive(Debug, Clone)]
pub struct BuildConfiguration {
    pub finsky_agent: String,
    pub finsky_version: String,
    pub api: String,
    pub version_code: String,
    pub sdk: String,
    pub device: String,
    pub hardware: String,
    pub product: String,
    pub platform_version_release: String,
    pub model: String,
    pub build_id: String,
    pub is_wide_screen: String,
    pub supported_abis: String,
}

impl BuildConfiguration {
    pub fn user_agent(&self) -> String {
        format!("{}/{} (api={},versionCode={},sdk={},device={},hardware={},product={},platformVersionRelease={},model={},buildId={},isWideScreen={},supportedAbis={})", 
          self.finsky_agent, self.finsky_version, self.api, self.version_code, self.sdk,
          self.device, self.hardware, self.product,
          self.platform_version_release, self.model, self.build_id,
          self.is_wide_screen, self.supported_abis
        )
    }
}

impl Default for BuildConfiguration {
    fn default() -> BuildConfiguration {
        use consts::defaults::api_user_agent::{
            DEFAULT_API, DEFAULT_BUILD_ID, DEFAULT_DEVICE, DEFAULT_HARDWARE,
            DEFAULT_IS_WIDE_SCREEN, DEFAULT_SUPPORTED_ABIS, DEFAULT_MODEL,
            DEFAULT_PLATFORM_VERSION_RELEASE, DEFAULT_PRODUCT, DEFAULT_SDK,
            DEFAULT_VERSION_CODE,
        };
        use consts::defaults::{DEFAULT_FINSKY_AGENT, DEFAULT_FINSKY_VERSION};

        BuildConfiguration {
            finsky_agent: DEFAULT_FINSKY_AGENT.to_string(),
            finsky_version: DEFAULT_FINSKY_VERSION.to_string(),
            api: DEFAULT_API.to_string(),
            version_code: DEFAULT_VERSION_CODE.to_string(),
            sdk: DEFAULT_SDK.to_string(),
            device: DEFAULT_DEVICE.to_string(),
            hardware: DEFAULT_HARDWARE.to_string(),
            product: DEFAULT_PRODUCT.to_string(),
            platform_version_release: DEFAULT_PLATFORM_VERSION_RELEASE.to_string(),
            model: DEFAULT_MODEL.to_string(),
            build_id: DEFAULT_BUILD_ID.to_string(),
            is_wide_screen: DEFAULT_IS_WIDE_SCREEN.to_string(),
            supported_abis: DEFAULT_SUPPORTED_ABIS.to_string(),
        }
    }
}

impl Default for LoginRequest {
    fn default() -> Self {
        let mut params = HashMap::new();
        params.insert(String::from("Email"), String::from(""));
        params.insert(String::from("EncryptedPasswd"), String::from(""));
        params.insert(String::from("add_account"), String::from("1"));
        params.insert(String::from("accountType"), String::from(consts::defaults::DEFAULT_ACCOUNT_TYPE));
        params.insert(String::from("google_play_services_version"), String::from(consts::defaults::DEFAULT_GOOGLE_PLAY_SERVICES_VERSION));
        params.insert(String::from("has_permission"), String::from("1"));
        params.insert(String::from("source"), String::from("android"));
        params.insert(String::from("device_country"), String::from(consts::defaults::DEFAULT_DEVICE_COUNTRY));
        params.insert(String::from("operatorCountry"), String::from(consts::defaults::DEFAULT_COUNTRY_CODE));
        params.insert(String::from("lang"), String::from(consts::defaults::DEFAULT_LANGUAGE));
        params.insert(String::from("client_sig"), String::from(consts::defaults::DEFAULT_CLIENT_SIG));
        params.insert(String::from("callerSig"), String::from(consts::defaults::DEFAULT_CALLER_SIG));
        params.insert(String::from("service"), String::from(consts::defaults::DEFAULT_SERVICE));
        params.insert(String::from("callerPkg"), String::from(consts::defaults::DEFAULT_ANDROID_VENDING));
        LoginRequest {
            params,
            build_config: None,
        }
    }
}

pub fn build_login_request(username: &str, encrypted_password: &str) -> LoginRequest {
    let encrypted_password = String::from(encrypted_password);
    let build_config = BuildConfiguration {
        ..Default::default()
    };
    let mut login_request = LoginRequest::default();
    login_request.build_config = Some(build_config);
    login_request.params.insert(String::from("Email"), String::from(username));
    login_request.params.insert(String::from("EncryptedPasswd"), String::from(encrypted_password));
    login_request
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login() {
        let enc = encrypt_login("foo", "bar").unwrap();
        println!("encrypted: {:?}", base64::encode(&enc));
        println!("base64_urlsafe: {:?}", base64_urlsafe(&enc));
    }

    #[test]
    fn parse_form() {
        let form_reply = "FOO=BAR\nbaz=qux";
        let x = parse_form_reply(&form_reply);
        println!("form (parsed): {:?}", x);
    }

    #[test]
    fn foobar() {
        assert!(1 == 1);
    }

    mod gpapi {

        use std::env;

        use super::Gpapi;
        use super::protos::googleplay::BulkDetailsRequest;

        #[tokio::test]
        async fn create_gpapi() {
            match (
                env::var("GOOGLE_LOGIN"),
                env::var("GOOGLE_PASSWORD"),
            ) {
                (Ok(username), Ok(password)) => {
                    let mut api = Gpapi::new(username, password);
                    api.authenticate().await.ok();
                    assert!(api.token != "");

                    let details = api.details("com.viber.voip").ok();
                    let pkg_names = ["com.viber.voip", "air.WatchESPN"];
                    let bulk_details = api.bulk_details(&pkg_names).ok();
                }
                _ => panic!("require login/password for test"),
            }
        }

        #[test]
        fn test_protobuf() {
            let mut x = BulkDetailsRequest::new();
            x.docid = vec!["test".to_string()].into();
            x.includeChildDocs = Some(true);
        }
    }
}