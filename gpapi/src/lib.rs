//! A library for interacting with the Google Play API, strongly following [google play python API](https://github.com/NoMore201/googleplay-api.git) patterns.
//!
//! # Getting Started
//!
//! Interacting with the API starts off with initializing the API and logging in.
//!
//! ```rust
//! let mut gpa = Gpapi::new("en_US", "UTC", "hero2lte");
//! gpa.login("someone@gmail.com", "somepass").await);
//! ```
//!
//! From here, you can get package details, get the URL to download a package, or use the library to download it.
//!
//! ```rust
//! let details = gpa.details("com.instagram.android");
//! println!("{:?}", details);
//!
//! let download_url = gpa.get_download_url("com.instagram.android", None);
//! println!("{:?}", download_url);
//!
//! gpa.download("com.instagram.android", None, &Path::new("/tmp/testing")).await;
//! ```

mod consts;

use std::collections::HashMap;
use std::error::Error;
use std::io::{Error as IOError, ErrorKind};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::stream::Stream;
use futures_util::StreamExt;
use hyper_openssl::HttpsConnector;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Method, Request};
use hyper::header::{HeaderValue as HyperHeaderValue, HeaderName as HyperHeaderName};
use openssl::ssl::{SslConnector, SslMethod};
use protobuf::{Message, SingularField, SingularPtrField};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Url;
use tokio_util::io::StreamReader;

use googleplay_protobuf::{
    AndroidCheckinProto, AndroidCheckinRequest, AndroidCheckinResponse, BulkDetailsRequest,
    BulkDetailsResponse, DetailsResponse, DeviceConfigurationProto, ResponseWrapper,
    UploadDeviceConfigRequest, UploadDeviceConfigResponse,
};

#[macro_use]
extern crate lazy_static;

static DEVICES_ENCODED: &[u8] = include_bytes!("device_properties.bin");
static CHECKINS_ENCODED: &[u8] = include_bytes!("android_checkins.bin");
lazy_static! {
    static ref DEVICE_CONFIGURATIONS: HashMap<String, DeviceConfigurationProto> = bincode::deserialize(DEVICES_ENCODED).unwrap();
    static ref ANDROID_CHECKINS: HashMap<String, AndroidCheckinProto> = bincode::deserialize(CHECKINS_ENCODED).unwrap();
}

/// The Gpapi object is the sole way to interact with the Play Store API.  It abstracts the logic
/// of low-level communication with Google's Play Store servers.
#[derive(Debug)]
pub struct Gpapi {
    locale: String,
    timezone: String,
    device_codename: String,
    pub(crate) auth_subtoken: Option<String>,
    pub(crate) device_config_token: Option<String>,
    pub(crate) device_checkin_consistency_token: Option<String>,
    dfe_cookie: Option<String>,
    gsf_id: Option<i64>,
    client: Box<reqwest::Client>,
    hyper_client: Box<hyper::Client<HttpsConnector<HttpConnector>>>,
}

impl Gpapi {
    /// Returns a Gpapi struct with locale, timezone, and the device codename specified.
    ///
    /// # Arguments
    ///
    /// * `locale` - A string type specifying the device locale, e.g. "en_US"
    /// * `timezone` - A string type specifying the timezone , e.g. "UTC"
    /// * `device_codename` - A string type specifying the device codename, e.g. "hero2lte"
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

    /// Log in to Google's Play Store API.  This is required for most other actions.
    ///
    /// # Arguments
    ///
    /// * `username` - A string type specifying the login username, usually a full email
    /// * `password` - A string type specifying an app password, created from your Google account
    /// settings.
    pub async fn login<S: Into<String> + Clone>(&mut self, username: S, password: S) -> Result<(), Box<dyn Error>> {
        let username = username.into();
        let login = encrypt_login(&username, &password.into()).unwrap();
        let encrypted_password = base64_urlsafe(&login);
        let form = self.authenticate(&username, &encrypted_password).await?;
        if let Some(token) = form.get("auth") {
            let token = token.to_string();
            self.gsf_id = self.checkin(&username, &token).await?;
            self.get_auth_subtoken(&username, &encrypted_password).await?;
            if let Some(upload_device_config_token) = self.upload_device_config().await? {
                self.device_config_token = Some(upload_device_config_token.uploadDeviceConfigToken.unwrap());
                Ok(())
            } else {
                Err("No device config token".into())
            }
        } else {
            Err("No GSF auth token".into())
        }
    }

    async fn checkin(&mut self, username: &str, ac2dm_token: &str) -> Result<Option<i64>, Box<dyn Error>> {
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
        let resp = self.execute_checkin_request(&bytes).await?;
        self.device_checkin_consistency_token = resp.deviceCheckinConsistencyToken.into_option();

        // checkin again to upload gfsid
        req_followup.id = resp.androidId.map(|id| id as i64);
        req_followup.securityToken = resp.securityToken;
        req_followup.accountCookie.push(format!("[{}]", username));
        req_followup.accountCookie.push(ac2dm_token.to_string());
        let bytes = req_followup.write_to_bytes()?;
        let resp = self.execute_checkin_request(&bytes).await?;
        Ok(resp.androidId.map(|id| id as i64))
    }

    async fn upload_device_config(&self) -> Result<Option<UploadDeviceConfigResponse>, Box<dyn Error>> {
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
            "uploadDeviceConfig", None, Some(&bytes), headers).await?;
        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.uploadDeviceConfigResponse.into_option())
        } else {
            Ok(None)
        }
    }

    /// Download a package, given a package ID, optional version code, and filesystem path.
    ///
    /// # Arguments
    ///
    /// * `pkg_name` - A string type specifying the package's app ID, e.g. `com.instagram.android`
    /// * `version_code` - An optinal version code, given in i32.  If omitted, the latest version will
    /// be used
    /// * `dst_path` - A path to download the file to.
    pub async fn download<S: Into<String>>(&self, pkg_name: S, version_code: Option<i32>, dst_path: &Path) -> Result<(), Box<dyn Error>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let pkg_name = pkg_name.into();
        if dst_path.is_dir() {
            if let Some(url) = self.get_download_url(pkg_name.clone(), version_code).await? {

                let mut http_async_reader = {
                    let http_stream = http_stream(&url).await?;
                    StreamReader::new(http_stream)
                };

                let mut dest = {
                    let fname = format!("{}.apk", pkg_name);
                    let fname = dst_path.join(fname);
                    tokio::fs::File::create(fname).await?
                };
                let mut buf = [0; 8 * 1024];
                loop {
                    let num_bytes = http_async_reader.read(&mut buf).await?;
                    if num_bytes > 0 {
		        dest.write(&mut buf[0..num_bytes]).await?;
                    } else {
                        break;
                    }
		}
                Ok(())
            } else {
                Err("Could not download app - no download URL available".into())
            }
        } else {
            Err("Destination path provided is not a valid directory".into())
        }
    }

    /// Retrieve the download URL for a package, given a package ID and optional version code.
    ///
    /// # Arguments
    ///
    /// * `pkg_name` - A string type specifying the package's app ID, e.g. `com.instagram.android`
    /// * `version_code` - An optinal version code, given in i32.  If omitted, the latest version will
    /// be used
    pub async fn get_download_url<S: Into<String>>(&self, pkg_name: S, mut version_code: Option<i32>) -> Result<Option<String>, Box<dyn Error>> {
        let pkg_name = pkg_name.into();
        if self.auth_subtoken.is_none() {
            return Err("Logging in is required for this action".into());
        }
        if version_code.is_none() {
            if let Some(details) = self.details(&pkg_name).await? {
                version_code = details.docV2.unwrap().details.unwrap().appDetails.unwrap().versionCode;
            } else {
                return Err(format!("Cannot get details for {}", pkg_name).into());
            }
        }
        let resp = {
            let version_code_str = version_code.unwrap().to_string();
            let mut req = HashMap::new();
            req.insert("ot", "1");
            req.insert("doc", &pkg_name);
            req.insert("vc", &version_code_str);
            self.execute_request_v2("purchase", Some(req), None, HeaderMap::new()).await?
        };
        if let Some(payload) = resp.payload.into_option() {
            if let Some(download_token) = payload.buyResponse.unwrap().downloadToken.into_option() {
                self.delivery(&pkg_name, version_code.clone(), &download_token).await
            } else {
                Err("App not purchased".into())
            }
        } else {
            Err("No valid response from server".into())
        }
    }

    async fn delivery<S: Into<String>>(&self, pkg_name: S, mut version_code: Option<i32>, download_token: S) -> Result<Option<String>, Box<dyn Error>> {
        let pkg_name = pkg_name.into();
        let download_token = download_token.into();
        if self.auth_subtoken.is_none() {
            return Err("Logging in is required for this action".into());
        }
        if version_code.is_none() {
            if let Some(details) = self.details(&pkg_name).await? {
                version_code = details.docV2.unwrap().details.unwrap().appDetails.unwrap().versionCode;
            } else {
                return Err(format!("Cannot get details for {}", pkg_name).into());
            }
        }
        let resp = {
            let version_code_str = version_code.unwrap().to_string();
            let mut req = HashMap::new();
            req.insert("ot", "1");
            req.insert("doc", &pkg_name);
            req.insert("vc", &version_code_str);
            req.insert("dtok", &download_token);
            self.execute_request_v2("delivery", Some(req), None, HeaderMap::new()).await?
        };
        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.deliveryResponse.unwrap().appDeliveryData.unwrap().downloadUrl.into_option())
        } else {
            Err("No valid response from server".into())
        }

    }

    /// Play Store package detail request (provides more detail than bulk requests).
    ///
    /// # Arguments
    ///
    /// * `pkg_name` - A string type specifying the package's app ID, e.g. `com.instagram.android`
    pub async fn details<S: Into<String>>(&self, pkg_name: S) -> Result<Option<DetailsResponse>, Box<dyn Error>> {
        let pkg_name = pkg_name.into();
        let mut req = HashMap::new();
        req.insert("doc", &pkg_name[..]);
        let resp = self.execute_request_v2("details", Some(req), None, HeaderMap::new()).await?;
        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.detailsResponse.into_option())
        } else {
            Ok(None)
        }
    }

    /// Play Store bulk detail request for multiple apps.
    ///
    /// # Arguments
    ///
    /// * `pkg_names` - An array of string types specifying package app IDs
    pub async fn bulk_details(
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
        ).await?;
        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.bulkDetailsResponse.into_option())
        } else {
            Ok(None)
        }
    }

    async fn get_auth_subtoken(&mut self, username: &str, encrypted_password: &str) -> Result<(), Box<dyn Error>> {
        let mut login_req = build_login_request(username, encrypted_password);
        login_req.params.insert(String::from("service"), String::from("androidmarket"));
        login_req.params.insert(String::from("app"), String::from("com.android.vending"));
        let second_login_req = login_req.clone();

        let reply = self.authenticate_helper(&login_req).await?;
        if let Some(master_token) = reply.get("token") {
            self.auth_subtoken = self.get_second_round_token(master_token, second_login_req).await?;
        }
        Ok(())
    }

    async fn get_second_round_token(&self, master_token: &str, mut login_req: LoginRequest) -> Result<Option<String>, Box<dyn Error>> {
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
        let reply = self.authenticate_helper(&login_req).await?;
        Ok(reply.get("auth").map(|a| String::from(a)))
    }

    /// Handles authenticating with Google Play Store, retrieving a set of tokens from
    /// the server that can be used for future requests.
    async fn authenticate(&self, username: &str, encrypted_password: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let login_req = build_login_request(username, encrypted_password);

        self.authenticate_helper(&login_req).await
    }

    async fn authenticate_helper(&self, login_req: &LoginRequest) -> Result<HashMap<String, String>, Box<dyn Error>> {
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
    async fn execute_request_v2(
        &self,
        endpoint: &str,
        query: Option<HashMap<&str, &str>>,
        msg: Option<&[u8]>,
        headers: HeaderMap,
    ) -> Result<ResponseWrapper, Box<dyn Error>> {
        let bytes = self.execute_request_helper(endpoint, query, msg, headers, true).await?;
        let mut resp = ResponseWrapper::new();
        resp.merge_from_bytes(&bytes)?;
        Ok(resp)
    }

    async fn execute_checkin_request(&self, msg: &[u8]) -> Result<AndroidCheckinResponse, Box<dyn Error>> {
        let bytes = self.execute_request_helper("checkin", None, Some(msg), HeaderMap::new(), false).await?;
        let mut resp = AndroidCheckinResponse::new();
        resp.merge_from_bytes(&bytes)?;
        Ok(resp)
    }

    async fn execute_request_helper(
        &self,
        endpoint: &str,
        query: Option<HashMap<&str, &str>>,
        msg: Option<&[u8]>,
        mut headers: HeaderMap,
        fdfe: bool,
    ) -> Result<Bytes, Box<dyn Error>> {
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

        let query2 = query.clone();
        if let Some(query) = query {
            let mut queries = url.query_pairs_mut();
            for (key, val) in query {
                queries.append_pair(key, val);
            }
        }

        let res = if endpoint == "purchase" {
            (*self.client)
                .post(url)
                .headers(headers)
                .form(&query2.unwrap())
                .send().await?
        } else {
            if let Some(msg) = msg {
                (*self.client)
                    .post(url)
                    .headers(headers)
                    .body(msg.to_owned())
                    .send().await?
            } else {
                (*self.client).get(url).headers(headers).send().await?
            }
        };

        Ok(res.bytes().await?)
    }
}

type S = dyn Stream<Item = Result<Bytes, IOError>> + Unpin;
async fn http_stream(url: &str) -> Result<Box<S>, Box<dyn Error>> {
    Ok(Box::new(reqwest::get(url)
        .await?
        .error_for_status()?
        .bytes_stream()
        .map(|result| result.map_err(|e| IOError::new(ErrorKind::Other, e)))))
}


#[derive(Debug)]
struct PubKey {
    pub modulus: Vec<u8>,
    pub exp: Vec<u8>,
}

fn parse_form_reply(data: &str) -> HashMap<String, String> {
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
fn encrypt_login(login: &str, password: &str) -> Option<Vec<u8>> {
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
fn base64_urlsafe(input: &[u8]) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

///
/// Gen up an `openssl::rsa::Rsa` from a `PubKey`.
///
fn build_openssl_rsa(p: &PubKey) -> openssl::rsa::Rsa<openssl::pkey::Public> {
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
struct LoginRequest {
    params: HashMap<String, String>,
    build_config: Option<BuildConfiguration>,
}

impl LoginRequest {
    pub fn form_post(&self) -> String {
        self.params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join("&")
    }
}

#[derive(Debug, Clone)]
struct BuildConfiguration {
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

fn build_login_request(username: &str, encrypted_password: &str) -> LoginRequest {
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
        assert!(base64::encode(&enc).starts_with("AFcb4K"));
        assert_eq!(base64::encode(&enc).len(), 180);
        assert!(!base64_urlsafe(&enc).contains("/"));
    }

    #[test]
    fn parse_form() {
        let form_reply = "FOO=BAR\nbaz=qux";
        let mut expected_reply = HashMap::new();
        expected_reply.insert("baz".to_string(), "qux".to_string());
        expected_reply.insert("foo".to_string(), "BAR".to_string());
        let parsed_form_reply = parse_form_reply(&form_reply);
        assert_eq!(expected_reply, parsed_form_reply);
    }

    mod gpapi {

        use std::env;

        use super::Gpapi;
        use googleplay_protobuf::BulkDetailsRequest;

        #[tokio::test]
        #[ignore]
        async fn create_gpapi() {
            match (
                env::var("GOOGLE_LOGIN"),
                env::var("GOOGLE_PASSWORD"),
            ) {
                (Ok(username), Ok(password)) => {
                    let mut api = Gpapi::new("en_US", "UTC", "hero2lte");
                    api.login(username, password).await.ok();
                    assert!(api.auth_subtoken.is_some());
                    assert!(api.device_config_token.is_some());
                    assert!(api.device_checkin_consistency_token.is_some());

                    assert!(api.details("com.viber.voip").await.is_ok());
                    let pkg_names = ["com.viber.voip", "air.WatchESPN"];
                    assert!(api.bulk_details(&pkg_names).await.is_ok());
                }
                _ => panic!("require login/password for test"),
            }
        }

        #[test]
        fn test_protobuf() {
            let mut bdr = BulkDetailsRequest::new();
            bdr.docid = vec!["test".to_string()].into();
            bdr.includeChildDocs = Some(true);
        }
    }
}
