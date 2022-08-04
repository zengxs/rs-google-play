/// Both sha1 and sha256 are encoded with base64 with URL and Filename Safe Alphabet with padding removed
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidAppDeliveryData {
    #[prost(int64, optional, tag="1")]
    pub download_size: ::core::option::Option<i64>,
    #[prost(string, optional, tag="2")]
    pub sha1: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub download_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="4")]
    pub additional_file: ::prost::alloc::vec::Vec<AppFileMetadata>,
    #[prost(message, repeated, tag="5")]
    pub download_auth_cookie: ::prost::alloc::vec::Vec<HttpCookie>,
    #[prost(bool, optional, tag="6")]
    pub forward_locked: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="7")]
    pub refund_timeout: ::core::option::Option<i64>,
    #[prost(bool, optional, tag="8")]
    pub server_initiated: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="9")]
    pub post_install_refund_window_millis: ::core::option::Option<i64>,
    #[prost(bool, optional, tag="10")]
    pub immediate_start_needed: ::core::option::Option<bool>,
    #[prost(message, optional, tag="11")]
    pub patch_data: ::core::option::Option<AndroidAppPatchData>,
    #[prost(message, optional, tag="12")]
    pub encryption_params: ::core::option::Option<EncryptionParams>,
    #[prost(string, optional, tag="13")]
    pub download_url_gzipped: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="14")]
    pub download_size_gzipped: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="15")]
    pub split: ::prost::alloc::vec::Vec<Split>,
    #[prost(string, optional, tag="19")]
    pub sha256: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Split {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="2")]
    pub size: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="3")]
    pub size_gzipped: ::core::option::Option<i64>,
    #[prost(string, optional, tag="4")]
    pub sha1: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub download_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub download_url_gzipped: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="9")]
    pub sha256: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidAppPatchData {
    #[prost(int32, optional, tag="1")]
    pub base_version_code: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub base_sha1: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub download_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="4")]
    pub patch_format: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="5")]
    pub max_patch_size: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppFileMetadata {
    #[prost(int32, optional, tag="1")]
    pub file_type: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub version_code: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="3")]
    pub size: ::core::option::Option<i64>,
    #[prost(string, optional, tag="4")]
    pub download_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="6")]
    pub size_gzipped: ::core::option::Option<i64>,
    #[prost(string, optional, tag="7")]
    pub download_url_gzipped: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="8")]
    pub sha1: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptionParams {
    #[prost(int32, optional, tag="1")]
    pub version: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub encryption_key: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub hmac_key: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpCookie {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Address {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub address_line1: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub address_line2: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub city: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub state: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub postal_code: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub postal_country: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="8")]
    pub dependent_locality: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="9")]
    pub sorting_code: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="10")]
    pub language_code: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="11")]
    pub phone_number: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="12")]
    pub is_reduced: ::core::option::Option<bool>,
    #[prost(string, optional, tag="13")]
    pub first_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="14")]
    pub last_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="15")]
    pub email: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BookAuthor {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub deprecated_query: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="3")]
    pub docid: ::core::option::Option<Docid>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BookDetails {
    #[prost(message, repeated, tag="3")]
    pub subject: ::prost::alloc::vec::Vec<BookSubject>,
    #[prost(string, optional, tag="4")]
    pub publisher: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub publication_date: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub isbn: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="7")]
    pub number_of_pages: ::core::option::Option<i32>,
    #[prost(string, optional, tag="8")]
    pub subtitle: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="9")]
    pub author: ::prost::alloc::vec::Vec<BookAuthor>,
    #[prost(string, optional, tag="10")]
    pub reader_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="11")]
    pub download_epub_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub download_pdf_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="13")]
    pub acs_epub_token_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="14")]
    pub acs_pdf_token_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="15")]
    pub epub_available: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="16")]
    pub pdf_available: ::core::option::Option<bool>,
    #[prost(string, optional, tag="17")]
    pub about_the_author: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(group, repeated, tag="18")]
    pub identifier: ::prost::alloc::vec::Vec<book_details::Identifier>,
}
/// Nested message and enum types in `BookDetails`.
pub mod book_details {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Identifier {
        #[prost(int32, optional, tag="19")]
        pub r#type: ::core::option::Option<i32>,
        #[prost(string, optional, tag="20")]
        pub identifier: ::core::option::Option<::prost::alloc::string::String>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BookSubject {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub query: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub subject_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BrowseLink {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub data_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="5")]
    pub icon: ::core::option::Option<Image>,
    #[prost(message, optional, tag="4")]
    pub unknown_category_container: ::core::option::Option<UnknownCategoryContainer>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnknownCategoryContainer {
    #[prost(message, optional, tag="5")]
    pub category_id_container: ::core::option::Option<CategoryIdContainer>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryIdContainer {
    #[prost(string, optional, tag="4")]
    pub category_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BrowseResponse {
    #[prost(string, optional, tag="1")]
    pub contents_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub promo_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="3")]
    pub category: ::prost::alloc::vec::Vec<BrowseLink>,
    #[prost(message, repeated, tag="4")]
    pub breadcrumb: ::prost::alloc::vec::Vec<BrowseLink>,
    #[prost(message, optional, tag="9")]
    pub category_container: ::core::option::Option<CategoryContainer>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryContainer {
    #[prost(message, repeated, tag="4")]
    pub category: ::prost::alloc::vec::Vec<BrowseLink>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddressChallenge {
    #[prost(string, optional, tag="1")]
    pub response_address_param: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub response_checkboxes_param: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub description_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="5")]
    pub checkbox: ::prost::alloc::vec::Vec<FormCheckbox>,
    #[prost(message, optional, tag="6")]
    pub address: ::core::option::Option<Address>,
    #[prost(message, repeated, tag="7")]
    pub error_input_field: ::prost::alloc::vec::Vec<InputValidationError>,
    #[prost(string, optional, tag="8")]
    pub error_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, repeated, packed="false", tag="9")]
    pub required_field: ::prost::alloc::vec::Vec<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthenticationChallenge {
    #[prost(int32, optional, tag="1")]
    pub authentication_type: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub response_authentication_type_param: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub response_retry_count_param: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub pin_header_text: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub pin_description_text_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub gaia_header_text: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub gaia_description_text_html: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BuyResponse {
    #[prost(message, optional, tag="1")]
    pub purchase_response: ::core::option::Option<PurchaseNotificationResponse>,
    #[prost(group, optional, tag="2")]
    pub checkoutinfo: ::core::option::Option<buy_response::CheckoutInfo>,
    #[prost(string, optional, tag="8")]
    pub continue_via_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="9")]
    pub purchase_status_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub checkout_service_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="13")]
    pub checkout_token_required: ::core::option::Option<bool>,
    #[prost(string, optional, tag="14")]
    pub base_checkout_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="37")]
    pub tos_checkbox_html: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="38")]
    pub iab_permission_error: ::core::option::Option<i32>,
    #[prost(message, optional, tag="39")]
    pub purchase_status_response: ::core::option::Option<PurchaseStatusResponse>,
    #[prost(string, optional, tag="46")]
    pub purchase_cookie: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="49")]
    pub challenge: ::core::option::Option<Challenge>,
    #[prost(string, optional, tag="55")]
    pub download_token: ::core::option::Option<::prost::alloc::string::String>,
}
/// Nested message and enum types in `BuyResponse`.
pub mod buy_response {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CheckoutInfo {
        #[prost(message, optional, tag="3")]
        pub item: ::core::option::Option<super::LineItem>,
        #[prost(message, repeated, tag="4")]
        pub sub_item: ::prost::alloc::vec::Vec<super::LineItem>,
        #[prost(group, repeated, tag="5")]
        pub checkoutoption: ::prost::alloc::vec::Vec<checkout_info::CheckoutOption>,
        #[prost(string, optional, tag="10")]
        pub deprecated_checkout_url: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="11")]
        pub add_instrument_url: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, repeated, tag="20")]
        pub footer_html: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        #[prost(int32, repeated, packed="false", tag="31")]
        pub eligible_instrument_family: ::prost::alloc::vec::Vec<i32>,
        #[prost(string, repeated, tag="36")]
        pub footnote_html: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        #[prost(message, repeated, tag="44")]
        pub eligible_instrument: ::prost::alloc::vec::Vec<super::Instrument>,
    }
    /// Nested message and enum types in `CheckoutInfo`.
    pub mod checkout_info {
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct CheckoutOption {
            #[prost(string, optional, tag="6")]
            pub form_of_payment: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="7")]
            pub encoded_adjusted_cart: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, optional, tag="15")]
            pub instrument_id: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(message, repeated, tag="16")]
            pub item: ::prost::alloc::vec::Vec<super::super::LineItem>,
            #[prost(message, repeated, tag="17")]
            pub sub_item: ::prost::alloc::vec::Vec<super::super::LineItem>,
            #[prost(message, optional, tag="18")]
            pub total: ::core::option::Option<super::super::LineItem>,
            #[prost(string, repeated, tag="19")]
            pub footer_html: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(int32, optional, tag="29")]
            pub instrument_family: ::core::option::Option<i32>,
            #[prost(int32, repeated, packed="false", tag="30")]
            pub deprecated_instrument_inapplicable_reason: ::prost::alloc::vec::Vec<i32>,
            #[prost(bool, optional, tag="32")]
            pub selected_instrument: ::core::option::Option<bool>,
            #[prost(message, optional, tag="33")]
            pub summary: ::core::option::Option<super::super::LineItem>,
            #[prost(string, repeated, tag="35")]
            pub footnote_html: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            #[prost(message, optional, tag="43")]
            pub instrument: ::core::option::Option<super::super::Instrument>,
            #[prost(string, optional, tag="45")]
            pub purchase_cookie: ::core::option::Option<::prost::alloc::string::String>,
            #[prost(string, repeated, tag="48")]
            pub disabled_reason: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Challenge {
    #[prost(message, optional, tag="1")]
    pub address_challenge: ::core::option::Option<AddressChallenge>,
    #[prost(message, optional, tag="2")]
    pub authentication_challenge: ::core::option::Option<AuthenticationChallenge>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FormCheckbox {
    #[prost(string, optional, tag="1")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="2")]
    pub checked: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="3")]
    pub required: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LineItem {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="3")]
    pub offer: ::core::option::Option<Offer>,
    #[prost(message, optional, tag="4")]
    pub amount: ::core::option::Option<Money>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Money {
    #[prost(int64, optional, tag="1")]
    pub micros: ::core::option::Option<i64>,
    #[prost(string, optional, tag="2")]
    pub currency_code: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub formatted_amount: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PurchaseNotificationResponse {
    #[prost(int32, optional, tag="1")]
    pub status: ::core::option::Option<i32>,
    #[prost(message, optional, tag="2")]
    pub debug_info: ::core::option::Option<DebugInfo>,
    #[prost(string, optional, tag="3")]
    pub localized_error_message: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub purchase_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PurchaseStatusResponse {
    #[prost(int32, optional, tag="1")]
    pub status: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub status_msg: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub status_title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub brief_message: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub info_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="6")]
    pub library_update: ::core::option::Option<LibraryUpdate>,
    #[prost(message, optional, tag="7")]
    pub rejected_instrument: ::core::option::Option<Instrument>,
    #[prost(message, optional, tag="8")]
    pub app_delivery_data: ::core::option::Option<AndroidAppDeliveryData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeliveryResponse {
    #[prost(message, optional, tag="2")]
    pub app_delivery_data: ::core::option::Option<AndroidAppDeliveryData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Docid {
    #[prost(string, optional, tag="1")]
    pub backend_docid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="3")]
    pub backend: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Install {
    #[prost(fixed64, optional, tag="1")]
    pub android_id: ::core::option::Option<u64>,
    #[prost(int32, optional, tag="2")]
    pub version: ::core::option::Option<i32>,
    #[prost(bool, optional, tag="3")]
    pub bundled: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Offer {
    #[prost(int64, optional, tag="1")]
    pub micros: ::core::option::Option<i64>,
    #[prost(string, optional, tag="2")]
    pub currency_code: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub formatted_amount: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="4")]
    pub converted_price: ::prost::alloc::vec::Vec<Offer>,
    #[prost(bool, optional, tag="5")]
    pub checkout_flow_required: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="6")]
    pub full_price_micros: ::core::option::Option<i64>,
    #[prost(string, optional, tag="7")]
    pub formatted_full_amount: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="8")]
    pub offer_type: ::core::option::Option<i32>,
    #[prost(message, optional, tag="9")]
    pub rental_terms: ::core::option::Option<RentalTerms>,
    #[prost(int64, optional, tag="10")]
    pub on_sale_date: ::core::option::Option<i64>,
    #[prost(string, repeated, tag="11")]
    pub promotion_label: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag="12")]
    pub subscription_terms: ::core::option::Option<SubscriptionTerms>,
    #[prost(string, optional, tag="13")]
    pub formatted_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="14")]
    pub formatted_description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="22")]
    pub sale: ::core::option::Option<bool>,
    #[prost(string, optional, tag="26")]
    pub message: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="30")]
    pub sale_end_timestamp: ::core::option::Option<i64>,
    #[prost(string, optional, tag="31")]
    pub sale_message: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OwnershipInfo {
    #[prost(int64, optional, tag="1")]
    pub initiation_timestamp_msec: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="2")]
    pub valid_until_timestamp_msec: ::core::option::Option<i64>,
    #[prost(bool, optional, tag="3")]
    pub auto_renewing: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="4")]
    pub refund_timeout_timestamp_msec: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="5")]
    pub post_delivery_refund_window_msec: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RentalTerms {
    #[prost(int32, optional, tag="1")]
    pub grant_period_seconds: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub activate_period_seconds: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscriptionTerms {
    #[prost(message, optional, tag="1")]
    pub recurring_period: ::core::option::Option<TimePeriod>,
    #[prost(message, optional, tag="2")]
    pub trial_period: ::core::option::Option<TimePeriod>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimePeriod {
    #[prost(int32, optional, tag="1")]
    pub unit: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub count: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BillingAddressSpec {
    #[prost(int32, optional, tag="1")]
    pub billing_address_type: ::core::option::Option<i32>,
    #[prost(int32, repeated, packed="false", tag="2")]
    pub required_field: ::prost::alloc::vec::Vec<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CarrierBillingCredentials {
    #[prost(string, optional, tag="1")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="2")]
    pub expiration: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CarrierBillingInstrument {
    #[prost(string, optional, tag="1")]
    pub instrument_key: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub account_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub currency_code: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="4")]
    pub transaction_limit: ::core::option::Option<i64>,
    #[prost(string, optional, tag="5")]
    pub subscriber_identifier: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="6")]
    pub encrypted_subscriber_info: ::core::option::Option<EncryptedSubscriberInfo>,
    #[prost(message, optional, tag="7")]
    pub credentials: ::core::option::Option<CarrierBillingCredentials>,
    #[prost(message, optional, tag="8")]
    pub accepted_carrier_tos: ::core::option::Option<CarrierTos>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CarrierBillingInstrumentStatus {
    #[prost(message, optional, tag="1")]
    pub carrier_tos: ::core::option::Option<CarrierTos>,
    #[prost(bool, optional, tag="2")]
    pub association_required: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="3")]
    pub password_required: ::core::option::Option<bool>,
    #[prost(message, optional, tag="4")]
    pub carrier_password_prompt: ::core::option::Option<PasswordPrompt>,
    #[prost(int32, optional, tag="5")]
    pub api_version: ::core::option::Option<i32>,
    #[prost(string, optional, tag="6")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CarrierTos {
    #[prost(message, optional, tag="1")]
    pub dcb_tos: ::core::option::Option<CarrierTosEntry>,
    #[prost(message, optional, tag="2")]
    pub pii_tos: ::core::option::Option<CarrierTosEntry>,
    #[prost(bool, optional, tag="3")]
    pub needs_dcb_tos_acceptance: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="4")]
    pub needs_pii_tos_acceptance: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CarrierTosEntry {
    #[prost(string, optional, tag="1")]
    pub url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub version: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreditCardInstrument {
    #[prost(int32, optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub escrow_handle: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub last_digits: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="4")]
    pub expiration_month: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="5")]
    pub expiration_year: ::core::option::Option<i32>,
    #[prost(message, repeated, tag="6")]
    pub escrow_efe_param: ::prost::alloc::vec::Vec<EfeParam>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EfeParam {
    #[prost(int32, optional, tag="1")]
    pub key: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InputValidationError {
    #[prost(int32, optional, tag="1")]
    pub input_field: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub error_message: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Instrument {
    #[prost(string, optional, tag="1")]
    pub instrument_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    pub billing_address: ::core::option::Option<Address>,
    #[prost(message, optional, tag="3")]
    pub credit_card: ::core::option::Option<CreditCardInstrument>,
    #[prost(message, optional, tag="4")]
    pub carrier_billing: ::core::option::Option<CarrierBillingInstrument>,
    #[prost(message, optional, tag="5")]
    pub billing_address_spec: ::core::option::Option<BillingAddressSpec>,
    #[prost(int32, optional, tag="6")]
    pub instrument_family: ::core::option::Option<i32>,
    #[prost(message, optional, tag="7")]
    pub carrier_billing_status: ::core::option::Option<CarrierBillingInstrumentStatus>,
    #[prost(string, optional, tag="8")]
    pub display_title: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PasswordPrompt {
    #[prost(string, optional, tag="1")]
    pub prompt: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub forgot_password_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContainerMetadata {
    #[prost(string, optional, tag="1")]
    pub browse_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub next_page_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(double, optional, tag="3")]
    pub relevance: ::core::option::Option<f64>,
    #[prost(int64, optional, tag="4")]
    pub estimated_results: ::core::option::Option<i64>,
    #[prost(string, optional, tag="5")]
    pub analytics_cookie: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="6")]
    pub ordered: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DebugInfo {
    #[prost(string, repeated, tag="1")]
    pub message: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(group, repeated, tag="2")]
    pub timing: ::prost::alloc::vec::Vec<debug_info::Timing>,
}
/// Nested message and enum types in `DebugInfo`.
pub mod debug_info {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Timing {
        #[prost(string, optional, tag="3")]
        pub name: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(double, optional, tag="4")]
        pub time_in_ms: ::core::option::Option<f64>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BulkDetailsEntry {
    #[prost(message, optional, tag="1")]
    pub doc: ::core::option::Option<DocV2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BulkDetailsRequest {
    #[prost(string, repeated, tag="1")]
    pub docid: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="2")]
    pub include_child_docs: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BulkDetailsResponse {
    #[prost(message, repeated, tag="1")]
    pub entry: ::prost::alloc::vec::Vec<BulkDetailsEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DetailsResponse {
    #[prost(message, optional, tag="1")]
    pub doc_v1: ::core::option::Option<DocV1>,
    #[prost(string, optional, tag="2")]
    pub analytics_cookie: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="3")]
    pub user_review: ::core::option::Option<Review>,
    #[prost(message, optional, tag="4")]
    pub doc_v2: ::core::option::Option<DocV2>,
    #[prost(string, optional, tag="5")]
    pub footer_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="7")]
    pub badge: ::prost::alloc::vec::Vec<Badge>,
    #[prost(message, optional, tag="12")]
    pub features: ::core::option::Option<Features>,
    #[prost(string, optional, tag="13")]
    pub details_stream_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="14")]
    pub user_review_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="17")]
    pub post_acquire_details_stream_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Badge {
    #[prost(string, optional, tag="1")]
    pub label: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    pub image: ::core::option::Option<Image>,
    #[prost(message, optional, tag="4")]
    pub badge_container1: ::core::option::Option<BadgeContainer1>,
    #[prost(string, optional, tag="11")]
    pub message: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BadgeContainer1 {
    #[prost(message, optional, tag="1")]
    pub badge_container2: ::core::option::Option<BadgeContainer2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BadgeContainer2 {
    #[prost(message, optional, tag="2")]
    pub badge_link_container: ::core::option::Option<BadgeLinkContainer>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BadgeLinkContainer {
    #[prost(string, optional, tag="2")]
    pub link: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Features {
    #[prost(message, repeated, tag="1")]
    pub feature_presence: ::prost::alloc::vec::Vec<Feature>,
    #[prost(message, repeated, tag="2")]
    pub feature_rating: ::prost::alloc::vec::Vec<Feature>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Feature {
    #[prost(string, optional, tag="1")]
    pub label: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceConfigurationProto {
    #[prost(int32, optional, tag="1")]
    pub touch_screen: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub keyboard: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="3")]
    pub navigation: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="4")]
    pub screen_layout: ::core::option::Option<i32>,
    #[prost(bool, optional, tag="5")]
    pub has_hard_keyboard: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="6")]
    pub has_five_way_navigation: ::core::option::Option<bool>,
    #[prost(int32, optional, tag="7")]
    pub screen_density: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="8")]
    pub gl_es_version: ::core::option::Option<i32>,
    #[prost(string, repeated, tag="9")]
    pub system_shared_library: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="10")]
    pub system_available_feature: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="11")]
    pub native_platform: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="12")]
    pub screen_width: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="13")]
    pub screen_height: ::core::option::Option<i32>,
    #[prost(string, repeated, tag="14")]
    pub system_supported_locale: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="15")]
    pub gl_extension: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="16")]
    pub device_class: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="17")]
    pub max_apk_download_size_mb: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Document {
    #[prost(message, optional, tag="1")]
    pub docid: ::core::option::Option<Docid>,
    #[prost(message, optional, tag="2")]
    pub fetch_docid: ::core::option::Option<Docid>,
    #[prost(message, optional, tag="3")]
    pub sample_docid: ::core::option::Option<Docid>,
    #[prost(string, optional, tag="4")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="6")]
    pub snippet: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag="7")]
    pub price_deprecated: ::core::option::Option<Offer>,
    #[prost(message, optional, tag="9")]
    pub availability: ::core::option::Option<Availability>,
    #[prost(message, repeated, tag="10")]
    pub image: ::prost::alloc::vec::Vec<Image>,
    #[prost(message, repeated, tag="11")]
    pub child: ::prost::alloc::vec::Vec<Document>,
    #[prost(message, optional, tag="13")]
    pub aggregate_rating: ::core::option::Option<AggregateRating>,
    #[prost(message, repeated, tag="14")]
    pub offer: ::prost::alloc::vec::Vec<Offer>,
    #[prost(message, repeated, tag="15")]
    pub translated_snippet: ::prost::alloc::vec::Vec<TranslatedText>,
    #[prost(message, repeated, tag="16")]
    pub document_variant: ::prost::alloc::vec::Vec<DocumentVariant>,
    #[prost(string, repeated, tag="17")]
    pub category_id: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="18")]
    pub decoration: ::prost::alloc::vec::Vec<Document>,
    #[prost(message, repeated, tag="19")]
    pub parent: ::prost::alloc::vec::Vec<Document>,
    #[prost(string, optional, tag="20")]
    pub privacy_policy_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DocumentVariant {
    #[prost(int32, optional, tag="1")]
    pub variation_type: ::core::option::Option<i32>,
    #[prost(message, optional, tag="2")]
    pub rule: ::core::option::Option<Rule>,
    #[prost(string, optional, tag="3")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="4")]
    pub snippet: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub recent_changes: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="6")]
    pub auto_translation: ::prost::alloc::vec::Vec<TranslatedText>,
    #[prost(message, repeated, tag="7")]
    pub offer: ::prost::alloc::vec::Vec<Offer>,
    #[prost(int64, optional, tag="9")]
    pub channel_id: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="10")]
    pub child: ::prost::alloc::vec::Vec<Document>,
    #[prost(message, repeated, tag="11")]
    pub decoration: ::prost::alloc::vec::Vec<Document>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Image {
    #[prost(int32, optional, tag="1")]
    pub image_type: ::core::option::Option<i32>,
    #[prost(group, optional, tag="2")]
    pub dimension: ::core::option::Option<image::Dimension>,
    #[prost(string, optional, tag="5")]
    pub image_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub alt_text_localized: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub secure_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="8")]
    pub position_in_sequence: ::core::option::Option<i32>,
    #[prost(bool, optional, tag="9")]
    pub supports_fife_url_options: ::core::option::Option<bool>,
    #[prost(group, optional, tag="10")]
    pub citation: ::core::option::Option<image::Citation>,
    #[prost(string, optional, tag="15")]
    pub color: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="21")]
    pub screenshot_set_number: ::core::option::Option<i32>,
}
/// Nested message and enum types in `Image`.
pub mod image {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Dimension {
        #[prost(int32, optional, tag="3")]
        pub width: ::core::option::Option<i32>,
        #[prost(int32, optional, tag="4")]
        pub height: ::core::option::Option<i32>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Citation {
        #[prost(string, optional, tag="11")]
        pub title_localized: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="12")]
        pub url: ::core::option::Option<::prost::alloc::string::String>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranslatedText {
    #[prost(string, optional, tag="1")]
    pub text: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub source_locale: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub target_locale: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PlusOneData {
    #[prost(bool, optional, tag="1")]
    pub set_by_user: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="2")]
    pub total: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="3")]
    pub circles_total: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="4")]
    pub circles_people: ::prost::alloc::vec::Vec<PlusPerson>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PlusPerson {
    #[prost(string, optional, tag="2")]
    pub display_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub profile_image_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AlbumDetails {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    pub details: ::core::option::Option<MusicDetails>,
    #[prost(message, optional, tag="3")]
    pub display_artist: ::core::option::Option<ArtistDetails>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppDetails {
    #[prost(string, optional, tag="1")]
    pub developer_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub major_version_number: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="3")]
    pub version_code: ::core::option::Option<i32>,
    #[prost(string, optional, tag="4")]
    pub version_string: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="7")]
    pub app_category: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="8")]
    pub content_rating: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="9")]
    pub installation_size: ::core::option::Option<i64>,
    #[prost(string, repeated, tag="10")]
    pub permission: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="11")]
    pub developer_email: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub developer_website: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="13")]
    pub num_downloads: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="14")]
    pub package_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="15")]
    pub recent_changes_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="16")]
    pub upload_date: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="17")]
    pub file: ::prost::alloc::vec::Vec<FileMetadata>,
    #[prost(string, optional, tag="18")]
    pub app_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="21")]
    pub unstable: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="24")]
    pub has_instant_link: ::core::option::Option<bool>,
    #[prost(string, optional, tag="30")]
    pub contains_ads: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="34")]
    pub dependencies: ::core::option::Option<Dependencies>,
    #[prost(message, optional, tag="35")]
    pub testing_program_info: ::core::option::Option<TestingProgramInfo>,
    #[prost(message, optional, tag="36")]
    pub early_access_info: ::core::option::Option<EarlyAccessInfo>,
    #[prost(string, optional, tag="43")]
    pub instant_link: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="45")]
    pub developer_address: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Dependencies {
    #[prost(int32, optional, tag="1")]
    pub unknown1: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="2")]
    pub unknown2: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="3")]
    pub dependency: ::prost::alloc::vec::Vec<Dependency>,
    #[prost(int32, optional, tag="4")]
    pub unknown3: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Dependency {
    #[prost(string, optional, tag="1")]
    pub package_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub version: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="4")]
    pub unknown4: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TestingProgramInfo {
    #[prost(bool, optional, tag="2")]
    pub subscribed: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="3")]
    pub subscribed1: ::core::option::Option<bool>,
    #[prost(string, optional, tag="5")]
    pub testing_program_email: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EarlyAccessInfo {
    #[prost(string, optional, tag="3")]
    pub email: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtistDetails {
    #[prost(string, optional, tag="1")]
    pub details_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="3")]
    pub external_links: ::core::option::Option<ArtistExternalLinks>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtistExternalLinks {
    #[prost(string, repeated, tag="1")]
    pub website_url: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub google_plus_profile_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub youtube_channel_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DocumentDetails {
    #[prost(message, optional, tag="1")]
    pub app_details: ::core::option::Option<AppDetails>,
    #[prost(message, optional, tag="2")]
    pub album_details: ::core::option::Option<AlbumDetails>,
    #[prost(message, optional, tag="3")]
    pub artist_details: ::core::option::Option<ArtistDetails>,
    #[prost(message, optional, tag="4")]
    pub song_details: ::core::option::Option<SongDetails>,
    #[prost(message, optional, tag="5")]
    pub book_details: ::core::option::Option<BookDetails>,
    #[prost(message, optional, tag="6")]
    pub video_details: ::core::option::Option<VideoDetails>,
    #[prost(message, optional, tag="7")]
    pub subscription_details: ::core::option::Option<SubscriptionDetails>,
    #[prost(message, optional, tag="8")]
    pub magazine_details: ::core::option::Option<MagazineDetails>,
    #[prost(message, optional, tag="9")]
    pub tv_show_details: ::core::option::Option<TvShowDetails>,
    #[prost(message, optional, tag="10")]
    pub tv_season_details: ::core::option::Option<TvSeasonDetails>,
    #[prost(message, optional, tag="11")]
    pub tv_episode_details: ::core::option::Option<TvEpisodeDetails>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileMetadata {
    #[prost(int32, optional, tag="1")]
    pub file_type: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub version_code: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="3")]
    pub size: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MagazineDetails {
    #[prost(string, optional, tag="1")]
    pub parent_details_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub device_availability_description_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub psv_description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub delivery_frequency_description: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MusicDetails {
    #[prost(int32, optional, tag="1")]
    pub censoring: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub duration_sec: ::core::option::Option<i32>,
    #[prost(string, optional, tag="3")]
    pub original_release_date: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub label: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="5")]
    pub artist: ::prost::alloc::vec::Vec<ArtistDetails>,
    #[prost(string, repeated, tag="6")]
    pub genre: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub release_date: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, repeated, packed="false", tag="8")]
    pub release_type: ::prost::alloc::vec::Vec<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SongDetails {
    #[prost(string, optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    pub details: ::core::option::Option<MusicDetails>,
    #[prost(string, optional, tag="3")]
    pub album_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="4")]
    pub track_number: ::core::option::Option<i32>,
    #[prost(string, optional, tag="5")]
    pub preview_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="6")]
    pub display_artist: ::core::option::Option<ArtistDetails>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscriptionDetails {
    #[prost(int32, optional, tag="1")]
    pub subscription_period: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Trailer {
    #[prost(string, optional, tag="1")]
    pub trailer_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub thumbnail_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub watch_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub duration: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TvEpisodeDetails {
    #[prost(string, optional, tag="1")]
    pub parent_details_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub episode_index: ::core::option::Option<i32>,
    #[prost(string, optional, tag="3")]
    pub release_date: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TvSeasonDetails {
    #[prost(string, optional, tag="1")]
    pub parent_details_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub season_index: ::core::option::Option<i32>,
    #[prost(string, optional, tag="3")]
    pub release_date: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub broadcaster: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TvShowDetails {
    #[prost(int32, optional, tag="1")]
    pub season_count: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub start_year: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="3")]
    pub end_year: ::core::option::Option<i32>,
    #[prost(string, optional, tag="4")]
    pub broadcaster: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VideoCredit {
    #[prost(int32, optional, tag="1")]
    pub credit_type: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub credit: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="3")]
    pub name: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VideoDetails {
    #[prost(message, repeated, tag="1")]
    pub credit: ::prost::alloc::vec::Vec<VideoCredit>,
    #[prost(string, optional, tag="2")]
    pub duration: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub release_date: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub content_rating: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="5")]
    pub likes: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="6")]
    pub dislikes: ::core::option::Option<i64>,
    #[prost(string, repeated, tag="7")]
    pub genre: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="8")]
    pub trailer: ::prost::alloc::vec::Vec<Trailer>,
    #[prost(message, repeated, tag="9")]
    pub rental_term: ::prost::alloc::vec::Vec<VideoRentalTerm>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VideoRentalTerm {
    #[prost(int32, optional, tag="1")]
    pub offer_type: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub offer_abbreviation: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub rental_header: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(group, repeated, tag="4")]
    pub term: ::prost::alloc::vec::Vec<video_rental_term::Term>,
}
/// Nested message and enum types in `VideoRentalTerm`.
pub mod video_rental_term {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Term {
        #[prost(string, optional, tag="5")]
        pub header: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="6")]
        pub body: ::core::option::Option<::prost::alloc::string::String>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Bucket {
    #[prost(message, repeated, tag="1")]
    pub document: ::prost::alloc::vec::Vec<DocV1>,
    #[prost(bool, optional, tag="2")]
    pub multi_corpus: ::core::option::Option<bool>,
    #[prost(string, optional, tag="3")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub icon_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub full_contents_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(double, optional, tag="6")]
    pub relevance: ::core::option::Option<f64>,
    #[prost(int64, optional, tag="7")]
    pub estimated_results: ::core::option::Option<i64>,
    #[prost(string, optional, tag="8")]
    pub analytics_cookie: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="9")]
    pub full_contents_list_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="10")]
    pub next_page_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="11")]
    pub ordered: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListResponse {
    #[prost(message, repeated, tag="1")]
    pub bucket: ::prost::alloc::vec::Vec<Bucket>,
    #[prost(message, repeated, tag="2")]
    pub doc: ::prost::alloc::vec::Vec<DocV2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DocV1 {
    #[prost(message, optional, tag="1")]
    pub finsky_doc: ::core::option::Option<Document>,
    #[prost(string, optional, tag="2")]
    pub docid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub details_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub reviews_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub related_list_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub more_by_list_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub share_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="8")]
    pub creator: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="9")]
    pub details: ::core::option::Option<DocumentDetails>,
    #[prost(string, optional, tag="10")]
    pub description_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="11")]
    pub related_browse_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub more_by_browse_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="13")]
    pub related_header: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="14")]
    pub more_by_header: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="15")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="16")]
    pub plus_one_data: ::core::option::Option<PlusOneData>,
    #[prost(string, optional, tag="17")]
    pub warning_message: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DocV2 {
    #[prost(string, optional, tag="1")]
    pub docid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub backend_docid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="3")]
    pub doc_type: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="4")]
    pub backend_id: ::core::option::Option<i32>,
    #[prost(string, optional, tag="5")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub creator: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub description_html: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="8")]
    pub offer: ::prost::alloc::vec::Vec<Offer>,
    #[prost(message, optional, tag="9")]
    pub availability: ::core::option::Option<Availability>,
    #[prost(message, repeated, tag="10")]
    pub image: ::prost::alloc::vec::Vec<Image>,
    #[prost(message, repeated, tag="11")]
    pub child: ::prost::alloc::vec::Vec<DocV2>,
    #[prost(message, optional, tag="12")]
    pub container_metadata: ::core::option::Option<ContainerMetadata>,
    #[prost(message, optional, tag="13")]
    pub details: ::core::option::Option<DocumentDetails>,
    #[prost(message, optional, tag="14")]
    pub aggregate_rating: ::core::option::Option<AggregateRating>,
    #[prost(message, optional, tag="15")]
    pub related_links: ::core::option::Option<RelatedLinks>,
    #[prost(string, optional, tag="16")]
    pub details_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="17")]
    pub share_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="18")]
    pub reviews_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="19")]
    pub backend_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="20")]
    pub purchase_details_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="21")]
    pub details_reusable: ::core::option::Option<bool>,
    #[prost(string, optional, tag="22")]
    pub subtitle: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="24")]
    pub unknown_category_container: ::core::option::Option<UnknownCategoryContainer>,
    #[prost(message, optional, tag="25")]
    pub unknown25: ::core::option::Option<Unknown25>,
    #[prost(string, optional, tag="27")]
    pub description_short: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="31")]
    pub review_snippets_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="34")]
    pub review_questions_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Unknown25 {
    #[prost(message, repeated, tag="2")]
    pub item: ::prost::alloc::vec::Vec<Unknown25Item>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Unknown25Item {
    #[prost(string, optional, tag="1")]
    pub label: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="3")]
    pub container: ::core::option::Option<Unknown25Container>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Unknown25Container {
    #[prost(string, optional, tag="2")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelatedLinks {
    #[prost(message, optional, tag="10")]
    pub unknown1: ::core::option::Option<RelatedLinksUnknown1>,
    #[prost(string, optional, tag="18")]
    pub privacy_policy_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="24")]
    pub you_might_also_like: ::core::option::Option<RelatedLink>,
    #[prost(message, optional, tag="29")]
    pub rated: ::core::option::Option<Rated>,
    #[prost(message, repeated, tag="34")]
    pub related_links: ::prost::alloc::vec::Vec<RelatedLink>,
    #[prost(message, optional, tag="53")]
    pub category_info: ::core::option::Option<CategoryInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelatedLinksUnknown1 {
    #[prost(message, optional, tag="2")]
    pub unknown2: ::core::option::Option<RelatedLinksUnknown2>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelatedLinksUnknown2 {
    #[prost(string, optional, tag="2")]
    pub home_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub next_page_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Rated {
    #[prost(string, optional, tag="1")]
    pub label: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    pub image: ::core::option::Option<Image>,
    #[prost(string, optional, tag="4")]
    pub learn_more_html_link: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelatedLink {
    #[prost(string, optional, tag="1")]
    pub label: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub url1: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub url2: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CategoryInfo {
    #[prost(string, optional, tag="1")]
    pub app_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub app_category: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedSubscriberInfo {
    #[prost(string, optional, tag="1")]
    pub data: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub encrypted_key: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub signature: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub init_vector: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="5")]
    pub google_key_version: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="6")]
    pub carrier_key_version: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Availability {
    #[prost(int32, optional, tag="5")]
    pub restriction: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="6")]
    pub offer_type: ::core::option::Option<i32>,
    #[prost(message, optional, tag="7")]
    pub rule: ::core::option::Option<Rule>,
    #[prost(group, repeated, tag="9")]
    pub perdeviceavailabilityrestriction: ::prost::alloc::vec::Vec<availability::PerDeviceAvailabilityRestriction>,
    #[prost(bool, optional, tag="13")]
    pub available_if_owned: ::core::option::Option<bool>,
    #[prost(message, repeated, tag="14")]
    pub install: ::prost::alloc::vec::Vec<Install>,
    #[prost(message, optional, tag="16")]
    pub filter_info: ::core::option::Option<FilterEvaluationInfo>,
    #[prost(message, optional, tag="17")]
    pub ownership_info: ::core::option::Option<OwnershipInfo>,
}
/// Nested message and enum types in `Availability`.
pub mod availability {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PerDeviceAvailabilityRestriction {
        #[prost(fixed64, optional, tag="10")]
        pub android_id: ::core::option::Option<u64>,
        #[prost(int32, optional, tag="11")]
        pub device_restriction: ::core::option::Option<i32>,
        #[prost(int64, optional, tag="12")]
        pub channel_id: ::core::option::Option<i64>,
        #[prost(message, optional, tag="15")]
        pub filter_info: ::core::option::Option<super::FilterEvaluationInfo>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FilterEvaluationInfo {
    #[prost(message, repeated, tag="1")]
    pub rule_evaluation: ::prost::alloc::vec::Vec<RuleEvaluation>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Rule {
    #[prost(bool, optional, tag="1")]
    pub negate: ::core::option::Option<bool>,
    #[prost(int32, optional, tag="2")]
    pub operator: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="3")]
    pub key: ::core::option::Option<i32>,
    #[prost(string, repeated, tag="4")]
    pub string_arg: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(int64, repeated, packed="false", tag="5")]
    pub long_arg: ::prost::alloc::vec::Vec<i64>,
    #[prost(double, repeated, packed="false", tag="6")]
    pub double_arg: ::prost::alloc::vec::Vec<f64>,
    #[prost(message, repeated, tag="7")]
    pub subrule: ::prost::alloc::vec::Vec<Rule>,
    #[prost(int32, optional, tag="8")]
    pub response_code: ::core::option::Option<i32>,
    #[prost(string, optional, tag="9")]
    pub comment: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(fixed64, repeated, packed="false", tag="10")]
    pub string_arg_hash: ::prost::alloc::vec::Vec<u64>,
    #[prost(int32, repeated, packed="false", tag="11")]
    pub const_arg: ::prost::alloc::vec::Vec<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuleEvaluation {
    #[prost(message, optional, tag="1")]
    pub rule: ::core::option::Option<Rule>,
    #[prost(string, repeated, tag="2")]
    pub actual_string_value: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(int64, repeated, packed="false", tag="3")]
    pub actual_long_value: ::prost::alloc::vec::Vec<i64>,
    #[prost(bool, repeated, packed="false", tag="4")]
    pub actual_bool_value: ::prost::alloc::vec::Vec<bool>,
    #[prost(double, repeated, packed="false", tag="5")]
    pub actual_double_value: ::prost::alloc::vec::Vec<f64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LibraryAppDetails {
    #[prost(string, optional, tag="2")]
    pub certificate_hash: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="3")]
    pub refund_timeout_timestamp_msec: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="4")]
    pub post_delivery_refund_window_msec: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LibraryInAppDetails {
    #[prost(string, optional, tag="1")]
    pub signed_purchase_data: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub signature: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LibraryMutation {
    #[prost(message, optional, tag="1")]
    pub docid: ::core::option::Option<Docid>,
    #[prost(int32, optional, tag="2")]
    pub offer_type: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="3")]
    pub document_hash: ::core::option::Option<i64>,
    #[prost(bool, optional, tag="4")]
    pub deleted: ::core::option::Option<bool>,
    #[prost(message, optional, tag="5")]
    pub app_details: ::core::option::Option<LibraryAppDetails>,
    #[prost(message, optional, tag="6")]
    pub subscription_details: ::core::option::Option<LibrarySubscriptionDetails>,
    #[prost(message, optional, tag="7")]
    pub in_app_details: ::core::option::Option<LibraryInAppDetails>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LibrarySubscriptionDetails {
    #[prost(int64, optional, tag="1")]
    pub initiation_timestamp_msec: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="2")]
    pub valid_until_timestamp_msec: ::core::option::Option<i64>,
    #[prost(bool, optional, tag="3")]
    pub auto_renewing: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="4")]
    pub trial_until_timestamp_msec: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LibraryUpdate {
    #[prost(int32, optional, tag="1")]
    pub status: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub corpus: ::core::option::Option<i32>,
    #[prost(bytes="vec", optional, tag="3")]
    pub server_token: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, repeated, tag="4")]
    pub mutation: ::prost::alloc::vec::Vec<LibraryMutation>,
    #[prost(bool, optional, tag="5")]
    pub has_more: ::core::option::Option<bool>,
    #[prost(string, optional, tag="6")]
    pub library_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidAppNotificationData {
    #[prost(int32, optional, tag="1")]
    pub version_code: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub asset_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InAppNotificationData {
    #[prost(string, optional, tag="1")]
    pub checkout_order_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub in_app_notification_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LibraryDirtyData {
    #[prost(int32, optional, tag="1")]
    pub backend: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Notification {
    #[prost(int32, optional, tag="1")]
    pub notification_type: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="3")]
    pub timestamp: ::core::option::Option<i64>,
    #[prost(message, optional, tag="4")]
    pub docid: ::core::option::Option<Docid>,
    #[prost(string, optional, tag="5")]
    pub doc_title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub user_email: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="7")]
    pub app_data: ::core::option::Option<AndroidAppNotificationData>,
    #[prost(message, optional, tag="8")]
    pub app_delivery_data: ::core::option::Option<AndroidAppDeliveryData>,
    #[prost(message, optional, tag="9")]
    pub purchase_removal_data: ::core::option::Option<PurchaseRemovalData>,
    #[prost(message, optional, tag="10")]
    pub user_notification_data: ::core::option::Option<UserNotificationData>,
    #[prost(message, optional, tag="11")]
    pub in_app_notification_data: ::core::option::Option<InAppNotificationData>,
    #[prost(message, optional, tag="12")]
    pub purchase_declined_data: ::core::option::Option<PurchaseDeclinedData>,
    #[prost(string, optional, tag="13")]
    pub notification_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="14")]
    pub library_update: ::core::option::Option<LibraryUpdate>,
    #[prost(message, optional, tag="15")]
    pub library_dirty_data: ::core::option::Option<LibraryDirtyData>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PurchaseDeclinedData {
    #[prost(int32, optional, tag="1")]
    pub reason: ::core::option::Option<i32>,
    #[prost(bool, optional, tag="2")]
    pub show_notification: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PurchaseRemovalData {
    #[prost(bool, optional, tag="1")]
    pub malicious: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserNotificationData {
    #[prost(string, optional, tag="1")]
    pub notification_title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub notification_text: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub ticker_text: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub dialog_title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub dialog_text: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregateRating {
    #[prost(int32, optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(float, optional, tag="2")]
    pub star_rating: ::core::option::Option<f32>,
    #[prost(uint64, optional, tag="3")]
    pub ratings_count: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="4")]
    pub one_star_ratings: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="5")]
    pub two_star_ratings: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="6")]
    pub three_star_ratings: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="7")]
    pub four_star_ratings: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="8")]
    pub five_star_ratings: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="9")]
    pub thumbs_up_count: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="10")]
    pub thumbs_down_count: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag="11")]
    pub comment_count: ::core::option::Option<u64>,
    #[prost(double, optional, tag="12")]
    pub bayesian_mean_rating: ::core::option::Option<f64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AcceptTosResponse {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CarrierBillingConfig {
    #[prost(string, optional, tag="1")]
    pub id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="3")]
    pub api_version: ::core::option::Option<i32>,
    #[prost(string, optional, tag="4")]
    pub provisioning_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub credentials_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="6")]
    pub tos_required: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="7")]
    pub per_transaction_credentials_required: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="8")]
    pub send_subscriber_id_with_carrier_billing_requests: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BillingConfig {
    #[prost(message, optional, tag="1")]
    pub carrier_billing_config: ::core::option::Option<CarrierBillingConfig>,
    #[prost(int32, optional, tag="2")]
    pub max_iab_api_version: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CorpusMetadata {
    #[prost(int32, optional, tag="1")]
    pub backend: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub landing_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub library_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub recs_widget_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub shop_name: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Experiments {
    #[prost(string, repeated, tag="1")]
    pub experiment_id: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SelfUpdateConfig {
    #[prost(int32, optional, tag="1")]
    pub latest_client_version_code: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TocResponse {
    #[prost(message, repeated, tag="1")]
    pub corpus: ::prost::alloc::vec::Vec<CorpusMetadata>,
    #[prost(int32, optional, tag="2")]
    pub tos_version_deprecated: ::core::option::Option<i32>,
    #[prost(string, optional, tag="3")]
    pub tos_content: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub home_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="5")]
    pub experiments: ::core::option::Option<Experiments>,
    #[prost(string, optional, tag="6")]
    pub tos_checkbox_text_marketing_emails: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub tos_token: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="9")]
    pub icon_override_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="10")]
    pub self_update_config: ::core::option::Option<SelfUpdateConfig>,
    #[prost(bool, optional, tag="11")]
    pub requires_upload_device_config: ::core::option::Option<bool>,
    #[prost(message, optional, tag="12")]
    pub billing_config: ::core::option::Option<BillingConfig>,
    #[prost(string, optional, tag="13")]
    pub recs_widget_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="15")]
    pub social_home_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="16")]
    pub age_verification_required: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="17")]
    pub gplus_signup_enabled: ::core::option::Option<bool>,
    #[prost(bool, optional, tag="18")]
    pub redeem_enabled: ::core::option::Option<bool>,
    #[prost(string, optional, tag="19")]
    pub help_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="20")]
    pub theme_id: ::core::option::Option<i32>,
    #[prost(string, optional, tag="21")]
    pub entertainment_home_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="22")]
    pub cookie: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Payload {
    #[prost(message, optional, tag="1")]
    pub list_response: ::core::option::Option<ListResponse>,
    #[prost(message, optional, tag="2")]
    pub details_response: ::core::option::Option<DetailsResponse>,
    #[prost(message, optional, tag="3")]
    pub review_response: ::core::option::Option<ReviewResponse>,
    #[prost(message, optional, tag="4")]
    pub buy_response: ::core::option::Option<BuyResponse>,
    #[prost(message, optional, tag="5")]
    pub search_response: ::core::option::Option<SearchResponse>,
    #[prost(message, optional, tag="6")]
    pub toc_response: ::core::option::Option<TocResponse>,
    #[prost(message, optional, tag="7")]
    pub browse_response: ::core::option::Option<BrowseResponse>,
    #[prost(message, optional, tag="8")]
    pub purchase_status_response: ::core::option::Option<PurchaseStatusResponse>,
    #[prost(string, optional, tag="10")]
    pub log_response: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="13")]
    pub flag_content_response: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="19")]
    pub bulk_details_response: ::core::option::Option<BulkDetailsResponse>,
    #[prost(message, optional, tag="21")]
    pub delivery_response: ::core::option::Option<DeliveryResponse>,
    #[prost(message, optional, tag="22")]
    pub accept_tos_response: ::core::option::Option<AcceptTosResponse>,
    #[prost(message, optional, tag="26")]
    pub android_checkin_response: ::core::option::Option<AndroidCheckinResponse>,
    #[prost(message, optional, tag="28")]
    pub upload_device_config_response: ::core::option::Option<UploadDeviceConfigResponse>,
    #[prost(message, optional, tag="40")]
    pub search_suggest_response: ::core::option::Option<SearchSuggestResponse>,
    #[prost(message, optional, tag="80")]
    pub testing_program_response: ::core::option::Option<TestingProgramResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreFetch {
    #[prost(string, optional, tag="1")]
    pub url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="2")]
    pub response: ::core::option::Option<ResponseWrapper>,
    #[prost(string, optional, tag="3")]
    pub etag: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="4")]
    pub ttl: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="5")]
    pub soft_ttl: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerMetadata {
    #[prost(int64, optional, tag="1")]
    pub latency_millis: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Targets {
    #[prost(int64, repeated, packed="false", tag="1")]
    pub target_id: ::prost::alloc::vec::Vec<i64>,
    #[prost(bytes="vec", optional, tag="2")]
    pub signature: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerCookie {
    #[prost(int32, optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(bytes="vec", optional, tag="2")]
    pub token: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerCookies {
    #[prost(message, repeated, tag="1")]
    pub server_cookie: ::prost::alloc::vec::Vec<ServerCookie>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResponseWrapper {
    #[prost(message, optional, tag="1")]
    pub payload: ::core::option::Option<Payload>,
    #[prost(message, optional, tag="2")]
    pub commands: ::core::option::Option<ServerCommands>,
    #[prost(message, repeated, tag="3")]
    pub pre_fetch: ::prost::alloc::vec::Vec<PreFetch>,
    #[prost(message, repeated, tag="4")]
    pub notification: ::prost::alloc::vec::Vec<Notification>,
    #[prost(message, optional, tag="5")]
    pub server_metadata: ::core::option::Option<ServerMetadata>,
    #[prost(message, optional, tag="6")]
    pub targets: ::core::option::Option<Targets>,
    #[prost(message, optional, tag="7")]
    pub server_cookies: ::core::option::Option<ServerCookies>,
    #[prost(bytes="vec", optional, tag="9")]
    pub server_logs_cookie: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResponseWrapperApi {
    #[prost(message, optional, tag="1")]
    pub payload: ::core::option::Option<PayloadApi>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PayloadApi {
    #[prost(message, optional, tag="5")]
    pub user_profile_response: ::core::option::Option<UserProfileResponse>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserProfileResponse {
    #[prost(message, optional, tag="1")]
    pub user_profile: ::core::option::Option<UserProfile>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerCommands {
    #[prost(bool, optional, tag="1")]
    pub clear_cache: ::core::option::Option<bool>,
    #[prost(string, optional, tag="2")]
    pub display_error_message: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub log_error_stacktrace: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetReviewsResponse {
    #[prost(message, repeated, tag="1")]
    pub review: ::prost::alloc::vec::Vec<Review>,
    #[prost(int64, optional, tag="2")]
    pub matching_count: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Review {
    #[prost(string, optional, tag="1")]
    pub author_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub source: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub document_version: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="5")]
    pub timestamp_msec: ::core::option::Option<i64>,
    #[prost(int32, optional, tag="6")]
    pub star_rating: ::core::option::Option<i32>,
    #[prost(string, optional, tag="7")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="8")]
    pub comment: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="9")]
    pub comment_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="19")]
    pub device_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="29")]
    pub reply_text: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="30")]
    pub reply_timestamp_msec: ::core::option::Option<i64>,
    #[prost(message, optional, tag="31")]
    pub author: ::core::option::Option<ReviewAuthor>,
    #[prost(message, optional, tag="33")]
    pub user_profile: ::core::option::Option<UserProfile>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReviewAuthor {
    #[prost(string, optional, tag="2")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="5")]
    pub avatar: ::core::option::Option<Image>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserProfile {
    #[prost(string, optional, tag="1")]
    pub person_id_string: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub person_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="3")]
    pub unknown1: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="4")]
    pub unknown2: ::core::option::Option<i32>,
    #[prost(string, optional, tag="5")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="10")]
    pub image: ::prost::alloc::vec::Vec<Image>,
    #[prost(string, optional, tag="19")]
    pub google_plus_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="22")]
    pub google_plus_tagline: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReviewResponse {
    #[prost(message, optional, tag="1")]
    pub get_response: ::core::option::Option<GetReviewsResponse>,
    #[prost(string, optional, tag="2")]
    pub next_page_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="3")]
    pub user_review: ::core::option::Option<Review>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RelatedSearch {
    #[prost(string, optional, tag="1")]
    pub search_url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub header: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="3")]
    pub backend_id: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="4")]
    pub doc_type: ::core::option::Option<i32>,
    #[prost(bool, optional, tag="5")]
    pub current: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SearchResponse {
    #[prost(string, optional, tag="1")]
    pub original_query: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub suggested_query: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="3")]
    pub aggregate_query: ::core::option::Option<bool>,
    #[prost(message, repeated, tag="4")]
    pub bucket: ::prost::alloc::vec::Vec<Bucket>,
    #[prost(message, repeated, tag="5")]
    pub doc: ::prost::alloc::vec::Vec<DocV2>,
    #[prost(message, repeated, tag="6")]
    pub related_search: ::prost::alloc::vec::Vec<RelatedSearch>,
    #[prost(string, optional, tag="10")]
    pub next_page_url: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SearchSuggestResponse {
    #[prost(message, repeated, tag="1")]
    pub entry: ::prost::alloc::vec::Vec<SearchSuggestEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SearchSuggestEntry {
    #[prost(int32, optional, tag="1")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub suggested_query: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="5")]
    pub image_container: ::core::option::Option<search_suggest_entry::ImageContainer>,
    #[prost(string, optional, tag="6")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="8")]
    pub package_name_container: ::core::option::Option<search_suggest_entry::PackageNameContainer>,
}
/// Nested message and enum types in `SearchSuggestEntry`.
pub mod search_suggest_entry {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ImageContainer {
        #[prost(string, optional, tag="5")]
        pub image_url: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PackageNameContainer {
        #[prost(string, optional, tag="1")]
        pub package_name: ::core::option::Option<::prost::alloc::string::String>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TestingProgramResponse {
    #[prost(message, optional, tag="2")]
    pub result: ::core::option::Option<TestingProgramResult>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TestingProgramResult {
    #[prost(message, optional, tag="4")]
    pub details: ::core::option::Option<TestingProgramDetails>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TestingProgramDetails {
    #[prost(bool, optional, tag="2")]
    pub flag1: ::core::option::Option<bool>,
    #[prost(int64, optional, tag="3")]
    pub id: ::core::option::Option<i64>,
    #[prost(bool, optional, tag="4")]
    pub unsubscribed: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogRequest {
    #[prost(int64, optional, tag="1")]
    pub timestamp: ::core::option::Option<i64>,
    #[prost(string, optional, tag="2")]
    pub download_confirmation_query: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TestingProgramRequest {
    #[prost(string, optional, tag="1")]
    pub package_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="2")]
    pub subscribe: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UploadDeviceConfigRequest {
    #[prost(message, optional, tag="1")]
    pub device_configuration: ::core::option::Option<DeviceConfigurationProto>,
    #[prost(string, optional, tag="2")]
    pub manufacturer: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub gcm_registration_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UploadDeviceConfigResponse {
    #[prost(string, optional, tag="1")]
    pub upload_device_config_token: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidCheckinRequest {
    #[prost(string, optional, tag="1")]
    pub imei: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="2")]
    pub id: ::core::option::Option<i64>,
    #[prost(string, optional, tag="3")]
    pub digest: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="4")]
    pub checkin: ::core::option::Option<AndroidCheckinProto>,
    #[prost(string, optional, tag="5")]
    pub desired_build: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub locale: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="7")]
    pub logging_id: ::core::option::Option<i64>,
    #[prost(string, optional, tag="8")]
    pub market_checkin: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="9")]
    pub mac_addr: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="10")]
    pub meid: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="11")]
    pub account_cookie: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub time_zone: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(fixed64, optional, tag="13")]
    pub security_token: ::core::option::Option<u64>,
    #[prost(int32, optional, tag="14")]
    pub version: ::core::option::Option<i32>,
    #[prost(string, repeated, tag="15")]
    pub ota_cert: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="16")]
    pub serial_number: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="17")]
    pub esn: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag="18")]
    pub device_configuration: ::core::option::Option<DeviceConfigurationProto>,
    #[prost(string, repeated, tag="19")]
    pub mac_addr_type: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="20")]
    pub fragment: ::core::option::Option<i32>,
    #[prost(string, optional, tag="21")]
    pub user_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="22")]
    pub user_serial_number: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidCheckinResponse {
    #[prost(bool, optional, tag="1")]
    pub stats_ok: ::core::option::Option<bool>,
    #[prost(message, repeated, tag="2")]
    pub intent: ::prost::alloc::vec::Vec<AndroidIntentProto>,
    #[prost(int64, optional, tag="3")]
    pub time_msec: ::core::option::Option<i64>,
    #[prost(string, optional, tag="4")]
    pub digest: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="5")]
    pub setting: ::prost::alloc::vec::Vec<GservicesSetting>,
    #[prost(bool, optional, tag="6")]
    pub market_ok: ::core::option::Option<bool>,
    #[prost(fixed64, optional, tag="7")]
    pub android_id: ::core::option::Option<u64>,
    #[prost(fixed64, optional, tag="8")]
    pub security_token: ::core::option::Option<u64>,
    #[prost(bool, optional, tag="9")]
    pub settings_diff: ::core::option::Option<bool>,
    #[prost(string, repeated, tag="10")]
    pub delete_setting: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub device_checkin_consistency_token: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GservicesSetting {
    #[prost(bytes="vec", optional, tag="1")]
    pub name: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes="vec", optional, tag="2")]
    pub value: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidBuildProto {
    #[prost(string, optional, tag="1")]
    pub id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub product: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub carrier: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub radio: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="5")]
    pub bootloader: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub client: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="7")]
    pub timestamp: ::core::option::Option<i64>,
    #[prost(int32, optional, tag="8")]
    pub google_services: ::core::option::Option<i32>,
    #[prost(string, optional, tag="9")]
    pub device: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="10")]
    pub sdk_version: ::core::option::Option<i32>,
    #[prost(string, optional, tag="11")]
    pub model: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="12")]
    pub manufacturer: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="13")]
    pub build_product: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag="14")]
    pub ota_installed: ::core::option::Option<bool>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidCheckinProto {
    #[prost(message, optional, tag="1")]
    pub build: ::core::option::Option<AndroidBuildProto>,
    #[prost(int64, optional, tag="2")]
    pub last_checkin_msec: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="3")]
    pub event: ::prost::alloc::vec::Vec<AndroidEventProto>,
    #[prost(message, repeated, tag="4")]
    pub stat: ::prost::alloc::vec::Vec<AndroidStatisticProto>,
    #[prost(string, repeated, tag="5")]
    pub requested_group: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, optional, tag="6")]
    pub cell_operator: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="7")]
    pub sim_operator: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="8")]
    pub roaming: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="9")]
    pub user_number: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidEventProto {
    #[prost(string, optional, tag="1")]
    pub tag: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag="3")]
    pub time_msec: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidIntentProto {
    #[prost(string, optional, tag="1")]
    pub action: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="2")]
    pub data_uri: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="3")]
    pub mime_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag="4")]
    pub java_class: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(group, repeated, tag="5")]
    pub extra: ::prost::alloc::vec::Vec<android_intent_proto::Extra>,
}
/// Nested message and enum types in `AndroidIntentProto`.
pub mod android_intent_proto {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Extra {
        #[prost(string, optional, tag="6")]
        pub name: ::core::option::Option<::prost::alloc::string::String>,
        #[prost(string, optional, tag="7")]
        pub value: ::core::option::Option<::prost::alloc::string::String>,
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidStatisticProto {
    #[prost(string, optional, tag="1")]
    pub tag: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub count: ::core::option::Option<i32>,
    #[prost(float, optional, tag="3")]
    pub sum: ::core::option::Option<f32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientLibraryState {
    #[prost(int32, optional, tag="1")]
    pub corpus: ::core::option::Option<i32>,
    #[prost(bytes="vec", optional, tag="2")]
    pub server_token: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(int64, optional, tag="3")]
    pub hash_code_sum: ::core::option::Option<i64>,
    #[prost(int32, optional, tag="4")]
    pub library_size: ::core::option::Option<i32>,
    #[prost(string, optional, tag="5")]
    pub library_id: ::core::option::Option<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidDataUsageProto {
    #[prost(int32, optional, tag="1")]
    pub version: ::core::option::Option<i32>,
    #[prost(int64, optional, tag="2")]
    pub current_report_msec: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="3")]
    pub key_to_package_name_mapping: ::prost::alloc::vec::Vec<KeyToPackageNameMapping>,
    #[prost(message, repeated, tag="4")]
    pub payload_level_app_stat: ::prost::alloc::vec::Vec<PayloadLevelAppStat>,
    #[prost(message, repeated, tag="5")]
    pub ip_layer_network_stat: ::prost::alloc::vec::Vec<IpLayerNetworkStat>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndroidUsageStatsReport {
    #[prost(int64, optional, tag="1")]
    pub android_id: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="2")]
    pub logging_id: ::core::option::Option<i64>,
    #[prost(message, optional, tag="3")]
    pub usage_stats: ::core::option::Option<UsageStatsExtensionProto>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppBucket {
    #[prost(int64, optional, tag="1")]
    pub bucket_start_msec: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="2")]
    pub bucket_duration_msec: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="3")]
    pub stat_counters: ::prost::alloc::vec::Vec<StatCounters>,
    #[prost(int64, optional, tag="4")]
    pub operation_count: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CounterData {
    #[prost(int64, optional, tag="1")]
    pub bytes: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="2")]
    pub packets: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpLayerAppStat {
    #[prost(int32, optional, tag="1")]
    pub package_key: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub application_tag: ::core::option::Option<i32>,
    #[prost(message, repeated, tag="3")]
    pub ip_layer_app_bucket: ::prost::alloc::vec::Vec<AppBucket>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpLayerNetworkBucket {
    #[prost(int64, optional, tag="1")]
    pub bucket_start_msec: ::core::option::Option<i64>,
    #[prost(int64, optional, tag="2")]
    pub bucket_duration_msec: ::core::option::Option<i64>,
    #[prost(message, repeated, tag="3")]
    pub stat_counters: ::prost::alloc::vec::Vec<StatCounters>,
    #[prost(int64, optional, tag="4")]
    pub network_active_duration: ::core::option::Option<i64>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IpLayerNetworkStat {
    #[prost(string, optional, tag="1")]
    pub network_details: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub r#type: ::core::option::Option<i32>,
    #[prost(message, repeated, tag="3")]
    pub ip_layer_network_bucket: ::prost::alloc::vec::Vec<IpLayerNetworkBucket>,
    #[prost(message, repeated, tag="4")]
    pub ip_layer_app_stat: ::prost::alloc::vec::Vec<IpLayerAppStat>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyToPackageNameMapping {
    #[prost(int32, optional, tag="1")]
    pub package_key: ::core::option::Option<i32>,
    #[prost(string, optional, tag="2")]
    pub uid_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag="3")]
    pub shared_package_list: ::prost::alloc::vec::Vec<PackageInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PackageInfo {
    #[prost(string, optional, tag="1")]
    pub pkg_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub version_code: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PayloadLevelAppStat {
    #[prost(int32, optional, tag="1")]
    pub package_key: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub application_tag: ::core::option::Option<i32>,
    #[prost(message, repeated, tag="3")]
    pub payload_level_app_bucket: ::prost::alloc::vec::Vec<AppBucket>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatCounters {
    #[prost(int32, optional, tag="1")]
    pub network_proto: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="2")]
    pub direction: ::core::option::Option<i32>,
    #[prost(message, optional, tag="3")]
    pub counter_data: ::core::option::Option<CounterData>,
    #[prost(int32, optional, tag="4")]
    pub fg_bg: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UsageStatsExtensionProto {
    #[prost(message, optional, tag="1")]
    pub data_usage: ::core::option::Option<AndroidDataUsageProto>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModifyLibraryRequest {
    #[prost(string, optional, tag="1")]
    pub library_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="2")]
    pub add_package_name: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, repeated, tag="3")]
    pub remove_package_name: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UrlRequestWrapper {
    #[prost(message, optional, tag="49")]
    pub developer_apps_request: ::core::option::Option<DeveloperAppsRequest>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeveloperAppsRequest {
    #[prost(message, optional, tag="1")]
    pub developer_id_container1: ::core::option::Option<DeveloperIdContainer>,
    #[prost(message, optional, tag="2")]
    pub developer_id_container2: ::core::option::Option<DeveloperIdContainer>,
    #[prost(int32, optional, tag="3")]
    pub unknown_int3: ::core::option::Option<i32>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeveloperIdContainer {
    #[prost(string, optional, tag="1")]
    pub developer_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int32, optional, tag="2")]
    pub unknown_int2: ::core::option::Option<i32>,
    #[prost(int32, optional, tag="3")]
    pub unknown_int3: ::core::option::Option<i32>,
}
