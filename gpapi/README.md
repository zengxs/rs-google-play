# `gpapi` - Google Play API for Rust

A library for interacting with the Google Play API, stronly following [google play python API](https://github.com/NoMore201/googleplay-api.git) patterns.

## Getting Started

Interacting with the API starts off with initializing the API and logging in.

```rust
let mut gpa = Gpapi::new("en_US", "UTC", "hero2lte");
gpa.login("someone@gmail.com", "somepass").await);
```

From here, you can get package details, get the URL to download a package, or use the library to download it.

```rust
let details = gpa.details("com.instagram.android");
println!("{:?}", details);

let download_url = gpa.get_download_url("com.instagram.android", None);
println!("{:?}", download_url);

gpa.download("com.instagram.android", None, &Path::new("/tmp/testing")).await;
```

## Todo

Some of the functionality of the python library is missing, such as browsing and searching for packages.

## Credits

This library was originally created by David Weinstein, and is currently maintained by Bill Budington.
