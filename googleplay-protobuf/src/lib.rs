pub mod googleplay {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}
pub use googleplay::*;
