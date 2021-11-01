#[cfg(feature = "manager-cacache")]
mod cacache;

#[cfg(feature = "manager-cacache")]
pub use self::cacache::CACacheManager;
