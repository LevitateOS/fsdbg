//! What a built LevitateOS rootfs must contain: the expectations the
//! checklists verify against.

pub mod auth;
mod bins;
mod etc;
mod filesystem;
mod systemd;
mod units;
mod users;

pub use bins::*;
pub use etc::*;
pub use filesystem::*;
pub use systemd::*;
pub use units::*;
pub use users::*;
