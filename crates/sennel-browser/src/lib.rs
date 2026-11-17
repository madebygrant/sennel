// KeePassXC's browser protocol, answered from a Sennel session, and the pieces that carry it: the
// proxy a browser starts, the socket it talks to, and the browser registrations. No UI here.

pub mod allow;
pub mod crypto;
pub mod matching;
pub mod pairing;
pub mod proxy;
pub mod registration;
pub mod server;
pub mod transport;

pub use server::{Answer, Effect, Handled, Prompt, Question, Server, Step};
