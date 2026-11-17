// KeePassXC's browser protocol, answered from a Sennel session. No sockets and no UI here: a front
// end passes each request in, puts any question to the user itself, and sends the reply back.

pub mod crypto;
pub mod matching;
pub mod pairing;
pub mod server;

pub use server::{Answer, Effect, Handled, Prompt, Question, Server, Step};
