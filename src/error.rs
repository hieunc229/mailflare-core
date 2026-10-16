/// Errors crossing the FFI boundary. Each variant carries a message the UI can
/// show; the variant tells the UI how to react (re-auth, retry, give up).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
	/// The server rejected the credentials.
	#[error("{message}")]
	Auth { message: String },
	/// No JMAP server could be found for the address.
	#[error("{message}")]
	Discovery { message: String },
	/// Transport failure; retrying later may succeed.
	#[error("{message}")]
	Network { message: String },
	/// The server answered with a JMAP or HTTP error.
	#[error("{message}")]
	Server { message: String },
	/// Local database failure.
	#[error("{message}")]
	Storage { message: String },
	#[error("{message}")]
	NotFound { message: String },
	#[error("{message}")]
	InvalidInput { message: String },
}

impl CoreError {
	pub fn server(message: impl Into<String>) -> Self {
		Self::Server { message: message.into() }
	}
	pub fn invalid(message: impl Into<String>) -> Self {
		Self::InvalidInput { message: message.into() }
	}
	pub fn not_found(message: impl Into<String>) -> Self {
		Self::NotFound { message: message.into() }
	}
}

impl From<rusqlite::Error> for CoreError {
	fn from(error: rusqlite::Error) -> Self {
		Self::Storage { message: error.to_string() }
	}
}

impl From<reqwest::Error> for CoreError {
	fn from(error: reqwest::Error) -> Self {
		let message = if error.is_timeout() {
			"The server took too long to respond.".to_string()
		} else if error.is_connect() {
			"Could not connect to the server.".to_string()
		} else {
			error.to_string()
		};
		Self::Network { message }
	}
}

impl From<serde_json::Error> for CoreError {
	fn from(error: serde_json::Error) -> Self {
		Self::Server { message: format!("Unexpected response: {error}") }
	}
}

pub type Result<T> = std::result::Result<T, CoreError>;
