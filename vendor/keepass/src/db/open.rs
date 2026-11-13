use thiserror::Error;

use crate::{
    config::DatabaseVersion,
    db::Database,
    format::{
        kdb::parse_kdb,
        kdbx3::{decrypt_kdbx3, parse_kdbx3},
        kdbx4::{decrypt_kdbx4, parse_kdbx4},
        DatabaseVersionParseError,
    },
    DatabaseKey,
};

impl Database {
    /// Parse a database from a std::io::Read
    pub fn open(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        Database::parse(data.as_ref(), key)
    }

    /// Parse a database from a byte slice
    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => parse_kdb(data, &key),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => parse_kdbx3(data, &key),
            DatabaseVersion::KDB4(_) => parse_kdbx4(data, &key),
        }
    }

    /// Helper function to load a database into its internal XML chunks
    pub fn get_xml(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Vec<u8>, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        let data = match database_version {
            DatabaseVersion::KDB(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            // SENNEL PATCH: both moved out of the buffer their decrypt wipes.
            DatabaseVersion::KDB3(_) => std::mem::take(&mut *decrypt_kdbx3(data.as_ref(), &key)?.2),
            DatabaseVersion::KDB4(_) => std::mem::take(&mut *decrypt_kdbx4(data.as_ref(), &key)?.3),
        };

        Ok(data)
    }

    /// SENNEL PATCH: the key derivation a file's header asks for, parsed exactly as `parse` would
    /// parse it but without running it, so a caller can refuse an unreasonable one first. `None`
    /// when the header does not parse. Malformed input can still panic, as `parse` can.
    pub fn kdf_config_of(data: &[u8]) -> Option<crate::config::KdfConfig> {
        match DatabaseVersion::parse(data).ok()? {
            DatabaseVersion::KDB(_) => crate::format::kdb::kdf_config_of(data),
            DatabaseVersion::KDB2(_) => None,
            DatabaseVersion::KDB3(_) => crate::format::kdbx3::kdf_config_of(data),
            DatabaseVersion::KDB4(_) => crate::format::kdbx4::kdf_config_of(data),
        }
    }

    /// Get the version of a database without decrypting it
    pub fn get_version(source: &mut dyn std::io::Read) -> Result<DatabaseVersion, DatabaseOpenError> {
        let mut data = vec![0; DatabaseVersion::get_version_header_size()];
        source.read_exact(&mut data)?;
        let version = DatabaseVersion::parse(data.as_ref())?;
        Ok(version)
    }
}

/// Errors that can occur when opening a database
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseOpenError {
    /// I/O errors that can occur while reading the database from the source
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An unexpected end of file was encountered while reading the database
    #[error("Unexpected end of file")]
    UnexpectedEof,

    /// Errors related to parsing the database version from the file header
    #[error(transparent)]
    VersionParse(#[from] DatabaseVersionParseError),

    /// Attempted to open a database with an unsupported version
    #[error("Unsupported database version")]
    UnsupportedVersion,

    /// Errors related to the database key, such as incorrect keys
    #[error(transparent)]
    Key(#[from] crate::key::DatabaseKeyError),

    /// Errors related to decryption
    #[error(transparent)]
    Cryptography(#[from] crate::crypt::CryptographyError),

    /// Errors related to parsing the database format
    #[error(transparent)]
    Format(#[from] DatabaseFormatError),
}

/// Format-specific database parsing errors
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseFormatError {
    /// Errors related to parsing KDB files
    #[error(transparent)]
    Kdb(#[from] crate::format::kdb::KdbOpenError),

    /// Errors related to parsing KDBX3 files
    #[error(transparent)]
    Kdbx3(#[from] crate::format::kdbx3::Kdbx3OpenError),

    /// Errors related to parsing KDBX4 files
    #[error(transparent)]
    Kdbx4(#[from] crate::format::kdbx4::Kdbx4OpenError),
}
