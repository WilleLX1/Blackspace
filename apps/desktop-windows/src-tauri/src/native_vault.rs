use std::sync::Mutex;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use tauri::{AppHandle, Manager, State};

const WRAP_AAD: &[u8] = b"blackspace:v1:windows-vault-wrapper";
const RECORD_AAD: &[u8] = b"blackspace:v1:windows-vault-record";

#[derive(Default)]
pub struct NativeVault {
    key: Mutex<Option<[u8; 32]>>,
}

struct Wrapper {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    protected_key: Vec<u8>,
}

fn open(app: &AppHandle) -> Result<Connection, String> {
    let directory = app
        .path()
        .app_local_data_dir()
        .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let connection = Connection::open(directory.join("blackspace-vault.sqlite3"))
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "PRAGMA secure_delete = ON;
         PRAGMA journal_mode = TRUNCATE;
         PRAGMA journal_size_limit = 1048576;
         CREATE TABLE IF NOT EXISTS vault (
           id INTEGER PRIMARY KEY CHECK (id = 1),
           salt BLOB NOT NULL,
           wrap_nonce BLOB NOT NULL,
           protected_key BLOB NOT NULL,
           record_nonce BLOB NOT NULL,
           ciphertext BLOB NOT NULL,
           updated_at INTEGER NOT NULL DEFAULT (unixepoch())
         );",
        )
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    if passphrase.len() < 10 {
        return Err("Use at least 10 characters for the vault passphrase.".into());
    }
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|error| error.to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|_| "Vault key derivation failed.".to_string())?;
    Ok(output)
}

fn aes_encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid vault key.".to_string())?
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Vault encryption failed.".to_string())
}

fn aes_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| "Invalid vault key.".to_string())?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "The passphrase is incorrect or the vault is damaged.".to_string())
}

#[cfg(target_os = "windows")]
fn dpapi_protect(value: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData},
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: value.len() as u32,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("Windows could not protect the vault key.".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}

#[cfg(target_os = "windows")]
fn dpapi_unprotect(value: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: value.len() as u32,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("Windows could not unlock the vault key for this user.".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}

#[cfg(not(target_os = "windows"))]
fn dpapi_protect(_value: &[u8]) -> Result<Vec<u8>, String> {
    Err("The native vault requires Windows DPAPI.".into())
}
#[cfg(not(target_os = "windows"))]
fn dpapi_unprotect(_value: &[u8]) -> Result<Vec<u8>, String> {
    Err("The native vault requires Windows DPAPI.".into())
}

fn load_wrapper(connection: &Connection) -> Result<Option<Wrapper>, String> {
    connection
        .query_row(
            "SELECT salt, wrap_nonce, protected_key FROM vault WHERE id = 1",
            [],
            |row| {
                Ok(Wrapper {
                    salt: row.get(0)?,
                    nonce: row.get(1)?,
                    protected_key: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|error| error.to_string())
}

fn unlock_key(connection: &Connection, passphrase: &str) -> Result<[u8; 32], String> {
    let wrapper =
        load_wrapper(connection)?.ok_or_else(|| "No Blackspace vault was found.".to_string())?;
    let wrapping_key = derive(passphrase, &wrapper.salt)?;
    let dpapi_blob = aes_decrypt(
        &wrapping_key,
        &wrapper.nonce,
        WRAP_AAD,
        &wrapper.protected_key,
    )?;
    let raw = dpapi_unprotect(&dpapi_blob)?;
    raw.try_into()
        .map_err(|_| "The protected vault key is invalid.".to_string())
}

#[tauri::command]
pub fn native_vault_exists(app: AppHandle) -> Result<bool, String> {
    Ok(load_wrapper(&open(&app)?)?.is_some())
}

#[tauri::command]
pub fn native_save_vault(
    app: AppHandle,
    vault: State<'_, NativeVault>,
    state: Value,
    passphrase: String,
) -> Result<(), String> {
    let connection = open(&app)?;
    let existing = load_wrapper(&connection)?;
    let mut cached = vault
        .key
        .lock()
        .map_err(|_| "The vault lock failed.".to_string())?;
    let (key, wrapper) = if let Some(key) = *cached {
        (
            key,
            existing.ok_or_else(|| "No Blackspace vault was found.".to_string())?,
        )
    } else if let Some(wrapper) = existing {
        (unlock_key(&connection, &passphrase)?, wrapper)
    } else {
        let mut key = [0_u8; 32];
        rand::rng().fill_bytes(&mut key);
        let mut salt = vec![0_u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let mut nonce = vec![0_u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let protected = dpapi_protect(&key)?;
        let wrapped = aes_encrypt(&derive(&passphrase, &salt)?, &nonce, WRAP_AAD, &protected)?;
        (
            key,
            Wrapper {
                salt,
                nonce,
                protected_key: wrapped,
            },
        )
    };
    *cached = Some(key);
    let mut record_nonce = vec![0_u8; 12];
    rand::rng().fill_bytes(&mut record_nonce);
    let plaintext = serde_json::to_vec(&state).map_err(|error| error.to_string())?;
    let ciphertext = aes_encrypt(&key, &record_nonce, RECORD_AAD, &plaintext)?;
    connection.execute(
        "INSERT INTO vault (id, salt, wrap_nonce, protected_key, record_nonce, ciphertext) VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET record_nonce = excluded.record_nonce, ciphertext = excluded.ciphertext, updated_at = unixepoch()",
        params![wrapper.salt, wrapper.nonce, wrapper.protected_key, record_nonce, ciphertext],
    ).map_err(|error| error.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn native_unlock_vault(
    app: AppHandle,
    vault: State<'_, NativeVault>,
    passphrase: String,
) -> Result<Value, String> {
    let connection = open(&app)?;
    let key = unlock_key(&connection, &passphrase)?;
    let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT record_nonce, ciphertext FROM vault WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    let plaintext = aes_decrypt(&key, &nonce, RECORD_AAD, &ciphertext)?;
    *vault
        .key
        .lock()
        .map_err(|_| "The vault lock failed.".to_string())? = Some(key);
    serde_json::from_slice(&plaintext)
        .map_err(|_| "The encrypted vault record is invalid.".to_string())
}

#[tauri::command]
pub fn native_lock_vault(vault: State<'_, NativeVault>) -> Result<(), String> {
    *vault
        .key
        .lock()
        .map_err(|_| "The vault lock failed.".to_string())? = None;
    Ok(())
}

#[tauri::command]
pub fn native_delete_vault(app: AppHandle, vault: State<'_, NativeVault>) -> Result<(), String> {
    let connection = open(&app)?;
    connection
        .execute("DELETE FROM vault WHERE id = 1", [])
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
        .map_err(|error| error.to_string())?;
    *vault
        .key
        .lock()
        .map_err(|_| "The vault lock failed.".to_string())? = None;
    Ok(())
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn dpapi_and_passphrase_layers_round_trip_for_current_user() {
        let raw = [7_u8; 32];
        let protected = dpapi_protect(&raw).unwrap();
        assert_ne!(protected, raw);
        assert_eq!(dpapi_unprotect(&protected).unwrap(), raw);

        let wrapping_key = derive("correct horse battery staple", &[3_u8; 16]).unwrap();
        let encrypted = aes_encrypt(&wrapping_key, &[4_u8; 12], WRAP_AAD, &protected).unwrap();
        assert_eq!(
            aes_decrypt(&wrapping_key, &[4_u8; 12], WRAP_AAD, &encrypted).unwrap(),
            protected
        );
    }
}
