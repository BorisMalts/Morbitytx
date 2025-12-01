use rusqlite::{params, Connection, Result};

use crate::encryption::encrypt;
use crate::models::User;

pub fn register_user(
    conn: &Connection,
    email: &str,
    password: &str,
    display_name: &str,
) -> Result<()> {
    let encrypted_password = encrypt(password);
    conn.execute(
        "INSERT INTO users (email, password, display_name, status, about)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![email, encrypted_password, display_name, "offline", ""],
    )?;
    Ok(())
}

pub fn login_user(conn: &Connection, email: &str, password: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, email, password, display_name, status, about
         FROM users
         WHERE email = ?1",
    )?;

    let mut rows = stmt.query(params![email])?;

    if let Some(row) = rows.next()? {
        let stored_password: String = row.get(2)?;
        let encrypted_input = encrypt(password);

        if stored_password == encrypted_input {
            let user = User {
                id: row.get(0)?,
                email: row.get(1)?,
                password: stored_password,
                display_name: row.get(3)?,
                status: row.get(4)?,
                about: row.get(5)?,
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub fn get_user_by_email(conn: &Connection, email: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, email, password, display_name, status, about
         FROM users
         WHERE email = ?1",
    )?;

    let mut rows = stmt.query(params![email])?;
    if let Some(row) = rows.next()? {
        Ok(Some(User {
            id: row.get(0)?,
            email: row.get(1)?,
            password: row.get(2)?,
            display_name: row.get(3)?,
            status: row.get(4)?,
            about: row.get(5)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn update_status(conn: &Connection, email: &str, status: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET status = ?1 WHERE email = ?2",
        params![status, email],
    )?;
    Ok(())
}

pub fn update_about(conn: &Connection, email: &str, about: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET about = ?1 WHERE email = ?2",
        params![about, email],
    )?;
    Ok(())
}

pub fn update_password(conn: &rusqlite::Connection, email: &str, new_password: &str) -> rusqlite::Result<()> {
    let enc = crate::encryption::encrypt(new_password);
    conn.execute(
        "UPDATE users SET password = ?1 WHERE email = ?2",
        (&enc, &email),
    )?;
    Ok(())
}