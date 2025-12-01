use rusqlite::{params, Connection, Result};

use crate::encryption::{decrypt, encrypt};

#[derive(Debug, Clone)]
pub struct Message {
    pub id: i64,
    pub sender_email: String,
    pub receiver_email: String,
    pub cipher_text: String,
    pub created_at: String,
    pub is_read: bool,
}

impl Message {
    pub fn body(&self) -> String {
        decrypt(&self.cipher_text)
    }
}

pub fn send_message(
    conn: &Connection,
    sender_email: &str,
    receiver_email: &str,
    text: &str,
) -> Result<()> {
    let cipher_text = encrypt(text);

    conn.execute(
        "INSERT INTO messages (sender_email, receiver_email, cipher_text, created_at)
         VALUES (?1, ?2, ?3, datetime('now'))",
        params![sender_email, receiver_email, cipher_text],
    )?;
    Ok(())
}

pub fn get_dialog(
    conn: &Connection,
    user1: &str,
    user2: &str,
) -> Result<Vec<Message>> {
    let mut stmt = conn.prepare(
        "SELECT id, sender_email, receiver_email, cipher_text, created_at, is_read
         FROM messages
         WHERE (sender_email = ?1 AND receiver_email = ?2)
            OR (sender_email = ?2 AND receiver_email = ?1)
         ORDER BY id ASC",
    )?;

    let rows = stmt.query_map(params![user1, user2], |row| {
        Ok(Message {
            id: row.get(0)?,
            sender_email: row.get(1)?,
            receiver_email: row.get(2)?,
            cipher_text: row.get(3)?,
            created_at: row.get(4)?,
            is_read: {
                let v: i64 = row.get(5)?;
                v != 0
            },
        })
    })?;

    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }
    Ok(result)
}

pub fn mark_as_read(conn: &Connection, message_id: i64) -> Result<()> {
    conn.execute(
        "UPDATE messages SET is_read = 1 WHERE id = ?1",
        params![message_id],
    )?;
    Ok(())
}