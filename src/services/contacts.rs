use rusqlite::{params, Connection, Result};

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: i64,
    pub owner_email: String,
    pub contact_email: String,
    pub alias: String,
}

pub fn add_contact(
    conn: &Connection,
    owner_email: &str,
    contact_email: &str,
    alias: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO contacts (owner_email, contact_email, alias)
         VALUES (?1, ?2, ?3)",
        params![owner_email, contact_email, alias],
    )?;
    Ok(())
}

pub fn remove_contact(conn: &Connection, owner_email: &str, contact_email: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM contacts WHERE owner_email = ?1 AND contact_email = ?2",
        params![owner_email, contact_email],
    )?;
    Ok(())
}

pub fn get_contacts(conn: &Connection, owner_email: &str) -> Result<Vec<Contact>> {
    let mut stmt = conn.prepare(
        "SELECT id, owner_email, contact_email, alias
         FROM contacts
         WHERE owner_email = ?1
         ORDER BY alias",
    )?;

    let rows = stmt.query_map(params![owner_email], |row| {
        Ok(Contact {
            id: row.get(0)?,
            owner_email: row.get(1)?,
            contact_email: row.get(2)?,
            alias: row.get(3)?,
        })
    })?;

    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }
    Ok(result)
}