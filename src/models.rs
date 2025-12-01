#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub status: String,
    pub about: String,
}