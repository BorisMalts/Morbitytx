mod db;
mod models;
mod encryption;
mod services;

use crate::services::{auth, messages};
use crate::models::User;
use db::{establish_connection, init_db};
use eframe::egui;
use rusqlite::Connection;
use std::path::PathBuf;
use rand::Rng;
use rfd::FileDialog;
use std::env;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use std::time::{Duration, Instant};
use std::net::{TcpStream, ToSocketAddrs};
use chrono::Local;
use std::collections::HashMap;
use image;

#[derive(Clone)]
struct UiMessage {
    id: i64,
    from: String,
    text: String,
    created_at: String,
    is_read: bool,
}

struct MyApp {
    conn: Connection,
    login_email: String,
    login_password: String,
    reg_email: String,
    reg_password: String,
    reg_password2: String,
    reg_display_name: String,
    current_user: Option<User>,
    peer_email: String,
    messages: Vec<UiMessage>,
    new_message_text: String,
    status: String,
    status_is_error: bool,
    verification_code: Option<String>,
    verification_input: String,
    email_verified: bool,
    theme_inited: bool,
    selected_file: Option<PathBuf>,
    selected_file_label: String,
    avatar_path: Option<PathBuf>,
    about_edit: String,
    unread_count: usize,
    unread_popup_visible: bool,
    pending_reg_email: Option<String>,
    pending_reg_password: Option<String>,
    pending_reg_display_name: Option<String>,
    chat_list: Vec<(String, usize)>,
    chatlist_last_refresh: Instant,
    chatlist_refresh_every: Duration,
    show_about_popup: bool,
    show_peer_about: bool,
    peer_about_text: String,
    avatar_textures: HashMap<String, egui::TextureHandle>,
    show_reset_dialog: bool,
    reset_email: String,
    reset_code: Option<String>,
    reset_code_input: String,
    reset_new_password: String,
}

impl MyApp {
    fn new() -> Self {
        let conn = establish_connection().expect("Failed to open DB");
        init_db(&conn).expect("Failed to init DB");
        Self {
            conn,
            login_email: String::new(),
            login_password: String::new(),
            reg_email: String::new(),
            reg_password: String::new(),
            reg_password2: String::new(),
            reg_display_name: String::new(),
            current_user: None,
            peer_email: String::new(),
            messages: Vec::new(),
            new_message_text: String::new(),
            status: "Welcome to Morbityx Messenger".to_string(),
            status_is_error: false,
            verification_code: None,
            verification_input: String::new(),
            email_verified: false,
            theme_inited: false,
            selected_file: None,
            selected_file_label: String::new(),
            avatar_path: None,
            about_edit: String::new(),
            unread_count: 0,
            unread_popup_visible: false,
            pending_reg_email: None,
            pending_reg_password: None,
            pending_reg_display_name: None,
            chat_list: Vec::new(),
            chatlist_last_refresh: Instant::now(),
            chatlist_refresh_every: Duration::from_millis(1500),
            show_about_popup: false,
            show_peer_about: false,
            peer_about_text: String::new(),
            avatar_textures: HashMap::new(),
            show_reset_dialog: false,
            reset_email: String::new(),
            reset_code: None,
            reset_code_input: String::new(),
            reset_new_password: String::new(),
        }
    }
    fn draw_avatar(&mut self, ctx: &egui::Context, ui: &mut egui::Ui, email: &str, size: f32, fill: egui::Color32) -> egui::Response {
        use egui::{Align2, FontId, Sense, Vec2, Rounding};
        let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
        let center = rect.center();

        if let Some(path) = Self::load_avatar_for(email) {
            let key = format!("{}::{}", email, path.to_string_lossy());
            if !self.avatar_textures.contains_key(&key) {
                if let Ok(img) = std::fs::read(&path) {
                    if let Ok(dynamic) = image::load_from_memory(&img) {
                        let rgba = dynamic.into_rgba8();
                        let size_px = [rgba.width() as usize, rgba.height() as usize];
                        let pixels = rgba.into_raw();
                        let color_image = egui::ColorImage::from_rgba_unmultiplied(size_px, &pixels);
                        let tex = ctx.load_texture(key.clone(), color_image, egui::TextureOptions::LINEAR);
                        self.avatar_textures.insert(key.clone(), tex);
                    }
                }
            }
            if let Some(tex) = self.avatar_textures.get(&key) {
                let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
                let mut mesh = egui::epaint::Mesh::with_texture(tex.id());
                mesh.add_rect_with_uv(rect, uv, egui::Color32::WHITE);
                ui.painter().add(egui::Shape::mesh(mesh));
                return response;
            }
        }
        ui.painter().circle_filled(center, size * 0.5, fill);
        let ch = email
            .chars()
            .find(|c| c.is_alphabetic())
            .unwrap_or_else(|| email.chars().next().unwrap_or('?'))
            .to_ascii_uppercase();
        ui.painter().text(
            center,
            Align2::CENTER_CENTER,
            ch.to_string(),
            FontId::proportional(size * 0.5),
            egui::Color32::WHITE,
        );
        response
    }

    fn purge_avatar_cache_for(&mut self, email: &str) {
        self.avatar_textures.retain(|k, _| !k.starts_with(&format!("{}::", email)));
    }
    fn avatar_store_path(email: &str) -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        let dir = PathBuf::from(home).join(".morbityx");
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join(format!("{}.avatar.txt", email.replace('@', "_at_").replace('/', "_"))))
    }
    fn load_avatar_for(email: &str) -> Option<PathBuf> {
        let path = Self::avatar_store_path(email)?;
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                let s = s.trim();
                if s.is_empty() { None } else { Some(PathBuf::from(s)) }
            }
            Err(_) => None,
        }
    }
    fn save_avatar_for(email: &str, file: Option<&PathBuf>) {
        if let Some(store) = Self::avatar_store_path(email) {
            let _ = if let Some(p) = file { std::fs::write(store, p.to_string_lossy().to_string()) } else { std::fs::write(store, "") };
        }
    }

    fn attachments_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".morbityx").join("attachments");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn refresh_chat_list(&mut self) {
        let Some(user) = &self.current_user else {
            self.chat_list.clear();
            return;
        };
        let mut stmt = match self.conn.prepare(
            r#"
                SELECT
                    CASE WHEN sender_email = ?1 THEN receiver_email ELSE sender_email END AS peer,
                    SUM(CASE WHEN receiver_email = ?1 AND is_read = 0 THEN 1 ELSE 0 END) AS unread,
                    MAX(created_at) AS last_ts
                FROM messages
                WHERE sender_email = ?1 OR receiver_email = ?1
                GROUP BY peer
                ORDER BY last_ts DESC
            "#
        ) {
            Ok(s) => s,
            Err(e) => {
                println!("[chats][error] prepare failed: {}", e);
                self.chat_list.clear();
                return;
            }
        };
        let mut rows = match stmt.query([user.email.as_str()]) {
            Ok(r) => r,
            Err(e) => {
                println!("[chats][error] query failed: {}", e);
                self.chat_list.clear();
                return;
            }
        };
        let mut out: Vec<(String, usize)> = Vec::new();
        while let Ok(Some(row)) = rows.next() {
            let peer: String = row.get(0).unwrap_or_default();
            let unread: i64 = row.get(1).unwrap_or(0);
            out.push((peer, unread as usize));
        }
        self.chat_list = out;
    }
    fn is_valid_email(s: &str) -> bool {
        let s = s.trim();
        if s.is_empty() { return false; }
        if let Some(at) = s.find('@') {
            if at == 0 || at == s.len() - 1 { return false; }
            let domain = &s[at+1..];
            return domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.');
        }
        false
    }

    fn generate_verification_code() -> String {
        let mut rng = rand::thread_rng();
        (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
    }

    fn send_verification_email(email: &str, code: &str) -> Result<(), String> {
        println!("[email] starting send_verification_email to={email}");

        let started = Instant::now();
        let smtp_host = match env::var("SMTP_HOST") {
            Ok(v) => { println!("[email] SMTP_HOST={v}"); v },
            Err(_) => return Err("Missing SMTP_HOST env var".to_string()),
        };
        let smtp_user = match env::var("SMTP_USERNAME") {
            Ok(v) => { println!("[email] SMTP_USERNAME={v}"); v },
            Err(_) => return Err("Missing SMTP_USERNAME env var".to_string()),
        };
        let smtp_pass = match env::var("SMTP_PASSWORD") {
            Ok(v) => {
                let redacted_len = v.len();
                println!("[email] SMTP_PASSWORD=*** (len={redacted_len})");
                v
            },
            Err(_) => return Err("Missing SMTP_PASSWORD env var".to_string()),
        };
        let from_addr = env::var("SMTP_FROM").unwrap_or_else(|_| format!("{}", smtp_user));
        println!("[email] SMTP_FROM={from_addr}");

        let subject = "Your Morbityx verification code";
        let body = format!(
            "Hello!\n\nYour verification code is: {code}\n\nIf you didn’t request this, you can ignore this email.\n\n— Morbityx Messenger"
        );

        println!("[email] building Message... to={email} subject={subject}");
        let email_msg = Message::builder()
            .from(from_addr.parse().map_err(|e| {
                let msg = format!("Invalid FROM address: {e}");
                println!("[email][error] {msg}");
                msg
            })?)
            .to(email.parse().map_err(|e| {
                let msg = format!("Invalid TO address: {e}");
                println!("[email][error] {msg}");
                msg
            })?)
            .subject(subject)
            .body(body)
            .map_err(|e| {
                let msg = format!("Failed to build email: {e}");
                println!("[email][error] {msg}");
                msg
            })?;

        println!("[email] creating SMTP credentials");
        let creds = Credentials::new(smtp_user.clone(), smtp_pass);

        let smtp_port: Option<u16> = env::var("SMTP_PORT").ok().and_then(|s| s.parse().ok());
        if let Some(port) = smtp_port { println!("[email] SMTP_PORT={port}"); } else { println!("[email] SMTP_PORT=<default>"); }
        let port = smtp_port.unwrap_or(587);
        let socket_spec = format!("{smtp_host}:{port}");
        println!("[email] preflight: resolving {socket_spec}");
        match socket_spec.to_socket_addrs() {
            Ok(addrs) => {
                let mut any_ok = false;
                for addr in addrs {
                    println!("[email] preflight: trying TCP connect to {addr}");
                    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                        Ok(_) => {
                            println!("[email] preflight: TCP connect OK to {addr}");
                            any_ok = true;
                            break;
                        }
                        Err(e) => {
                            println!("[email][warn] preflight: TCP connect failed to {addr}: {e}");
                        }
                    }
                }
                if !any_ok {
                    let msg = format!("Network cannot reach {socket_spec} (TCP connect failed). Check firewall/VPN/ISP or try a different SMTP_PORT (e.g., 465). ");
                    println!("[email][error] {msg}");
                    return Err(msg);
                }
            }
            Err(e) => {
                let msg = format!("DNS resolve failed for {socket_spec}: {e}");
                println!("[email][error] {msg}");
                return Err(msg);
            }
        }

        println!("[email] building SmtpTransport relay={smtp_host}");
        let mut builder = SmtpTransport::relay(&smtp_host)
            .map_err(|e| {
                let msg = format!("Failed to create SMTP relay: {e}");
                println!("[email][error] {msg}");
                msg
            })?
            .credentials(creds)
            .timeout(Some(Duration::from_secs(15)));

        if let Some(port) = smtp_port {
            builder = builder.port(port);
        }

        let mailer = builder.build();
        println!("[email] transport built. attempting to send...");

        let send_started = Instant::now();
        let result = mailer.send(&email_msg);
        let send_elapsed = send_started.elapsed();
        println!("[email] send() returned in {:?}", send_elapsed);

        match result {
            Ok(res) => {
                println!("[email] send OK: {:?}", res);
                println!("[email] total elapsed: {:?}", started.elapsed());
                Ok(())
            }
            Err(e) => {
                let msg = format!("Failed to send email: {e}");
                println!("[email][error] {msg}");
                Err(msg)
            }
        }
    }

    fn setup_theme(&mut self, ctx: &egui::Context) {
        if self.theme_inited {
            return;
        }
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = egui::Color32::from_rgb(18, 22, 35);
        visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(30, 37, 55);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(60, 94, 150);
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(45, 60, 90);
        visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(230, 235, 245);
        ctx.set_visuals(visuals);
        self.theme_inited = true;
    }

    fn reload_dialog(&mut self) {
        println!("[chat] reload_dialog invoked");
        let Some(user) = &self.current_user else {
            println!("[chat] reload_dialog early-return: no current_user");
            self.status = "Please log in first".to_string();
            self.status_is_error = false;
            return;
        };
        println!("[chat] current_user={} peer_email='{}'", user.email, self.peer_email);
        if self.peer_email.trim().is_empty() {
            println!("[chat] reload_dialog early-return: peer_email empty");
            self.status = "Select a chat partner (email)".to_string();
            self.status_is_error = false;
            return;
        }
        println!("[chat] calling services::messages::get_dialog(...)");
        match messages::get_dialog(&self.conn, user.email.as_str(), self.peer_email.as_str()) {
            Ok(list) => {
                println!("[chat] get_dialog OK: {} message(s) returned", list.len());
                self.messages = list
                    .into_iter()
                    .map(|m| UiMessage {
                        id: m.id,
                        from: m.sender_email.clone(),
                        text: m.body(),
                        created_at: m.created_at.clone(),
                        is_read: m.is_read,
                    })
                    .collect();
                if let Some(first) = self.messages.first() {
                    println!("[chat] first message: from={} at={} text_len={}", first.from, first.created_at, first.text.len());
                } else {
                    println!("[chat] no messages in dialog");
                }
                let mut unread = 0usize;
                for m in &self.messages {
                    if m.from != user.email && !m.is_read {
                        unread += 1;
                        let _ = messages::mark_as_read(&self.conn, m.id);
                    }
                }
                self.unread_count = unread;
                self.unread_popup_visible = false;
                self.refresh_chat_list();
                if self.messages.is_empty() {
                    self.status = format!("No messages yet with {} — start typing below and press Send", self.peer_email);
                } else {
                    self.status = format!("Chat with {}", self.peer_email);
                }
                self.status_is_error = false;
            }
            Err(e) => {
                println!("[chat][error] get_dialog failed: {}", e);
                self.status = format!("Failed to load chat: {e}");
                self.status_is_error = true;
            }
        }
    }

    fn send_message(&mut self) {
        let Some(user) = &self.current_user else {
            self.status = "Please log in first".to_string();
            self.status_is_error = false;
            return;
        };
        if self.peer_email.trim().is_empty() {
            self.status = "Select a chat partner (email)".to_string();
            self.status_is_error = false;
            return;
        }
        if self.new_message_text.trim().is_empty() && self.selected_file.is_none() {
            return;
        }
        let mut text = self.new_message_text.clone();
        let mut attached_any = false;
        if let Some(path) = &self.selected_file {
            let filename = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".to_string());
            let target_dir = Self::attachments_dir();
            let ts = Local::now().format("%Y%m%d_%H%M%S");
            let target_path = target_dir.join(format!("{}_{}", ts, filename));
            let _ = std::fs::copy(path, &target_path);
            let ext = path.extension().and_then(|e| e.to_str()).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
            let is_image = matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp");
            let tag = if is_image { "image" } else { "file" };
            if !text.is_empty() { text.push(' '); }
            text.push_str(&format!("[{}:{}]", tag, target_path.to_string_lossy()));
            attached_any = true;
        }
        if text.trim().is_empty() && attached_any {
        }
        match messages::send_message(
            &self.conn,
            user.email.as_str(),
            self.peer_email.as_str(),
            text.as_str(),
        ) {
            Ok(()) => {
                self.new_message_text.clear();
                self.selected_file = None;
                self.selected_file_label.clear();
                self.reload_dialog();
            }
            Err(e) => {
                self.status = format!("Failed to send message: {e}");
                self.status_is_error = true;
            }
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.setup_theme(ctx);
        if self.current_user.is_some() {
            if self.chatlist_last_refresh.elapsed() >= self.chatlist_refresh_every {
                self.refresh_chat_list();
                self.chatlist_last_refresh = Instant::now();
            }
        }
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.heading("Morbityx Messenger");
            if !self.status.is_empty() {
                if self.status_is_error {
                    ui.colored_label(egui::Color32::RED, self.status.clone());
                } else {
                    ui.label(self.status.clone());
                }
            }
            if self.current_user.is_some() {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Search / chat with:");
                    let resp = ui.add_sized(
                        egui::vec2(300.0, 24.0),
                        egui::TextEdit::singleline(&mut self.peer_email).hint_text("user@example.com"),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if Self::is_valid_email(&self.peer_email) {
                            self.reload_dialog();
                        } else {
                            self.status = "Enter a valid email like user@example.com".to_string();
                            self.status_is_error = true;
                        }
                    }
                    let email_ok = Self::is_valid_email(&self.peer_email);
                    if ui.add_enabled(email_ok, egui::Button::new("Open chat")).clicked() {
                        self.reload_dialog();
                    }
                });
            }
        });

        egui::SidePanel::left("left_panel")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.heading("Account");
                if let Some(user) = self.current_user.clone() {
                    let user_email = user.email.clone();
                    let user_display = user.display_name.clone();
                    ui.horizontal(|ui| {
                        let color = egui::Color32::from_rgb(60, 94, 150);
                        let resp = self.draw_avatar(ctx, ui, &user_email, 28.0, color);
                        if resp.clicked() { self.show_about_popup = !self.show_about_popup; }
                        ui.vertical(|ui| {
                            ui.label(format!("Logged in as: {}", user_display));
                            ui.label(format!("<{}>", user_email));
                        });
                    });
                    if self.show_about_popup {
                        ui.add_space(4.0);
                        ui.group(|ui| {
                            ui.label("About:");
                            if self.about_edit.trim().is_empty() {
                                ui.weak("(empty)");
                            } else {
                                ui.label(self.about_edit.clone());
                            }
                        });
                    }
                    if ui.button("Log out").clicked() {
                        self.current_user = None;
                        self.messages.clear();
                        self.peer_email.clear();
                        self.chat_list.clear();
                        self.status = "Logged out successfully".to_string();
                        self.status_is_error = false;
                        self.show_about_popup = false;
                        self.show_peer_about = false;
                        self.peer_about_text.clear();
                    }
                    ui.separator();
                    ui.collapsing("Profile", |ui| {
                        if let Some(u) = self.current_user.clone() {
                            let email = u.email.clone();
                            ui.horizontal(|ui| {
                                ui.label("Avatar:");
                                if ui.button("Choose...").clicked() {
                                    if let Some(path) = FileDialog::new().add_filter("Images", &["png", "jpg", "jpeg", "webp", "bmp", "gif"]).pick_file() {
                                        self.avatar_path = Some(path.clone());
                                        Self::save_avatar_for(&email, Some(&path));
                                        self.purge_avatar_cache_for(&email);
                                    }
                                }
                                if let Some(p) = &self.avatar_path { ui.label(p.file_name().unwrap_or_default().to_string_lossy()); }
                                if self.avatar_path.is_some() && ui.small_button("Clear").clicked() {
                                    self.avatar_path = None;
                                    Self::save_avatar_for(&email, None);
                                    self.purge_avatar_cache_for(&email);
                                }
                            });
                            ui.label("About me:");
                            ui.text_edit_multiline(&mut self.about_edit);
                            if ui.button("Save profile").clicked() {
                                if let Err(e) = services::auth::update_about(&self.conn, &email, &self.about_edit) {
                                    self.status = format!("Failed to save profile: {}", e);
                                    self.status_is_error = true;
                                } else {
                                    self.status = "Profile saved".to_string();
                                    self.status_is_error = false;
                                }
                            }
                        }
                    });
                } else {
                    ui.collapsing("Login", |ui| {
                        ui.label("Email");
                        ui.text_edit_singleline(&mut self.login_email);
                        ui.label("Password");
                        ui.add(egui::TextEdit::singleline(&mut self.login_password).password(true));
                        ui.horizontal(|ui| {
                            if ui.small_button("Forgot password?").clicked() {
                                self.show_reset_dialog = true;
                                self.reset_email = self.login_email.clone();
                                self.reset_code = None;
                                self.reset_code_input.clear();
                                self.reset_new_password.clear();
                                self.status.clear();
                                self.status_is_error = false;
                            }
                        });
                        if ui.button("Log in").clicked() {
                            println!("[login] click; email='{}'", self.login_email);
                            match auth::login_user(
                                &self.conn,
                                self.login_email.as_str(),
                                self.login_password.as_str(),
                            ) {
                                Ok(Some(user)) => {
                                    println!("[login] success: user='{}'", user.email);
                                    self.status = format!("Login successful: {}", user.display_name);
                                    self.status_is_error = false;
                                    self.current_user = Some(user);
                                    if let Some(u) = self.current_user.clone() {
                                        let email = u.email.clone();
                                        let about = u.about.clone();
                                        self.avatar_path = Self::load_avatar_for(&email);
                                        self.purge_avatar_cache_for(&email);
                                        self.about_edit = about;
                                        self.show_about_popup = false;
                                    }
                                    self.refresh_chat_list();
                                }
                                Ok(None) => {
                                    println!("[login] invalid credentials");
                                    self.status = "Invalid email or password".to_string();
                                    self.status_is_error = true;
                                }
                                Err(e) => {
                                    println!("[login][error] {}", e);
                                    self.status = format!("Login error: {e}");
                                    self.status_is_error = true;
                                }
                            }
                        }
                    });

                    ui.separator();

                    ui.collapsing("Register", |ui| {
                        ui.label("Email");
                        ui.text_edit_singleline(&mut self.reg_email);
                        ui.label("Display name");
                        ui.text_edit_singleline(&mut self.reg_display_name);
                        ui.label("Password");
                        ui.add(egui::TextEdit::singleline(&mut self.reg_password).password(true));
                        ui.label("Confirm password");
                        ui.add(egui::TextEdit::singleline(&mut self.reg_password2).password(true));
                        if ui.button("Register").clicked() {
                            if self.reg_email.trim().is_empty() || self.reg_password.is_empty() || self.reg_display_name.trim().is_empty() {
                                self.status = "Please fill in Email, Display name and Password".to_string();
                                self.status_is_error = true;
                            } else if !Self::is_valid_email(&self.reg_email) {
                                self.status = "Invalid email format".to_string();
                                self.status_is_error = true;
                            } else if self.reg_password != self.reg_password2 {
                                self.status = "Passwords do not match".to_string();
                                self.status_is_error = true;
                            } else {
                                match auth::get_user_by_email(&self.conn, self.reg_email.as_str()) {
                                    Ok(Some(_existing)) => {
                                        println!("[register] email already registered: {}", self.reg_email);
                                        self.status = "This email is already registered. Please log in.".to_string();
                                        self.status_is_error = true;
                                        self.login_email = self.reg_email.clone();
                                        return;
                                    }
                                    Ok(None) => {
                                    }
                                    Err(e) => {
                                        println!("[register][error] lookup failed: {}", e);
                                        self.status = format!("Could not check email: {e}");
                                        self.status_is_error = true;
                                        return;
                                    }
                                }
                                let code = MyApp::generate_verification_code();
                                self.verification_code = Some(code.clone());
                                self.verification_input.clear();
                                self.pending_reg_email = Some(self.reg_email.clone());
                                self.pending_reg_password = Some(self.reg_password.clone());
                                self.pending_reg_display_name = Some(self.reg_display_name.clone());
                                self.status = "Sending verification email...".to_string();
                                println!("[ui] sending verification email to {}", self.reg_email);
                                match MyApp::send_verification_email(self.reg_email.as_str(), code.as_str()) {
                                    Ok(()) => {
                                        self.status = "Verification code sent. Check your email and enter the code below".to_string();
                                        self.status_is_error = false;
                                    }
                                    Err(err) => {
                                        self.status = format!("Failed to send verification email: {err}");
                                        self.status_is_error = true;
                                    }
                                }
                            }
                        }
                    });
                }

                if self.verification_code.is_some() && !self.email_verified {
                    ui.separator();
                    ui.heading("Email Verification");
                    ui.label("Enter the code from your email:");
                    ui.text_edit_singleline(&mut self.verification_input);
                    if ui.button("Verify").clicked() {
                        if let Some(code) = &self.verification_code {
                            if self.verification_input == *code {
                                println!("[verify] code match OK");
                                if let (Some(email), Some(password), Some(display_name)) = (
                                    self.pending_reg_email.clone(),
                                    self.pending_reg_password.clone(),
                                    self.pending_reg_display_name.clone(),
                                ) {
                                    match auth::get_user_by_email(&self.conn, email.as_str()) {
                                        Ok(Some(_)) => {
                                            println!("[verify] user already exists, skipping creation");
                                            self.email_verified = true;
                                            self.status = "Email verified. This email is already registered — please log in.".to_string();
                                            self.status_is_error = false;
                                            self.login_email = email.clone();
                                            self.pending_reg_email = None;
                                            self.pending_reg_password = None;
                                            self.pending_reg_display_name = None;
                                            self.verification_code = None;
                                        }
                                        Ok(None) => {
                                            println!("[verify] creating user email={}", email);
                                            match auth::register_user(
                                                &self.conn,
                                                email.as_str(),
                                                password.as_str(),
                                                display_name.as_str(),
                                            ) {
                                                Ok(()) => {
                                                    println!("[verify] user created successfully");
                                                    self.email_verified = true;
                                                    self.status = "Email verified and account created. You can now log in.".to_string();
                                                    self.status_is_error = false;
                                                    self.pending_reg_email = None;
                                                    self.pending_reg_password = None;
                                                    self.pending_reg_display_name = None;
                                                    self.verification_code = None;
                                                }
                                                Err(e) => {
                                                    println!("[verify][error] failed to create user: {}", e);
                                                    if e.to_string().contains("UNIQUE constraint failed") {
                                                        self.status = "Email verified. This email is already registered — please log in.".to_string();
                                                        self.status_is_error = false;
                                                        self.login_email = email.clone();
                                                        self.pending_reg_email = None;
                                                        self.pending_reg_password = None;
                                                        self.pending_reg_display_name = None;
                                                        self.verification_code = None;
                                                    } else {
                                                        self.status = format!("Email verified, but failed to create account: {e}");
                                                        self.status_is_error = true;
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            println!("[verify][error] lookup failed: {}", e);
                                            self.status = format!("Verified, but could not check existing user: {e}");
                                            self.status_is_error = true;
                                        }
                                    }
                                } else {
                                    println!("[verify][warn] pending registration data missing");
                                    self.status = "Verification succeeded, but registration data is missing. Please register again.".to_string();
                                    self.status_is_error = true;
                                    self.verification_code = None;
                                }
                            } else {
                                println!("[verify] code mismatch: expected={}, got={}", code, self.verification_input);
                                self.status = "Incorrect verification code".to_string();
                                self.status_is_error = true;
                            }
                        }
                    }
                    if ui.button("Cancel registration").clicked() {
                        if let Some(email) = &self.pending_reg_email {
                            let _ = self.conn.execute(
                                "DELETE FROM users WHERE email = ?1",
                                [&email.as_str()]
                            );
                        }
                        self.pending_reg_email = None;
                        self.pending_reg_password = None;
                        self.pending_reg_display_name = None;
                        self.verification_code = None;
                        self.verification_input.clear();
                        self.status = "Registration cancelled (any existing record was removed).".to_string();
                        self.status_is_error = false;
                    }
                }

                if self.show_reset_dialog {
                    ui.separator();
                    ui.heading("Reset password");
                    ui.label("Email");
                    ui.text_edit_singleline(&mut self.reset_email);
                    ui.horizontal(|ui| {
                        if ui.button("Send code").clicked() {
                            if !Self::is_valid_email(&self.reset_email) {
                                self.status = "Enter a valid email".to_string();
                                self.status_is_error = true;
                            } else if let Ok(Some(_u)) = services::auth::get_user_by_email(&self.conn, &self.reset_email) {
                                let code = MyApp::generate_verification_code();
                                self.reset_code = Some(code.clone());
                                self.reset_code_input.clear();
                                self.reset_new_password.clear();
                                match MyApp::send_verification_email(&self.reset_email, &code) {
                                    Ok(()) => { self.status = "Reset code sent. Check your email.".to_string(); self.status_is_error = false; }
                                    Err(e) => { self.status = format!("Failed to send code: {e}"); self.status_is_error = true; }
                                }
                            } else {
                                self.status = "No account with this email".to_string();
                                self.status_is_error = true;
                            }
                        }
                        if ui.button("Close").clicked() { self.show_reset_dialog = false; }
                    });
                    if self.reset_code.is_some() {
                        ui.label("Verification code");
                        ui.text_edit_singleline(&mut self.reset_code_input);
                        ui.label("New password");
                        ui.add(egui::TextEdit::singleline(&mut self.reset_new_password).password(true));
                        if ui.button("Set new password").clicked() {
                            if let Some(code) = &self.reset_code {
                                if self.reset_code_input == *code {
                                    match services::auth::update_password(&self.conn, &self.reset_email, &self.reset_new_password) {
                                        Ok(()) => {
                                            self.status = "Password updated. You can log in now.".to_string();
                                            self.status_is_error = false;
                                            self.show_reset_dialog = false;
                                            self.reset_code = None;
                                            self.reset_code_input.clear();
                                            self.reset_new_password.clear();
                                            self.login_email = self.reset_email.clone();
                                        }
                                        Err(e) => { self.status = format!("Failed to update password: {e}"); self.status_is_error = true; }
                                    }
                                } else {
                                    self.status = "Incorrect code".to_string();
                                    self.status_is_error = true;
                                }
                            }
                        }
                    }
                }

                ui.separator();
                ui.heading("Chats");
                if self.current_user.is_some() {
                    egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                        if self.chat_list.is_empty() { ui.label("No chats yet"); }
                        for (peer, unread) in self.chat_list.clone() {
                            ui.horizontal(|ui| {
                                let color = egui::Color32::from_rgb(60, 94, 150);
                                let _ = self.draw_avatar(ctx, ui, &peer, 22.0, color);
                                let mut label = peer.clone();
                                if unread > 0 { label.push_str(&format!("  ({} new)", unread)); }
                                if ui.selectable_label(self.peer_email == peer, label).clicked() {
                                    self.peer_email = peer.clone();
                                    self.reload_dialog();
                                }
                            });
                        }
                    });
                } else {
                    ui.label("Please log in to access chats.");
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let current_user_owned = self.current_user.clone();
            match (current_user_owned, self.peer_email.is_empty()) {
                (Some(user), false) => {
                    ui.horizontal(|ui| {
                        let color = egui::Color32::from_rgb(60, 94, 150);
                        let peer_email = self.peer_email.clone();
                        let resp = self.draw_avatar(ctx, ui, &peer_email, 30.0, color);
                        if resp.clicked() {
                            match services::auth::get_user_by_email(&self.conn, &peer_email) {
                                Ok(Some(u)) => { self.peer_about_text = u.about.clone(); }
                                _ => { self.peer_about_text.clear(); }
                            }
                            self.show_peer_about = true;
                        }
                        ui.heading(format!("Chat: {} ↔ {}", user.email, peer_email));
                    });
                    ui.separator();
                }
                (Some(user), true) => {
                    ui.heading(format!("Hi, {}! Choose a chat partner on the left.", user.display_name));
                    ui.separator();
                }
                (None, _) => {
                    ui.heading("Log in to start chatting");
                    ui.separator();
                }
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for msg in &self.messages {
                        let is_me = self
                            .current_user
                            .as_ref()
                            .map(|u| u.email == msg.from)
                            .unwrap_or(false);

                        let prefix = if is_me { "You: " } else { &msg.from };
                        ui.horizontal(|ui| {
                            let content = msg.text.as_str();
                            if let Some(rest) = content.strip_prefix("[image:") {
                                let p = rest.trim_end_matches(']');
                                ui.label(format!("{}  [{}]:", prefix, msg.created_at));
                                ui.horizontal(|ui| {
                                    ui.label("📷 Image");
                                    ui.hyperlink_to("Open", format!("file://{}", p));
                                });
                            } else if let Some(rest) = content.strip_prefix("[file:") {
                                let p = rest.trim_end_matches(']');
                                ui.label(format!("{}  [{}]:", prefix, msg.created_at));
                                if let Some(name) = std::path::Path::new(p).file_name() {
                                    ui.hyperlink_to(name.to_string_lossy(), format!("file://{}", p));
                                } else {
                                    ui.hyperlink_to("Open file", format!("file://{}", p));
                                }
                            } else {
                                ui.label(format!("{}  [{}]: {}", prefix, msg.created_at, content));
                            }
                        });
                        ui.add_space(4.0);
                    }
                });
            if self.show_peer_about {
                ui.add_space(6.0);
                ui.group(|ui| {
                    ui.heading("Profile");
                    ui.label(format!("Email: {}", self.peer_email));
                    ui.label("About:");
                    if self.peer_about_text.trim().is_empty() { ui.weak("(empty)"); } else { ui.label(self.peer_about_text.clone()); }
                    if ui.button("Close").clicked() { self.show_peer_about = false; }
                });
                ui.add_space(6.0);
            }
        });
        egui::TopBottomPanel::bottom("bottom_composer").show(ctx, |ui| {
            ui.add_space(4.0);
            if self.current_user.is_some() {
                ui.horizontal(|ui| {
                    let attach = ui.button("📎");
                    if attach.clicked() {
                        if let Some(path) = FileDialog::new().pick_file() {
                            self.selected_file_label = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "file".to_string());
                            self.selected_file = Some(path);
                            println!("[composer] file selected: {}", self.selected_file_label);
                        }
                    }
                    if !self.selected_file_label.is_empty() {
                        ui.label(format!("Attached: {}", self.selected_file_label));
                    }

                    let email_ok = Self::is_valid_email(&self.peer_email);
                    let avail_w = ui.available_width();
                    let text_w = (avail_w - 110.0).max(120.0);
                    let text_edit = egui::TextEdit::singleline(&mut self.new_message_text)
                        .hint_text(if email_ok { "Type a message..." } else { "Enter a valid partner email above to start" })
                        .desired_width(text_w);
                    let response = if email_ok { ui.add(text_edit) } else { ui.add_enabled(false, text_edit) };

                    let can_send_now = email_ok && (!self.new_message_text.trim().is_empty() || self.selected_file.is_some());

                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && can_send_now {
                        println!("[composer] Enter -> send");
                        self.send_message();
                    }

                    let send_btn = ui.add_enabled(can_send_now, egui::Button::new("Send"));
                    if send_btn.clicked() {
                        println!("[composer] Send clicked; text_len={}", self.new_message_text.len());
                        self.send_message();
                    }
                });
            } else {
                ui.horizontal(|ui| {
                    ui.add_enabled(false, egui::TextEdit::singleline(&mut self.new_message_text).hint_text("Log in to start chatting"));
                    ui.add_enabled(false, egui::Button::new("Send"));
                });
            }
            ui.add_space(4.0);
        });
    }
}

fn main() -> eframe::Result<()> {
    dotenvy::dotenv().ok();
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Morbityx Messenger",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::new()))),
    )
}