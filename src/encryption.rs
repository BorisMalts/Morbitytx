const SHIFT: i8 = 3;

pub fn encrypt(text: &str) -> String {
    shift_text(text, SHIFT)
}

pub fn decrypt(text: &str) -> String {
    shift_text(text, -SHIFT)
}

fn shift_text(text: &str, shift: i8) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let pos = c as u8 - base;
                let new_pos = (pos as i8 + shift).rem_euclid(26) as u8;
                (base + new_pos) as char
            } else {
                c
            }
        })
        .collect()
}