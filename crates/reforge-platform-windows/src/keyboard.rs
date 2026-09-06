//! Windows keyboard-layout helpers used by terminal input handling.

use windows::Win32::UI::{
    Input::KeyboardAndMouse::{GetKeyboardLayout, VkKeyScanExW},
    WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId},
};

const VK_C: u8 = b'C';

/// Return whether a character came from the physical C key in the foreground layout.
///
/// Windows console input carries the translated character, so Ctrl+C can arrive as
/// `Ctrl+с` under a Cyrillic layout. The virtual-key translation preserves the
/// physical shortcut without treating every Ctrl-modified character as cancellation.
pub fn is_physical_c_key(character: char) -> bool {
    if character.eq_ignore_ascii_case(&'c') {
        return true;
    }
    let mut utf16 = [0u16; 2];
    let encoded = character.encode_utf16(&mut utf16);
    if encoded.len() != 1 {
        return false;
    }
    let foreground_thread = unsafe { GetWindowThreadProcessId(GetForegroundWindow(), None) };
    let layout = unsafe { GetKeyboardLayout(foreground_thread) };
    translated_virtual_key(unsafe { VkKeyScanExW(encoded[0], layout) }) == Some(VK_C)
}

fn translated_virtual_key(result: i16) -> Option<u8> {
    (result != -1).then_some((result as u16 & 0xff) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_key_translation_rejects_failure_and_ignores_shift_state() {
        assert_eq!(translated_virtual_key(-1), None);
        assert_eq!(translated_virtual_key(i16::from(VK_C)), Some(VK_C));
        assert_eq!(translated_virtual_key(0x0143), Some(VK_C));
    }
}
