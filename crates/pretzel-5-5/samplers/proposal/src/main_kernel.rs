//! Output of one call of a sixteen-lane kernel.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub values: [i16; 16],
    pub ready: [u8; 16],
}
impl Output {
    pub fn new() -> Self {
        Self {
            values: [0; 16],
            ready: [0; 16],
        }
    }
}
