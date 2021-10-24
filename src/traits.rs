// Copy paritally from <corentinhenry@gmail.com> Corentin Henry in project:
//  https://github.com/little-dude/netlink/
//  which is licensed under MIT

pub trait Emitable {
    /// Return the length of the serialized data.
    fn buffer_len(&self) -> usize;

    /// Serialize this types and write the serialized data into the given
    /// buffer.
    ///
    /// # Panic
    ///
    /// This method panic if the buffer is not big enough. You **must** make
    /// sure the buffer is big enough before calling this method. You can use
    /// [`buffer_len()`](trait.Emitable.html#method.buffer_len) to check how big
    /// the storage needs to be.
    fn emit(&self, buffer: &mut [u8]);
}

impl<'a, T: Emitable> Emitable for &'a [T] {
    fn buffer_len(&self) -> usize {
        self.iter().fold(0, |acc, o| acc + o.buffer_len())
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut cur_len: usize = 0;
        for item in *self {
            item.emit(&mut buffer[cur_len..item.buffer_len()]);
            cur_len += item.buffer_len();
        }
    }
}
