//! Exclusive temporary files and atomic, no-clobber publication using std.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

fn name(parent: &Path) -> io::Result<PathBuf> {
    let mut random = [0; 16];
    crate::crypto::fill_random(&mut random)
        .map_err(|_| io::Error::other("Temporary path entropy unavailable"))?;
    Ok(parent.join(format!(".ipg-{}", crate::hex::encode(random))))
}

pub struct NamedTempFile {
    file: File,
    path: PathBuf,
}
impl NamedTempFile {
    pub fn new_in(parent: impl AsRef<Path>) -> io::Result<Self> {
        for _ in 0..16 {
            let path = name(parent.as_ref())?;
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => return Ok(Self { file, path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Temporary path collision limit",
        ))
    }
    pub fn as_file(&self) -> &File {
        &self.file
    }
    pub fn as_file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn persist_noclobber(self, target: impl AsRef<Path>) -> io::Result<()> {
        // Hard-link creation is atomic and cannot replace a destination, including
        // a dangling symlink. On unsupported filesystems fail, never copy/rename
        // to a partially visible or overwriteable destination as a fallback.
        self.file.sync_all()?;
        fs::hard_link(&self.path, target)?;
        Ok(())
    }
}
impl Write for NamedTempFile {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.file.write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Drop for NamedTempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Temporary directory used by repository test harnesses.
pub struct TempDir {
    path: PathBuf,
}
impl TempDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
pub fn tempdir() -> io::Result<TempDir> {
    for _ in 0..16 {
        let path = name(&std::env::temp_dir())?;
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => return Ok(TempDir { path }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Temporary directory collision limit",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_never_overwrites_and_failed_work_is_removed() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("output");
        let mut temp = NamedTempFile::new_in(dir.path()).unwrap();
        temp.write_all(b"authenticated").unwrap();
        assert!(!target.exists());
        temp.persist_noclobber(&target).unwrap();
        let mut replacement = NamedTempFile::new_in(dir.path()).unwrap();
        replacement.write_all(b"replacement").unwrap();
        assert_eq!(
            replacement.persist_noclobber(&target).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&target).unwrap(), b"authenticated");
        drop(NamedTempFile::new_in(dir.path()).unwrap());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn private_permissions_and_dangling_symlink_are_preserved() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempdir().unwrap();
        let temp = NamedTempFile::new_in(dir.path()).unwrap();
        assert_eq!(
            temp.file.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        let target = dir.path().join("output");
        symlink("missing", &target).unwrap();
        assert_eq!(
            temp.persist_noclobber(&target).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read_link(target).unwrap(), Path::new("missing"));
    }
}
