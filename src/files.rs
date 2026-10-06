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

/// Host-configured limits on the paths tool calls may use.
///
/// Installed for the duration of one call by `crate::execute_with`. Paths are
/// resolved against the current directory, `.` and `..` are applied
/// lexically, and the longest existing prefix is canonicalized, so symlinks
/// cannot escape the root. On Windows comparisons ignore case, as the
/// filesystem does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathPolicy {
    /// Every path must resolve inside this directory.
    pub root: Option<PathBuf>,
    /// Passphrase and PIN files must be here, and only the secret channel may read it.
    pub secrets: Option<PathBuf>,
    /// Exact paths tools may never read or write (the host audit log, its
    /// lock, the HTTP bearer token).
    pub protected: Vec<PathBuf>,
}

/// How a path is about to be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    /// A passphrase or PIN file.
    Secret,
}

thread_local! {
    static ACTIVE: std::cell::RefCell<Option<PathPolicy>> = const { std::cell::RefCell::new(None) };
}

/// Installs a policy for one call and restores the previous one when dropped.
pub struct PathScope(Option<PathPolicy>);
impl PathScope {
    pub fn install(policy: Option<PathPolicy>) -> Self {
        Self(ACTIVE.with(|active| active.replace(policy)))
    }
}
impl Drop for PathScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        ACTIVE.with(|active| active.replace(previous));
    }
}

impl PathPolicy {
    /// Canonicalize configured directories once, when the host starts.
    pub fn new(root: Option<&str>, secrets: Option<&str>) -> io::Result<Self> {
        let canonical = |p: Option<&str>| p.map(fs::canonicalize).transpose();
        Ok(Self {
            root: canonical(root)?,
            secrets: canonical(secrets)?,
            protected: Vec::new(),
        })
    }
    /// Reserve an exact path for the host.
    pub fn protect(&mut self, path: &str) -> io::Result<()> {
        self.protected.push(resolve(Path::new(path))?);
        Ok(())
    }
}

/// Absolute, lexically normalized path with its longest existing prefix canonicalized.
pub fn resolve(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut lexical = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                lexical.pop();
            }
            other => lexical.push(other.as_os_str()),
        }
    }
    let mut existing = lexical;
    let mut tail = Vec::new();
    while !existing.exists() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => break,
        }
    }
    let mut resolved = fs::canonicalize(&existing).unwrap_or(existing);
    for name in tail.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn comparable(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}
fn inside(path: &Path, dir: &Path) -> bool {
    let (path, dir) = (comparable(path), comparable(dir));
    path == dir
        || path
            .strip_prefix(&dir)
            .is_some_and(|rest| rest.starts_with(std::path::MAIN_SEPARATOR))
}

/// Check a tool-supplied path against the active host policy, if any.
pub fn guard(path: &str, access: Access) -> crate::error::Result<()> {
    let denied = |message: &str| crate::error::Error::new("policy_mismatch", message.to_owned());
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(policy) = active.as_ref() else {
            return Ok(());
        };
        let resolved = resolve(Path::new(path))?;
        // The host's secrets directory may lie outside the root.
        let host_secret = access == Access::Secret
            && policy
                .secrets
                .as_ref()
                .is_some_and(|d| inside(&resolved, d));
        if let Some(root) = &policy.root
            && !host_secret
            && !inside(&resolved, root)
        {
            return Err(denied("Path is outside the host root"));
        }
        if let Some(secrets) = &policy.secrets {
            let in_secrets = inside(&resolved, secrets);
            if access == Access::Secret && !in_secrets {
                return Err(denied(
                    "Passphrase and PIN files must be in the host secrets directory",
                ));
            }
            if access != Access::Secret && in_secrets {
                return Err(denied(
                    "The host secrets directory is readable only as passphrase or PIN files",
                ));
            }
        }
        if policy
            .protected
            .iter()
            .any(|p| comparable(p) == comparable(&resolved))
        {
            return Err(denied("Path is reserved by the host"));
        }
        Ok(())
    })
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
