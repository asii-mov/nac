use crate::{hash, ArtifactRef, Result};
use anyhow::{ensure, Context};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions, OpenOptionsExt},
};
use std::{
    io::{Read, Write},
    path::{Component, Path},
};

pub struct ArtifactStore {
    directory: Dir,
}

impl ArtifactStore {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            directory: private_directory(path)?,
        })
    }

    pub fn write(&self, bytes: &[u8], max_bytes: u64) -> Result<ArtifactRef> {
        ensure!(
            bytes.len() as u64 <= max_bytes,
            "artifact exceeds individual output limit"
        );
        let reference = ArtifactRef {
            sha256: hash(bytes),
            bytes: bytes.len().try_into()?,
        };
        let name = artifact_name(&reference)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW);
        let temporary = format!("upload-{}", uuid::Uuid::new_v4());
        let mut file = self.directory.open_with(&temporary, &options)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match self.directory.hard_link(&temporary, &self.directory, &name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.verify(&reference)?;
            }
            Err(error) => return Err(error.into()),
        }
        self.directory.remove_file(temporary)?;
        self.directory.try_clone()?.into_std_file().sync_all()?;
        Ok(reference)
    }

    pub fn verify(&self, reference: &ArtifactRef) -> Result<()> {
        let name = artifact_name(reference)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut file = self
            .directory
            .open_with(name, &options)
            .context("evidence is missing or unsafe")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() == reference.bytes,
            "evidence size or file type mismatch"
        );
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        ensure!(
            format!("{:x}", digest.finalize()) == reference.sha256,
            "evidence hash mismatch"
        );
        Ok(())
    }
}

fn artifact_name(reference: &ArtifactRef) -> Result<String> {
    ensure!(valid_hash(&reference.sha256), "malformed artifact hash");
    Ok(format!("evidence-{}", reference.sha256))
}

pub(crate) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn private_directory(path: &Path) -> Result<Dir> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut directory = Dir::open_ambient_dir("/", ambient_authority())?;
    let components: Vec<_> = absolute.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                if index == components.len() - 1 {
                    let mut builder = cap_std::fs::DirBuilder::new();
                    use cap_std::fs::DirBuilderExt;
                    builder.mode(0o700);
                    match directory.create_dir_with(name, &builder) {
                        Ok(()) => directory.try_clone()?.into_std_file().sync_all()?,
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut options = OpenOptions::new();
                options
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
                directory = Dir::from_std_file(directory.open_with(name, &options)?.into_std());
            }
            _ => anyhow::bail!("state directory requires a normal, no-follow path"),
        }
    }
    use cap_std::fs::PermissionsExt;
    let metadata = directory.dir_metadata()?;
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "state directory must be owner-only (0700)"
    );
    Ok(directory)
}
