use crate::{artifacts::valid_hash, hash, require_version, ResearchBrief, Result};
use anyhow::{ensure, Context};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions, OpenOptionsExt},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;
const COMPATIBILITY: &str = "nac-source-review-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillLock {
    pub schema_version: u32,
    pub compatibility: String,
    pub registry_sha256: String,
    pub skills: BTreeMap<String, LockedSkill>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSkill {
    pub version: String,
    pub stages: Vec<String>,
    pub entry: String,
    pub dependencies: Vec<String>,
    pub files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenSkill {
    pub id: String,
    pub version: String,
    pub reason: String,
    pub files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenResearch {
    pub root: PathBuf,
    pub lock: SkillLock,
    pub lock_sha256: String,
    pub brief: ResearchBrief,
    pub stages: BTreeMap<String, String>,
    pub selected: BTreeMap<String, Vec<FrozenSkill>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub templates: BTreeMap<String, Vec<FrozenSkill>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub workflow: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedResearch {
    pub prompt: String,
    pub prompt_sha256: String,
    pub brief_sha256: String,
    pub lock_sha256: String,
    pub skills: Vec<FrozenSkill>,
}

impl FrozenResearch {
    pub fn resolve(
        root: &Path,
        brief: ResearchBrief,
        stages: BTreeMap<String, String>,
    ) -> Result<Self> {
        ensure!(root.is_absolute(), "skill root must be absolute");
        brief.render()?;
        let directory = open_root(root)?;
        let lock_bytes = read_file(&directory, "skills.lock.json")?;
        let lock: SkillLock = serde_json::from_slice(&lock_bytes)?;
        require_version(lock.schema_version)?;
        ensure!(
            lock.compatibility == COMPATIBILITY,
            "incompatible skill lock"
        );
        let registry_bytes = read_file(&directory, "skills.md")?;
        ensure!(
            hash(&registry_bytes) == lock.registry_sha256,
            "skill registry drift"
        );
        let registry = std::str::from_utf8(&registry_bytes)?;
        let registry_json = registry
            .split_once("```json\n")
            .context("skills.md needs its stage registry")?
            .1
            .split_once("\n```")
            .context("unterminated stage registry")?
            .0;
        let registry: BTreeMap<String, Vec<String>> = serde_json::from_str(registry_json)?;
        let mut templates = BTreeMap::new();
        for (stage, ids) in &registry {
            ensure!(!ids.is_empty(), "stage skills are empty");
            let mut seen = BTreeSet::new();
            let mut visiting = BTreeSet::new();
            let mut skills = Vec::new();
            for id in ids {
                resolve_skill(
                    id,
                    stage,
                    &lock,
                    &directory,
                    &mut seen,
                    &mut visiting,
                    &mut skills,
                )?;
            }
            templates.insert(stage.clone(), skills);
        }
        let selected = stages
            .iter()
            .map(|(task, stage)| {
                Ok((
                    task.clone(),
                    templates
                        .get(stage)
                        .context("stage has no registered skills")?
                        .clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(!selected.is_empty(), "research needs a stage assignment");
        Ok(Self {
            root: root.to_path_buf(),
            lock,
            lock_sha256: hash(&lock_bytes),
            brief,
            stages,
            selected,
            templates,
            workflow: false,
        })
    }

    pub fn verify(&self) -> Result<()> {
        let mut actual = Self::resolve(&self.root, self.brief.clone(), self.stages.clone())?;
        if self.templates.is_empty() {
            actual.templates.clear();
        }
        actual.workflow = self.workflow;
        if self.workflow {
            ensure!(
                self.stages.len() == 1 && self.stages.values().all(|stage| stage == "recon"),
                "workflow starts with exactly one recon root"
            );
            for stage in ["recon", "discovery", "validation", "synthesis"] {
                ensure!(
                    self.templates.contains_key(stage),
                    "workflow stage missing from original frozen lock: {stage}"
                );
            }
        }
        ensure!(
            serde_json::to_vec(&actual)? == serde_json::to_vec(self)?,
            "frozen research input drift"
        );
        Ok(())
    }

    pub fn prepare(&self, task: &str) -> Result<PreparedResearch> {
        self.verify()?;
        let skills = self
            .selected
            .get(task)
            .context("task has no selected skill")?
            .clone();
        self.render(skills)
    }

    pub fn prepare_stage(&self, stage: &str) -> Result<PreparedResearch> {
        self.verify()?;
        self.render(self.templates.get(stage).context("stage absent from original frozen templates; start a new campaign to adopt skills")?.clone())
    }

    fn render(&self, skills: Vec<FrozenSkill>) -> Result<PreparedResearch> {
        let brief = self.brief.render()?;
        let mut prompt = brief.text;
        for skill in &skills {
            prompt.push_str(&format!(
                "\nSelected bootstrap skill {}@{}: {}\n",
                skill.id, skill.version, skill.reason
            ));
            for (path, body) in &skill.files {
                prompt.push_str(&format!("\n--- frozen resource {path} ---\n{body}\n"));
            }
        }
        ensure!(
            prompt.len() as u64 <= MAX_INPUT_BYTES,
            "effective skill prompt exceeds input bound"
        );
        Ok(PreparedResearch {
            prompt_sha256: hash(prompt.as_bytes()),
            prompt,
            brief_sha256: brief.sha256,
            lock_sha256: self.lock_sha256.clone(),
            skills,
        })
    }
}

fn resolve_skill(
    id: &str,
    stage: &str,
    lock: &SkillLock,
    directory: &Dir,
    seen: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
    output: &mut Vec<FrozenSkill>,
) -> Result<()> {
    if seen.contains(id) {
        return Ok(());
    }
    ensure!(visiting.insert(id.to_string()), "cyclic skill dependency");
    let skill = lock
        .skills
        .get(id)
        .context("missing transitive helper skill")?;
    ensure!(
        skill.version == "1.0.0",
        "unsupported bootstrap skill version"
    );
    ensure!(
        skill
            .stages
            .iter()
            .any(|value| value == stage || value == "*"),
        "skill incompatible with stage"
    );
    ensure!(
        skill.files.contains_key(&skill.entry),
        "skill entry is not locked"
    );
    for dependency in &skill.dependencies {
        resolve_skill(dependency, stage, lock, directory, seen, visiting, output)?;
    }
    let mut files = BTreeMap::new();
    for (path, expected) in &skill.files {
        ensure!(valid_hash(expected), "invalid skill resource hash");
        let bytes = read_file(directory, path)?;
        ensure!(hash(&bytes) == *expected, "skill resource drift: {path}");
        files.insert(path.clone(), String::from_utf8(bytes)?);
    }
    output.push(FrozenSkill {
        id: id.to_string(),
        version: skill.version.clone(),
        reason: if skill.stages.iter().any(|value| value == "*") {
            format!("transitive evidence helper required by stage {stage}")
        } else {
            format!("registry selected stage procedure for {stage}")
        },
        files,
    });
    visiting.remove(id);
    seen.insert(id.to_string());
    Ok(())
}

fn open_root(path: &Path) -> Result<Dir> {
    let mut directory = Dir::open_ambient_dir("/", ambient_authority())?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let mut options = OpenOptions::new();
                options
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
                directory = Dir::from_std_file(directory.open_with(name, &options)?.into_std());
            }
            _ => anyhow::bail!("unsafe skill root"),
        }
    }
    Ok(directory)
}

fn read_file(directory: &Dir, path: &str) -> Result<Vec<u8>> {
    ensure!(
        !path.is_empty()
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !path.contains(['\\', '\0']),
        "unsafe skill resource path"
    );
    let mut directory = directory.try_clone()?;
    let components: Vec<_> = Path::new(path).components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            anyhow::bail!("unsafe skill resource path")
        };
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if index + 1 < components.len() {
                    libc::O_DIRECTORY
                } else {
                    0
                },
        );
        let mut file = directory.open_with(name, &options)?;
        if index + 1 == components.len() {
            ensure!(
                file.metadata()?.is_file() && file.metadata()?.len() <= MAX_INPUT_BYTES,
                "skill resource must be a bounded regular file"
            );
            let mut bytes = Vec::new();
            file.by_ref()
                .take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_INPUT_BYTES,
                "skill resource grew beyond bound"
            );
            return Ok(bytes);
        }
        directory = Dir::from_std_file(file.into_std());
    }
    anyhow::bail!("missing skill resource")
}
