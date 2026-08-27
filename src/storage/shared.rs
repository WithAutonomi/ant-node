//! Daemon-wide physical chunk storage with identity-scoped ownership leases.
//!
//! A chunk's bytes are content addressed and therefore safe to share. The
//! decision that a logical identity is responsible for those bytes is not
//! shared: it is represented by a durable `(identity, address)` lease. This
//! split lets pruning, repair and dynamic identity changes coordinate without
//! allowing one identity to delete data still required by another.

use super::{ChunkStore, LmdbStorage, LmdbStorageConfig, StorageStats, XorName};
use crate::ant_protocol::XORNAME_LEN;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use async_trait::async_trait;
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};
use saorsa_core::identity::PeerId;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;
use tokio_util::task::TaskTracker;

const LEASE_KEY_LEN: usize = 32 + XORNAME_LEN;
const LEASE_MAP_SIZE: usize = 512 * 1_024 * 1_024;

/// Configuration for one daemon-wide chunk store.
#[derive(Debug, Clone)]
pub struct SharedChunkStoreConfig {
    /// Stable daemon data directory. The lease catalogue is stored here.
    pub daemon_root: PathBuf,
    /// Physical chunk volumes. A blob is placed on exactly one preferred
    /// volume, while reads tolerate an old placement during rebalancing.
    pub volume_roots: Vec<PathBuf>,
    /// Verify content hashes when blobs are read.
    pub verify_on_read: bool,
    /// Optional per-volume LMDB map cap. Zero means automatic growth.
    pub max_map_size: usize,
    /// Free bytes preserved on every volume.
    pub disk_reserve: u64,
}

impl SharedChunkStoreConfig {
    /// Build a single-volume configuration rooted below the daemon directory.
    #[must_use]
    pub fn single_volume(daemon_root: PathBuf, disk_reserve: u64) -> Self {
        Self {
            volume_roots: vec![daemon_root.join("chunk-volumes").join("volume-0")],
            daemon_root,
            verify_on_read: true,
            max_map_size: 0,
            disk_reserve,
        }
    }
}

struct LeaseCatalog {
    env: Env,
    db: Database<Bytes, Bytes>,
    refs: Database<Bytes, Bytes>,
    tracker: TaskTracker,
}

impl LeaseCatalog {
    #[allow(unsafe_code)]
    async fn new(root: &Path) -> Result<Self> {
        let env_dir = root.join("chunk-leases.mdb");
        std::fs::create_dir_all(&env_dir).map_err(|error| {
            Error::Storage(format!("Failed to create shared lease directory: {error}"))
        })?;
        let open_dir = env_dir.clone();
        let (env, db, refs) = spawn_blocking(move || -> Result<_> {
            // SAFETY: only one SharedChunkStoreBase is created for a daemon
            // root, and it owns this environment for the process lifetime.
            let env = unsafe {
                EnvOpenOptions::new()
                    .map_size(LEASE_MAP_SIZE)
                    .max_dbs(2)
                    .open(&open_dir)
                    .map_err(|error| {
                        Error::Storage(format!("Failed to open shared lease catalogue: {error}"))
                    })?
            };
            let mut txn = env.write_txn().map_err(|error| {
                Error::Storage(format!(
                    "Failed to create shared lease transaction: {error}"
                ))
            })?;
            let db: Database<Bytes, Bytes> =
                env.create_database(&mut txn, None).map_err(|error| {
                    Error::Storage(format!("Failed to create shared lease database: {error}"))
                })?;
            let refs: Database<Bytes, Bytes> = env
                .create_database(&mut txn, Some("chunk_refs"))
                .map_err(|error| {
                    Error::Storage(format!(
                        "Failed to create shared reference database: {error}"
                    ))
                })?;

            // Rebuild the reverse count index from the authoritative lease
            // set on every open. This also upgrades catalogues created before
            // the reverse index existed and repairs an interrupted index write.
            refs.clear(&mut txn).map_err(|error| {
                Error::Storage(format!("Failed to reset shared reference index: {error}"))
            })?;
            let mut counts = HashMap::<XorName, u64>::new();
            {
                let iter = db.iter(&txn).map_err(|error| {
                    Error::Storage(format!("Failed to scan shared leases: {error}"))
                })?;
                for entry in iter {
                    let (key, _) = entry.map_err(|error| {
                        Error::Storage(format!("Failed to rebuild shared references: {error}"))
                    })?;
                    if key.len() == LEASE_KEY_LEN {
                        let mut address = [0_u8; XORNAME_LEN];
                        address.copy_from_slice(&key[32..]);
                        *counts.entry(address).or_default() += 1;
                    }
                }
            }
            for (address, count) in counts {
                let encoded_count = count.to_be_bytes();
                refs.put(&mut txn, address.as_ref(), encoded_count.as_ref())
                    .map_err(|error| {
                        Error::Storage(format!("Failed to rebuild shared reference: {error}"))
                    })?;
            }
            txn.commit().map_err(|error| {
                Error::Storage(format!("Failed to commit shared lease database: {error}"))
            })?;
            Ok((env, db, refs))
        })
        .await
        .map_err(|error| Error::Storage(format!("Shared lease init task failed: {error}")))??;
        info!(path = %env_dir.display(), "Opened daemon-wide chunk lease catalogue");
        Ok(Self {
            env,
            db,
            refs,
            tracker: TaskTracker::new(),
        })
    }

    fn encoded(owner: &PeerId, address: &XorName) -> [u8; LEASE_KEY_LEN] {
        let mut key = [0_u8; LEASE_KEY_LEN];
        key[..32].copy_from_slice(owner.as_bytes());
        key[32..].copy_from_slice(address);
        key
    }

    fn contains(&self, owner: &PeerId, address: &XorName) -> Result<bool> {
        let key = Self::encoded(owner, address);
        let txn = self.env.read_txn().map_err(|error| {
            Error::Storage(format!("Failed to read shared lease catalogue: {error}"))
        })?;
        self.db
            .get(&txn, &key)
            .map(|value| value.is_some())
            .map_err(|error| Error::Storage(format!("Failed to check shared lease: {error}")))
    }

    async fn insert(&self, owner: PeerId, address: XorName) -> Result<bool> {
        let env = self.env.clone();
        let db = self.db;
        let refs = self.refs;
        let key = Self::encoded(&owner, &address);
        self.tracker
            .spawn_blocking(move || -> Result<bool> {
                let mut txn = env.write_txn().map_err(|error| {
                    Error::Storage(format!("Failed to write shared lease catalogue: {error}"))
                })?;
                if db
                    .get(&txn, &key)
                    .map_err(|error| {
                        Error::Storage(format!("Failed to check shared lease: {error}"))
                    })?
                    .is_some()
                {
                    return Ok(false);
                }
                db.put(&mut txn, &key, &[]).map_err(|error| {
                    Error::Storage(format!("Failed to insert shared lease: {error}"))
                })?;
                let count = refs
                    .get(&txn, &address)
                    .map_err(|error| {
                        Error::Storage(format!("Failed to read shared reference: {error}"))
                    })?
                    .and_then(|bytes| bytes.try_into().ok())
                    .map_or(0, u64::from_be_bytes)
                    .saturating_add(1);
                refs.put(&mut txn, &address, &count.to_be_bytes())
                    .map_err(|error| {
                        Error::Storage(format!("Failed to update shared reference: {error}"))
                    })?;
                txn.commit().map_err(|error| {
                    Error::Storage(format!("Failed to commit shared lease: {error}"))
                })?;
                Ok(true)
            })
            .await
            .map_err(|error| Error::Storage(format!("Shared lease insert task failed: {error}")))?
    }

    async fn remove(&self, owner: PeerId, address: XorName) -> Result<bool> {
        let env = self.env.clone();
        let db = self.db;
        let refs = self.refs;
        let key = Self::encoded(&owner, &address);
        self.tracker
            .spawn_blocking(move || -> Result<bool> {
                let mut txn = env.write_txn().map_err(|error| {
                    Error::Storage(format!("Failed to write shared lease catalogue: {error}"))
                })?;
                let removed = db.delete(&mut txn, &key).map_err(|error| {
                    Error::Storage(format!("Failed to remove shared lease: {error}"))
                })?;
                if removed {
                    let count = refs
                        .get(&txn, &address)
                        .map_err(|error| {
                            Error::Storage(format!("Failed to read shared reference: {error}"))
                        })?
                        .and_then(|bytes| bytes.try_into().ok())
                        .map_or(1, u64::from_be_bytes);
                    if count <= 1 {
                        refs.delete(&mut txn, &address).map_err(|error| {
                            Error::Storage(format!("Failed to remove shared reference: {error}"))
                        })?;
                    } else {
                        refs.put(&mut txn, &address, &(count - 1).to_be_bytes())
                            .map_err(|error| {
                                Error::Storage(format!(
                                    "Failed to decrement shared reference: {error}"
                                ))
                            })?;
                    }
                }
                txn.commit().map_err(|error| {
                    Error::Storage(format!("Failed to commit shared lease removal: {error}"))
                })?;
                Ok(removed)
            })
            .await
            .map_err(|error| Error::Storage(format!("Shared lease remove task failed: {error}")))?
    }

    fn owner_keys(&self, owner: &PeerId) -> Result<Vec<XorName>> {
        let txn = self.env.read_txn().map_err(|error| {
            Error::Storage(format!("Failed to read shared lease catalogue: {error}"))
        })?;
        let iter = self
            .db
            .prefix_iter(&txn, owner.as_bytes())
            .map_err(|error| {
                Error::Storage(format!("Failed to iterate identity leases: {error}"))
            })?;
        let mut keys = Vec::new();
        for entry in iter {
            let (key, _) = entry
                .map_err(|error| Error::Storage(format!("Failed to read shared lease: {error}")))?;
            if key.len() == LEASE_KEY_LEN && &key[..32] == owner.as_bytes() {
                let mut address = [0_u8; XORNAME_LEN];
                address.copy_from_slice(&key[32..]);
                keys.push(address);
            }
        }
        Ok(keys)
    }

    fn has_any_owner(&self, address: &XorName) -> Result<bool> {
        let txn = self.env.read_txn().map_err(|error| {
            Error::Storage(format!("Failed to read shared lease catalogue: {error}"))
        })?;
        self.refs
            .get(&txn, address)
            .map(|count| count.is_some())
            .map_err(|error| {
                Error::Storage(format!("Failed to read shared reference count: {error}"))
            })
    }

    async fn wait_idle(&self) {
        self.tracker.close();
        self.tracker.wait().await;
        self.tracker.reopen();
    }
}

/// Physical storage and durable ownership state shared by a machine daemon.
pub struct SharedChunkStoreBase {
    volumes: Vec<Arc<LmdbStorage>>,
    leases: LeaseCatalog,
    /// Serialises the safe blob/lease ordering and coordinates prune/repair.
    mutation: Mutex<()>,
    /// Identities in their no-new-responsibility drain phase.
    retiring: parking_lot::RwLock<HashSet<PeerId>>,
}

impl SharedChunkStoreBase {
    /// Open the physical volumes and lease catalogue.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid volume configuration or if a volume or
    /// the lease catalogue cannot be opened.
    pub async fn new(config: SharedChunkStoreConfig) -> Result<Arc<Self>> {
        if config.volume_roots.is_empty() {
            return Err(Error::Config(
                "daemon shared storage requires at least one volume".to_string(),
            ));
        }
        let mut seen = HashSet::new();
        let mut volumes = Vec::with_capacity(config.volume_roots.len());
        for root in config.volume_roots {
            if !seen.insert(root.clone()) {
                return Err(Error::Config(format!(
                    "duplicate daemon storage volume: {}",
                    root.display()
                )));
            }
            let storage = LmdbStorage::new(LmdbStorageConfig {
                root_dir: root,
                verify_on_read: config.verify_on_read,
                max_map_size: config.max_map_size,
                disk_reserve: config.disk_reserve,
            })
            .await?;
            volumes.push(Arc::new(storage));
        }
        let leases = LeaseCatalog::new(&config.daemon_root).await?;
        Ok(Arc::new(Self {
            volumes,
            leases,
            mutation: Mutex::new(()),
            retiring: parking_lot::RwLock::new(HashSet::new()),
        }))
    }

    /// Create the identity-scoped logical view consumed by node business logic.
    #[must_use]
    pub fn view(self: &Arc<Self>, owner: PeerId, identity_root: PathBuf) -> Arc<SharedChunkStore> {
        Arc::new(SharedChunkStore {
            base: Arc::clone(self),
            owner,
            identity_root,
        })
    }

    fn preferred_volume(&self, address: &XorName) -> usize {
        self.volumes
            .iter()
            .enumerate()
            .max_by_key(|(_, volume)| {
                let mut input = Vec::with_capacity(XORNAME_LEN + 128);
                input.extend_from_slice(address);
                input.extend_from_slice(volume.root_dir().to_string_lossy().as_bytes());
                *blake3::hash(&input).as_bytes()
            })
            .map_or(0, |(index, _)| index)
    }

    fn physical_volume(&self, address: &XorName) -> Result<Option<usize>> {
        for (index, volume) in self.volumes.iter().enumerate() {
            if volume.exists(address)? {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    async fn put_physical(&self, address: &XorName, content: &[u8]) -> Result<()> {
        if self.physical_volume(address)?.is_some() {
            return Ok(());
        }
        let preferred = self.preferred_volume(address);
        let mut last_error = None;
        for offset in 0..self.volumes.len() {
            let volume = &self.volumes[(preferred + offset) % self.volumes.len()];
            if let Err(error) = volume.check_capacity() {
                last_error = Some(error);
                continue;
            }
            volume.put(address, content).await?;
            return Ok(());
        }
        Err(last_error.unwrap_or_else(|| {
            Error::Storage("no shared chunk volume can accept a write".to_string())
        }))
    }

    async fn get_physical(&self, address: &XorName, raw: bool) -> Result<Option<Vec<u8>>> {
        for volume in &self.volumes {
            let value = if raw {
                volume.get_raw(address).await?
            } else {
                volume.get(address).await?
            };
            if value.is_some() {
                return Ok(value);
            }
        }
        Ok(None)
    }

    /// Scan the physical catalogue once, irrespective of identity count.
    ///
    /// # Errors
    ///
    /// Returns an error when any configured volume cannot be scanned.
    pub async fn all_physical_keys(&self) -> Result<Vec<XorName>> {
        let mut keys = HashSet::new();
        for volume in &self.volumes {
            keys.extend(volume.all_keys().await?);
        }
        Ok(keys.into_iter().collect())
    }

    /// Copy blobs to their rendezvous-selected volume, then remove stale
    /// copies. This supports adding drives without changing identity stores.
    ///
    /// # Errors
    ///
    /// Returns an error when a blob cannot be read, copied, verified or
    /// removed.
    pub async fn rebalance_once(&self, limit: usize) -> Result<usize> {
        let _guard = self.mutation.lock().await;
        let mut moved = 0;
        for address in self.all_physical_keys().await? {
            if moved >= limit {
                break;
            }
            let preferred = self.preferred_volume(&address);
            if self.volumes[preferred].exists(&address)? {
                continue;
            }
            let Some(content) = self.get_physical(&address, true).await? else {
                continue;
            };
            if self.volumes[preferred].check_capacity().is_err() {
                continue;
            }
            self.volumes[preferred].put(&address, &content).await?;
            for (index, volume) in self.volumes.iter().enumerate() {
                if index != preferred {
                    volume.delete(&address).await?;
                }
            }
            moved += 1;
        }
        Ok(moved)
    }

    /// Import a legacy per-process store without deleting its source. The
    /// blob is verified by the shared store before the lease is committed.
    ///
    /// # Errors
    ///
    /// Returns an error when the legacy store cannot be read or shared state
    /// cannot be committed.
    pub async fn import_identity(
        self: &Arc<Self>,
        owner: PeerId,
        identity_root: PathBuf,
        legacy: &LmdbStorage,
    ) -> Result<u64> {
        let view = self.view(owner, identity_root);
        let mut imported = 0;
        for address in legacy.all_keys().await? {
            let Some(bytes) = legacy.get(&address).await? else {
                continue;
            };
            if view.put(&address, &bytes).await? {
                imported += 1;
            }
        }
        Ok(imported)
    }

    /// Remove physical blobs that have no durable identity owner. This is a
    /// crash-recovery operation: writes persist bytes before leases, and
    /// deletes remove leases before bytes so obligations are never lost.
    ///
    /// # Errors
    ///
    /// Returns an error when the catalogue cannot be scanned or an orphan
    /// cannot be removed.
    pub async fn reconcile_orphans(&self, limit: usize) -> Result<usize> {
        let _guard = self.mutation.lock().await;
        let mut removed = 0;
        for address in self.all_physical_keys().await? {
            if removed >= limit {
                break;
            }
            if !self.leases.has_any_owner(&address)? {
                for volume in &self.volumes {
                    volume.delete(&address).await?;
                }
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Move all storage obligations from a retiring identity to another local
    /// identity without touching physical bytes. The target lease is committed
    /// before the source lease is released, so a crash cannot lose ownership.
    ///
    /// # Errors
    ///
    /// Returns an error when either lease update cannot be committed.
    pub async fn transfer_identity_leases(&self, from: PeerId, to: PeerId) -> Result<u64> {
        if from == to {
            return Ok(0);
        }
        let _guard = self.mutation.lock().await;
        let keys = self.leases.owner_keys(&from)?;
        let mut transferred = 0;
        for address in keys {
            self.leases.insert(to, address).await?;
            if self.leases.remove(from, address).await? {
                transferred += 1;
            }
        }
        Ok(transferred)
    }

    /// Prevent an identity from acquiring new storage obligations before its
    /// existing leases are drained.
    pub fn begin_identity_drain(&self, owner: PeerId) {
        self.retiring.write().insert(owner);
    }
}

/// An identity's logical view over daemon-wide physical chunk storage.
pub struct SharedChunkStore {
    base: Arc<SharedChunkStoreBase>,
    owner: PeerId,
    identity_root: PathBuf,
}

impl SharedChunkStore {
    /// Identity that owns leases through this view.
    #[must_use]
    pub fn owner(&self) -> &PeerId {
        &self.owner
    }
}

#[async_trait]
impl ChunkStore for SharedChunkStore {
    async fn put(&self, address: &XorName, content: &[u8]) -> Result<bool> {
        if LmdbStorage::compute_address(content) != *address {
            return Err(Error::Storage(format!(
                "Content address mismatch for shared chunk {}",
                hex::encode(address)
            )));
        }
        let _guard = self.base.mutation.lock().await;
        if self.base.retiring.read().contains(&self.owner) {
            return Err(Error::Storage(format!(
                "identity {} is draining and cannot accept new chunks",
                self.owner
            )));
        }
        if self.base.leases.contains(&self.owner, address)? {
            return Ok(false);
        }
        // Crash-safe ordering: bytes before lease can leave only a harmless
        // orphan; the inverse could leave a durable obligation with no bytes.
        self.base.put_physical(address, content).await?;
        let inserted = self.base.leases.insert(self.owner, *address).await?;
        debug!(owner = %self.owner, address = %hex::encode(address), "Acquired shared chunk lease");
        Ok(inserted)
    }

    async fn get(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        if !self.exists(address)? {
            return Ok(None);
        }
        self.base.get_physical(address, false).await
    }

    fn exists(&self, address: &XorName) -> Result<bool> {
        self.base.leases.contains(&self.owner, address)
    }

    async fn delete(&self, address: &XorName) -> Result<bool> {
        let _guard = self.base.mutation.lock().await;
        // Crash-safe ordering: release our lease before deleting unowned bytes.
        if !self.base.leases.remove(self.owner, *address).await? {
            return Ok(false);
        }
        if !self.base.leases.has_any_owner(address)? {
            for volume in &self.base.volumes {
                volume.delete(address).await?;
            }
        }
        Ok(true)
    }

    fn stats(&self) -> StorageStats {
        let mut total = StorageStats::default();
        for volume in &self.base.volumes {
            let stats = volume.stats();
            total.chunks_stored += stats.chunks_stored;
            total.chunks_retrieved += stats.chunks_retrieved;
            total.bytes_stored += stats.bytes_stored;
            total.bytes_retrieved += stats.bytes_retrieved;
            total.duplicates += stats.duplicates;
            total.verification_failures += stats.verification_failures;
        }
        total.current_chunks = self.current_chunks().unwrap_or_else(|error| {
            warn!("Failed to count identity leases: {error}");
            0
        });
        total
    }

    fn current_chunks(&self) -> Result<u64> {
        Ok(self.base.leases.owner_keys(&self.owner)?.len() as u64)
    }

    fn root_dir(&self) -> &Path {
        &self.identity_root
    }

    async fn all_keys(&self) -> Result<Vec<XorName>> {
        self.base.leases.owner_keys(&self.owner)
    }

    async fn get_raw(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        if !self.exists(address)? {
            return Ok(None);
        }
        self.base.get_physical(address, true).await
    }

    fn check_capacity(&self) -> Result<()> {
        if self
            .base
            .volumes
            .iter()
            .any(|volume| volume.check_capacity().is_ok())
        {
            Ok(())
        } else {
            Err(Error::Storage(
                "all daemon chunk volumes are below their disk reserve".to_string(),
            ))
        }
    }

    async fn acquire_local(&self, address: &XorName) -> Result<bool> {
        let _guard = self.base.mutation.lock().await;
        if self.base.retiring.read().contains(&self.owner) {
            return Ok(false);
        }
        if self.base.leases.contains(&self.owner, address)? {
            return Ok(false);
        }
        if self.base.physical_volume(address)?.is_none() {
            return Ok(false);
        }
        self.base.leases.insert(self.owner, *address).await?;
        debug!(owner = %self.owner, address = %hex::encode(address), "Adopted existing local chunk without download");
        Ok(true)
    }

    async fn wait_idle(&self) {
        self.base.leases.wait_idle().await;
        for volume in &self.base.volumes {
            volume.wait_idle().await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn config(root: &Path, volumes: usize) -> SharedChunkStoreConfig {
        SharedChunkStoreConfig {
            daemon_root: root.join("daemon"),
            volume_roots: (0..volumes)
                .map(|index| root.join(format!("volume-{index}")))
                .collect(),
            verify_on_read: true,
            max_map_size: 16 * 1_024 * 1_024,
            disk_reserve: 0,
        }
    }

    #[tokio::test]
    async fn leases_deduplicate_bytes_and_coordinate_pruning() {
        let root = tempdir().expect("tempdir");
        let base = SharedChunkStoreBase::new(config(root.path(), 2))
            .await
            .expect("base");
        let one = base.view(PeerId::from_bytes([1; 32]), root.path().join("one"));
        let two = base.view(PeerId::from_bytes([2; 32]), root.path().join("two"));
        let bytes = b"shared bytes";
        let address = LmdbStorage::compute_address(bytes);

        assert!(one.put(&address, bytes).await.expect("put"));
        assert!(two.acquire_local(&address).await.expect("adopt"));
        assert_eq!(base.all_physical_keys().await.expect("keys"), vec![address]);
        assert!(one.delete(&address).await.expect("delete first lease"));
        assert_eq!(two.get(&address).await.expect("get"), Some(bytes.to_vec()));
        assert!(two.delete(&address).await.expect("delete final lease"));
        assert!(base.all_physical_keys().await.expect("keys").is_empty());
    }

    #[tokio::test]
    async fn imports_legacy_identity_without_removing_source() {
        let root = tempdir().expect("tempdir");
        let legacy = LmdbStorage::new(LmdbStorageConfig {
            root_dir: root.path().join("legacy"),
            verify_on_read: true,
            max_map_size: 16 * 1_024 * 1_024,
            disk_reserve: 0,
        })
        .await
        .expect("legacy");
        let bytes = b"legacy bytes";
        let address = LmdbStorage::compute_address(bytes);
        legacy.put(&address, bytes).await.expect("legacy put");
        let base = SharedChunkStoreBase::new(config(root.path(), 1))
            .await
            .expect("base");
        let owner = PeerId::from_bytes([3; 32]);

        assert_eq!(
            base.import_identity(owner, root.path().join("identity"), &legacy)
                .await
                .expect("import"),
            1
        );
        assert!(legacy.exists(&address).expect("source preserved"));
        assert!(base
            .view(owner, root.path().join("identity"))
            .exists(&address)
            .expect("lease"));
    }

    #[tokio::test]
    async fn rebalance_moves_blob_to_deterministic_preferred_volume() {
        let root = tempdir().expect("tempdir");
        let base = SharedChunkStoreBase::new(config(root.path(), 2))
            .await
            .expect("base");
        let bytes = b"misplaced bytes";
        let address = LmdbStorage::compute_address(bytes);
        let preferred = base.preferred_volume(&address);
        let wrong = (preferred + 1) % 2;
        base.volumes[wrong]
            .put(&address, bytes)
            .await
            .expect("put wrong volume");
        let view = base.view(PeerId::from_bytes([4; 32]), root.path().join("identity"));
        assert!(view.acquire_local(&address).await.expect("lease"));

        assert_eq!(base.rebalance_once(1).await.expect("rebalance"), 1);
        assert!(base.volumes[preferred].exists(&address).expect("preferred"));
        assert!(!base.volumes[wrong].exists(&address).expect("old removed"));
    }

    #[tokio::test]
    async fn identity_drain_transfers_lease_before_releasing_source() {
        let root = tempdir().expect("tempdir");
        let base = SharedChunkStoreBase::new(config(root.path(), 1))
            .await
            .expect("base");
        let from = PeerId::from_bytes([5; 32]);
        let to = PeerId::from_bytes([6; 32]);
        let source = base.view(from, root.path().join("source"));
        let bytes = b"drained bytes";
        let address = LmdbStorage::compute_address(bytes);
        source.put(&address, bytes).await.expect("put");
        base.begin_identity_drain(from);
        let refused_bytes = b"new responsibility";
        let refused_address = LmdbStorage::compute_address(refused_bytes);
        assert!(source.put(&refused_address, refused_bytes).await.is_err());

        assert_eq!(
            base.transfer_identity_leases(from, to)
                .await
                .expect("transfer"),
            1
        );
        assert!(!source.exists(&address).expect("source released"));
        assert_eq!(
            base.view(to, root.path().join("target"))
                .get(&address)
                .await
                .expect("target read"),
            Some(bytes.to_vec())
        );
    }

    #[tokio::test]
    async fn reverse_reference_index_rebuilds_across_restart() {
        let root = tempdir().expect("tempdir");
        let shared_config = config(root.path(), 1);
        let address = LmdbStorage::compute_address(b"restart bytes");
        {
            let base = SharedChunkStoreBase::new(shared_config.clone())
                .await
                .expect("base");
            let one = base.view(PeerId::from_bytes([7; 32]), root.path().join("one"));
            let two = base.view(PeerId::from_bytes([8; 32]), root.path().join("two"));
            one.put(&address, b"restart bytes").await.expect("put");
            two.acquire_local(&address).await.expect("second lease");
            one.wait_idle().await;
        }

        let reopened = SharedChunkStoreBase::new(shared_config)
            .await
            .expect("reopen");
        let one = reopened.view(PeerId::from_bytes([7; 32]), root.path().join("one"));
        let two = reopened.view(PeerId::from_bytes([8; 32]), root.path().join("two"));
        one.delete(&address).await.expect("release one");
        assert!(two.exists(&address).expect("second lease retained"));
        assert_eq!(
            two.get(&address).await.expect("physical retained"),
            Some(b"restart bytes".to_vec())
        );
    }
}
