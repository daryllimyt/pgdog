//! Token cache that validates a token we received
//! from the client is actually valid with whatever mechanism
//! we authenticate to Postgres with.
//!
//! This is effectively passthrough auth for RDS IAM, Azure Workload Identity, etc.
//!

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use pgdog_config::ServerAuth;
use rand::seq::{IndexedRandom, IteratorRandom};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::sync::OnceCell;
use tracing::error;

use super::Error;
use crate::tasks;
use crate::{backend::pool::Connection, config::config};

/// Client token cache.
///
/// Tokens expire on lookup according to their provider's expected lifetime.
pub static AUTH_TOKEN_CACHE: Lazy<AuthTokenCache> = Lazy::new(|| {
    let cache = AuthTokenCache::default();
    let background = cache.clone();

    tasks::spawn("auth token cache", async move {
        let shutdown = tasks::shutdown_signal();
        tokio::select! {
            _ = background.eviction_loop() => {}
            _ = shutdown.cancelled() => {}
        }
    });

    cache
});

#[derive(Debug)]
struct Entry {
    // Hardcoded to documented expiration time in the future.
    expires_at: SystemTime,
    // Only the initializing caller validates; waiters share its result.
    validation: OnceCell<bool>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
struct KeyInner {
    user: String,
    database: String,
    token: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
struct Key {
    inner: Arc<KeyInner>,
}

impl Key {
    fn new(user: &str, database: &str, token: &str) -> Self {
        Self {
            inner: Arc::new(KeyInner {
                user: user.to_owned(),
                database: database.to_owned(),
                token: token.to_owned(),
            }),
        }
    }
}

impl Entry {
    fn expired(&self) -> bool {
        self.expires_at <= SystemTime::now()
    }

    fn valid(&self) -> bool {
        self.validation.get() == Some(&true) && !self.expired()
    }

    fn new(expires_at: SystemTime) -> Self {
        Self {
            expires_at,
            validation: OnceCell::new(),
        }
    }
}

#[derive(Debug, Default)]
struct Stats {
    evictions: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

#[derive(Debug, Default)]
struct CacheInner {
    keys: HashMap<Key, Arc<Entry>>,
    keys_ord: VecDeque<Key>,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthTokenCache {
    inner: Arc<Mutex<CacheInner>>,
    stats: Arc<Stats>,
}

impl Default for AuthTokenCache {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CacheInner::default())),
            stats: Arc::new(Stats::default()),
        }
    }
}

fn expires_at(server_auth: ServerAuth) -> SystemTime {
    match server_auth {
        ServerAuth::RdsIam => crate::backend::auth::rds_iam::expires_at(),
        ServerAuth::AzureWorkloadIdentity => {
            crate::backend::auth::azure_workload_identity::hardcoded_expires_at()
        }
        _ => SystemTime::now() + Duration::from_hours(24), // Not expected, but used in tests.
    }
}

impl AuthTokenCache {
    /// Check a token against the external token provider, e.g., RDS.
    ///
    /// Shares initialization of each token so a connection storm from clients
    /// only creates one connection to the actual database.
    ///
    /// # Arguments
    ///
    /// - `user`: user name from users.toml
    /// - `database`: database name from pgdog.toml
    /// - `token`: the token we got from the client.
    ///
    pub(crate) async fn check(
        &self,
        user: &str,
        database: &str,
        token: &str,
    ) -> Result<bool, Error> {
        let key = Key::new(user, database, token);

        if self.get_and_check(&key) {
            return Ok(true);
        }

        // Get a random pool from any of the shards.
        //
        // Invariant: all shards have the same IAM permissions.
        //
        let conn = Connection::new(user, database, false)?;
        let shard = conn
            .cluster()?
            .shards()
            .choose(&mut rand::rng())
            .expect("to have at least one shard");
        let pool = shard
            .pool_iter()
            .choose(&mut rand::rng())
            .expect("to have at least one pool");
        let server_auth = pool.addr().server_auth;

        let entry = self.insert(&key, server_auth);

        // Validate until we get an auth error.
        // Connection errors are bubbled up.
        // Multiple clients can attempt validation if server
        // returns a non-auth error.
        if let Err(err) = entry
            .validation
            .get_or_try_init(|| async {
                let valid = pool.validate_token(token).await?;
                Ok::<bool, crate::backend::Error>(valid)
            })
            .await
        {
            error!("client token validation error: {}", err);
            return Ok(false);
        }

        Ok(entry.valid())
    }

    fn insert(&self, key: &Key, server_auth: ServerAuth) -> Arc<Entry> {
        let expires_at = expires_at(server_auth);
        let mut guard = self.inner.lock();

        match guard.keys.get(key) {
            Some(entry) if !entry.expired() => entry.clone(),
            // Clients can keep sending a token after its cache entry
            // expires (e.g., Azure tokens outlive the cache lifetime).
            // Replace the entry so the token is validated again.
            Some(_) => {
                let value = Arc::new(Entry::new(expires_at));
                // Key is already in keys_ord.
                guard.keys.insert(key.clone(), value.clone());
                value
            }
            None => {
                let value = Arc::new(Entry::new(expires_at));
                guard.keys.insert(key.clone(), value.clone());
                guard.keys_ord.push_back(key.clone());
                value
            }
        }
    }

    fn get_and_check(&self, key: &Key) -> bool {
        let ok = self
            .inner
            .lock()
            .keys
            .get(key)
            .map(|key| key.valid())
            .unwrap_or_default();

        if ok {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
        }

        ok
    }

    fn run_eviction(&self, capacity: usize) {
        let mut guard = self.inner.lock();

        while guard.keys_ord.len() > capacity {
            let key = guard.keys_ord.pop_front();
            if let Some(key) = key {
                guard.keys.remove(&key);
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    async fn eviction_loop(&self) {
        loop {
            tokio::time::sleep(Duration::from_millis(333)).await;
            let capacity = config().config.general.auth_token_cache_size as usize;
            self.run_eviction(capacity);
        }
    }

    /// Get stats from cache.
    pub(crate) fn stats(&self) -> TokenCacheStats {
        TokenCacheStats {
            entries: self.inner.lock().keys.len() as u64,
            evictions: self.stats.evictions.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
            hits: self.stats.hits.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TokenCacheStats {
    pub(crate) entries: u64,
    pub(crate) evictions: u64,
    pub(crate) misses: u64,
    pub(crate) hits: u64,
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_cache() {
        crate::logger();
        crate::config::load_test();
        let valid = AUTH_TOKEN_CACHE
            .check("pgdog", "pgdog", "pgdog")
            .await
            .unwrap();
        assert!(valid);

        let err = AUTH_TOKEN_CACHE
            .check("doesn't_exist", "pgdog", "pgdog")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Backend(_)));
    }

    /// Store an entry that has already expired, with the given validation result.
    async fn insert_expired(cache: &AuthTokenCache, key: &Key, valid: bool) {
        let entry = Arc::new(Entry::new(SystemTime::now() - Duration::from_secs(1)));
        entry.validation.get_or_init(|| async { valid }).await;

        let mut guard = cache.inner.lock();
        guard.keys.insert(key.clone(), entry);
        guard.keys_ord.push_back(key.clone());
    }

    #[tokio::test]
    async fn test_token_cache_expired_valid_entry_is_revalidated() {
        let cache = AuthTokenCache::default();
        let key = Key::new("user", "db", "token");
        insert_expired(&cache, &key, true).await;
        assert!(!cache.get_and_check(&key));

        let entry = cache.insert(&key, ServerAuth::Password);
        assert!(entry.validation.get().is_none());

        let mut validations = 0;
        entry
            .validation
            .get_or_init(|| async {
                validations += 1;
                true
            })
            .await;

        assert_eq!(validations, 1);
        assert!(entry.valid());
        assert!(cache.get_and_check(&key));
    }

    #[tokio::test]
    async fn test_token_cache_expired_entry_failed_recheck_is_rejected() {
        let cache = AuthTokenCache::default();
        let key = Key::new("user", "db", "token");
        insert_expired(&cache, &key, true).await;

        // The expired entry is replaced by a fresh, unvalidated one.
        let entry = cache.insert(&key, ServerAuth::Password);
        assert!(!entry.expired());
        assert!(entry.validation.get().is_none());

        let mut validations = 0;
        entry
            .validation
            .get_or_init(|| async {
                validations += 1;
                false
            })
            .await;

        assert_eq!(validations, 1);
        assert_eq!(entry.validation.get(), Some(&false));
        assert!(!entry.valid());
        assert!(!cache.get_and_check(&key));
    }

    #[tokio::test]
    async fn test_token_cache_concurrent_callers_share_replacement() {
        let cache = AuthTokenCache::default();
        let key = Key::new("user", "db", "token");
        insert_expired(&cache, &key, true).await;
        let expired = cache.inner.lock().keys.get(&key).cloned().unwrap();

        let barrier = std::sync::Barrier::new(2);
        let (a, b) = std::thread::scope(|s| {
            let insert = || {
                barrier.wait();
                cache.insert(&key, ServerAuth::Password)
            };
            let a = s.spawn(insert);
            let b = s.spawn(insert);
            (a.join().unwrap(), b.join().unwrap())
        });

        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &expired));
        assert!(a.validation.get().is_none());
    }

    #[tokio::test]
    async fn test_token_cache_replace_does_not_grow_keys_ord() {
        let cache = AuthTokenCache::default();
        let key = Key::new("user", "db", "token");
        insert_expired(&cache, &key, true).await;

        let replaced = cache.insert(&key, ServerAuth::Password);
        assert_eq!(cache.inner.lock().keys_ord.len(), 1);

        // A live entry is returned as-is.
        let live = cache.insert(&key, ServerAuth::Password);
        assert!(Arc::ptr_eq(&replaced, &live));

        let guard = cache.inner.lock();
        assert_eq!(guard.keys.len(), 1);
        assert_eq!(guard.keys_ord.len(), 1);
    }
}
