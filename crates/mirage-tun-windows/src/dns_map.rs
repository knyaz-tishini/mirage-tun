use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_ENTRIES: usize = 8192;
const TTL: Duration = Duration::from_secs(300);

pub struct DnsMap {
    inner: Mutex<DnsMapInner>,
}

struct DnsMapInner {
    map: HashMap<IpAddr, (String, Instant)>,
    order: VecDeque<IpAddr>,
}

impl DnsMap {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DnsMapInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub fn insert(&self, ip: IpAddr, domain: String) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if inner.map.insert(ip, (domain, now)).is_none() {
            inner.order.push_back(ip);
        }
        // Evict expired + overflow
        while inner.order.len() > MAX_ENTRIES {
            if let Some(old_ip) = inner.order.pop_front() {
                inner.map.remove(&old_ip);
            }
        }
    }

    pub fn insert_many(&self, ips: &[IpAddr], domain: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        for &ip in ips {
            if inner.map.insert(ip, (domain.to_owned(), now)).is_none() {
                inner.order.push_back(ip);
            }
        }
        while inner.order.len() > MAX_ENTRIES {
            if let Some(old_ip) = inner.order.pop_front() {
                inner.map.remove(&old_ip);
            }
        }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((domain, inserted_at)) = inner.map.get(ip) {
            if inserted_at.elapsed() < TTL {
                return Some(domain.clone());
            }
        }
        None
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.map.clear();
        inner.order.clear();
    }

    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.map.values().filter(|(_, ts)| ts.elapsed() < TTL).count()
    }
}
