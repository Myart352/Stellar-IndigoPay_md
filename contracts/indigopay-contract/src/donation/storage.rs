use soroban_sdk::{Address, Env, Vec};

use crate::donation::types::{DataKey, StealthDonation};

const PERSISTENT_TTL_THRESHOLD: u32 = 10_000;
const PERSISTENT_TTL_EXTEND_TO: u32 = 50_000;

fn extend_persistent_ttl(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND_TO);
}

pub fn get_stealth_counter(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&DataKey::StealthCounter)
        .unwrap_or(0u64)
}

pub fn set_stealth_counter(env: &Env, counter: u64) {
    env.storage()
        .instance()
        .set(&DataKey::StealthCounter, &counter);
}

pub fn set_stealth_donation(env: &Env, id: u64, donation: &StealthDonation) {
    let key = DataKey::StealthDonation(id);
    env.storage()
        .persistent()
        .set(&key, donation);
    extend_persistent_ttl(env, &key);
}

pub fn get_stealth_donation(env: &Env, id: u64) -> StealthDonation {
    let key = DataKey::StealthDonation(id);
    let donation: StealthDonation = env
        .storage()
        .persistent()
        .get(&key)
        .expect("stealth donation not found");
    extend_persistent_ttl(env, &key);
    donation
}

pub fn add_project_donation(env: &Env, project: &Address, donation_id: u64) {
    let key = DataKey::ProjectDonations(project.clone());
    let mut ids: Vec<u64> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));
    ids.push_back(donation_id);
    env.storage()
        .persistent()
        .set(&key, &ids);
    extend_persistent_ttl(env, &key);
}

pub fn get_project_donations(env: &Env, project: &Address) -> Vec<u64> {
    let key = DataKey::ProjectDonations(project.clone());
    let ids: Vec<u64> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Vec::new(env));
    if !ids.is_empty() {
        extend_persistent_ttl(env, &key);
    }
    ids
}
