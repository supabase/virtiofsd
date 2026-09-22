// SPDX-License-Identifier: BSD-3-Clause

use crate::oslib;
use crate::passthrough::util::einval;
use crate::soft_idmap::{HostGid, HostUid, Id};
use std::io;

pub struct UnixCredentials {
    uid: HostUid,
    gid: HostGid,
    sup_gids: Vec<HostGid>,
    keep_capability: bool,
}

impl UnixCredentials {
    pub fn new(uid: HostUid, gid: HostGid) -> Self {
        UnixCredentials {
            uid,
            gid,
            sup_gids: vec![],
            keep_capability: false,
        }
    }

    /// Set supplementary groups. Set `supported_extension` to `false` to signal that
    /// supplementary groups may be required, but the guest was not able to tell us which,
    /// so we have to rely on keeping the DAC_OVERRIDE capability.
    pub fn supplementary_gid(self, supported_extension: bool, sup_gids: Vec<HostGid>) -> Self {
        UnixCredentials {
            uid: self.uid,
            gid: self.gid,
            sup_gids,
            keep_capability: !supported_extension,
        }
    }

    /// Changes the effective uid/gid of the current thread to `val`.  Changes
    /// the thread's credentials back to root when the returned struct is dropped.
    pub fn set(self) -> io::Result<UnixCredentialsGuard> {
        // Safe: Always succesful
        let current_uid = HostUid::from(unsafe { libc::geteuid() });
        let current_gid = HostGid::from(unsafe { libc::getegid() });

        // Not to change UID/GID when they’re 0 (root) is legacy behavior that we’re afraid to
        // change
        let change_uid = !self.uid.is_root() && self.uid != current_uid;
        let change_gid = !self.gid.is_root() && self.gid != current_gid;

        // We have to change the gid before we change the uid because if we
        // change the uid first then we lose the capability to change the gid.
        // However changing back can happen in any order.
        let sup_guard = ScopedSupGids::new(&self.sup_gids)?;
        let gid_guard = change_gid
            .then(|| ScopedGid::new(current_gid, self.gid))
            .transpose()?;
        let uid_guard = change_uid
            .then(|| ScopedUid::new(current_uid, self.uid))
            .transpose()?;

        if change_uid && self.keep_capability {
            // Before kernel 6.3, we don't have access to process supplementary groups.
            // To work around this we can set the `DAC_OVERRIDE` in the effective set.
            // We are allowed to set the capability because we only change the effective
            // user ID, so we still have the 'DAC_OVERRIDE' in the permitted set.
            // After switching back to root the permitted set is copied to the effective set,
            // so no additional steps are required.
            if let Err(e) = crate::util::add_cap_to_eff("DAC_OVERRIDE") {
                warn!("failed to add 'DAC_OVERRIDE' to the effective set of capabilities: {e}");
            }
        }

        Ok(UnixCredentialsGuard {
            _uid: uid_guard,
            _gid: gid_guard,
            _sup_gids: sup_guard,
        })
    }
}

macro_rules! scoped_id {
    ($name:ident, $id_type:ty, $set_fn:path, $label:literal) => {
        struct $name($id_type);

        impl $name {
            fn new(current: $id_type, target: $id_type) -> io::Result<Self> {
                $set_fn(target)?;
                Ok($name(current))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                $set_fn(self.0).unwrap_or_else(|e| {
                    error!("failed to change {} back to {}: {e}", $label, self.0);
                });
            }
        }
    };
}

scoped_id!(ScopedUid, HostUid, oslib::seteffuid, "uid");
scoped_id!(ScopedGid, HostGid, oslib::seteffgid, "gid");

struct ScopedSupGids;

impl ScopedSupGids {
    fn new(gids: &[HostGid]) -> io::Result<Option<Self>> {
        if gids.is_empty() {
            return Ok(None);
        }
        oslib::setsupgroup(gids)?;
        Ok(Some(ScopedSupGids))
    }
}

impl Drop for ScopedSupGids {
    fn drop(&mut self) {
        oslib::dropsupgroups().unwrap_or_else(|e| {
            error!("failed to drop supplementary groups: {e}");
        });
    }
}

// Dropped in declaration order
pub struct UnixCredentialsGuard {
    _uid: Option<ScopedUid>,
    _gid: Option<ScopedGid>,
    _sup_gids: Option<ScopedSupGids>,
}

pub struct ScopedCaps {
    cap: capng::Capability,
}

impl ScopedCaps {
    fn new(cap_name: &str) -> io::Result<Option<Self>> {
        use capng::{Action, CUpdate, Set, Type};

        let cap = capng::name_to_capability(cap_name).map_err(|_| {
            let err = io::Error::last_os_error();
            error!("couldn't get the capability id for name {cap_name}: {err:?}");
            err
        })?;

        if capng::have_capability(Type::EFFECTIVE, cap) {
            let req = vec![CUpdate {
                action: Action::DROP,
                cap_type: Type::EFFECTIVE,
                capability: cap,
            }];
            capng::update(req).map_err(|e| {
                error!("couldn't drop {cap} capability: {e:?}");
                einval()
            })?;
            capng::apply(Set::CAPS).map_err(|e| {
                error!("couldn't apply capabilities after dropping {cap}: {e:?}");
                einval()
            })?;
            Ok(Some(Self { cap }))
        } else {
            Ok(None)
        }
    }
}

impl Drop for ScopedCaps {
    fn drop(&mut self) {
        use capng::{Action, CUpdate, Set, Type};

        let req = vec![CUpdate {
            action: Action::ADD,
            cap_type: Type::EFFECTIVE,
            capability: self.cap,
        }];

        if let Err(e) = capng::update(req) {
            panic!("couldn't restore {} capability: {:?}", self.cap, e);
        }
        if let Err(e) = capng::apply(Set::CAPS) {
            panic!(
                "couldn't apply capabilities after restoring {}: {:?}",
                self.cap, e
            );
        }
    }
}

pub fn drop_effective_cap(cap_name: &str) -> io::Result<Option<ScopedCaps>> {
    ScopedCaps::new(cap_name)
}
