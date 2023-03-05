use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    logger,
    service::{Service, ServiceLoader},
};

use ms_hostcall::{
    types::{HostWriteFunc, ServiceName},
    CommonHostCall, HostCallID, IsolationContext,
};

use lazy_static::lazy_static;

const TARGET_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target");

type IsolID = usize;
lazy_static! {
    pub static ref ISOL_TABLE: Mutex<HashMap<IsolID, Arc<Isolation>>> = Mutex::new(HashMap::new());
}

#[derive(Default)]
pub struct IsolationInner {
    modules: HashMap<ServiceName, Arc<Service>>,
}

impl IsolationInner {}

pub struct Isolation {
    id: IsolID,
    user_app: Arc<Service>,
    loader: ServiceLoader,

    inner: Mutex<IsolationInner>,
}

impl Isolation {
    pub fn new() -> Arc<Self> {
        let new_id = { ISOL_TABLE.lock().unwrap().len() };

        let loader = ServiceLoader::new()
            .register(
                "hello1".to_string(),
                PathBuf::from(TARGET_DIR)
                    .join("debug")
                    .join("libhello_world.so"),
            )
            .register(
                "fs".to_string(),
                PathBuf::from(TARGET_DIR)
                    .join("debug")
                    .join("libnative_fs.so"),
            );

        let user_app = loader.load_service(
            IsolationContext {
                isol_id: new_id,
                find_handler: find_host_call as usize,
            },
            &"hello1".to_string(),
        );

        let isol = Arc::from(Self {
            id: new_id,
            user_app,
            loader,
            inner: Mutex::new(IsolationInner::default()),
        });
        ISOL_TABLE
            .lock()
            .unwrap()
            .insert(isol.id, Arc::clone(&isol));
        isol
    }

    pub fn inner_access(&self) -> MutexGuard<'_, IsolationInner> {
        self.inner.lock().unwrap()
    }

    pub fn run(&self) {
        self.user_app.run();
        ISOL_TABLE.lock().unwrap().remove(&self.id);
    }
}

/// # Safety
/// This is unsafe because it it be a callback function used to lookup the address of
/// hostcall function symbols, and it should be only invocated by service modules.
///
pub unsafe extern "C" fn find_host_call(isol_id: usize, hc_id: HostCallID) -> usize {
    // let id = HostCallID::Common(CommonHostCall::Write);
    logger::debug!("find_host_call, isol_id={}, call_id={:?}", isol_id, hc_id);
    let isol = {
        let isol_table = ISOL_TABLE.lock().unwrap();
        Arc::clone(isol_table.get(&isol_id).unwrap())
    };

    let addr = match hc_id {
        HostCallID::Common(CommonHostCall::Write) => {
            let mut isol_inner = isol.inner_access();
            let fs_module = match isol_inner.modules.get("fs") {
                Some(fs) => Arc::clone(fs),
                None => {
                    let fs = isol.loader.load_service(
                        IsolationContext {
                            isol_id,
                            find_handler: find_host_call as usize,
                        },
                        &"fs".to_owned(),
                    );
                    isol_inner.modules.insert("fs".to_string(), Arc::clone(&fs));
                    fs
                }
            };
            let func: HostWriteFunc = *fs_module.symbol("host_write");
            func as usize
        }
        _ => todo!(),
    };
    log::debug!("host_write addr = 0x{:x}", addr);
    addr
}
