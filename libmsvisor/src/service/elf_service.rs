//! `elf_service` use POSIX API `dlopen` to create service.
//! In the future, it will be **discarded**.

use std::{
    collections::{BTreeMap, HashSet},
    ffi::c_void,
    mem::{forget, transmute, MaybeUninit},
    sync::Arc,
    fs,
};

use anyhow::Ok;
use lazy_static::lazy_static;
use libloading::{Library, Symbol};

use log::info;
use ms_hostcall::{
    types::{DropHandlerFunc, IsolationID, MetricEvent, ServiceName},
    IsolationContext, SERVICE_HEAP_SIZE,
};
use nix::libc::{sleep, RTLD_DI_LMID};
use nix::libc;
use nix::sys::mman;
use thiserror::Error;
use nix::libc::{size_t, syscall, SYS_pkey_alloc, SYS_pkey_mprotect};

use crate::{
    isolation::handler::{find_host_call, panic_handler},
    logger,
    metric::SvcMetricBucket,
    GetHandlerFuncSybmol, RustMainFuncSybmol, SetHandlerFuncSybmol,
    mpk,
    utils,
};

use super::loader::Namespace;
use core::arch::asm;

use ms_hostcall::types::RustMainFunc;
use std::num::NonZeroUsize;

use core::result;

lazy_static! {
    static ref SHOULD_NOT_SET_CONTEXT: Arc<HashSet<ServiceName>> = Arc::from({
        let mut hs = HashSet::new();
        #[cfg(feature = "namespace")]
        {
            hs.insert("libc".to_owned());
        }
        hs.insert("stdio".to_owned());
        hs.insert("time".to_owned());
        hs
    });
}

#[test]
fn test_should_not_set_context() {
    assert!(
        SHOULD_NOT_SET_CONTEXT.contains("stdio"),
        "SHOULD_NOT_SET_CONTEXT do not have 'stdio'"
    )
}

#[repr(C, align(4096))]
struct ServiceHeap {
    heap: [u8; SERVICE_HEAP_SIZE],
}

pub struct ElfService {
    pub name: String,
    lib: Arc<Library>,
    metric: Arc<SvcMetricBucket>,
}

impl ElfService {
    pub fn new(name: &str, lib: Arc<Library>, metric: Arc<SvcMetricBucket>) -> Self {
        metric.mark(MetricEvent::SvcInit);
        logger::debug!("ELFService::new, name={name}");
        Self {
            name: name.to_string(),
            lib,
            metric,
        }
    }

    pub fn symbol<T>(&self, symbol: &str) -> Option<Symbol<T>> {
        unsafe { self.lib.get(symbol.as_bytes()) }.ok()
    }

    pub fn init(&self, _isol_id: IsolationID) -> anyhow::Result<()> {
        Ok(())
    }

    extern "C" fn invoke_elf_symbol(
        &self,
        rust_main: RustMainFuncSybmol,
        args: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        log::info!(
            "service_{} rust_main={:x} thread_name={}",
            self.name,
            (*rust_main) as usize,
            std::thread::current().name().unwrap()
        );
        let rust_main: RustMainFunc = unsafe { transmute(*rust_main as usize ) };
        self.metric.mark(MetricEvent::SvcRun);

        #[cfg(feature = "enable_mpk")] {
            // 为用户栈分配空间，设置为系统默认limit 8MB
            let user_stack = unsafe {
                mman::mmap_anonymous(
                    None,
                    NonZeroUsize::new(8 * 1024 * 1024).ok_or("zero user stack size?")?,
                    mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                    mman::MapFlags::MAP_PRIVATE | mman::MapFlags::MAP_STACK,
                )
                .map_err(|e| format!("mmap_anonymous failed: {:?}", e))?
            };
            let user_stack_top: u64 = unsafe {
                mman::mprotect(user_stack, 4 * 1024, mman::ProtFlags::PROT_NONE)
                .map_err(|e| format!("mprotect failed: {:?}", e))?;
                let user_stack_top = unsafe { user_stack.as_ptr().add(8 * 1024 * 1024) };
                user_stack_top as u64
            };

            let lib_name = "/home/cyc/mslibos/user/hello_world/target/debug/libhello_world.so";

            let maps_str = fs::read_to_string("/proc/self/maps").unwrap();
            let segments = utils::parse_memory_segments(&maps_str).unwrap();
            let needs = [lib_name.to_owned()];
            for segment in segments {
                if segment.clone().path.is_some_and(|seg| needs.contains(&seg)) {
                    println!("{:x?}", segment);
                    mpk::pkey_mprotect(segment.start_addr as *mut c_void, segment.length, segment.perm, 0x1).unwrap();
                }
            }

            mpk::pkey_mprotect(user_stack.as_ptr() as *mut c_void, 8 * 1024 * 1024, libc::PROT_READ | libc::PROT_WRITE, 0x1).unwrap();

            // 开启函数分区的权限
            mpk::pkey_set(0x1, 0); //.unwrap();
            // println!("pkru after open: {:x}", mpk::pkey_read());
            // 关闭非函数部分的权限
            // mpk::pkey_set(0, 3); //.unwrap();



            unsafe {
                // 把旧栈的 rsp 压入新栈，并修改 rsp 的值到新栈
                asm!(
                    "mov r11, {rust_main}",
                    "mov [{user_rsp}+8], rsp",
                    "mov rsp, {user_rsp}",
                    "mov eax, 0x55555553",
                    "xor rcx, rcx",
                    "mov rdx, rcx",
                    "wrpkru",
                    "call r11",
                    user_rsp = in(reg) (user_stack_top-16),
                    in("rdi") args,
                    rust_main = in(reg) rust_main,
                );

                // 复原 rsp 寄存器的值
                asm!("mov rsp, [rsp+8]");
                // 释放 protect
                asm!(
                    "wrpkru",
                    in("rax") 0x55555550,
                    in("rcx") 0,
                    in("rdx") 0,
                )
            };
        }

        #[cfg(not(feature = "enable_mpk"))] {
            unsafe { rust_main(args); }
        }

        self.metric.mark(MetricEvent::SvcEnd);

        logger::info!("{} complete.", self.name);
        // result.map_err(|e| {
        //     let err_msg = format!("function {} run failed: {}", self.name, e);
        //     // forget because String refer to heap of libos modules.
        //     forget(e);
        //     err_msg
        // })

        result::Result::Ok(())
    }

    pub fn run(&self, args: &BTreeMap<String, String>) -> Result<(), String> {
        let rust_main: RustMainFuncSybmol = self.symbol("main").ok_or("missing main?")?;
        self.invoke_elf_symbol(rust_main, args)
    }

    pub fn namespace(&self) -> Namespace {
        // The reason for using this hack, is same to `fn load_dynlib()`, that must
        // get `handle: *mut c_void` to call `dlinfo()`.
        let handle: usize = *unsafe { core::mem::transmute::<&Library, &usize>(self.lib.as_ref()) };
        let mut result: Namespace = Namespace::default();

        let info = &mut result as *mut Namespace as usize;
        unsafe { nix::libc::dlinfo(handle as *mut c_void, RTLD_DI_LMID, info as *mut c_void) };
        info!("service_{} belong to namespace: {}", self.name, result);
        result
    }
}

impl Drop for ElfService {
    fn drop(&mut self) {
        if let Some(drop_fn) = self.symbol::<DropHandlerFunc>("drop") {
            logger::info!("service {} will invoke drop symbol.", self.name);
            unsafe { drop_fn() }
        }
    }
}

#[derive(Error, Debug)]
enum ServiceInitError {
    #[error("set isol context failed")]
    SetIsolCtxErr,
    #[error("missing set_handler_addr?")]
    MissingSetCtx,
    #[error("missing get_handler_addr?")]
    MissingGetCtx,
    #[error("check isol ctx failed.")]
    CtxCheckFailed,
}

pub struct WithLibOSService {
    elf: ElfService,

    heap: Box<MaybeUninit<ServiceHeap>>,
}

impl WithLibOSService {
    pub fn new(name: &str, lib: Arc<Library>, metric: Arc<SvcMetricBucket>) -> Self {
        Self {
            elf: ElfService::new(name, lib, metric),
            heap: Box::new_uninit(),
        }
    }

    fn should_set_context(&self) -> bool {
        !SHOULD_NOT_SET_CONTEXT.contains(&self.elf.name.to_owned())
    }

    #[inline]
    pub fn name(&self) -> String {
        self.elf.name.clone()
    }

    pub fn init(&self, isol_id: IsolationID) -> anyhow::Result<()> {
        let heap_start = self.heap.as_ptr() as usize;
        let heap_range = (heap_start, heap_start + SERVICE_HEAP_SIZE);
        logger::debug!(
            "init for service_{}, isol_id={}, find_host_call_addr=0x{:x}, heap_range={:x?}",
            self.elf.name,
            isol_id,
            find_host_call as usize,
            heap_range
        );

        // If this is a common_service that does not dependent on IsolationContext,
        // then directly return. Because it is not a no_std elf, and not have
        // symbols `set_handler_addr` and `get_handler_addr`.
        if !self.should_set_context() {
            return Ok(());
        };

        let isol_ctx = IsolationContext {
            isol_id,
            find_handler: find_host_call as usize,
            panic_handler: panic_handler as usize,
            heap_range,
        };

        let set_handler: SetHandlerFuncSybmol = self
            .symbol("set_handler_addr")
            .ok_or(ServiceInitError::MissingSetCtx)?;

        logger::info!("start set_handler...");
        unsafe { set_handler(&isol_ctx) }.map_err(|_| ServiceInitError::SetIsolCtxErr)?;
        logger::info!("set_handler complete.");

        let get_handler: GetHandlerFuncSybmol = self
            .symbol("get_handler_addr")
            .ok_or(ServiceInitError::MissingGetCtx)?;

        logger::debug!(
            "service_{} get_hander addr=0x{:x}.",
            self.elf.name,
            *get_handler as usize
        );

        if unsafe { get_handler() } != find_host_call as usize {
            Err(ServiceInitError::CtxCheckFailed)?
        }

        // 为 Heap 设置 MPK 保护
        #[cfg(feature = "enable_mpk")] {
            let _ = mpk::pkey_alloc();
            /* unsafe { libc::syscall(SYS_pkey_alloc, 0, 0); }; */
            mpk::pkey_mprotect(
                heap_start as *mut c_void,
                SERVICE_HEAP_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                1
            ).unwrap();
        }

        Ok(())
    }

    pub fn symbol<T>(&self, symbol: &str) -> Option<Symbol<T>> {
        self.elf.symbol(symbol)
    }

    pub fn run(&self, args: &BTreeMap<String, String>) -> Result<(), String> {
        let rust_main: RustMainFuncSybmol = self.symbol("rust_main").ok_or("missing rust_main?")?;
        self.elf.invoke_elf_symbol(rust_main, args)
    }

    pub fn namespace(&self) -> Namespace {
        self.elf.namespace()
    }
}
