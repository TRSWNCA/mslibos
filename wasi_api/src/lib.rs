#![no_std]

extern crate alloc;
use alloc::{string::String, vec::Vec};
pub use tinywasm;
use tinywasm::{Extern, Imports};

mod data_buffer;
mod wasi;

pub fn set_wasi_args(id: usize, _args: Vec<String>) {
    wasi::set_wasi_state(id, _args);
}

pub fn import_all() -> tinywasm::Result<Imports> {
    let mut imports = Imports::new();

    imports
        .define(
            "env",
            "buffer_register",
            Extern::typed_func(data_buffer::buffer_register),
        )?
        .define(
            "env",
            "access_buffer",
            Extern::typed_func(data_buffer::access_buffer),
        )?
        .define(
            "wasi_snapshot_preview1",
            "args_get",
            Extern::typed_func(wasi::args_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "args_sizes_get",
            Extern::typed_func(wasi::args_sizes_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "clock_time_get",
            Extern::typed_func(wasi::clock_time_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "environ_get",
            Extern::typed_func(wasi::environ_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "environ_sizes_get",
            Extern::typed_func(wasi::environ_sizes_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_close",
            Extern::typed_func(wasi::fd_close),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_fdstat_get",
            Extern::typed_func(wasi::fd_fdstat_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_fdstat_set_flags",
            Extern::typed_func(wasi::fd_fdstat_set_flags),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_filestat_get",
            Extern::typed_func(wasi::fd_filestat_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_filestat_set_size",
            Extern::typed_func(wasi::fd_filestat_set_size),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_prestat_get",
            Extern::typed_func(wasi::fd_prestat_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_prestat_dir_name",
            Extern::typed_func(wasi::fd_prestat_dir_name),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_read",
            Extern::typed_func(wasi::fd_read),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_read",
            Extern::typed_func(wasi::fd_read),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_readdir",
            Extern::typed_func(wasi::fd_readdir),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_seek",
            Extern::typed_func(wasi::fd_seek),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_sync",
            Extern::typed_func(wasi::fd_sync),
        )?
        .define(
            "wasi_snapshot_preview1",
            "fd_write",
            Extern::typed_func(wasi::fd_write),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_create_directory",
            Extern::typed_func(wasi::path_create_directory),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_link",
            Extern::typed_func(wasi::path_link),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_open",
            Extern::typed_func(wasi::path_open),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_readlink",
            Extern::typed_func(wasi::path_readlink),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_filestat_get",
            Extern::typed_func(wasi::path_filestat_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_filestat_set_times",
            Extern::typed_func(wasi::path_filestat_set_times),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_remove_directory",
            Extern::typed_func(wasi::path_remove_directory),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_rename",
            Extern::typed_func(wasi::path_rename),
        )?
        .define(
            "wasi_snapshot_preview1",
            "path_unlink_file",
            Extern::typed_func(wasi::path_unlink_file),
        )?
        .define(
            "wasi_snapshot_preview1",
            "poll_oneoff",
            Extern::typed_func(wasi::poll_oneoff),
        )?
        .define(
            "wasi_snapshot_preview1",
            "proc_exit",
            Extern::typed_func(wasi::proc_exit),
        )?
        .define(
            "wasi_snapshot_preview1",
            "random_get",
            Extern::typed_func(wasi::random_get),
        )?
        .define(
            "wasi_snapshot_preview1",
            "sched_yield",
            Extern::typed_func(wasi::sched_yield),
        )?;

    Ok(imports)
}
