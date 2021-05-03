use std::env;
use std::path::PathBuf;

use gcrypt_src::Build;

fn main() {
    gpgrt_src::rerun_if_src_changed();
    gcrypt_src::rerun_if_src_changed();

    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().parse().unwrap();

    let gpgrt = {
        let build = gpgrt_src::Build::new();
        build.build();
        build.check();
        build.install()
    };

    let build = Build::new(gpgrt);
    build.build();
    build.check();
    let artifacts = build.install();
    artifacts.print_cargo_metadata();

    bindgen::builder()
        .header(artifacts.include_dir.join("gcrypt.h").display().to_string())
        .size_t_is_usize(true)
        .use_core()
        .default_enum_style(bindgen::EnumVariation::NewType { is_bitfield: true })
        .generate_comments(false)
        .allowlist_var("GCRY.*")
        .allowlist_var("gcry.*")
        .allowlist_type("GCRY.*")
        .allowlist_type("gcry.*")
        .allowlist_function("GCRY.*")
        .allowlist_function("gcry.*")
        .generate()
        .unwrap()
        .write_to_file(manifest_dir.join("src/ffi.rs"))
        .unwrap();
}
