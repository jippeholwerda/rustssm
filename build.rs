fn main() {
    // Keep the module mapped across dlclose. TLS
    // destructors (std internals, rand's thread_rng) registered on host
    // threads point into module code; surviving them after dlclose depends
    // on glibc implementation details (__cxa_thread_atexit_impl pinning)
    // that musl and older glibc lack. p11-kit/NSS load PKCS#11 modules with
    // RTLD_NODELETE semantics for the same reason.
    println!("cargo:rustc-link-arg-cdylib=-Wl,-z,nodelete");

    generate::generate_bindings()
}

mod generate {
    use std::env;
    use std::path::PathBuf;

    use bindgen::callbacks::IntKind;
    use bindgen::callbacks::ParseCallbacks;

    #[derive(Debug)]
    pub struct CargoCallbacks;

    /// The PKCS#11 headers define their constants as untyped `#define`s.
    /// Bindgen would emit them all as bare integers, so nothing would stop a
    /// mechanism value being passed where an attribute type is expected. This
    /// callback assigns each constant the PKCS#11 typedef its prefix implies
    /// (`CKM_*` -> `CK_MECHANISM_TYPE`, `CKR_*` -> `CK_RV`, ...), giving the
    /// generated bindings distinct types. `CK_TRUE`/`CK_FALSE` are special-
    /// cased to `CK_BBOOL`.
    impl ParseCallbacks for CargoCallbacks {
        fn int_macro(&self, name: &str, _: i64) -> Option<IntKind> {
            let prefixes = [
                ("CK_", "CK_ULONG"),
                ("CKA_", "CK_ATTRIBUTE_TYPE"),
                ("CKC_", "CK_CERTIFICATE_TYPE"),
                ("CKD_", "CK_EC_KDF_TYPE"),
                ("CKF_", "CK_FLAGS"),
                ("CKG_MGF1_", "CK_RSA_PKCS_MGF_TYPE"),
                ("CKH_", "CK_HW_FEATURE_TYPE"),
                ("CKK_", "CK_KEY_TYPE"),
                ("CKM_", "CK_MECHANISM_TYPE"),
                ("CKN_", "CK_NOTIFICATION"),
                ("CKO_", "CK_OBJECT_CLASS"),
                ("CKP_", "CK_PROFILE_ID"),
                ("CKR_", "CK_RV"),
                ("CKS_", "CK_STATE"),
                ("CKU_", "CK_USER_TYPE"),
                ("CKZ_", "CK_RSA_PKCS_OAEP_SOURCE_TYPE"),
                ("CRYPTOKI_VERSION_", "CK_BYTE"),
            ];

            if ["CK_TRUE", "CK_FALSE"].contains(&name) {
                Some(IntKind::Custom {
                    name: "CK_BBOOL",
                    is_signed: false,
                })
            } else {
                let mut result = None;
                for (prefix, variable) in &prefixes {
                    if name.starts_with(prefix) {
                        result = Some(IntKind::Custom {
                            name: variable,
                            is_signed: false,
                        })
                    }
                }
                result
            }
        }
    }

    pub fn generate_bindings() {
        println!("cargo:rerun-if-changed=pkcs11.h");
        println!("cargo:rerun-if-changed=pkcs11t.h");
        println!("cargo:rerun-if-changed=pkcs11f.h");

        let bindings = bindgen::Builder::default()
            .header("pkcs11.h")
            // Bind only the PKCS#11 headers themselves (the argument is a
            // regex over the full file path); this keeps libc/stddef
            // internals out of the generated bindings.
            .allowlist_file(".*pkcs11[ft]?\\.h")
            .parse_callbacks(Box::new(CargoCallbacks))
            .generate_cstr(true)
            .derive_debug(true)
            .generate()
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
