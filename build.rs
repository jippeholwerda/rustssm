fn main() {
    generate::generate_bindings()
}

mod generate {
    use std::{env, path::PathBuf};

    use bindgen::{
        callbacks,
        callbacks::{IntKind, ParseCallbacks},
    };

    #[derive(Debug)]
    pub struct CargoCallbacks;

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
                Some(callbacks::IntKind::Custom {
                    name: "CK_BBOOL",
                    is_signed: false,
                })
            } else {
                let mut result = None;
                for (prefix, variable) in &prefixes {
                    if name.starts_with(prefix) {
                        result = Some(callbacks::IntKind::Custom {
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
        // Tell cargo to invalidate the built crate whenever the wrapper changes
        println!("cargo:rerun-if-changed=pkcs11.h");

        let bindings = bindgen::Builder::default()
            .header("pkcs11.h")
            .allowlist_function("C_GetFunctionList")
            // This is needed because no types will be generated if `allowlist_function` is used.
            // Unsure if this is a bug.
            .allowlist_type(".*")
            .allowlist_file(".*")
            .allowlist_var(".*")
            // .allowlist_file("pkcs11.h")
            // .allowlist_file("pkcs11t.h")
            // .allowlist_file("pkcs11f.h")
            .parse_callbacks(Box::new(CargoCallbacks))
            // .blocklist_type("max_align_t")
            // .generate_cstr(true)
            .derive_debug(true)
            // Finish the builder and generate the bindings.
            .generate()
            // Unwrap the Result and panic on failure.
            .expect("Unable to generate bindings");

        // Write the bindings to the $OUT_DIR/bindings.rs file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
