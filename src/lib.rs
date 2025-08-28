// Copyright (c) 2025 shashasha developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. All files in the project carrying such notice may not be copied,
// modified, or distributed except according to those terms.

//! # SHA3
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>
//!
//! ```
//! # use anyhow::Result;
//! # use shashasha::{b2h, bits, BitVec, Hasher, HasherBits, Lsb0, Sha3_224, SHA3_224_BYTES};
//! # pub fn main() -> Result<()> {
//! // Hash some byte data
//! let mut hasher = Sha3_224::new();
//! let mut result = [0u8; SHA3_224_BYTES];
//! hasher.update(b"Hello, world!");
//! hasher.finalize(&mut result)?;
//! assert_eq!(result.len(), SHA3_224_BYTES);
//! let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
//! assert_eq!("6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69", res);
//!
//! // ...or hash some bits
//! let mut hasher = Sha3_224::new();
//! let mut result = [0u8; SHA3_224_BYTES];
//! hasher.update_bits(bits![u8, Lsb0; 1, 0, 1]);
//! hasher.finalize(&mut result)?;
//! assert_eq!(result.len(), SHA3_224_BYTES);
//! let res = b2h(&BitVec::<u8, Lsb0>::from_slice(&result), false, false)?;
//! assert_eq!("d115e9e3c619f6180c234dba721b302ffe0992df07eeea47464923c0", res);
//!
//!
//! #     Ok(())
//! # }
//! ```
//!

// rustc lints
#![cfg_attr(
    all(feature = "unstable", nightly),
    feature(
        multiple_supertrait_upcastable,
        must_not_suspend,
        non_exhaustive_omitted_patterns_lint,
        rustdoc_missing_doc_code_examples,
        strict_provenance_lints,
        supertrait_item_shadowing,
        unqualified_local_imports,
    )
)]
#![cfg_attr(nightly, allow(single_use_lifetimes))]
#![cfg_attr(
    nightly,
    deny(
        aarch64_softfloat_neon,
        absolute_paths_not_starting_with_crate,
        ambiguous_glob_reexports,
        ambiguous_negative_literals,
        ambiguous_wide_pointer_comparisons,
        anonymous_parameters,
        array_into_iter,
        asm_sub_register,
        async_fn_in_trait,
        bad_asm_style,
        bare_trait_objects,
        boxed_slice_into_iter,
        break_with_label_and_loop,
        clashing_extern_declarations,
        closure_returning_async_block,
        coherence_leak_check,
        confusable_idents,
        const_evaluatable_unchecked,
        const_item_mutation,
        dangling_pointers_from_locals,
        dangling_pointers_from_temporaries,
        dead_code,
        dependency_on_unit_never_type_fallback,
        deprecated,
        deprecated_in_future,
        deprecated_safe_2024,
        deprecated_where_clause_location,
        deref_into_dyn_supertrait,
        deref_nullptr,
        double_negations,
        drop_bounds,
        dropping_copy_types,
        dropping_references,
        duplicate_macro_attributes,
        dyn_drop,
        edition_2024_expr_fragment_specifier,
        elided_lifetimes_in_paths,
        ellipsis_inclusive_range_patterns,
        explicit_outlives_requirements,
        exported_private_dependencies,
        ffi_unwind_calls,
        forbidden_lint_groups,
        forgetting_copy_types,
        forgetting_references,
        for_loops_over_fallibles,
        function_item_references,
        hidden_glob_reexports,
        if_let_rescope,
        impl_trait_overcaptures,
        impl_trait_redundant_captures,
        improper_ctypes,
        improper_ctypes_definitions,
        inline_no_sanitize,
        internal_features,
        invalid_from_utf8,
        invalid_macro_export_arguments,
        invalid_nan_comparisons,
        invalid_value,
        irrefutable_let_patterns,
        keyword_idents_2018,
        keyword_idents_2024,
        large_assignments,
        late_bound_lifetime_arguments,
        let_underscore_drop,
        macro_use_extern_crate,
        malformed_diagnostic_attributes,
        malformed_diagnostic_format_literals,
        map_unit_fn,
        meta_variable_misuse,
        mismatched_lifetime_syntaxes,
        misplaced_diagnostic_attributes,
        missing_abi,
        missing_copy_implementations,
        missing_debug_implementations,
        missing_docs,
        missing_unsafe_on_extern,
        mixed_script_confusables,
        named_arguments_used_positionally,
        never_type_fallback_flowing_into_unsafe,
        no_mangle_generic_items,
        non_ascii_idents,
        non_camel_case_types,
        non_contiguous_range_endpoints,
        non_fmt_panics,
        non_local_definitions,
        non_shorthand_field_patterns,
        non_snake_case,
        non_upper_case_globals,
        noop_method_call,
        opaque_hidden_inferred_bound,
        overlapping_range_endpoints,
        path_statements,
        private_bounds,
        private_interfaces,
        ptr_to_integer_transmute_in_consts,
        redundant_imports,
        redundant_lifetimes,
        redundant_semicolons,
        refining_impl_trait_internal,
        refining_impl_trait_reachable,
        renamed_and_removed_lints,
        repr_transparent_external_private_fields,
        rust_2021_incompatible_closure_captures,
        rust_2021_incompatible_or_patterns,
        rust_2021_prefixes_incompatible_syntax,
        rust_2021_prelude_collisions,
        rust_2024_guarded_string_incompatible_syntax,
        rust_2024_incompatible_pat,
        rust_2024_prelude_collisions,
        self_constructor_from_outer_item,
        single_use_lifetimes,
        special_module_name,
        stable_features,
        static_mut_refs,
        suspicious_double_ref_op,
        tail_expr_drop_order,
        trivial_bounds,
        trivial_casts,
        trivial_numeric_casts,
        type_alias_bounds,
        tyvar_behind_raw_pointer,
        uncommon_codepoints,
        unconditional_recursion,
        uncovered_param_in_projection,
        unexpected_cfgs,
        unfulfilled_lint_expectations,
        ungated_async_fn_track_caller,
        uninhabited_static,
        unit_bindings,
        unknown_diagnostic_attributes,
        unknown_lints,
        unnameable_test_items,
        unnameable_types,
        unnecessary_transmutes,
        unpredictable_function_pointer_comparisons,
        unreachable_code,
        unreachable_patterns,
        unreachable_pub,
        unsafe_attr_outside_unsafe,
        unsafe_code,
        unsafe_op_in_unsafe_fn,
        unstable_name_collisions,
        unstable_syntax_pre_expansion,
        unsupported_calling_conventions,
        unused_allocation,
        unused_assignments,
        unused_associated_type_bounds,
        unused_attributes,
        unused_braces,
        unused_comparisons,
        unused_crate_dependencies,
        unused_doc_comments,
        unused_extern_crates,
        unused_features,
        unused_import_braces,
        unused_imports,
        unused_labels,
        unused_lifetimes,
        unused_macro_rules,
        unused_macros,
        unused_must_use,
        unused_mut,
        unused_parens,
        unused_qualifications,
        unused_results,
        unused_unsafe,
        unused_variables,
        useless_ptr_null_checks,
        uses_power_alignment,
        variant_size_differences,
        while_true,
    )
)]
// If nightly and unstable, allow `incomplete_features` and `unstable_features`
#![cfg_attr(
    all(feature = "unstable", nightly),
    allow(incomplete_features, unstable_features)
)]
// If nightly and not unstable, deny `incomplete_features` and `unstable_features`
#![cfg_attr(
    all(not(feature = "unstable"), nightly),
    deny(incomplete_features, unstable_features)
)]
// The unstable lints
#![cfg_attr(
    all(feature = "unstable", nightly),
    deny(
        fuzzy_provenance_casts,
        lossy_provenance_casts,
        multiple_supertrait_upcastable,
        must_not_suspend,
        non_exhaustive_omitted_patterns,
        supertrait_item_shadowing_definition,
        supertrait_item_shadowing_usage,
        unqualified_local_imports,
    )
)]
// clippy lints
#![cfg_attr(nightly, deny(clippy::all, clippy::pedantic))]
// rustdoc lints
#![cfg_attr(
    nightly,
    deny(
        rustdoc::bare_urls,
        rustdoc::broken_intra_doc_links,
        rustdoc::invalid_codeblock_attributes,
        rustdoc::invalid_html_tags,
        rustdoc::missing_crate_level_docs,
        rustdoc::private_doc_tests,
        rustdoc::private_intra_doc_links,
    )
)]
#![cfg_attr(
    all(feature = "unstable", nightly),
    deny(rustdoc::missing_doc_code_examples)
)]
#![cfg_attr(all(doc, nightly), feature(doc_auto_cfg))]
#![cfg_attr(all(docsrs, nightly), feature(doc_cfg))]

mod constants;
mod error;
mod keccak;
mod lane;
mod sha3;
mod shake;
mod sponge;
mod traits;
mod utils;

pub use self::constants::LANE_COUNT;
pub use self::constants::SHA3_224_BYTES;
pub use self::constants::SHA3_256_BYTES;
pub use self::constants::SHA3_384_BYTES;
pub use self::constants::SHA3_512_BYTES;
pub use self::error::Sha3Error;
pub use self::keccak::f_200;
pub use self::keccak::f_400;
pub use self::keccak::f_800;
pub use self::keccak::f_1600;
pub use self::keccak::p_200;
pub use self::keccak::p_400;
pub use self::keccak::p_800;
pub use self::keccak::p_1600;
pub use self::sha3::sha224::Sha3_224;
pub use self::sha3::sha256::Sha3_256;
pub use self::sha3::sha384::Sha3_384;
pub use self::sha3::sha512::Sha3_512;
pub use self::shake::shake128::Shake128;
pub use self::shake::shake256::Shake256;
pub use self::traits::Hasher;
pub use self::traits::HasherBits;
pub use self::traits::XofHasher;
pub use self::utils::b2h;
pub use bitvec::prelude::BitSlice;
pub use bitvec::prelude::BitVec;
pub use bitvec::prelude::Lsb0;
pub use bitvec::prelude::bits;
pub use bitvec::prelude::bitvec;

#[cfg(test)]
mod test {
    use bitvec::{bits, bitvec, order::Lsb0, vec::BitVec};

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Mode {
        Sha3_1600,
        Sha3_1605,
        Sha3_1630,
    }

    pub(crate) fn create_test_vector(mode: Mode) -> BitVec<u8, Lsb0> {
        // Create 1600-bit test vector
        let mut bit_vec = bitvec![u8, Lsb0;];
        for _ in 0..50 {
            bit_vec.extend_from_bitslice(bits![u8, Lsb0; 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]);
        }

        match mode {
            Mode::Sha3_1600 => {}
            // Add 5 bits for 1605-bit test vector
            Mode::Sha3_1605 => {
                bit_vec.extend_from_bitslice(bits![u8, Lsb0; 1, 1, 0, 0, 0]);
            }
            // Add 30 bits for 1630-bit test vector
            Mode::Sha3_1630 => {
                bit_vec.extend_from_bitslice(bits![u8, Lsb0; 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1]);
            }
        }
        bit_vec
    }
}
