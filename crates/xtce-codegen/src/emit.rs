//! Turning a [`Plan`] into Rust source.
//!
//! Everything the layout decides — which byte a field starts in, how far to shift, what to
//! mask with — is computed here, at generation time, and appears in the output as a literal.
//! The generated module has no table to consult and no cursor to advance.
//!
//! Two details make the output as fast as it can be without `unsafe`:
//!
//! * Each container's `decode` first narrows the packet to `&[u8; N]` for its own fixed
//!   length. From then on every index is provably in range, so the bounds checks disappear
//!   without a single `unsafe` block.
//! * A field's bytes are assembled with `u64::from_be_bytes` over a literal array, which
//!   `rustc` compiles to one wide load. Fields wider than 57 bits at an unaligned offset
//!   span nine bytes and go through `u128` — the same case that catches hand-written bit
//!   readers, handled here by construction.

use proc_macro2::{Ident, Literal, Span, TokenStream};
use quote::quote;

use crate::plan::{
    Calibration, ContainerPlan, Criterion, Field, Guard, Node, Plan, Repr, TextCharset,
    TextDelimiter, Width,
};
use xtce_model::{CompareOp, IntegerCoding};

/// Renders a plan as formatted Rust source.
///
/// The output contains no inner attributes (`#![..]`) and no module-level doc comments,
/// because the primary way to use it is `include!`, and inner attributes are not permitted
/// in an included file. The header is written as ordinary comments and the caller supplies
/// whatever `#[allow(..)]` the surrounding module needs.
pub fn module(plan: &Plan, source: &str, root: &str) -> String {
    let header = header(plan, source, root);
    let items = items(plan);
    format!("{header}{items}")
}

fn header(plan: &Plan, source: &str, root: &str) -> String {
    format!(
        "// Decoder generated from `{source}` by `xtce-codegen`, rooted at `{root}`.\n\
         //\n\
         // {} container(s) are decoded here. Every bit offset and mask below was computed\n\
         // when this file was generated; nothing consults the XTCE definition at run time.\n\
         //\n\
         // Do not edit: regenerate instead. Intended to be included inside a module that\n\
         // carries the lint allowances generated code needs, for example:\n\
         //\n\
         //     #[allow(dead_code, clippy::all, clippy::pedantic)]\n\
         //     mod telemetry {{\n\
         //         include!(concat!(env!(\"OUT_DIR\"), \"/telemetry.rs\"));\n\
         //     }}\n\n",
        plan.containers.len()
    )
}

fn items(plan: &Plan) -> String {
    let preamble = preamble();
    let structs = plan.containers.iter().map(container);
    let packet = packet_enum(plan);
    let dispatch = dispatcher(plan);
    let helpers = helpers(plan);

    let tokens = quote! {
        #preamble
        #(#structs)*
        #packet
        #dispatch
        #helpers
    };

    // `prettyplease` needs a parsed file. Generation is deterministic and the tokens come
    // from `quote!`, so a parse failure would be a bug in this emitter rather than bad
    // input; falling back to the unformatted tokens keeps that visible instead of hiding it.
    if let Ok(file) = syn::parse2::<syn::File>(tokens.clone()) {
        prettyplease::unparse(&file)
    } else {
        format!("// xtce-codegen produced unparsable output:\n{tokens}")
    }
}

/// Items every generated module needs, independent of the definition.
fn preamble() -> TokenStream {
    quote! {
        /// Why a packet could not be decoded.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum DecodeError {
            /// The packet is shorter than the container it matched.
            TooShort {
                /// Bytes the container needs.
                needed: usize,
                /// Bytes the packet has.
                got: usize,
            },
            /// No inheritor of an abstract container matched, so the packet is of a type
            /// this definition does not describe.
            Unrecognized {
                /// The container that ran out of options.
                container: &'static str,
            },
            /// More than one inheritor matched, so the packet type is ambiguous.
            Ambiguous {
                /// The container being specialised.
                container: &'static str,
            },
            /// A string field's bytes are not valid text in its declared character set.
            InvalidText {
                /// The parameter being decoded.
                parameter: &'static str,
            },
            /// A string declares a termination character its buffer does not contain.
            UnterminatedString {
                /// The parameter being decoded.
                parameter: &'static str,
            },
            /// A leading-size prefix declares a length its buffer cannot hold.
            BadStringLength {
                /// The parameter being decoded.
                parameter: &'static str,
            },
            /// A field's width, read from the packet, is not a usable length.
            BadFieldSize {
                /// The parameter being decoded.
                parameter: &'static str,
                /// The width that was computed, in bits.
                bits: i64,
            },
            /// A text or binary field of data-dependent width did not land on a byte
            /// boundary, so it cannot be handed out as a slice of the packet.
            ///
            /// The interpreter copies the bits into a new buffer instead; this decoder
            /// refuses rather than allocate. See `SUPPORTED.md`.
            Unaligned {
                /// The parameter being decoded.
                parameter: &'static str,
                /// Bit offset the field started at.
                at: usize,
                /// Width of the field, in bits.
                bits: usize,
            },
            /// A spline calibrator was asked for a value outside its points, and the
            /// definition does not allow extrapolation.
            Calibration {
                /// The parameter being calibrated.
                parameter: &'static str,
            },
        }

        impl core::fmt::Display for DecodeError {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    Self::TooShort { needed, got } => {
                        write!(f, "packet has {got} byte(s), container needs {needed}")
                    }
                    Self::Unrecognized { container } => {
                        write!(f, "no inheritor of {container} matches this packet")
                    }
                    Self::Ambiguous { container } => {
                        write!(f, "more than one inheritor of {container} matches")
                    }
                    Self::InvalidText { parameter } => {
                        write!(f, "{parameter}: bytes are not valid text")
                    }
                    Self::UnterminatedString { parameter } => {
                        write!(f, "{parameter}: termination character not found")
                    }
                    Self::BadStringLength { parameter } => {
                        write!(f, "{parameter}: leading size is larger than the buffer")
                    }
                    Self::BadFieldSize { parameter, bits } => {
                        write!(f, "{parameter}: computed width {bits} bits is not usable")
                    }
                    Self::Unaligned { parameter, at, bits } => write!(
                        f,
                        "{parameter}: {bits} bit(s) at bit {at} is not byte-aligned, so it \
                         cannot be borrowed from the packet"
                    ),
                    Self::Calibration { parameter } => write!(
                        f,
                        "{parameter}: query point falls outside the spline points and \
                         extrapolate is false"
                    ),
                }
            }
        }

        impl core::error::Error for DecodeError {}

        /// A decoded value, in the same shape the interpreted decoder produces.
        ///
        /// Text and binary values borrow from the packet, so nothing is copied out of it.
        #[derive(Clone, Copy, PartialEq, Debug)]
        pub enum Value<'a> {
            /// An unsigned integer field.
            Unsigned(u64),
            /// A signed integer field.
            Signed(i64),
            /// A float field.
            Float(f64),
            /// A boolean parameter's value.
            Bool(bool),
            /// An enumeration label.
            Label(&'static str),
            /// Text decoded from the packet.
            Text(&'a str),
            /// Bytes as they appear in the packet.
            Bytes(&'a [u8]),
        }
    }
}

fn container(plan: &ContainerPlan) -> TokenStream {
    let type_ident = ident(&plan.type_ident);
    let xtce_name = &plan.xtce_name;

    // A container that hands out slices of the packet has to name the packet's lifetime; one
    // made only of scalars must not, or the parameter would be unused and the module would
    // not compile.
    let borrows = plan.fields.iter().any(|field| field.repr.borrows());
    let generics = if borrows { quote!(<'a>) } else { quote!() };
    let self_ty = if borrows {
        quote!(#type_ident<'a>)
    } else {
        quote!(#type_ident)
    };
    let data_ref = if borrows {
        quote!(&'a [u8])
    } else {
        quote!(&[u8])
    };

    let (length_doc, length_consts) = if let Some(bits) = plan.bit_length {
        let bit_length = Literal::usize_unsuffixed(bits);
        let byte_length = Literal::usize_unsuffixed(bits.div_ceil(8));
        (
            format!("{bits} bit(s)"),
            quote! {
                /// Total width of this container's fields, in bits.
                pub const BIT_LENGTH: usize = #bit_length;

                /// Bytes a packet must have for this container to decode.
                pub const BYTE_LENGTH: usize = #byte_length;
            },
        )
    } else {
        let prefix = Literal::usize_unsuffixed(plan.static_prefix_bits);
        (
            format!(
                "{} fixed bit(s) then a data-dependent tail",
                plan.static_prefix_bits
            ),
            quote! {
                /// Width of the leading fields whose offsets are fixed, in bits.
                ///
                /// This container has no total length: one of its fields takes its width
                /// from the packet.
                pub const STATIC_PREFIX_BITS: usize = #prefix;
            },
        )
    };

    let doc = format!(
        " `{xtce_name}`: {} field(s) in {length_doc}.",
        plan.fields.len()
    );

    let fields = plan.fields.iter().flat_map(struct_fields);
    let accessors = plan.fields.iter().filter_map(accessor);
    let body = decode_body(plan);

    // An entry list may name the same parameter twice — CTIM's `APID_20_Packet` has two
    // `SPARE_8` entries. The struct keeps both, because both really are in the packet at
    // different offsets, but the *reported* values collapse to one: the interpreter stores
    // them in a dictionary, where the second assignment overwrites the first and the key
    // keeps its original position. Reporting both would disagree with it on field count.
    let reported = reported_fields(&plan.fields);

    let visits = reported.iter().map(|&index| {
        let field = plan.fields.get(index);
        let xtce_name = field.map_or("", |field| field.xtce_name.as_str());
        let (raw, eng) = field.map_or_else(
            || (quote!(Value::Unsigned(0)), quote!(Value::Unsigned(0))),
            visit_values,
        );
        quote! { visit(#xtce_name, #raw, #eng); }
    });

    let field_names = reported.iter().map(|&index| {
        let name = plan
            .fields
            .get(index)
            .map_or("", |field| field.xtce_name.as_str());
        quote! { #name }
    });
    let field_count = Literal::usize_unsuffixed(reported.len());

    quote! {
        #[doc = #doc]
        #[derive(Clone, Copy, PartialEq, Debug, Default)]
        pub struct #type_ident #generics {
            #(#fields)*
        }

        impl #generics #self_ty {
            /// Name of this container in the XTCE definition.
            pub const NAME: &'static str = #xtce_name;

            #length_consts

            /// Parameter names, in decode order.
            pub const FIELDS: [&'static str; #field_count] = [#(#field_names),*];

            /// Decodes this container from the start of `data`.
            ///
            /// # Errors
            ///
            /// [`DecodeError::TooShort`] if the packet does not hold the whole container, or
            /// a text error if a string field does not hold valid text.
            #[inline]
            pub fn decode(data: #data_ref) -> Result<Self, DecodeError> {
                #body
            }

            /// Calls `visit(name, raw, engineering)` for every field, in decode order.
            ///
            /// The values borrow for as long as `self` does, so a caller may collect them
            /// rather than only look at them in passing.
            #[inline]
            pub fn for_each_value<'v>(
                &'v self,
                mut visit: impl FnMut(&'static str, Value<'v>, Value<'v>),
            ) {
                #(#visits)*
            }

            #(#accessors)*
        }
    }
}

/// Which field indices `for_each_value` reports, in order.
///
/// One entry per distinct parameter, positioned where it first appears and carrying the value
/// of where it last appears — which is what assigning twice into a Python dictionary does,
/// and therefore what the interpreter does.
fn reported_fields(fields: &[Field]) -> Vec<usize> {
    let mut last_of: std::collections::HashMap<xtce_model::ParamId, usize> =
        std::collections::HashMap::new();
    for (index, field) in fields.iter().enumerate() {
        last_of.insert(field.parameter, index);
    }

    let mut seen = std::collections::HashSet::new();
    fields
        .iter()
        .enumerate()
        .filter(|(_, field)| seen.insert(field.parameter))
        .filter_map(|(_, field)| last_of.get(&field.parameter).copied())
        .collect()
}

/// The struct field or fields one XTCE parameter contributes.
///
/// Everything contributes one, except text: XTCE gives a string both a raw buffer and the
/// string found inside it, and reproducing the reference exactly needs both.
fn struct_fields(field: &Field) -> Vec<TokenStream> {
    let name = ident(&field.ident);
    let ty = rust_type(&field.repr);
    let placement = match (field.bit_offset, field.width.fixed()) {
        (Some(offset), Some(width)) => format!("{width} bit(s) at bit {offset}"),
        (Some(offset), None) => format!("a data-dependent width, from bit {offset}"),
        (None, Some(width)) => format!("{width} bit(s), after a data-dependent width"),
        (None, None) => "a data-dependent width and offset".to_owned(),
    };
    let doc = format!(
        " `{}` — {placement}.{}",
        field.xtce_name,
        match &field.repr {
            Repr::Bool => " Stored raw; see the accessor for the boolean value.",
            Repr::Enumerated(_) => " Stored raw; see the accessor for the label.",
            Repr::Text { .. } => " The string, after applying its delimiter.",
            _ => "",
        }
    );
    let mut out = vec![quote! {
        #[doc = #doc]
        pub #name: #ty,
    }];

    if let Some(raw_ident) = &field.raw_ident {
        let raw_name = ident(raw_ident);
        let raw_doc = format!(
            " `{}` — the raw buffer as allocated, including any terminator or padding.",
            field.xtce_name
        );
        out.push(quote! {
            #[doc = #raw_doc]
            pub #raw_name: &'a [u8],
        });
    }
    if let Some(eng_ident) = &field.eng_ident {
        let eng_name = ident(eng_ident);
        let eng_doc = format!(
            " `{}` — the engineering value, after its calibrator. The field above is the \
             raw one the packet carried.",
            field.xtce_name
        );
        out.push(quote! {
            #[doc = #eng_doc]
            pub #eng_name: f64,
        });
    }
    out
}

/// The field initialisers one XTCE parameter contributes to `Self { .. }`.
fn field_initialisers(field: &Field, packet: &Ident) -> Vec<TokenStream> {
    let name = ident(&field.ident);
    let value = read_field(field, packet);
    let mut out = vec![quote! { #name: #value, }];

    if let Some(raw_ident) = &field.raw_ident {
        let raw_name = ident(raw_ident);
        let slice = byte_slice(field, packet);
        out.push(quote! { #raw_name: #slice, });
    }
    if let Some(eng_ident) = &field.eng_ident {
        let eng_name = ident(eng_ident);
        // The raw value is read a second time rather than referred to: these are struct
        // initialisers, so the first one is not a binding anything else can name.
        let raw = read_field(field, packet);
        let calibrated = calibrate(field, &quote!(__raw), packet);
        out.push(quote! {
            #eng_name: { let __raw = #raw; #calibrated },
        });
    }
    out
}

/// The `&packet[a..b]` slice for a byte-aligned field at a literal offset.
fn byte_slice(field: &Field, packet: &Ident) -> TokenStream {
    let Some((offset, width)) = field.static_span() else {
        return quote! {
            compile_error!("xtce-codegen: a literal slice of a field with no fixed span")
        };
    };
    let start = Literal::usize_unsuffixed(offset / 8);
    let end = Literal::usize_unsuffixed((offset + width as usize) / 8);
    quote! { &#packet[#start..#end] }
}

/// The body of a container's `decode`.
///
/// Two shapes. When every width is fixed, the packet is narrowed to an array once and each
/// field is a literal offset into it — no cursor exists at run time. When one field takes its
/// width from the packet, everything before it still reads that way, and only the tail is
/// walked with a cursor. The split is the honest one: the offsets after a data-dependent
/// width are a property of the data, not of this generator.
fn decode_body(plan: &ContainerPlan) -> TokenStream {
    let packet = ident("packet");
    let prefix_bits = if plan.is_dynamic() {
        plan.static_prefix_bits
    } else {
        plan.bit_length.unwrap_or(0)
    };
    let prefix_bytes = Literal::usize_unsuffixed(prefix_bits.div_ceil(8));

    // Narrowing to a fixed-size array once is what removes the bounds check from every
    // literal-offset read below, with no `unsafe`. The length is spelled out rather than
    // written `Self::BYTE_LENGTH`: an associated constant of a type with a lifetime
    // parameter cannot appear in an array type.
    let narrow = quote! {
        let #packet: &[u8; #prefix_bytes] = match data.get(..#prefix_bytes) {
            Some(prefix) => match prefix.try_into() {
                Ok(array) => array,
                Err(_) => {
                    return Err(DecodeError::TooShort {
                        needed: #prefix_bytes,
                        got: data.len(),
                    });
                }
            },
            None => {
                return Err(DecodeError::TooShort {
                    needed: #prefix_bytes,
                    got: data.len(),
                });
            }
        };
    };

    if !plan.is_dynamic() {
        let assignments = plan
            .fields
            .iter()
            .flat_map(|field| field_initialisers(field, &packet));
        return quote! {
            #narrow
            Ok(Self { #(#assignments)* })
        };
    }

    // The cursor takes over at the first field the packet has any say over — which is the
    // field with the data-dependent *width*, not the first one with an unknown offset. Its
    // own offset is still known; everything after it is not. It is declared exactly once,
    // immediately before that field.
    let last = plan.fields.len().saturating_sub(1);
    let first_dynamic = plan
        .fields
        .iter()
        .position(|field| field.static_span().is_none());

    let mut statements = Vec::new();
    let mut names = Vec::new();

    for (index, field) in plan.fields.iter().enumerate() {
        if Some(index) == first_dynamic {
            let start = Literal::usize_unsuffixed(plan.static_prefix_bits);
            // `mut` only where something moves it: if the dynamic field is the last one,
            // nothing reads the cursor again and the generated code would warn.
            let cursor = if index == last {
                quote! { let at: usize = #start; }
            } else {
                quote! { let mut at: usize = #start; }
            };
            statements.push(cursor);
        }

        let name = ident(&field.ident);
        let raw_name = field.raw_ident.as_deref().map(ident);
        let eng_name = field.eng_ident.as_deref().map(ident);
        names.push(quote! { #name });

        if field.static_span().is_some() {
            let value = read_field(field, &packet);
            statements.push(quote! { let #name = #value; });
            if let Some(raw_name) = &raw_name {
                let slice = byte_slice(field, &packet);
                statements.push(quote! { let #raw_name = #slice; });
            }
        } else {
            let source = match field.width {
                Width::Dynamic { source, .. } => {
                    plan.fields.get(source).map(|source| ident(&source.ident))
                }
                Width::Fixed(_) => None,
            };
            statements.extend(runtime_field(
                field,
                &name,
                raw_name.as_ref(),
                source.as_ref(),
                index != last,
            ));
        }

        if let Some(raw_name) = raw_name {
            names.push(quote! { #raw_name });
        }
        // Calibration reads the binding above, so it goes after both branches rather than
        // being duplicated into each.
        if let Some(eng_name) = eng_name {
            let calibrated = calibrate(field, &quote!(#name), &packet);
            statements.push(quote! { let #eng_name: f64 = #calibrated; });
            names.push(quote! { #eng_name });
        }
    }

    quote! {
        #narrow
        #(#statements)*
        Ok(Self { #(#names),* })
    }
}

/// Statements for one field whose offset is only known while decoding.
///
/// The cursor `at` is in bits and is advanced by each field in turn — the same walk the
/// interpreter does, except that the widths, conversions and names are all fixed here rather
/// than looked up per packet.
fn runtime_field(
    field: &Field,
    name: &Ident,
    raw_name: Option<&Ident>,
    source: Option<&Ident>,
    advance: bool,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    let xtce_name = &field.xtce_name;

    // The width: a literal, or a value computed from a field already decoded.
    let width = match field.width {
        Width::Fixed(bits) => {
            let bits = Literal::usize_unsuffixed(bits as usize);
            quote! { #bits }
        }
        Width::Dynamic { adjustment, .. } => {
            let bits_ident = ident(&format!("{name}_bits"));
            let Some(source) = source else {
                return vec![quote! {
                    compile_error!("xtce-codegen: dynamic width with no resolved source");
                }];
            };
            // Matching the interpreter exactly: it multiplies and adds in `f64` and then
            // truncates toward zero. Doing the arithmetic any other way would give a
            // different length for a value the two implementations must agree on.
            let compute = if let Some(adjustment) = adjustment {
                let slope = Literal::f64_unsuffixed(adjustment.slope);
                let intercept = Literal::f64_unsuffixed(adjustment.intercept);
                quote! { ((#slope * (#source as f64)) + #intercept) as i64 }
            } else {
                quote! { i64::try_from(#source).unwrap_or(i64::MAX) }
            };
            out.push(quote! {
                let #bits_ident: usize = {
                    let bits = #compute;
                    match usize::try_from(bits) {
                        Ok(bits) => bits,
                        Err(_) => {
                            return Err(DecodeError::BadFieldSize {
                                parameter: #xtce_name,
                                bits,
                            });
                        }
                    }
                };
            });
            quote! { #bits_ident }
        }
    };

    match &field.repr {
        Repr::Binary => out.push(quote! {
            let #name = take_bytes(data, at, #width, #xtce_name)?;
        }),
        Repr::Text { charset, delimiter } => {
            let raw_name = raw_name
                .cloned()
                .unwrap_or_else(|| ident(&format!("{name}_raw")));
            out.push(quote! {
                let #raw_name = take_bytes(data, at, #width, #xtce_name)?;
            });
            let ascii = matches!(charset, TextCharset::UsAscii);
            out.push(match delimiter {
                TextDelimiter::WholeBuffer => {
                    quote! { let #name = text_whole(#raw_name, #ascii, #xtce_name)?; }
                }
                TextDelimiter::TerminationChar(bytes) => {
                    let terminator = bytes.iter().map(|byte| Literal::u8_unsuffixed(*byte));
                    quote! {
                        let #name =
                            text_terminated(#raw_name, &[#(#terminator),*], #ascii, #xtce_name)?;
                    }
                }
                TextDelimiter::LeadingSize { size_in_bits } => {
                    let size = Literal::u32_unsuffixed(*size_in_bits);
                    quote! { let #name = text_leading(#raw_name, #size, #ascii, #xtce_name)?; }
                }
            });
        }
        repr => {
            let bits = Literal::u32_unsuffixed(field.width.fixed().unwrap_or(0));
            // Past the cursor the offset is a run-time value, so the reversed-load shortcut
            // is not available and the swap happens where the interpreter puts it.
            let raw = if field.swap_bytes && field.width.fixed().unwrap_or(0) > 8 {
                let width = Literal::u32_unsuffixed(field.width.fixed().unwrap_or(0));
                Expr::atom(quote! { swap_byte_order(__raw, #width) })
            } else {
                Expr::atom(quote! { __raw })
            };
            let value = numeric_from_u64(repr, &raw, field.width, unmasked_sign(field));
            out.push(quote! {
                let #name = {
                    let __raw = read_at(data, at, #bits, #xtce_name)?;
                    #value
                };
            });
        }
    }

    // Nothing reads the cursor past the last field, and assigning to it there would warn.
    if advance {
        out.push(quote! { at = at.saturating_add(#width); });
    }
    out
}

/// An accessor for reprs whose stored form is the raw integer.
fn accessor(field: &Field) -> Option<TokenStream> {
    let stored = ident(&field.ident);
    match &field.repr {
        Repr::Bool => {
            let name = ident(&format!("{}_value", field.ident));
            let doc = format!(
                " `{}` as a boolean: true when the raw value is non-zero.",
                field.xtce_name
            );
            Some(quote! {
                #[doc = #doc]
                #[inline]
                pub fn #name(&self) -> bool {
                    self.#stored != 0
                }
            })
        }
        Repr::Enumerated(entries) => {
            let name = ident(&format!("{}_label", field.ident));
            let doc = format!(" `{}` as its enumeration label.", field.xtce_name);
            let arms = entries.iter().map(|(value, max, label)| {
                let low = Literal::i128_unsuffixed(*value);
                let high = Literal::i128_unsuffixed(*max);
                if value == max {
                    quote! { #low => Some(#label), }
                } else {
                    quote! { #low..=#high => Some(#label), }
                }
            });
            Some(quote! {
                #[doc = #doc]
                #[inline]
                pub fn #name(&self) -> Option<&'static str> {
                    match i128::from(self.#stored) {
                        #(#arms)*
                        _ => None,
                    }
                }
            })
        }
        _ => None,
    }
}

/// The expression that turns a field's raw value into its engineering value.
///
/// Every line of this has to produce the same bits as `xtce_decode::calibrate`, because the
/// two are compared field by field on every packet of the differential suite. Floating-point
/// addition is neither associative nor commutative, so "the same arithmetic in a different
/// order" is a different answer, and a calibrator is where that is easiest to get wrong.
///
/// Two things carry that:
///
/// * **Terms are summed in document order**, not by Horner's method and not sorted.
/// * **The integer and float paths are separate.** For an integral raw the power is computed
///   in `i128` and converted once, exactly as the reference does with its arbitrary-precision
///   integers; for a float raw it is `powi`, which rounds at every multiply. The same number
///   through the two paths gives different bits, so the path is chosen by the field's
///   encoding and never by convenience.
fn calibrate(field: &Field, raw: &TokenStream, packet: &Ident) -> TokenStream {
    let Some(calibration) = &field.calibration else {
        return quote!(0.0f64);
    };

    // A `<ContextCalibratorList>` is tried in order and the first whose criteria all hold
    // wins; the default is what applies when none does. The plan refuses a list without a
    // default, so the chain always ends in one and the value always has a type.
    if !field.contexts.is_empty() {
        let default = apply_calibration(field, calibration, raw);
        // Built from the back so the tail is spliced without braces: an `else` followed by
        // another `if` is `else if`, and a chain of five contexts nested five blocks deep is
        // not something anyone should have to read in an audit.
        let mut chain = quote! { { #default } };
        for context in field.contexts.iter().rev() {
            let condition = criterion_condition(&context.criteria, packet);
            let applied = apply_calibration(field, &context.calibration, raw);
            chain = quote! { if #condition { #applied } else #chain };
        }
        return chain;
    }

    apply_calibration(field, calibration, raw)
}

/// One calibrator, applied to a raw value.
fn apply_calibration(field: &Field, calibration: &Calibration, raw: &TokenStream) -> TokenStream {
    let integral = matches!(field.repr, Repr::Unsigned | Repr::Signed(_));
    let xtce_name = &field.xtce_name;

    match calibration {
        Calibration::Polynomial(terms) => {
            let accumulate = terms.iter().map(|term| {
                let coefficient = Literal::f64_unsuffixed(term.coefficient);
                let exponent = Literal::i32_unsuffixed(term.exponent);
                if integral {
                    quote! { sum += #coefficient * integer_power(base, #exponent); }
                } else {
                    quote! { sum += #coefficient * powi(base, #exponent); }
                }
            });
            let base = if integral {
                quote! { let base = i128::from(#raw); }
            } else {
                quote! { let base = #raw; }
            };
            quote! {
                {
                    #base
                    let mut sum = 0.0f64;
                    #(#accumulate)*
                    sum
                }
            }
        }
        Calibration::Spline(spline) => {
            let points = spline.points.iter().map(|point| {
                let raw = Literal::f64_unsuffixed(point.raw);
                let calibrated = Literal::f64_unsuffixed(point.calibrated);
                quote! { (#raw, #calibrated) }
            });
            let order = Literal::u8_unsuffixed(spline.order);
            let extrapolate = spline.extrapolate;
            // `as_f64` on the reference's input: an integral raw goes through `i128` first,
            // which for the widths compiled here is the same value either way, but is
            // written the same way so the two are read as the same conversion.
            let query = if integral {
                quote! { i128::from(#raw) as f64 }
            } else {
                quote! { #raw }
            };
            quote! {
                {
                    const POINTS: &[(f64, f64)] = &[#(#points),*];
                    match spline_value(POINTS, #order, #extrapolate, #query) {
                        Some(value) => value,
                        None => {
                            return Err(DecodeError::Calibration { parameter: #xtce_name });
                        }
                    }
                }
            }
        }
    }
}

/// The `(raw, engineering)` pair a field contributes to `for_each_value`.
fn visit_values(field: &Field) -> (TokenStream, TokenStream) {
    let stored = ident(&field.ident);

    // A calibrated parameter's engineering value is the calibrator's output, whatever the
    // raw encoding was. Only a numeric field ever carries one — an enumeration and a boolean
    // are looked up from the raw value and never reach a calibrator.
    if let Some(eng_ident) = &field.eng_ident {
        let eng = ident(eng_ident);
        let raw = match &field.repr {
            Repr::Signed(_) => quote! { Value::Signed(self.#stored) },
            Repr::Float16 | Repr::Float32 | Repr::Float64 | Repr::Mil1750a => {
                quote! { Value::Float(self.#stored) }
            }
            _ => quote! { Value::Unsigned(self.#stored) },
        };
        return (raw, quote! { Value::Float(self.#eng) });
    }

    match &field.repr {
        Repr::Unsigned => (
            quote! { Value::Unsigned(self.#stored) },
            quote! { Value::Unsigned(self.#stored) },
        ),
        Repr::Signed(_) => (
            quote! { Value::Signed(self.#stored) },
            quote! { Value::Signed(self.#stored) },
        ),
        Repr::Float16 | Repr::Float32 | Repr::Float64 | Repr::Mil1750a => (
            quote! { Value::Float(self.#stored) },
            quote! { Value::Float(self.#stored) },
        ),
        Repr::Bool => {
            let accessor = ident(&format!("{}_value", field.ident));
            (
                quote! { Value::Unsigned(self.#stored) },
                quote! { Value::Bool(self.#accessor()) },
            )
        }
        Repr::Enumerated(_) => {
            let accessor = ident(&format!("{}_label", field.ident));
            (
                quote! { Value::Unsigned(self.#stored) },
                quote! { Value::Label(self.#accessor().unwrap_or("")) },
            )
        }
        // A string's raw value is the buffer as allocated; its engineering value is the
        // string found inside it. The reference draws exactly this distinction.
        Repr::Text { .. } => {
            let raw = ident(field.raw_ident.as_deref().unwrap_or(&field.ident));
            (
                quote! { Value::Bytes(self.#raw) },
                quote! { Value::Text(self.#stored) },
            )
        }
        Repr::Binary => (
            quote! { Value::Bytes(self.#stored) },
            quote! { Value::Bytes(self.#stored) },
        ),
    }
}

fn rust_type(repr: &Repr) -> TokenStream {
    match repr {
        Repr::Unsigned | Repr::Bool | Repr::Enumerated(_) => quote!(u64),
        Repr::Signed(_) => quote!(i64),
        Repr::Float16 | Repr::Float32 | Repr::Float64 | Repr::Mil1750a => quote!(f64),
        Repr::Text { .. } => quote!(&'a str),
        Repr::Binary => quote!(&'a [u8]),
    }
}

/// The expression that turns a field's bits into its stored value.
fn read_field(field: &Field, packet: &Ident) -> TokenStream {
    // Text and binary are byte-aligned by construction — `plan` refuses them otherwise — so
    // they are a slice of the packet rather than a shift-and-mask.
    match &field.repr {
        Repr::Binary => return byte_slice(field, packet),
        Repr::Text { charset, delimiter } => {
            let buffer = byte_slice(field, packet);
            let name = &field.xtce_name;
            let ascii = matches!(charset, TextCharset::UsAscii);
            return match delimiter {
                TextDelimiter::WholeBuffer => quote! { text_whole(#buffer, #ascii, #name)? },
                TextDelimiter::TerminationChar(bytes) => {
                    let terminator = bytes.iter().map(|byte| Literal::u8_unsuffixed(*byte));
                    quote! { text_terminated(#buffer, &[#(#terminator),*], #ascii, #name)? }
                }
                TextDelimiter::LeadingSize { size_in_bits } => {
                    let size = Literal::u32_unsuffixed(*size_in_bits);
                    quote! { text_leading(#buffer, #size, #ascii, #name)? }
                }
            };
        }
        _ => {}
    }

    let Some((offset, width)) = field.static_span() else {
        return quote! {
            compile_error!("xtce-codegen: a literal read of a field with no fixed span")
        };
    };
    let raw = read_field_bits(field, offset, width, packet);
    numeric_from_u64(&field.repr, &raw, field.width, unmasked_sign(field))
}

/// Whether a field's sign extension has to keep the bits above its width.
///
/// Only a byte swap can put any there, and only when the width is not a whole number of
/// bytes. See `xtce_decode::bits::twos_complement_unmasked`.
fn unmasked_sign(field: &Field) -> bool {
    field.swap_bytes && field.width.fixed().is_some_and(|width| width % 8 != 0)
}

/// A field's raw bits, with its byte order applied.
///
/// `leastSignificantByteFirst` means the reference reads the field big-endian and then
/// reverses `ceil(width / 8)` bytes of the result — not that it reads it differently. For a
/// field that starts on a byte and occupies whole ones the two descriptions coincide and a
/// reversed load says it in one instruction; for anything else they do not, and the reversal
/// has to happen after the read, exactly where the interpreter does it.
fn read_field_bits(field: &Field, offset: usize, width: u32, packet: &Ident) -> Expr {
    if !field.swap_bytes {
        return read_bits(offset, width, packet);
    }
    swap_bytes_of(read_bits(offset, width, packet), offset, width, packet)
}

/// The same, given the read already built — the cursor path has its own.
fn swap_bytes_of(raw: Expr, offset: usize, width: u32, packet: &Ident) -> Expr {
    let bytes = (width as usize).div_ceil(8);
    if bytes <= 1 {
        // One byte reversed is one byte. The interpreter returns early here too.
        return raw;
    }

    // Byte-aligned and a whole number of bytes: reversing the load is the reversal.
    if offset % 8 == 0 && width % 8 == 0 {
        let first = offset / 8;
        let slots = match bytes {
            2 => 2usize,
            3..=4 => 4,
            5..=8 => 8,
            _ => 16,
        };
        let ty = match slots {
            2 => quote!(u16),
            4 => quote!(u32),
            8 => quote!(u64),
            _ => quote!(u128),
        };
        // Zero padding goes at the *end* for a little-endian load: those are the high bytes.
        let loaded = (first..first + bytes)
            .map(|index| {
                let index = Literal::usize_unsuffixed(index);
                quote! { #packet[#index] }
            })
            .chain((bytes..slots).map(|_| quote!(0)));
        let load = quote!(#ty::from_le_bytes([#(#loaded),*]));
        return Expr::of_width(load, (slots * 8) as u32);
    }

    let value = raw.widened(64).into_tokens();
    let width = Literal::u32_unsuffixed(width);
    Expr::atom(quote!(swap_byte_order(#value, #width)))
}

/// Turns a `u64` of raw bits into the field's value.
///
/// Shared by the literal-offset path and the cursor path, so a signed field or a float is
/// converted identically whichever side of a data-dependent width it falls on.
fn numeric_from_u64(repr: &Repr, raw: &Expr, width: Width, unmasked: bool) -> TokenStream {
    let bits = width.fixed().unwrap_or(64);
    match repr {
        Repr::Signed(coding) => signed(raw, bits, *coding, unmasked),
        // These three sit in argument position, where parentheses would only trip
        // `unused_parens`.
        Repr::Mil1750a => {
            let value = raw.widened(64).into_tokens();
            quote! { mil_std_1750a(#value) }
        }
        Repr::Float16 => {
            let value = raw.widened(16).into_tokens();
            quote! { half_to_f64(#value) }
        }
        Repr::Float32 => {
            let value = raw.widened(32).into_tokens();
            quote! { f64::from(f32::from_bits(#value)) }
        }
        Repr::Float64 => {
            let value = raw.widened(64).into_tokens();
            quote! { f64::from_bits(#value) }
        }
        _ => raw.widened(64).into_tokens(),
    }
}

fn signed(raw: &Expr, width: u32, coding: IntegerCoding, unmasked: bool) -> TokenStream {
    let widened = raw.widened(64);
    // Two forms, because the same value is spliced in front of an operator in some arms and
    // stands alone as the value of a `let` in others.
    let value = widened.embedded();
    let alone = widened.bare();
    match coding {
        IntegerCoding::Unsigned => quote! { #value as i64 },
        IntegerCoding::TwosComplement if unmasked => {
            // After a byte swap of a field that is not a whole number of bytes the value
            // carries bits above `width`, and the reference sign-extends without masking
            // them away — so shifting, which masks, would give a different number. The plan
            // refuses the widths where this cannot fit an `i64`, so the subtraction is safe
            // here even though it would not be in general.
            let sign = Literal::u64_unsuffixed(1u64 << (width - 1));
            let magnitude = Literal::i64_unsuffixed(1i64 << width);
            quote! {
                {
                    let raw = #alone;
                    if raw & #sign == 0 { raw as i64 } else { (raw as i64) - #magnitude }
                }
            }
        }
        IntegerCoding::TwosComplement => {
            // Sign-extend by shifting. Subtracting `2 ^ width` overflows at width 63.
            let shift = Literal::u32_unsuffixed(64 - width);
            quote! { ((#value << #shift) as i64) >> #shift }
        }
        IntegerCoding::SignMagnitude => {
            let sign = Literal::u64_unsuffixed(1u64 << (width - 1));
            let magnitude = Literal::u64_unsuffixed((1u64 << (width - 1)) - 1);
            quote! {
                {
                    let raw = #alone;
                    let magnitude = (raw & #magnitude) as i64;
                    if raw & #sign == 0 { magnitude } else { -magnitude }
                }
            }
        }
        IntegerCoding::OnesComplement => {
            let sign = Literal::u64_unsuffixed(1u64 << (width - 1));
            let mask = Literal::u64_unsuffixed(mask_for(width));
            quote! {
                {
                    let raw = #alone;
                    if raw & #sign == 0 {
                        raw as i64
                    } else {
                        -((((!raw) & #mask)) as i64)
                    }
                }
            }
        }
    }
}

const fn mask_for(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

/// The expression that extracts `width` bits at `offset` as a `u64`.
///
/// The byte span, shift and mask are all decided here, so the emitted code is a load, a
/// shift and an `and` — no loop, no cursor, no branch.
///
/// The load uses the narrowest integer that spans the field rather than always padding to
/// eight bytes. That is not cosmetic: a 1.6 MB mission database has nine thousand fields, and
/// padding every one of them to an eight-element array literal turned the generated file into
/// five megabytes of source that `rustc` then had to chew through.
///
/// Padding goes at the *front*. Reading past `last` to reach a convenient width would index
/// beyond the packet for a field that ends at its final byte, which on a fixed-size array is
/// a compile error rather than something to discover later.
/// A generated expression, and whether embedding it needs parentheses.
///
/// Rust binds `as` and `<<` tighter than `&`, so splicing `a & b` into `#expr as u32` would
/// silently produce `a & (b as u32)`. Tracking atomicity means the parentheses go in exactly
/// where they are needed — adding them everywhere would trip `unused_parens`, which a file
/// meant for `include!` cannot switch off.
#[derive(Clone)]
struct Expr {
    tokens: TokenStream,
    atomic: bool,
    /// Width of the expression's own type, so a cast is only emitted when it changes
    /// something. Without this every float read came out as `... as u64 as u32`.
    natural_bits: u32,
}

impl Expr {
    /// An expression that needs no parentheses anywhere, already a `u64`.
    fn atom(tokens: TokenStream) -> Self {
        Self::of_width(tokens, 64)
    }

    /// The same, of a narrower or wider integer type.
    fn of_width(tokens: TokenStream, natural_bits: u32) -> Self {
        Self {
            tokens,
            atomic: true,
            natural_bits,
        }
    }

    /// The expression as a `bits`-wide unsigned integer, casting only if it is not already
    /// one. Returns an `Expr` rather than tokens so that a value needing no cast keeps its
    /// atomicity: dropping it here once turned a masked load spliced before a shift into a
    /// silent misparse.
    fn widened(&self, bits: u32) -> Self {
        if self.natural_bits == bits {
            return self.clone();
        }
        let target = match bits {
            8 => quote!(u8),
            16 => quote!(u16),
            32 => quote!(u32),
            128 => quote!(u128),
            _ => quote!(u64),
        };
        let value = self.embedded();
        // Not atomic. `x as u64 << 48` does not parse: the type after `as` swallows the `<<`
        // as the start of generic arguments, and rustc reports it as an error rather than
        // quietly picking one reading — but only for the shift. Anything spliced in front of
        // an operator needs the parentheses.
        Self {
            tokens: quote! { #value as #target },
            atomic: false,
            natural_bits: bits,
        }
    }

    /// The expression, parenthesised if splicing it into a tighter-binding context would
    /// otherwise change what it means.
    fn embedded(&self) -> TokenStream {
        let tokens = &self.tokens;
        if self.atomic {
            quote! { #tokens }
        } else {
            quote! { (#tokens) }
        }
    }

    fn into_tokens(self) -> TokenStream {
        self.tokens
    }

    /// The expression as written, with no added parentheses.
    ///
    /// Correct wherever the expression stands alone — the value of a `let`, an argument —
    /// and wrong wherever a tighter-binding operator follows it.
    fn bare(&self) -> TokenStream {
        self.tokens.clone()
    }
}

fn read_bits(offset: usize, width: u32, packet: &Ident) -> Expr {
    let first = offset / 8;
    let last = (offset + width as usize - 1) / 8;
    let span = last - first + 1;
    let bit_in_byte = (offset % 8) as u32;
    let mask = mask_for(width);

    // Smallest integer that holds the span. Nine bytes only happens for a wide field at an
    // unaligned offset, which is exactly the case a single 64-bit load gets wrong.
    let slots = match span {
        1 => 1usize,
        2 => 2,
        3..=4 => 4,
        5..=8 => 8,
        _ => 16,
    };
    let pad = slots - span;

    // The load keeps its own width; a cast is added only where a caller needs a wider one.
    let natural_bits = (slots * 8) as u32;
    let load = if slots == 1 {
        let index = Literal::usize_unsuffixed(first);
        quote! { #packet[#index] }
    } else {
        let bytes = (0..pad)
            .map(|_| quote!(0))
            .chain((first..=last).map(|index| {
                let index = Literal::usize_unsuffixed(index);
                quote! { #packet[#index] }
            }));
        let ty = match slots {
            2 => quote!(u16),
            4 => quote!(u32),
            8 => quote!(u64),
            _ => quote!(u128),
        };
        quote! { #ty::from_be_bytes([#(#bytes),*]) }
    };

    // The span's bytes sit in the low `span * 8` bits of the loaded value, so the field's
    // low bit is this far up — independent of how much zero padding went in front.
    let shift = (span as u32) * 8 - bit_in_byte - width;
    let whole = shift == 0 && width == (span as u32) * 8;

    // Every load is either an index or a call, so an unmasked one never needs parentheses.
    if whole {
        return Expr::of_width(load, natural_bits);
    }
    // The shift and mask happen in the load's own width, never narrower.
    //
    // A narrower load is widened to `u64` first, because the mask is a `u64` value. A *wider*
    // one — the `u128` a nine-byte span needs — stays `u128` until after the shift: narrowing
    // it first would discard the top of the field, which is precisely the case `u128` is here
    // for. The caller widens or narrows the result, and knows which because `natural_bits`
    // says what it is.
    let (base, natural_bits) = if natural_bits < 64 {
        (quote! { #load as u64 }, 64)
    } else {
        (load, natural_bits)
    };
    let mask = Literal::u64_unsuffixed(mask);
    if shift == 0 {
        return Expr {
            tokens: quote! { (#base) & #mask },
            atomic: false,
            natural_bits,
        };
    }
    let shift = Literal::u32_unsuffixed(shift);
    Expr {
        tokens: quote! { (#base >> #shift) & #mask },
        atomic: false,
        natural_bits,
    }
}

fn packet_enum(plan: &Plan) -> TokenStream {
    let borrows = plan_borrows(plan);
    let generics = if borrows { quote!(<'a>) } else { quote!() };
    let self_ty = if borrows {
        quote!(Packet<'a>)
    } else {
        quote!(Packet)
    };

    let variants = plan.containers.iter().map(|container| {
        let variant = ident(&container.type_ident);
        let doc = format!(" A packet decoded as `{}`.", container.xtce_name);
        let inner = if container.fields.iter().any(|field| field.repr.borrows()) {
            quote!(#variant<'a>)
        } else {
            quote!(#variant)
        };
        quote! {
            #[doc = #doc]
            #variant(#inner),
        }
    });

    let name_arms = plan.containers.iter().map(|container| {
        let variant = ident(&container.type_ident);
        quote! { Self::#variant(_) => #variant::NAME, }
    });

    let visit_arms = plan.containers.iter().map(|container| {
        let variant = ident(&container.type_ident);
        quote! { Self::#variant(packet) => packet.for_each_value(visit), }
    });

    quote! {
        /// A packet, decoded as whichever container matched.
        #[derive(Clone, Copy, PartialEq, Debug)]
        pub enum Packet #generics {
            #(#variants)*
        }

        impl #generics #self_ty {
            /// Name of the container this packet matched.
            #[inline]
            pub fn container_name(&self) -> &'static str {
                match self {
                    #(#name_arms)*
                }
            }

            /// Calls `visit(name, raw, engineering)` for every field, in decode order.
            ///
            /// The values borrow for as long as `self` does, so a caller may collect them
            /// rather than only look at them in passing.
            #[inline]
            pub fn for_each_value<'v>(
                &'v self,
                visit: impl FnMut(&'static str, Value<'v>, Value<'v>),
            ) {
                match self {
                    #(#visit_arms)*
                }
            }
        }
    }
}

/// Whether any container in the plan hands out slices of the packet.
fn plan_borrows(plan: &Plan) -> bool {
    plan.containers
        .iter()
        .any(|container| container.fields.iter().any(|field| field.repr.borrows()))
}

/// Emits the dispatcher: read the discriminators, then descend.
fn dispatcher(plan: &Plan) -> TokenStream {
    let borrows = plan_borrows(plan);
    let data_ref = if borrows {
        quote!(&'_ [u8])
    } else {
        quote!(&[u8])
    };
    let return_ty = if borrows {
        quote!(Packet<'_>)
    } else {
        quote!(Packet)
    };
    let head_bytes = head_bytes(plan);
    let head_literal = Literal::usize_unsuffixed(head_bytes);
    let body = descend(plan, &plan.root);
    let root_name = &plan.root_name;

    let head = if head_bytes == 0 {
        quote! {}
    } else {
        quote! {
            // Every discriminator lives in this prefix, so one narrowing serves the whole
            // walk and the guards below index a fixed-size array.
            let head: &[u8; #head_literal] = match data.get(..#head_literal) {
                Some(prefix) => match prefix.try_into() {
                    Ok(array) => array,
                    Err(_) => {
                        return Err(DecodeError::TooShort {
                            needed: #head_literal,
                            got: data.len(),
                        });
                    }
                },
                None => {
                    return Err(DecodeError::TooShort {
                        needed: #head_literal,
                        got: data.len(),
                    });
                }
            };
        }
    };

    let doc = format!(
        " Decodes one packet, starting from `{root_name}`.\n\n \
         Reads the discriminator fields, descends to whichever inheritor's restriction\n \
         criteria hold, and decodes that container. The walk mirrors the interpreted\n \
         decoder exactly, including its treatment of an ambiguous match as an error.\n\n \
         # Errors\n\n \
         See [`DecodeError`]."
    );
    let doc_lines: Vec<TokenStream> = doc.lines().map(|line| quote! { #[doc = #line] }).collect();

    quote! {
        #(#doc_lines)*
        #[inline]
        pub fn decode(data: #data_ref) -> Result<#return_ty, DecodeError> {
            #head
            #body
        }
    }
}

/// The code for one node: choose an inheritor, or stop here.
fn descend(plan: &Plan, node: &Node) -> TokenStream {
    let name = &node.xtce_name;

    let stop = if let Some(index) = node.plan {
        let variant = plan
            .containers
            .get(index)
            .map(|container| ident(&container.type_ident));
        quote! { Ok(Packet::#variant(#variant::decode(data)?)) }
    } else {
        quote! { Err(DecodeError::Unrecognized { container: #name }) }
    };

    if node.children.is_empty() {
        return stop;
    }

    // Every inheritor is tested, not just the first that matches: the interpreted decoder
    // treats two matching inheritors as an ambiguity rather than picking one, and a
    // generated decoder that silently picked one would disagree with it.
    let tests = node
        .children
        .iter()
        .enumerate()
        .map(|(index, (guards, _))| {
            let index = Literal::usize_unsuffixed(index);
            let condition = criterion_condition(guards, &ident("head"));
            quote! {
                if #condition {
                    matched += 1;
                    which = #index;
                }
            }
        });

    let arms = node.children.iter().enumerate().map(|(index, (_, child))| {
        let index = Literal::usize_unsuffixed(index);
        let body = descend(plan, child);
        quote! { #index => { #body } }
    });

    quote! {
        {
            let mut matched = 0u32;
            let mut which = usize::MAX;
            #(#tests)*
            if matched > 1 {
                return Err(DecodeError::Ambiguous { container: #name });
            }
            match which {
                #(#arms)*
                _ => { #stop }
            }
        }
    }
}

/// The condition under which an inheritor is selected.
///
/// A conjunction of comparisons was all this ever had to be until `<BooleanExpression>`
/// arrived; `<ORedConditions>` nests, so it is a tree now. Empty nodes keep the
/// interpreter's answers: `all([])` is true and `any([])` is false.
fn criterion_condition(criterion: &Criterion, packet: &Ident) -> TokenStream {
    match criterion {
        Criterion::Test(guard) => guard_test(guard, packet),
        Criterion::All(children) if children.is_empty() => quote!(true),
        Criterion::Any(children) if children.is_empty() => quote!(false),
        Criterion::All(children) => {
            let tests = children.iter().map(|child| nested_condition(child, packet));
            quote! { #(#tests)&&* }
        }
        Criterion::Any(children) => {
            let tests = children.iter().map(|child| nested_condition(child, packet));
            quote! { #(#tests)||* }
        }
    }
}

/// The same, parenthesised where the precedence of `&&` over `||` would otherwise decide it.
fn nested_condition(criterion: &Criterion, packet: &Ident) -> TokenStream {
    let condition = criterion_condition(criterion, packet);
    match criterion {
        // A comparison is already tighter than either connective.
        Criterion::Test(_) => condition,
        Criterion::All(children) | Criterion::Any(children) if children.is_empty() => condition,
        _ => quote! { (#condition) },
    }
}

fn guard_test(guard: &Guard, head: &Ident) -> TokenStream {
    let raw = read_bits(guard.bit_offset, guard.bit_width, head);
    // A criterion on a little-endian field tests the swapped value, because that is the
    // value the interpreter compares.
    let raw = if guard.swap_bytes {
        swap_bytes_of(raw, guard.bit_offset, guard.bit_width, head)
    } else {
        raw
    };

    // Narrow the comparison to the value's own type where the literal allows it, so the
    // dispatcher compares machine words rather than 128-bit integers.
    let is_signed = matches!(guard.repr, Repr::Signed(_));
    let value = match guard.repr {
        Repr::Signed(coding) => signed(
            &raw,
            guard.bit_width,
            coding,
            guard.swap_bytes && guard.bit_width % 8 != 0,
        ),
        // `&` binds tighter than `==`, so a masked load compares correctly unparenthesised.
        _ => raw.into_tokens(),
    };

    let operator = compare_op(guard.operator);

    if is_signed {
        match i64::try_from(guard.value) {
            Ok(literal) => {
                let literal = Literal::i64_unsuffixed(literal);
                quote! { #value #operator #literal }
            }
            Err(_) => constant_outcome(guard, true),
        }
    } else {
        match u64::try_from(guard.value) {
            Ok(literal) => {
                let literal = Literal::u64_unsuffixed(literal);
                quote! { #value #operator #literal }
            }
            // The literal is outside the field's range, so the comparison has one answer for
            // every possible packet. Emitting the constant is both faster and clearer than
            // widening to `i128` to compute something already known.
            Err(_) => constant_outcome(guard, false),
        }
    }
}

/// The fixed answer to a comparison whose literal cannot fit the field's type.
fn constant_outcome(guard: &Guard, literal_fits_signed: bool) -> TokenStream {
    let literal_below = if literal_fits_signed {
        guard.value < i128::from(i64::MIN)
    } else {
        guard.value < 0
    };
    // The literal cannot equal any value the field can hold, so equality is decided; the
    // ordering operators depend only on which side of the range the literal falls.
    let outcome = match guard.operator {
        CompareOp::Equal => false,
        CompareOp::NotEqual => true,
        CompareOp::Less | CompareOp::LessOrEqual => !literal_below,
        CompareOp::Greater | CompareOp::GreaterOrEqual => literal_below,
    };
    quote! { #outcome }
}

fn compare_op(operator: CompareOp) -> TokenStream {
    match operator {
        CompareOp::Equal => quote!(==),
        CompareOp::NotEqual => quote!(!=),
        CompareOp::Less => quote!(<),
        CompareOp::LessOrEqual => quote!(<=),
        CompareOp::Greater => quote!(>),
        CompareOp::GreaterOrEqual => quote!(>=),
    }
}

/// Bytes the dispatcher must have before it can test any guard.
fn head_bytes(plan: &Plan) -> usize {
    fn reach(criterion: &Criterion, most: &mut usize) {
        match criterion {
            Criterion::Test(guard) => {
                *most = (*most).max(guard.bit_offset + guard.bit_width as usize);
            }
            Criterion::All(children) | Criterion::Any(children) => {
                for child in children {
                    reach(child, most);
                }
            }
        }
    }
    fn walk(node: &Node, most: &mut usize) {
        for (criteria, child) in &node.children {
            reach(criteria, most);
            walk(child, most);
        }
    }
    let mut most = 0;
    walk(&plan.root, &mut most);
    most.div_ceil(8)
}

/// Helper functions the generated code needs, emitted only when something uses them.
fn helpers(plan: &Plan) -> TokenStream {
    let reprs = || {
        plan.containers
            .iter()
            .flat_map(|c| &c.fields)
            .map(|f| &f.repr)
    };
    let needs_half = reprs().any(|repr| *repr == Repr::Float16);
    let needs_mil = reprs().any(|repr| *repr == Repr::Mil1750a);
    let needs_text = reprs().any(|repr| matches!(repr, Repr::Text { .. }));
    let needs_terminator = reprs().any(|repr| {
        matches!(
            repr,
            Repr::Text {
                delimiter: TextDelimiter::TerminationChar(_),
                ..
            }
        )
    });
    let needs_leading = reprs().any(|repr| {
        matches!(
            repr,
            Repr::Text {
                delimiter: TextDelimiter::LeadingSize { .. },
                ..
            }
        )
    });

    // Every calibrator a field can reach, not only its default: a spline used solely by a
    // context still needs its helper emitted, and the compiler is the only thing that would
    // have said so.
    let calibrations = || {
        plan.containers
            .iter()
            .flat_map(|c| &c.fields)
            .flat_map(|f| {
                f.calibration
                    .iter()
                    .chain(f.contexts.iter().map(|context| &context.calibration))
            })
    };
    let needs_power = calibrations().any(|c| matches!(c, Calibration::Polynomial(_)));
    // Every polynomial needs it: the integral path falls back to it on overflow, and the
    // float path is nothing else. So does MIL-STD-1750A, which scales by a power of two.
    let needs_powi = needs_power || needs_mil;
    let needs_spline = calibrations().any(|c| matches!(c, Calibration::Spline(_)));

    // Only where a swap survives the reversed-load shortcut: a field off a byte boundary, or
    // one whose width is not a whole number of bytes, or one past a cursor.
    let needs_swap = plan.containers.iter().flat_map(|c| &c.fields).any(|field| {
        field.swap_bytes
            && field.width.fixed().is_none_or(|width| {
                width > 8 && (field.bit_offset.is_none_or(|at| at % 8 != 0) || width % 8 != 0)
            })
    }) || guards_of(plan).any(|guard| {
        guard.swap_bytes
            && guard.bit_width > 8
            && (guard.bit_offset % 8 != 0 || guard.bit_width % 8 != 0)
    });

    let needs_cursor = plan.containers.iter().any(ContainerPlan::is_dynamic);
    let cursor = if needs_cursor {
        cursor_helpers()
    } else {
        quote!()
    };
    let half = if needs_half { half_helper() } else { quote!() };
    let mil = if needs_mil { mil_helper() } else { quote!() };
    let text = if needs_text { text_helper() } else { quote!() };
    let terminated = if needs_terminator {
        terminated_helper()
    } else {
        quote!()
    };
    let leading = if needs_leading {
        leading_helper()
    } else {
        quote!()
    };
    let swap = if needs_swap { swap_helper() } else { quote!() };

    // Only where a polynomial over an integral encoding actually appears: the helper is only
    // reachable from that path, and an unused function in generated code is noise a reviewer
    // has to rule out.
    let power = if needs_power {
        integer_power_helper()
    } else {
        quote!()
    };
    let powi = if needs_powi { powi_helper() } else { quote!() };
    let spline = if needs_spline {
        spline_helpers()
    } else {
        quote!()
    };

    quote! {
        #cursor
        #half
        #mil
        #text
        #terminated
        #leading
        #swap
        #powi
        #power
        #spline
    }
}

/// `base^exponent` as the reference computes it for an integral raw value.
///
/// Exactly, in `i128`, converted once — not by repeated `f64` multiplication, which rounds at
/// every step. The reference uses arbitrary-precision integers, so for anything that fits in
/// an `i128` this is the same number; when it does not fit there is no exact route left and
/// both fall back to floating point.
fn integer_power_helper() -> TokenStream {
    quote! {
        fn integer_power(base: i128, exponent: i32) -> f64 {
            if exponent < 0 {
                return powi(base as f64, exponent);
            }
            match u32::try_from(exponent)
                .ok()
                .and_then(|exponent| base.checked_pow(exponent))
            {
                Some(exact) => exact as f64,
                None => powi(base as f64, exponent),
            }
        }
    }
}

/// Every guard anywhere in the tree.
fn guards_of(plan: &Plan) -> impl Iterator<Item = &Guard> {
    fn collect<'a>(criterion: &'a Criterion, out: &mut Vec<&'a Guard>) {
        match criterion {
            Criterion::Test(guard) => out.push(guard),
            Criterion::All(children) | Criterion::Any(children) => {
                for child in children {
                    collect(child, out);
                }
            }
        }
    }
    fn walk<'a>(node: &'a Node, out: &mut Vec<&'a Guard>) {
        for (criteria, child) in &node.children {
            collect(criteria, out);
            walk(child, out);
        }
    }
    let mut out = Vec::new();
    walk(&plan.root, &mut out);
    out.into_iter()
}

/// Reverses a field's bytes, as `leastSignificantByteFirst` means it.
///
/// Line for line what `xtce_decode::bits::swap_byte_order` does, which in turn is what the
/// reference does: `int.from_bytes(val.to_bytes(ceil(width / 8), "little"), "big")`. Note
/// that for a width which is not a whole number of bytes the result can be *wider* than the
/// field — a twelve-bit `0x0AB` comes back as `0xAB00`. That is not a mistake to be fixed
/// here; it is what the reference computes, and a signed coding then discards the excess
/// while an unsigned one does not.
fn swap_helper() -> TokenStream {
    quote! {
        fn swap_byte_order(value: u64, width: u32) -> u64 {
            let bytes = (width as usize).div_ceil(8);
            if bytes <= 1 {
                return value;
            }
            let mut out = 0u64;
            let mut remaining = value;
            for _ in 0..bytes {
                out = (out << 8) | (remaining & 0xFF);
                remaining >>= 8;
            }
            out
        }
    }
}

/// MIL-STD-1750A, which is not a float format in the IEEE sense.
///
/// A 24-bit two's-complement mantissa in the top of the word and an 8-bit two's-complement
/// exponent in the bottom, neither biased, no implicit leading one, no infinities and no
/// NaN. Line for line what `xtce_decode::decoder::mil_std_1750a` computes, which in turn is
/// what the reference computes: `mantissa * 2 ** (exponent - 23)`.
///
/// Both fields are masked before the sign extension, so the shifts below have nothing above
/// their width to discard and the masking and unmasked forms coincide.
fn mil_helper() -> TokenStream {
    quote! {
        fn mil_std_1750a(bits: u64) -> f64 {
            let word = bits as u32;
            let exponent = ((((word & 0xFF) as u64) << 56) as i64) >> 56;
            let mantissa = (((((word >> 8) & 0x00FF_FFFF) as u64) << 40) as i64) >> 40;
            (mantissa as f64) * powi(2.0, (exponent as i32) - 23)
        }
    }
}

/// `f64::powi`, written out.
///
/// Not a nicety: `powi` lives in `std`, and this file names nothing outside `core` so that it
/// can be included in a bare-metal build. The sequence below is the one `powi` performs —
/// square and multiply, lowest bit first — so it is bit-identical, which matters because the
/// interpreter this is compared against calls the real thing.
fn powi_helper() -> TokenStream {
    quote! {
        fn powi(x: f64, exponent: i32) -> f64 {
            // `unsigned_abs`, not negation: `-i32::MIN` overflows.
            let mut remaining = exponent.unsigned_abs();
            let mut result = 1.0f64;
            let mut base = x;
            let mut started = false;
            while remaining > 0 {
                if remaining & 1 == 1 {
                    result = if started { result * base } else { base };
                    started = true;
                }
                remaining >>= 1;
                if remaining > 0 {
                    base = base * base;
                }
            }
            let value = if started { result } else { 1.0 };
            if exponent < 0 { 1.0 / value } else { value }
        }
    }
}

/// Spline interpolation, line for line as `xtce_decode::calibrate::interpolate` does it.
///
/// The order and the extrapolation flag are passed in rather than specialised away, so that
/// the two implementations can be read side by side; both are constants at every call site,
/// so nothing survives optimisation.
///
/// Orders above one and an empty point list are refused when the code is generated, which is
/// why the only failure left here is a query outside the points.
fn spline_helpers() -> TokenStream {
    quote! {
        fn spline_line(x: f64, x0: f64, x1: f64, y0: f64, y1: f64) -> f64 {
            if (x1 - x0) == 0.0 {
                return y0;
            }
            let slope = (y1 - y0) / (x1 - x0);
            slope * (x - x0) + y0
        }

        fn spline_value(
            points: &[(f64, f64)],
            order: u8,
            extrapolate: bool,
            query: f64,
        ) -> Option<f64> {
            let first = *points.first()?;
            let last = *points.last()?;

            if query < first.0 {
                if !extrapolate {
                    return None;
                }
                return Some(match order {
                    0 => first.1,
                    _ => match points.get(1) {
                        Some(second) => {
                            spline_line(query, first.0, second.0, first.1, second.1)
                        }
                        None => first.1,
                    },
                });
            }

            if query > last.0 {
                if !extrapolate {
                    return None;
                }
                return Some(match order {
                    0 => last.1,
                    _ => match points.len().checked_sub(2).and_then(|at| points.get(at)) {
                        Some(previous) => {
                            spline_line(query, previous.0, last.0, previous.1, last.1)
                        }
                        None => last.1,
                    },
                });
            }

            // The index of the first point strictly above the query. A NaN query makes both
            // comparisons above false and every predicate here false too, so it lands at
            // zero — which is what the floor is for.
            let hi = points.partition_point(|point| point.0 <= query).max(1);

            Some(match order {
                0 => points.get(hi - 1).map_or(first.1, |point| point.1),
                _ => {
                    if points.len() < 2 {
                        return Some(first.1);
                    }
                    // A query equal to the last raw value has no point above it;
                    // interpolating over the final segment lands exactly on it.
                    let upper = hi.min(points.len() - 1);
                    match (points.get(upper - 1), points.get(upper)) {
                        (Some(lower), Some(higher)) => {
                            spline_line(query, lower.0, higher.0, lower.1, higher.1)
                        }
                        _ => first.1,
                    }
                }
            })
        }
    }
}

/// Readers for the part of a container that follows a data-dependent width.
///
/// Only emitted when a container needs them. Their offsets are run-time values, which is
/// unavoidable: what follows a field whose width the packet decides is at a position the
/// packet decides. Everything before it is still read at literal offsets.
fn cursor_helpers() -> TokenStream {
    quote! {
        /// Reads `width` bits at a run-time bit offset.
        ///
        /// A 64-bit field at a non-zero bit offset spans nine bytes, so the accumulator is a
        /// `u128`; loading eight bytes and shifting would silently truncate it.
        #[inline]
        fn read_at(
            data: &[u8],
            at: usize,
            width: u32,
            parameter: &'static str,
        ) -> Result<u64, DecodeError> {
            if width == 0 {
                return Ok(0);
            }
            let end = at.saturating_add(width as usize);
            if end > data.len().saturating_mul(8) {
                return Err(DecodeError::TooShort {
                    needed: end.div_ceil(8),
                    got: data.len(),
                });
            }

            let byte = at / 8;
            let bit_in_byte = (at % 8) as u32;
            let mut window = [0u8; 16];
            let tail = data.get(byte..).unwrap_or_default();
            let take = tail.len().min(16);
            if let (Some(slot), Some(source)) = (window.get_mut(..take), tail.get(..take)) {
                slot.copy_from_slice(source);
            }
            let window = u128::from_be_bytes(window);

            let shift = 128 - bit_in_byte - width;
            let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
            let _ = parameter;
            Ok(((window >> shift) as u64) & mask)
        }

        /// Borrows `bits` bits at a run-time bit offset, as bytes.
        #[inline]
        fn take_bytes<'a>(
            data: &'a [u8],
            at: usize,
            bits: usize,
            parameter: &'static str,
        ) -> Result<&'a [u8], DecodeError> {
            if at % 8 != 0 || bits % 8 != 0 {
                return Err(DecodeError::Unaligned { parameter, at, bits });
            }
            let start = at / 8;
            let end = start.saturating_add(bits / 8);
            data.get(start..end).ok_or(DecodeError::TooShort {
                needed: end,
                got: data.len(),
            })
        }
    }
}

/// The shared validator every text helper ends in.
fn text_helper() -> TokenStream {
    quote! {
        /// Validates a byte range as text and returns it borrowed from the packet.
        ///
        /// Invalid bytes are an error, never a replacement character: a corrupt field must
        /// not come back looking like a plausible string.
        #[inline]
        fn text_checked<'a>(
            bytes: &'a [u8],
            ascii: bool,
            parameter: &'static str,
        ) -> Result<&'a str, DecodeError> {
            if ascii && !bytes.is_ascii() {
                return Err(DecodeError::InvalidText { parameter });
            }
            core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidText { parameter })
        }

        /// The whole buffer is the string.
        #[inline]
        fn text_whole<'a>(
            buffer: &'a [u8],
            ascii: bool,
            parameter: &'static str,
        ) -> Result<&'a str, DecodeError> {
            text_checked(buffer, ascii, parameter)
        }
    }
}

fn terminated_helper() -> TokenStream {
    quote! {
        /// The string ends at the first occurrence of `terminator`.
        #[inline]
        fn text_terminated<'a>(
            buffer: &'a [u8],
            terminator: &[u8],
            ascii: bool,
            parameter: &'static str,
        ) -> Result<&'a str, DecodeError> {
            if terminator.is_empty() {
                return text_checked(&buffer[..0], ascii, parameter);
            }
            let end = buffer
                .windows(terminator.len())
                .position(|window| window == terminator)
                .ok_or(DecodeError::UnterminatedString { parameter })?;
            match buffer.get(..end) {
                Some(text) => text_checked(text, ascii, parameter),
                None => Err(DecodeError::BadStringLength { parameter }),
            }
        }
    }
}

fn leading_helper() -> TokenStream {
    quote! {
        /// The buffer starts with a length, in bits, of `size_in_bits`.
        #[inline]
        fn text_leading<'a>(
            buffer: &'a [u8],
            size_in_bits: u32,
            ascii: bool,
            parameter: &'static str,
        ) -> Result<&'a str, DecodeError> {
            let prefix_bytes = (size_in_bits as usize).div_ceil(8);
            let mut length_bits: u64 = 0;
            for index in 0..prefix_bytes {
                let byte = *buffer
                    .get(index)
                    .ok_or(DecodeError::BadStringLength { parameter })?;
                length_bits = (length_bits << 8) | u64::from(byte);
            }
            // The prefix is right-aligned within whole bytes, matching how the interpreter
            // reads it.
            let slack = prefix_bytes as u32 * 8 - size_in_bits;
            length_bits >>= slack;
            if length_bits % 8 != 0 {
                return Err(DecodeError::BadStringLength { parameter });
            }
            let length = (length_bits / 8) as usize;
            match buffer.get(prefix_bytes..prefix_bytes + length) {
                Some(text) => text_checked(text, ascii, parameter),
                None => Err(DecodeError::BadStringLength { parameter }),
            }
        }
    }
}

fn half_helper() -> TokenStream {
    quote! {
        /// Widens IEEE-754 binary16 to `f64`, exactly.
        ///
        /// Subnormals need renormalising: for a subnormal fraction `m` the value is
        /// `m * 2^-24`, so with `p` the index of its highest set bit the `f32` exponent
        /// field is `p + 103`.
        #[inline]
        fn half_to_f64(bits: u16) -> f64 {
            let sign = u32::from(bits >> 15) << 31;
            let exponent = u32::from((bits >> 10) & 0x1F);
            let fraction = u32::from(bits & 0x03FF);
            let single = match exponent {
                0 if fraction == 0 => f32::from_bits(sign),
                0 => {
                    let shift = fraction.leading_zeros() - 21;
                    let exponent = 113 - shift;
                    let fraction = (fraction << shift) & 0x03FF;
                    f32::from_bits(sign | (exponent << 23) | (fraction << 13))
                }
                0x1F => f32::from_bits(sign | 0x7F80_0000 | (fraction << 13)),
                _ => f32::from_bits(sign | ((exponent + 127 - 15) << 23) | (fraction << 13)),
            };
            f64::from(single)
        }
    }
}

fn ident(name: &str) -> Ident {
    Ident::new(name, Span::call_site())
}
