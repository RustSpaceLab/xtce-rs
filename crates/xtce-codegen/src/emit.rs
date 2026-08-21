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

use crate::plan::{ContainerPlan, Field, Guard, Node, Plan, Repr};
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
                }
            }
        }

        impl core::error::Error for DecodeError {}

        /// A decoded value, in the same shape the interpreted decoder produces.
        #[derive(Clone, Copy, PartialEq, Debug)]
        pub enum Value {
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
        }
    }
}

fn container(plan: &ContainerPlan) -> TokenStream {
    let type_ident = ident(&plan.type_ident);
    let xtce_name = &plan.xtce_name;
    let bit_length = Literal::usize_unsuffixed(plan.bit_length);
    let byte_length = Literal::usize_unsuffixed(plan.bit_length.div_ceil(8));

    let doc = format!(
        " `{xtce_name}`: {} field(s) in {} bit(s).",
        plan.fields.len(),
        plan.bit_length
    );

    let fields = plan.fields.iter().map(|field| {
        let name = ident(&field.ident);
        let ty = rust_type(&field.repr);
        let doc = format!(
            " `{}` — {} bit(s) at bit {}.{}",
            field.xtce_name,
            field.bit_width,
            field.bit_offset,
            match &field.repr {
                Repr::Bool => " Stored raw; see the accessor for the boolean value.",
                Repr::Enumerated(_) => " Stored raw; see the accessor for the label.",
                _ => "",
            }
        );
        quote! {
            #[doc = #doc]
            pub #name: #ty,
        }
    });

    let assignments = plan.fields.iter().map(|field| {
        let name = ident(&field.ident);
        let value = read_field(field, &ident("packet"));
        quote! { #name: #value, }
    });

    let accessors = plan.fields.iter().filter_map(accessor);

    let visits = plan.fields.iter().map(|field| {
        let name = ident(&field.ident);
        let xtce_name = &field.xtce_name;
        let (raw, eng) = visit_values(field, &name);
        quote! { visit(#xtce_name, #raw, #eng); }
    });

    let field_names = plan.fields.iter().map(|field| {
        let name = &field.xtce_name;
        quote! { #name }
    });
    let field_count = Literal::usize_unsuffixed(plan.fields.len());

    quote! {
        #[doc = #doc]
        #[derive(Clone, Copy, PartialEq, Debug, Default)]
        pub struct #type_ident {
            #(#fields)*
        }

        impl #type_ident {
            /// Name of this container in the XTCE definition.
            pub const NAME: &'static str = #xtce_name;

            /// Total width of this container's fields, in bits.
            pub const BIT_LENGTH: usize = #bit_length;

            /// Bytes a packet must have for this container to decode.
            pub const BYTE_LENGTH: usize = #byte_length;

            /// Parameter names, in decode order.
            pub const FIELDS: [&'static str; #field_count] = [#(#field_names),*];

            /// Decodes this container from the start of `data`.
            ///
            /// # Errors
            ///
            /// [`DecodeError::TooShort`] if the packet is smaller than [`Self::BYTE_LENGTH`].
            #[inline]
            pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
                // Narrowing to a fixed-size array once is what removes the bounds check from
                // every field read below, with no `unsafe`.
                let packet: &[u8; Self::BYTE_LENGTH] = match data.get(..Self::BYTE_LENGTH) {
                    Some(prefix) => match prefix.try_into() {
                        Ok(array) => array,
                        Err(_) => {
                            return Err(DecodeError::TooShort {
                                needed: Self::BYTE_LENGTH,
                                got: data.len(),
                            });
                        }
                    },
                    None => {
                        return Err(DecodeError::TooShort {
                            needed: Self::BYTE_LENGTH,
                            got: data.len(),
                        });
                    }
                };
                Ok(Self { #(#assignments)* })
            }

            /// Calls `visit(name, raw, engineering)` for every field, in decode order.
            #[inline]
            pub fn for_each_value(&self, mut visit: impl FnMut(&'static str, Value, Value)) {
                #(#visits)*
            }

            #(#accessors)*
        }
    }
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

/// The `(raw, engineering)` pair a field contributes to `for_each_value`.
fn visit_values(field: &Field, stored: &Ident) -> (TokenStream, TokenStream) {
    match &field.repr {
        Repr::Unsigned => (
            quote! { Value::Unsigned(self.#stored) },
            quote! { Value::Unsigned(self.#stored) },
        ),
        Repr::Signed(_) => (
            quote! { Value::Signed(self.#stored) },
            quote! { Value::Signed(self.#stored) },
        ),
        Repr::Float16 | Repr::Float32 | Repr::Float64 => (
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
    }
}

fn rust_type(repr: &Repr) -> TokenStream {
    match repr {
        Repr::Unsigned | Repr::Bool | Repr::Enumerated(_) => quote!(u64),
        Repr::Signed(_) => quote!(i64),
        Repr::Float16 | Repr::Float32 | Repr::Float64 => quote!(f64),
    }
}

/// The expression that turns a field's bits into its stored value.
fn read_field(field: &Field, packet: &Ident) -> TokenStream {
    let raw = read_bits(field.bit_offset, field.bit_width, packet);
    match &field.repr {
        Repr::Unsigned | Repr::Bool | Repr::Enumerated(_) => raw,
        Repr::Signed(coding) => signed(&raw, field.bit_width, *coding),
        Repr::Float16 => quote! { half_to_f64(#raw as u16) },
        Repr::Float32 => quote! { f64::from(f32::from_bits(#raw as u32)) },
        Repr::Float64 => quote! { f64::from_bits(#raw) },
    }
}

fn signed(raw: &TokenStream, width: u32, coding: IntegerCoding) -> TokenStream {
    match coding {
        IntegerCoding::Unsigned => quote! { #raw as i64 },
        IntegerCoding::TwosComplement => {
            // Sign-extend by shifting. Subtracting `2 ^ width` overflows at width 63.
            let shift = Literal::u32_unsuffixed(64 - width);
            quote! { ((#raw << #shift) as i64) >> #shift }
        }
        IntegerCoding::SignMagnitude => {
            let sign = Literal::u64_unsuffixed(1u64 << (width - 1));
            let magnitude = Literal::u64_unsuffixed((1u64 << (width - 1)) - 1);
            quote! {
                {
                    let raw = #raw;
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
                    let raw = #raw;
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
fn read_bits(offset: usize, width: u32, packet: &Ident) -> TokenStream {
    let first = offset / 8;
    let last = (offset + width as usize - 1) / 8;
    let span = last - first + 1;
    let bit_in_byte = (offset % 8) as u32;
    let mask = mask_for(width);

    // A span of nine bytes only happens for wide fields at an unaligned offset, and it is
    // exactly the case a single 64-bit load gets wrong.
    let (accumulator, accumulator_bits) = if span <= 8 {
        (quote!(u64), 64u32)
    } else {
        (quote!(u128), 128u32)
    };
    let slots = (accumulator_bits / 8) as usize;
    let pad = slots - span;

    let bytes = (0..pad)
        .map(|_| quote!(0))
        .chain((first..=last).map(|index| {
            let index = Literal::usize_unsuffixed(index);
            quote! { #packet[#index] }
        }));
    let load = quote! { #accumulator::from_be_bytes([#(#bytes),*]) };

    let shift = (span as u32) * 8 - bit_in_byte - width;
    let whole = shift == 0 && width == (span as u32) * 8;

    match (whole, span <= 8) {
        // A field that fills its bytes exactly needs neither shift nor mask.
        (true, true) => load,
        (true, false) => quote! { #load as u64 },
        (false, true) if shift == 0 => {
            let mask = Literal::u64_unsuffixed(mask);
            quote! { #load & #mask }
        }
        (false, true) => {
            let shift = Literal::u32_unsuffixed(shift);
            let mask = Literal::u64_unsuffixed(mask);
            quote! { (#load >> #shift) & #mask }
        }
        (false, false) => {
            let shift = Literal::u32_unsuffixed(shift);
            let mask = Literal::u64_unsuffixed(mask);
            quote! { ((#load >> #shift) as u64) & #mask }
        }
    }
}

fn packet_enum(plan: &Plan) -> TokenStream {
    let variants = plan.containers.iter().map(|container| {
        let variant = ident(&container.type_ident);
        let doc = format!(" A packet decoded as `{}`.", container.xtce_name);
        quote! {
            #[doc = #doc]
            #variant(#variant),
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
        pub enum Packet {
            #(#variants)*
        }

        impl Packet {
            /// Name of the container this packet matched.
            #[inline]
            pub fn container_name(&self) -> &'static str {
                match self {
                    #(#name_arms)*
                }
            }

            /// Calls `visit(name, raw, engineering)` for every field, in decode order.
            #[inline]
            pub fn for_each_value(&self, visit: impl FnMut(&'static str, Value, Value)) {
                match self {
                    #(#visit_arms)*
                }
            }
        }
    }
}

/// Emits the dispatcher: read the discriminators, then descend.
fn dispatcher(plan: &Plan) -> TokenStream {
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
        pub fn decode(data: &[u8]) -> Result<Packet, DecodeError> {
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
            let condition = guard_condition(guards);
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
fn guard_condition(guards: &[Guard]) -> TokenStream {
    if guards.is_empty() {
        // `all([])` is true, which is what the interpreted decoder does. It is usually a
        // modelling mistake and shows up as an ambiguity, not as a silent choice.
        return quote!(true);
    }
    let tests = guards.iter().map(guard_test);
    quote! { #(#tests)&&* }
}

fn guard_test(guard: &Guard) -> TokenStream {
    let head = ident("head");
    let raw = read_bits(guard.bit_offset, guard.bit_width, &head);

    // Narrow the comparison to the value's own type where the literal allows it, so the
    // dispatcher compares machine words rather than 128-bit integers.
    let is_signed = matches!(guard.repr, Repr::Signed(_));
    let value = match guard.repr {
        Repr::Signed(coding) => signed(&raw, guard.bit_width, coding),
        _ => raw,
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
    fn walk(node: &Node, most: &mut usize) {
        for (guards, child) in &node.children {
            for guard in guards {
                *most = (*most).max(guard.bit_offset + guard.bit_width as usize);
            }
            walk(child, most);
        }
    }
    let mut most = 0;
    walk(&plan.root, &mut most);
    most.div_ceil(8)
}

/// Helper functions the generated code needs, emitted only when something uses them.
fn helpers(plan: &Plan) -> TokenStream {
    let needs_half = plan
        .containers
        .iter()
        .flat_map(|container| &container.fields)
        .any(|field| field.repr == Repr::Float16);

    if !needs_half {
        return quote! {};
    }

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
