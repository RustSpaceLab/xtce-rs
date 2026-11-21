# Audyt Repozytorium, Rejestr Decyzji Architektonicznych (ADR) oraz Macierz Pokrycia XTCE 1.2 (2027)

> **Status dokumentu:** Zatwierdzony (Baseline Architektoniczny 2027)  
> **Repozytorium:** `RustSpaceLab/xtce-rs` (wersja workspace `0.2.1`, Rust Edition `2024`, MSRV `1.85`)  
> **Zakres:** Zadania 1, 2, 3, 4 i 5 z planu *RustSpaceLab Roadmap & Architektura 2027*

---

## 1. Zadanie 1: Audyt Repozytorium (`crates/*` oraz `xtask`)

### 1.1. Podsumowanie struktury Workspace i poszczególnych Crates

Główny plik `Cargo.toml` (linie `1–48`) definiuje workspace z `resolver = "3"`, `edition = "2024"` oraz `rust-version = "1.85"`. Członkami workspace są `crates/*` oraz `xtask`, z celowym wykluczeniem `crates/xtce-py` (`exclude = ["crates/xtce-py"]`, linia `7`), aby `cargo build --workspace` nie wymagało obecności biblioteki `libpython` na maszynach CI testujących czysty łańcuch narzędziowy Rust.

| Crate / Moduł | Ścieżka | Typ | Środowisko (`std`/`no_std`) | Zależności produkcyjne (`[dependencies]`) | Liczba testów `#[test]` |
|---|---|---|---|---|---|
| **`xtce-model`** | `crates/xtce-model` | `lib` | `std` | `quick-xml = "0.38"`, `thiserror = "2"` | **46** (7 unit + 39 integr.) |
| **`xtce-decode`** | `crates/xtce-decode` | `lib` | `std` | `xtce-model`, `thiserror = "2"` | **74** (34 unit + 40 integr.) |
| **`xtce-codegen`** | `crates/xtce-codegen` | `lib` (emituje kod `core`/`no_std`) | `std` (generator) / `core` (wyjście) | `xtce-model`, `thiserror = "2"`, `proc-macro2 = "1"`, `quote = "1"`, `prettyplease = "0.2"`, `syn = "2"` | **15** (1 unit + 14 integr.) |
| **`xtce-codegen-e2e`** | `crates/xtce-codegen-e2e` | `lib` (`publish = false`) | `std` | `[build-dependencies]`: `xtce-model`, `xtce-codegen`; `[dev-dependencies]`: `xtce-model`, `xtce-decode` | **19** (19 integr. E2E) |
| **`xtce-pus`** | `crates/xtce-pus` | `lib` | **`#![no_std]`** (zero alokacji) | **Brak (`0` zależności zewnętrznych)** | **9** (9 unit/HIL) |
| **`xtce-wasm`** | `crates/xtce-wasm` | `cdylib` + `rlib` | `std` + `wasm32-unknown-unknown` (C-ABI, zero bindgen) | `xtce-model`, `xtce-decode`, `xtce-pus` | **3** (3 unit/HIL/PCAP) |
| **`xtce-cli`** | `crates/xtce-cli` | `bin` (`xtce`) | `std` | `xtce-model`, `xtce-decode`, `xtce-codegen`, `xtce-pus`, `clap = "4"` (`derive`) | **42** (42 unit, w tym `lsp` i `compile`) |
| **`xtce-py`** | `crates/xtce-py` | `cdylib` (`xtce`, osobny workspace) | `std` + CPython ABI3 | `xtce-model`, `xtce-decode`, `pyo3 = "0.28"` (`abi3-py310`, `extension-module`) | **14** uruchomień `pytest` (6 funkcji + 2×4 parametryzacji) |
| **`xtask`** | `xtask` | `bin` (`publish = false`) | `std` | `xtce-model`, `xtce-decode`, `serde_json = "1"`, `clap = "4"` | **12** (12 unit) |

*Łączna liczba testów Rust (`#[test]` w workspace):* **219 testów** (+ 5 doc-testów + 14 przypadków testowych `pytest` w `crates/xtce-py/tests/test_against_reference.py` oraz 18 zestawów referencyjnych *golden files* weryfikowanych przez `cargo xtask diff`).

---

### 1.2. Publiczne API poszczególnych Crates

#### 1.2.1. `xtce-model` (`crates/xtce-model/src/lib.rs`)
* **Główny punkt wejścia (IR bazy telemetrycznej i telekomend):**
  * `XtceDb` (`crates/xtce-model/src/db.rs:35`): `XtceDb::from_path(path)` (linia `114`), `XtceDb::from_xml(text)` (linia `132`), `source()`, `xmlns()`, `skipped_sections()`, `unsupported()`, `interner()`, `name(NameId)`, `space_systems()`, `types()`, `parameters()`, `containers()`, `entries()`, `meta_commands()`, `meta_command(MetaCommandId)`, `fixed_value(Span)`, `find_meta_command(&str)`, `root_containers()`, `space_system(SpaceSystemId)`, `parameter(ParamId)`, `parameter_type(TypeId)`, `container(ContainerId)`, `container_entries(ContainerId)`, `type_of(ParamId)`, `find_parameter(&str)`, `find_container(&str)`, `find_type(&str)`, `boolean_label(TypeId, bool)`, `default_root_container()`, `stats() -> Stats`.
  * **Silnie typowane identyfikatory aren (`crates/xtce-model/src/ids.rs`):** `SpaceSystemId`, `TypeId`, `ParamId`, `ContainerId`, `MetaCommandId`, `Span`.
  * **Interner napisów (`crates/xtce-model/src/intern.rs`):** `Interner`, `NameId`.
  * **Reprezentacja typów i kodowań (`crates/xtce-model/src/types.rs`):** `Parameter`, `ParameterType`, `TypeKind` (`Integer`, `Float`, `Enumerated`, `Boolean`, `String`, `Binary`, `AbsoluteTime`, `RelativeTime`, `Array`, `Aggregate`, `Unsupported`), `DataEncoding` (`Integer`, `Float`, `String`, `Binary`, `None`), `IntegerEncoding`, `IntegerCoding`, `FloatEncoding`, `FloatCoding`, `StringEncoding`, `StringDelimiter`, `Charset`, `BinaryEncoding`, `ByteOrder`, `SizeSpec` (`Fixed`, `Dynamic`, `DiscreteLookup`, `Unsupported`), `LinearAdjustment`, `DiscreteLookup`, `EnumerationList`, `Enumeration`, `Calibrator` (`Polynomial`, `Spline`, `Unsupported`), `ContextCalibrator`, `PolynomialTerm`, `Spline`, `SplinePoint`, `ArrayDimension`, `AggregateMember`.
  * **Kontenery i kryteria (`crates/xtce-model/src/containers.rs`):** `SpaceSystem`, `Container`, `Entry`, `EntryKind` (`Parameter`, `Container`, `FixedValue`, `Unsupported`), `Location`, `LocationReference`, `MatchCriteria` (`Comparison`, `Boolean`, `Unsupported`), `Comparison`, `ComparisonValue`, `CompareOp`, `BooleanExpr` (`Condition`, `And`, `Or`), `Condition`, `Operand`.
  * **Telekomendy (`crates/xtce-model/src/commands.rs`):** `MetaCommand`.
  * **Drzewo DOM XML (`crates/xtce-model/src/xml.rs`):** `Dom`, `Element`, `Node`, `Children`, `Tag`, `AttrKey`.
  * **Błędy i diagnostyka (`crates/xtce-model/src/error.rs`):** `XtceError` (`#[non_exhaustive]`), `ParseError`, `RefKind`, `Unsupported`, `Stats`.

#### 1.2.2. `xtce-decode` (`crates/xtce-decode/src/lib.rs`)
* **Interpreter pakietów (`crates/xtce-decode/src/decoder.rs`):**
  * `Decoder<'db>` (linia `31`): `Decoder::new(&'db XtceDb)` (linia `49`), `Decoder::with_root(&'db XtceDb, &str)` (linia `63`), `db()`, `root()`, `decode<'p>(&self, data: &'p [u8]) -> Result<DecodedPacket<'db, 'p>, DecodeError>` (linia `102`), `decode_into<'p>(&self, packet: &mut DecodedPacket<'db, 'p>, data: &'p [u8]) -> Result<(), DecodeError>` (linia `132`), `new_packet<'p>(&self, data: &'p [u8]) -> DecodedPacket<'db, 'p>` (linia `195`).
* **Ramkowanie CCSDS Space Packet (`crates/xtce-decode/src/ccsds.rs`):**
  * `PRIMARY_HEADER_BYTES` (`6`), `SpacePacketBytes<'a>` (metody: `new`, `bytes`, `version`, `packet_type`, `secondary_header_flag`, `apid`, `sequence_flags`, `sequence_count`, `data_length`, `user_data`).
  * `PacketIter<'a>` (linia `131`): bezalokacyjny iterator po wycinku `&'a [u8]` z obsługą `skip_header_bytes`.
  * `PacketReader<R: Read>` (linia `242`): strumieniowy czytnik z dowolnego źródła `std::io::Read` z reużywalnym buforem wewnętrznym (`next_packet(&mut self)`).
  * Błędy ramkowania: `FramingError` (`ShortHeader`, `ShortPacket`), `PacketReadError` (`Framing`, `Io`).
* **Wartości i kursor bitowy (`crates/xtce-decode/src/value.rs`, `bits.rs`, `error.rs`):**
  * `DecodedPacket<'db, 'p>`, `ParameterValue<'db, 'p>`, `RawValue<'p>` (`Unsigned(u64)`, `Signed(i64)`, `Float(f64)`, `Bytes(Cow<'p, [u8]>)`), `EngValue<'db, 'p>` (`Unsigned(u64)`, `Signed(i64)`, `Float(f64)`, `Bool(bool)`, `Label(&'db str)`, `Text(Cow<'p, str>)`, `Bytes(Cow<'p, [u8]>)`).
  * `BitCursor<'a>`, `BitError`, `DecodeError` (`#[non_exhaustive]`).

#### 1.2.3. `xtce-codegen` (`crates/xtce-codegen/src/lib.rs`)
* **Generator statycznych dekoderów Rust (`crates/xtce-codegen/src/lib.rs`):**
  * `generate(db: &XtceDb, options: &Options) -> Result<String, CodegenError>` (linia `100`).
  * `plan(db: &XtceDb, options: &Options) -> Result<Plan, CodegenError>` (linia `125`).
  * `Options` (`root: Option<String>`, `source_label: Option<String>`), `CodegenError` (`NoSuchContainer`, `AmbiguousRoot`, `Unsupported`, `DanglingIndex`).
* **Planer układu bitowego (`crates/xtce-codegen/src/plan.rs`):**
  * `Plan`, `Node`, `ContainerPlan`, `Field`, `FixedBits`, `Guard`, `GuardTest`, `Criterion`, `Calibration`, `ContextCalibration`, `Repr`, `TextCharset`, `TextDelimiter`, `Width`, `plan::build(db, root)`, `field_ident(&str)`, `type_ident(&str)`.
* **Właściwości generowanego kodu (`crates/xtce-codegen/src/emit.rs`):**
  * Wygenerowany moduł używa wyłącznie biblioteki `core` (kompatybilny z `#![no_std]`, w tym własna implementacja `powi` oraz `integer_power`), nie zawiera ani jednego bloku `unsafe`, a sprawdzanie granic tablic eliminuje poprzez jednokrotne zawężenie wycinka do tablicy stałego rozmiaru `&[u8; N]` (`emit.rs:466–482`).

#### 1.2.4. `xtce-pus` (`crates/xtce-pus/src/lib.rs`)
* **`#![no_std]` implementacja ECSS-E-ST-70-41C (PUS-C) oraz OBC HIL Responder:**
  * **Ramkowanie (`packet.rs`):** `PusPacket<'a>::parse(&'a [u8])`, `PusHeader` (`Telemetry`, `Telecommand`), `AckFlags`, `CucTimestamp`, `TmParams`, `TcParams`, `encode_tm`, `encode_tc`, `PusError`.
  * **Usługi PUS (`services.rs`):** `PusService` (`ST[01]` Verification, `ST[03]` Housekeeping, `ST[05]` Event Reporting, `ST[06]` Memory Management, `ST[08]` Function Management, `ST[11]` Time-Based Scheduling, `ST[12]` On-Board Monitoring, `ST[17]` Test, `ST[20]` Parameter Management), `ObcHousekeeping`.
  * **Bezpieczeństwo telekomend (`security.rs`):** `TcSecurityGate` (`new`, `last_counter`, `verify_and_strip`), `compute_mac_tag` (SipHash-2-4, 64-bit MAC), `build_auth_trailer` (12-bajtowy trailer: 4B licznik anty-replay + 8B MAC), `SecurityError` (`MissingTrailer`, `ReplayAttack`, `InvalidMacTag`).
  * **Symulator OBC HIL (`hil.rs`):** `PusResponder` (`new`, `with_security_key`, `tick_second`, `process_telecommand`).
  * **Suma kontrolna (`crc.rs`):** `crc16_ccitt`, `verify_crc16_ccitt`.

#### 1.2.5. `xtce-cli` (`crates/xtce-cli/src/main.rs`)
* Narzędzie wiersza poleceń `xtce` z 13 podkomendami (`Command` enum):
  1. `xtce info <files...> [--verbose]` (`src/info.rs`)
  2. `xtce decode <definition> <packets> [--root] [--skip-header-bytes] [--limit] [--param] [--format table|jsonl|csv] [--raw] [--no-summary]` (`src/decode.rs`)
  3. `xtce codegen <definition> [--root] [--out]` (`src/main.rs`)
  4. `xtce compile <definition> [--target rust-ground|wireshark|json-schema|docs|dashboard|c-header|python-ctypes] [--root] [--out]` (`src/compile.rs` — wielocelowy kompilator misji XTCE)
  5. `xtce wireshark <definition> [--root] [--out] [--udp-port]` (`src/wireshark.rs` — generator dysektora Lua dla Wireshark)
  6. `xtce pcap <packets> [--out] [--skip-header-bytes] [--limit]` (`src/pcap.rs` — opakowanie strumienia CCSDS w `DLT_USER0` `.pcap`)
  7. `xtce encode <definition> <target> [--root] [--set NAME=VAL] [--out] [--hex] [--crc]` (`src/encode.rs` — koder pakietów TM/TC z definicji XTCE)
  8. `xtce pus [packets] [--hil-demo] [--hil-udp ADDR] [--emit-xtce] [--out] [--skip-header-bytes] [--limit]` (`src/pus.rs`)
  9. `xtce bench <file> [--iterations]` (`src/main.rs`)
  10. `xtce diff <old> <new> [--root] [--fail-on-breaking]` (`src/diff.rs` — Zadanie 4: Semantic Diff MVP dla definicji XTCE)
  11. `xtce validate <definition> [--root] [--json] [--strict]` (`src/validate.rs` — Zadanie 3: Walidator semantyczny i eksporter kanonicznego słownika JSON)
  12. `xtce sim [--scenario nominal|voltage-drop|overheat|comm-loss|reboot|attitude-loss|sensor-glitch] [--packets N] [--seed S] [--pcap] [--out]` (`src/sim.rs` — Zadanie 5: Deterministyczny symulator telemetrii z wstrzykiwaniem awarii)
  13. `xtce lsp` (`src/lsp.rs` — Language Server Protocol JSON-RPC 2.0 przez `stdio` z indeksem linii $O(1)$ i translacją kolumn UTF-16 -> UTF-8)

#### 1.2.6. `xtce-wasm` (`crates/xtce-wasm/src/lib.rs`)
* Biblioteka WebAssembly (`wasm32-unknown-unknown`, `cdylib` + `rlib`) z czystym C-ABI (0 zależności od `wasm-bindgen`):
  * Eksporty C-ABI: `wasm_alloc`, `wasm_free`, `wasm_result_ptr`, `wasm_result_len`, `wasm_inspect_xtce`, `wasm_decode_xtce_and_packets`, `wasm_generate_pus_stream`, `wasm_encode_pus_tc_and_hil`.
  * Funkcje Rust: `inspect_xtce_to_json`, `decode_xtce_and_packets_to_json`, `extract_packets_if_pcap`, `generate_pus_stream_bytes`, `wrap_in_pcap`, `encode_pus_tc_and_hil_to_json`.

#### 1.2.7. `xtce-py` (`crates/xtce-py/src/lib.rs`)
* Moduł natywny Python (`#[pymodule] fn xtce`, `abi3-py310`):
  * Klasa `xtce.Definition(path)` (linia `95`): `Definition.from_string(xml)`, właściwości `source`, `parameter_count`, `container_count`, metody `parameter_names()`, `container_names()`, `unsupported()`, `decode_stream(data, *, skip_header_bytes=0, root=None, raw=false, skip_unrecognized=false)` (zwalnia GIL przez `py.detach`, linia `202`), `decode(data, *, root=None, raw=false)`, `container_of_each(data, *, skip_header_bytes=0, root=None)`.

---

### 1.3. Limity Bezpieczeństwa, Ochrona Pamięci i Obsługa Encji XML

W całym kodzie bibliotecznym i wykonywalnym wymuszono dyrektywy kompilatora:
`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` oraz `#![deny(clippy::todo, clippy::unimplemented)]`.

| Mechanizm / Stała | Wartość | Dokładna lokalizacja (plik i linia) | Cel i działanie ochronne |
|---|---|---|---|
| **`MAX_EXPANDED_FIELDS`** *(limit liści tablicy/agregatu, odpowiednik `MAX_ARRAY_LEAVES`)* | `4096` (`usize`) | `crates/xtce-model/src/lower.rs:2258` (egzekwowane w `lower.rs:1641–1648`) | Chroni przed bombami kombinatorycznymi podczas rozwijania wielowymiarowych `<ArrayParameterType>` i `<AggregateParameterType>`. Przekroczenie zwraca `XtceError::ArrayNotExpanded`. Dodatkowo w `lower.rs:1601–1609` iloczyn wymiarów używa `checked_mul`, chroniąc przed przepełnieniem `usize`. |
| **`MAX_CONTAINER_DEPTH`** / **`MAX_DEPTH`** | `64` (`usize`) | `crates/xtce-decode/src/decoder.rs:25` (egzekwowane w `decoder.rs:211`, `924`, `960`) oraz `crates/xtce-codegen/src/plan.rs:482` (egzekwowane w `plan.rs:562`, `629`) | Chroni przed cyklicznymi referencjami `<ContainerRefEntry>` oraz zbyt głębokimi drzewami dziedziczenia kontenerów, zamieniając przepełnienie stosu (`stack overflow`) na kontrolowany błąd `DecodeError::Unsupported` / `CodegenError::Unsupported`. |
| **Detekcja cykli dziedziczenia i typów** | Trójkolorowe znakowanie / stos odwiedzin | `crates/xtce-model/src/lower.rs:2366–2413` (`check_acyclic`), `lower.rs:598–618` (`resolve_command_bases`), `lower.rs:1557–1566` (`Lowering::enter`) | Wykrywa cykle w `<BaseContainer>`, `<BaseMetaCommand>` oraz rekurencyjnych typach `<AggregateParameterType>` / `<ArrayParameterType>` na etapie ładowania pliku (`XtceError::InheritanceCycle` / `XtceError::ArrayNotExpanded`). |
| **`MAX_DEFINITION_BYTES`** | `256 * 1024 * 1024` (`256 MiB`) | `crates/xtce-cli/src/main.rs:281` oraz `crates/xtce-cli/src/decode.rs:45` | Ogranicza rozmiar dokumentu XTCE wczytywanego ze standardowego wejścia (`stdin.take(MAX_DEFINITION_BYTES)`), zapobiegając wyczerpaniu pamięci RAM (OOM) przy nieskończonym strumieniu. |
| **`MAX_HIL_FRAME_LEN`** & **`OBC_SCRATCHPAD_LEN`** | `64` B / `256` B | `crates/xtce-pus/src/hil.rs:13`, `:16` | Stałe bufory stosowe dla `#![no_std]` symulatora pokładowego OBC, gwarantujące deterministyczny rozmiar ramki i pamięci roboczej dla `ST[06]`. |
| **Obsługa encji XML i odrzucanie DTD / XXE** | Brak ekspansji encji DTD, ignorowanie `Event::DocType` | `crates/xtce-model/src/xml.rs:358–444` oraz `xml.rs:771–795` (`push_entity`) | Parser `quick-xml` działa na pojedynczej arenie tekstowej `String`. Zdarzenie `Event::DocType(_)` jest całkowicie ignorowane (`xml.rs:443`). W `Event::GeneralRef` funkcja `push_entity` (`xml.rs:771–795`) rozwija **wyłącznie** referencje znakowe (`&#...;`, `entity.is_char_ref()`) oraz 5 predefiniowanych encji XML (`amp`, `lt`, `gt`, `apos`, `quot`). Wszelkie inne encje (np. zadeklarowane w DTD) są zapisywane dosłownie jako `&nazwa;` (`xml.rs:789–793`), co całkowicie eliminuje podatności typu *Billion Laughs* (XML Entity Expansion) oraz *XXE*. |
| **Pomijanie nieużywanych sekcji XML w locie** | `Tag::is_skipped_section` | `crates/xtce-model/src/xml.rs:202–212` oraz `xml.rs:381–401`, `465–468` | Sekcje `ServiceSet`, `MessageSet`, `StreamSet`, `AlgorithmSet`, `AliasSet`, `AncillaryDataSet` są odrzucane w pętli zdarzeń SAX przed alokacją węzłów w arenie `Dom`, co chroni pamięć przed nadmiarowymi metadanymi. |

---

### 1.4. Przepływy CI/CD (`.github/workflows/*`)

1. **`ci.yml` (`.github/workflows/ci.yml:1–102`):**
   * **`check` (bramka blokująca, linie `12–43`):** Przypięty toolchain `1.93.1` (`dtolnay/rust-toolchain@1.93.1`), weryfikacja `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, testy jednostkowe i integracyjne `cargo test --workspace` oraz testy różnicowe `cargo run -p xtask --release -- diff`.
   * **`latest` (advisory, linie `44–56`):** Clippy na najnowszym `stable` z `continue-on-error: true`.
   * **`python` (advisory, linie `58–94`):** Python `3.12`, instalacja `space_packet_parser` z przypiętego commita `6de220ff25e75d0a8b6258086f9d99ce9eae820b`, budowa koła przez `maturin build --release` dla `crates/xtce-py/Cargo.toml` i testy różnicowe `pytest crates/xtce-py/tests -q`.
   * **`msrv` (bramka blokująca, linie `95–102`):** Weryfikacja kompatybilności wstecznej z Rust `1.85.0` (`cargo check --workspace`).
2. **`release.yml` (`.github/workflows/release.yml:1–93`):** Budowa binariów `xtce-cli` na tagach `v*` dla `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin` i `aarch64-apple-darwin`, `strip`, pomiar rozmiaru i publikacja GitHub Release (wymaga ręcznie przygotowanych notatek w `docs/releases/v*.md`).
3. **`publish.yml` (`.github/workflows/publish.yml:1–43`):** Publikacja na `crates.io` w porządku topologicznym: `xtce-pus` -> `xtce-model` -> `xtce-decode` -> `xtce-codegen` -> `xtce-cli`.
4. **`pypi.yml` (`.github/workflows/pypi.yml:1–56`):** Budowa kół Python (`abi3-py310`) na Linux, macOS i Windows oraz publikacja na PyPI przez `maturin upload`.

---

## 2. Zadanie 2: Rejestr Decyzji Architektonicznych (ADR 001–005)

### ADR-001: Kanoniczna reprezentacja pośrednia (Canonical IR) oparta na płaskich arenach w `xtce-model`

* **Status:** Zaakceptowany (Zaimplementowany w `crates/xtce-model`)
* **Kontekst:** Dokumenty XTCE 1.2 w misjach kosmicznych (np. CTIM: 1,6 MB XML, ~46 000 elementów, 9493 parametrów, 38 kontenerów) zawierają dwukierunkowe referencje ścieżkowe (`<BaseContainer>`, `<ParameterRefEntry>`, `<ArgumentTypeRef>`) oraz typy złożone (tablice wielowymiarowe i agregaty). Tradycyjne podejście oparte na drzewach `Rc<RefCell<...>>` lub `Box<dyn ...>` generuje dziesiątki tysięcy drobnych alokacji sterty, uniemożliwia współdzielenie modelu między wątkami i zmusza każdy komponent (interpreter, generator kodu, koder TC, generator Lua Wireshark) do osobnej implementacji rozwiązywania nazw, rozwijania tablic i obsługi telekomend.
* **Decyzja:**
  1. Wprowadzamy dwufazowy proces ładowania w `xtce-model`: najpierw lekki, bezalokacyjny dla węzłów parser `xml::Dom` oparty na pojedynczej arenie tekstowej (`crates/xtce-model/src/xml.rs:291–303`), który jest zwalniany natychmiast po zakończeniu fazy obniżania (*lowering*).
  2. Fazę `Lowering` (`crates/xtce-model/src/lower.rs:71–201`) dzielimy na Przebieg 1 (rejestracja przestrzeni nazw `SpaceSystem`, typów, parametrów, kontenerów i telekomend `<MetaCommand>`) oraz Przebieg 2 (rozwiązywanie referencji do 32-bitowych indeksów `TypeId`, `ParamId`, `ContainerId`, `MetaCommandId`).
  3. Typy złożone (`<ArrayParameterType>`, `<AggregateParameterType>`) są rozwijane w trakcie ładowania (`lower.rs:1454–1654`) do płaskich parametrów liści (`ARR[0]`, `P.voltage`) z twardym limitem `MAX_EXPANDED_FIELDS = 4096`.
  4. Telekomendy (`<MetaCommand>`, `<CommandContainer>`, `<ArgumentAssignment>`) są obniżane do tych samych struktur `Container` i `MatchCriteria` co telemetria (`lower.rs:1249–1251`, `1719–1759`), z wydzieloną przestrzenią nazw dla `<ArgumentTypeSet>` (`lower.rs:97–101`).
  5. Wynikowy obiekt `XtceDb` (`crates/xtce-model/src/db.rs:35`) jest niemutowalny, przechowuje wszystkie encje w płaskich wektorach `Vec<T>` oraz jednym `Interner`, i implementuje `Send + Sync`.
* **Konsekwencje:**
  * *Pozytywne:* Błyskawiczne ładowanie dużych baz (rzędu kilku milisekund dla 1,6 MB XML), pełna przyjazność dla pamięci podręcznej procesora (cache locality), brak specjalnych ścieżek dla tablic i telekomend w `xtce-decode` oraz `xtce-codegen`.
  * *Kompromisy:* Wymiary tablic zależne od zawartości pakietu (`DynamicValue` w `StartingIndex`/`EndingIndex`) nie mogą zostać rozwinięte w czasie ładowania i są jawnie raportowane jako `Unsupported` (`lower.rs:788–796`).

---

### ADR-002: Granice Crates oraz warstwowanie `#![no_std]` / `std`

* **Status:** Zaakceptowany (Zaimplementowany w całym repozytorium)
* **Kontekst:** Narzędzia naziemne (stacje EGSE, analiza strumieni CCSDS, integracja z Pythonem i Wiresharkiem) wymagają bogatego ekosystemu `std` (system plików, wielowątkowość, CLI, parsowanie XML), podczas gdy oprogramowanie pokładowe (OBC na mikrokontrolerach Cortex-M `thumbv7em-none-eabihf`, RISC-V, LEON/SPARC) oraz wygenerowane statyczne dekodery pakietów muszą działać w rygorystycznym środowisku `#![no_std]` bez alokatora sterty (`alloc`).
* **Decyzja:**
  1. **Warstwa `#![no_std]` czasu wykonania (Flight & Embedded Core):**
     * Crate `xtce-pus` (`crates/xtce-pus/src/lib.rs:16`) jest w 100% `#![no_std]`, nie posiada żadnych zależności zewnętrznych (`Cargo.toml:14`) i nie wykonuje żadnych alokacji sterty (wszystkie operacje ramkowania PUS-C, CRC-16-CCITT, bramki kryptograficznej `TcSecurityGate` SipHash-2-4 oraz symulatora `PusResponder` operują na buforach przekazanych przez wywołującego).
     * Kod źródłowy Rust generowany przez `xtce-codegen` (`crates/xtce-codegen/src/emit.rs:83–209`) odwołuje się wyłącznie do przestrzeni `core::*` (np. `core::fmt::Display`, `core::error::Error`, własna funkcja `powi`), pożycza bufory tekstowe i binarne bezpośrednio z wycinka pakietu (`&'a str`, `&'a [u8]`) i nie wymaga `std` ani `alloc`.
  2. **Warstwa `std` czasu analizy i narzędzi naziemnych (Ground & Tooling):**
     * `xtce-model` (parser XML i budowa IR), `xtce-decode` (dynamiczny interpreter z obsługą transkodowania UTF-16/UTF-32/Latin-1 przez `Cow`), `xtce-codegen` (kompilator definicji używający `syn`/`quote`/`prettyplease`) oraz `xtce-cli` korzystają z `std`.
  3. **Izolacja wiązań FFI (`xtce-py`):**
     * `crates/xtce-py` jest wykluczony z głównego workspace (`Cargo.toml:7`) i stanowi osobny workspace (`crates/xtce-py/Cargo.toml:4`), dzięki czemu kompilacja i testy workspace Rust nigdy nie zależą od nagłówków CPython.
* **Konsekwencje:**
  * *Pozytywne:* Ten sam kod protokołu PUS-C (`xtce-pus`) oraz wygenerowane przez `xtce-codegen` dekodery mogą być kompilowane bezpośrednio do firmware'u satelity (np. misje PIAST/CAMILA) oraz używane na ziemi w `xtce-cli`.
  * *Kompromisy:* Konstrukcje XTCE wymagające alokacji podczas dekodowania (np. nieobrównane do bajtu napisy lub kodowania UTF-16/UTF-32 wymagające transkodowania) są obsługiwane przez interpreter `xtce-decode` (`Cow::Owned`), ale świadomie odrzucane przez `xtce-codegen` (`crates/xtce-codegen/src/plan.rs:738–748`, `1285–1290`), aby nie wprowadzać alokacji na ścieżkę krytyczną `no_std`.

---

### ADR-003: Strumieniowy `PacketReader<R: Read>` kontra bezkopiowy (zero-copy) `PacketIter<'a>`

* **Status:** Zaakceptowany (Zaimplementowany w `crates/xtce-decode/src/ccsds.rs` oraz `crates/xtce-cli/src/decode.rs`)
* **Kontekst:** Strumienie telemetrii CCSDS 133.0-B trafiają do dekodera w dwóch fundamentalnie różnych scenariuszach:
  1. *Przetwarzanie buforów w pamięci* (np. pliki zmapowane w pamięci, pojedyncze okna odbiorcze w `xtce-py` `decode_stream`, testy jednostkowe i benchmarki), gdzie kluczowa jest praca bez kopiowania bajtów (*zero-copy*).
  2. *Przetwarzanie wielogigabajtowych archiwów lub potoków na żywo* (`stdin`, gniazda TCP/UDP, duże pliki na dysku w `xtce decode` / `xtce pcap`), gdzie wczytanie całego strumienia przez `std::fs::read` doprowadziłoby do wyczerpania pamięci RAM.
* **Decyzja:**
  Udostępniamy w module `xtce_decode::ccsds` (`crates/xtce-decode/src/ccsds.rs`) dwa komplementarne mechanizmy ramkowania zwracające ten sam typ widoku `SpacePacketBytes<'_>`:
  1. **`PacketIter<'a>` (`ccsds.rs:131–201`):** Przyjmuje wycinek `&'a [u8]` i `skip_header_bytes: usize`. Nie alokuje pamięci — każdy kolejny `SpacePacketBytes<'a>` jest bezpośrednim podwycinkiem bufora wejściowego. Współpracuje z `Decoder::decode_into(&mut packet, bytes)` (`decoder.rs:132`), co pozwala zdekodować cały strumień przy **zerowej liczbie alokacji** po pierwszym pakiecie.
  2. **`PacketReader<R: Read>` (`ccsds.rs:242–389`):** Opakowuje dowolny czytnik `R: std::io::Read`, pomija `skip_header_bytes`, wczytuje 6-bajtowy nagłówek główny CCSDS, oblicza długość pakietu `6 + C + 1` i doczytuje resztę ramki do pojedynczego, reużywalnego bufora `Vec<u8>` (maksymalnie ~64 KiB dla najdłuższego pakietu CCSDS).
  3. Oba interfejsy traktują ucięty ogon strumienia (niepełny nagłówek lub mniej bajtów niż zadeklarowano w polu `C`) jako jawny błąd `FramingError::ShortHeader` / `FramingError::ShortPacket`, zamiast po cichu kończyć iterację (`ccsds.rs:175–196`, `338–373`).
* **Konsekwencje:**
  * *Pozytywne:* `xtce-cli` (`crates/xtce-cli/src/decode.rs` oraz `pcap.rs`) przetwarza dowolnie duże pliki i potoki `stdin` w stałej pamięci $O(1)$ za pomocą `PacketReader<BufReader<...>>`, podczas gdy `xtce-py` i `xtask diff` osiągają maksymalną przepustowość w pamięci dzięki `PacketIter`.
  * *Kompromisy:* `PacketReader::next_packet(&mut self)` zwraca `SpacePacketBytes<'_>` pożyczający z wewnętrznego bufora czytnika (*lending iterator pattern*), dlatego nie implementuje standardowego traitu `Iterator` (który w Rust nie obsługuje pożyczek z `self` bez GAT).

---

### ADR-004: Taksonomia błędów bez ścieżek paniki (No-Panic Error Taxonomy)

* **Status:** Zaakceptowany (Zaimplementowany we wszystkich crates)
* **Kontekst:** Dekoder telemetrii i odbiornik telekomend pracują na żywym łączu radiowym (downlink/uplink), gdzie uszkodzone ramki, zakłócenia RF lub złośliwie spreparowane pakiety są zjawiskiem normalnym. Wywołanie `panic!`, `unwrap()` lub `expect()` na poziomie biblioteki oznaczałoby awarię całego procesu stacji naziemnej lub reset komputera pokładowego OBC. Równocześnie użytkownik ładujący bazę XTCE, która w 95% składa się ze wspieranych konstrukcji, a w 5% używa rzadkich elementów (np. `<MathOperationCalibrator>`), musi móc załadować bazę i zdekodować wszystkie pakiety nieużywające tego elementu.
* **Decyzja:**
  1. **Bezwzględny zakaz paniki w kodzie bibliotecznym i CLI:** Wszystkie crates wymuszają `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` oraz `#![deny(clippy::todo, clippy::unimplemented)]`. Dostęp do wycinków i aren odbywa się wyłącznie przez bezpieczne metody `.get(...)` z propagacją `Result` lub niejawnym węzłem zastępczym (`DETACHED` w `xml.rs:590`).
  2. **Trójpoziomowa semantyka wsparcia XTCE (`SUPPORTED.md:7–17`):**
     * *Decodable:* Pełny model w IR i pełne dekodowanie.
     * *Represented:* Konstrukcja jest parsowana do wariantu `Unsupported` w IR (`TypeKind::Unsupported`, `EntryKind::Unsupported`, `SizeSpec::Unsupported`, `Calibrator::Unsupported`, `MatchCriteria::Unsupported`) i rejestrowana na liście `XtceDb::unsupported()`. Ładowanie pliku przez `XtceDb::from_xml` **kończy się sukcesem**, a błąd `DecodeError::Unsupported { element, context }` jest zgłaszany *dopiero wtedy*, gdy dekodowany pakiet faktycznie natrafi na dany element.
     * *Rejected (Load-Time Fatal):* Błędy strukturalne uniemożliwiające bezpieczną budowę IR (np. uszkodzony XML, cykl dziedziczenia kontenerów `XtceError::InheritanceCycle`, nierozwiązana referencja `XtceError::UnresolvedReference`, nieudane rozwinięcie tablicy `XtceError::ArrayNotExpanded`, które przesunęłoby offsety wszystkich kolejnych pól) przerywają ładowanie natychmiast.
  3. **Rozdzielona hierarchia typów błędów dla każdej warstwy:**
     * `xtce_model::XtceError` (`#[non_exhaustive]`, `crates/xtce-model/src/error.rs:9`) + `ParseError` z dokładnym offsetem bajtowym w XML.
     * `xtce_decode::DecodeError` (`#[non_exhaustive]`, `crates/xtce-decode/src/error.rs:14`) + `BitError` + `FramingError` + `PacketReadError`.
     * `xtce_codegen::CodegenError` (`#[non_exhaustive]`, `crates/xtce-codegen/src/lib.rs:63`): odmawia kompilacji niewspieranej konstrukcji **z podaniem jej nazwy i kontenera** (nigdy nie wykonuje cichego fallbacku do interpretera).
     * `xtce_pus::PusError` (`crates/xtce-pus/src/packet.rs:24`) oraz `SecurityError` (`security.rs:25`): lekkie typy `Copy + PartialEq + Eq` kompatybilne z `core::error::Error` w `#![no_std]`.
* **Konsekwencje:**
  * *Pozytywne:* Odporność na fuzzing (`proptest` w `xtce-decode/src/bits.rs`) i uszkodzone strumienie; możliwość inspekcji dowolnej bazy misyjnej komendą `xtce info` oraz walidacji komendą `xtce validate` przed uruchomieniem dekodera.
  * *Kompromisy:* Kod wewnętrzny musi jawnie obsługiwać warianty `DecodeError::DanglingIndex` / `CodegenError::DanglingIndex` zamiast używać indeksowania `vec[i]`.

---

### ADR-005: Potok Walidacji, Semantic Diff (`xtce diff`) i Testów Różnicowych (Three-Rung Validation Pipeline)

* **Status:** Zaakceptowany (Zaimplementowany w `xtask`, `xtce-codegen-e2e`, `xtce-py` oraz `xtce-cli/src/{diff,validate,sim}.rs`)
* **Kontekst:** Standard XTCE 1.2 zawiera liczne niejednoznaczności (np. kolejność sumowania wyrazów wielomianu kalibratora zmiennoprzecinkowego, traktowanie bitów wysuniętych poza szerokość pola przy odwracaniu kolejności bajtów `leastSignificantByteFirst`, porównywanie `NaN` w kryteriach wyboru kontenera). Równocześnie w cyklu życia misji kosmicznej (Faza B/C/D) definicje XTCE ewoluują między zespołami FSW i Ground Segment — przypadkowa zmiana rozmiaru pola z 16 na 32 bity przesuwa wszystkie kolejne pola w pakiecie o 16 bitów, czego zwykły `git diff` na plikach XML nie potrafi wykryć.
* **Decyzja:**
  1. **Trójstopniowy potok weryfikacji różnicowej (*Three-Rung Differential Pipeline*):**
     * **Stopień 1: Interpreter Rust (`xtce-decode`) vs Referencja Python (`space_packet_parser` @ `6de220ff`) przez `cargo xtask diff` (`xtask/src/diff.rs`):** Weryfikuje 18 zestawów testowych (*golden files* w `testdata/golden/*.json`), łącząc porównanie szczegółowe (parametr po parametrze dla pierwszych 64 pakietów) ze skrótem SHA-256 (`xtask/src/sha256.rs`) liczonego po kanonicznej serializacji wszystkich pakietów w strumieniu.
     * **Stopień 2: Statyczny Generator Kodu (`xtce-codegen`) vs Interpreter Rust (`xtce-decode`) w `xtce-codegen-e2e` (`crates/xtce-codegen-e2e/tests/against_interpreter.rs`):** Skrypt `build.rs` kompiluje wszystkie 18 definicji XTCE do statycznych modułów Rust i porównuje je bit-po-bicie (`to_bits()` dla `f64`) z interpreterem.
     * **Stopień 3: Wiązania Python (`xtce-py`) vs `space_packet_parser` (`crates/xtce-py/tests/test_against_reference.py`):** Weryfikuje granicę FFI PyO3 oraz zwalnianie blokady GIL (`py.detach`).
  2. **Semantic Diff (`xtce diff <OLD.xml> <NEW.xml> [--fail-on-breaking]`, `crates/xtce-cli/src/diff.rs`):**
     * Porównuje dwie bazy na poziomie kanonicznego IR (`XtceDb`) oraz spłaszczonego planu bitowego (`xtce_codegen::Plan`), klasyfikując każdą zmianę jako `BREAKING` (usunięcie parametru/kontenera, zmiana typu/szerokości/znaku/endianness, usunięcie lub zmiana wartości enuma, przesunięcie `bit_offset` w kontenerze), `WARNING` (dodanie nowej wartości enuma lub pola na końcu kontenera) albo `COMPATIBLE` (dodanie nowego niezależnego parametru lub kontenera).
  3. **Walidator semantyczny i eksporter JSON (`xtce validate <DEF.xml> [--json] [--strict]`, `crates/xtce-cli/src/validate.rs`) oraz deterministyczny symulator misji (`xtce sim`, `crates/xtce-cli/src/sim.rs`):**
     * `xtce validate` weryfikuje spójność IR, martwe gałęzie abstrakcyjnych kontenerów i gotowość do kompilacji `xtce-codegen`, oraz eksportuje znormalizowany słownik metadanych do JSON.
     * `xtce sim` generuje powtarzalne strumienie CCSDS / ECSS PUS-C (z ziarnem SplitMix64 `--seed`) dla scenariuszy `nominal`, `voltage-drop`, `overheat`, `comm-loss`, `reboot`.
* **Konsekwencje:**
  * *Pozytywne:* Gwarancja zgodności bitowej między wygenerowanym kodem `#![no_std]`, interpreterem Rust oraz referencyjnym parserem LASP Python, połączona z bramką CI (`xtce diff --fail-on-breaking` i `xtce validate --strict`) chroniącą przed niekompatybilnymi zmianami formatu ramek.

---

## 3. Zadanie 3: Macierz Pokrycia i Walidacji XTCE 1.2 (Evidence-Backed Matrix)

Poniższa macierz zestawia pełne pokrycie standardu **OMG XTCE 1.2 (CCSDS 660.1-G-2)** z dokładnymi dowodami w kodzie źródłowym:
* **`crates/xtce-model/src/lower.rs`** (oraz `xml.rs` dla sekcji pomijanych),
* **`crates/xtce-decode/src/decoder.rs`** (oraz moduły pomocnicze `calibrate.rs`, `charset.rs`, `bits.rs`),
* **`crates/xtce-codegen/src/plan.rs`** (oraz `emit.rs`),
* **`SUPPORTED.md`**.

### Legenda kategorii pokrycia
1. **Wspierane w Interpreterze i Static Codegen (`Interpreter + Codegen`)** — konstrukcja w pełni zamodelowana w IR, dekodowana przez `xtce-decode` i kompilowana do statycznego kodu Rust przez `xtce-codegen`.
2. **Wspierane tylko w Interpreterze (`Tylko Interpreter / Częściowe w Codegen`)** — konstrukcja w pełni dekodowana przez `xtce-decode`, natomiast `xtce-codegen` świadomie odmawia jej kompilacji (`CodegenError::Unsupported`), np. ze względu na brak wyrównania do bajtu, konieczność alokacji przy transkodowaniu lub przesunięcia bitowe `LocationInContainerInBits`.
3. **Częściowo wspierane / Reprezentowane w IR (`Represented / Partial`)** — konstrukcja jest parsowana i obecna w IR (`XtceDb::unsupported()`), dzięki czemu plik XTCE ładuje się poprawnie, ale próba zdekodowania parametru od niej zależnego zwraca `DecodeError::Unsupported` (lub wybrane atrybuty pomocnicze nie są aplikowane w arytmetyce).
4. **Niewspierane / Odrzucane (`Unsupported / Rejected`)** — sekcja pomijana na etapie parsera XML (`skipped_sections`) lub powodująca błąd ładowania `XtceError` (np. dynamiczny wymiar tablicy).

---

### 3.1. Sekcje główne dokumentu `<SpaceSystem>`

| Konstrukcja XTCE 1.2 | Status pokrycia | `xtce-model` (`xml.rs` / `lower.rs`) | `xtce-decode` (`decoder.rs`) | `xtce-codegen` (`plan.rs`) | `SUPPORTED.md` |
|---|---|---|---|---|---|
| `SpaceSystem` (hierarchia i referencje ścieżkowe `/`, `.`, `..`) | **Interpreter + Codegen** | `lower.rs:151–158`, `205–265`, `1937–2012`, `2134–2164` | `decoder.rs:49–78` | `plan.rs:458–471` | `L21–24` |
| `TelemetryMetaData` (`ParameterTypeSet`, `ParameterSet`, `ContainerSet`) | **Interpreter + Codegen** | `lower.rs:240–256` | `decoder.rs:102–192` | `plan.rs:555–618` | `L23` |
| `CommandMetaData` (`ArgumentTypeSet`, `MetaCommandSet`, `CommandContainerSet`) | **Interpreter + Codegen** | `lower.rs:258–316` | `decoder.rs:102–192` (wspólna maszyneria kontenerów) | `plan.rs:555–699` | `L24`, `L28–50`, `L181–185` |
| `ServiceSet`, `MessageSet`, `StreamSet`, `AlgorithmSet` | **Rejected (Skipped)** | `xml.rs:202–212`, `465–468` (pomijane w locie, zapisywane w `skipped_sections`) | — | — | `L25` |
| `AliasSet`, `AncillaryDataSet` | **Rejected (Skipped)** | `xml.rs:202–212`, `465–468` | — | — | `L26` |

---

### 3.2. Telekomendy (`<CommandMetaData>`)

| Konstrukcja XTCE 1.2 | Status pokrycia | `xtce-model` (`lower.rs`) | `xtce-decode` (`decoder.rs`) | `xtce-codegen` (`plan.rs`) | `SUPPORTED.md` |
|---|---|---|---|---|---|
| `MetaCommand` (w tym `abstract="true"`) | **Interpreter + Codegen** | `lower.rs:363–468`, `634–639`, `1276–1281`, `1762–1796` | `decoder.rs:176–184` (respektuje `is_abstract`) | `plan.rs:580–601` | `L37`, `L181` |
| `BaseMetaCommand` (dziedziczenie, detekcja cykli) | **Interpreter + Codegen** | `lower.rs:572–631` (`resolve_command_bases`) | `decoder.rs:141–187` | `plan.rs:555–618` | `L38`, `L181` |
| `ArgumentList`, `Argument` (kwalifikowane pod komendą `/SS/Cmd/ARG`) | **Interpreter + Codegen** | `lower.rs:394–423`, `1169–1192`, `1703–1709` | `decoder.rs:278–306` | `plan.rs:703–836` | `L39`, `L181` |
| `ArgumentAssignmentList`, `ArgumentAssignment` (w tym na wyliczeniach `Enumerated`) | **Interpreter + Codegen** | `lower.rs:1249–1251`, `1719–1759` (`use_calibrated: true`) | `decoder.rs:720–806` | `plan.rs:510–529`, `1337–1361`, `1478–1508` (`GuardTest::Labels`) | `L40`, `L50`, `L182–183` |
| `CommandContainer` oraz `CommandContainerSet` | **Interpreter + Codegen** | `lower.rs:298–308`, `426–457` (`is_command: true`) | `decoder.rs:204–275` | `plan.rs:555–699` | `L41`, `L47`, `L181` |
| `ArgumentRefEntry`, `ArrayArgumentRefEntry` | **Interpreter + Codegen** | `lower.rs:1359–1416` (`lower_argument_lookup`) | `decoder.rs:244–246` | `plan.rs:684–697` | `L42`, `L181` |
| `FixedValueEntry` (`binaryValue`, `sizeInBits`) | **Interpreter + Codegen** (w Codegen wymagany stały offset) | `lower.rs:1306–1333`, `1417` | `decoder.rs:255–265` (`cursor.skip`) | `plan.rs:243–259`, `490–504`, `654–676` (odrzuca po dynamicznej szerokości: `plan.rs:660–667`) | `L44`, `L119`, `L184–185` |
| `*ArgumentType` (`Integer`, `Float`, `String`, `Binary`, `Boolean`, `Enumerated`, `AbsoluteTime`, `Array`, `Aggregate`) | **Interpreter + Codegen** | `lower.rs:280–288`, `320–353`, `506–533`, `673–713` | `decoder.rs:308–377` | `plan.rs:1103–1183` | `L45–46` |
| `RelativeTimeArgumentType` | **Represented (Partial)** | `lower.rs:705–707` (`TypeKind::RelativeTime`) | `decoder.rs:342` (dekoduje surowe bity jeśli ma kodowanie, brak arytmetyki epoki) | **Refused:** `plan.rs:1176–1181` | `L45`, `L63` |
| `BlockMetaCommand`, `VerifierSet`, `TransmissionConstraintList`, `Interlock`, `ParameterToSetList` | **Rejected** | Nierozpoznawane jako definicje pakietów (`xml.rs:48`, `lower.rs:269–316`) | — | — | `L48–49` |

---

### 3.3. Typy Parametrów (`<ParameterTypeSet>`)

| Konstrukcja XTCE 1.2 | Status pokrycia | `xtce-model` (`lower.rs`) | `xtce-decode` (`decoder.rs`) | `xtce-codegen` (`plan.rs`) | `SUPPORTED.md` |
|---|---|---|---|---|---|
| `IntegerParameterType` (1–64 bity: `unsigned`, `twosComplement`/`twosCompliment`/`signed`, `signMagnitude`, `onesComplement`) | **Interpreter + Codegen** (w Codegen i Interpreterze odrzucane LE signed 57–63 bity niepodzielne przez 8) | `lower.rs:674`, `912–918`, `2228–2237` | `decoder.rs:453–486` (błąd dla 57–63b LE `twosComplement`: `decoder.rs:471–481`) | `plan.rs:759–784`, `1117`, `1242–1252` (odrzuca 57–63b LE signed: `plan.rs:775–784`) | `L56`, `L114`, `L149`, `L155` |
| `FloatParameterType` — IEEE-754 (`16`, `32`, `64` bity) | **Interpreter + Codegen** | `lower.rs:675`, `919–925`, `2239–2244` | `decoder.rs:488–505`, `1115–1150` (`half_to_f32` z subnormalnymi i zachowaniem NaN payload) | `plan.rs:1117`, `1253–1263` (inne szerokości odrzucane: `plan.rs:1258–1263`) | `L57`, `L126`, `L150` |
| `FloatParameterType` — `MILSTD_1750A` / `MIL-1750A` (`32` bity) | **Interpreter + Codegen** (szerokości $\neq 32$ odrzucane) | `lower.rs:2239–2244` | `decoder.rs:512–519`, `1156–1161` (odrzuca $\neq 32$ bity: `decoder.rs:512–517`) | `plan.rs:31–36`, `1264–1272` (odrzuca $\neq 32$ bity: `plan.rs:1267–1272`) | `L57`, `L190–191`, `L237–242` |
| `EnumeratedParameterType` (`EnumerationList`, `Enumeration`, zakresy `maxValue`) | **Interpreter + Codegen** (Codegen wymaga kodowania całkowitoliczbowego) | `lower.rs:686–688`, `860–897` | `decoder.rs:348–362` | `plan.rs:1129–1148` (odrzuca enum na kodowaniu float: `plan.rs:1130–1135`) | `L58`, `L120`, `L151` |
| `BooleanParameterType` (`zeroStringValue`, `oneStringValue`) | **Interpreter + Codegen** | `lower.rs:678–685` (`db.rs:319–329` `boolean_label`) | `decoder.rs:363–371` | `plan.rs:1118` | `L59`, `L151` |
| `StringParameterType` (UTF-8, US-ASCII, wyrównane do bajtu, `Fixed` / `DynamicValue`, `TerminationChar`, `LeadingSize`) | **Interpreter + Codegen** | `lower.rs:676`, `926–928`, `951–1012` | `decoder.rs:326–340`, `543–629` | `plan.rs:730–748`, `1152–1160`, `1280–1306` | `L60`, `L170`, `L174` |
| `StringParameterType` — niewyrównane do granicy bajtu, `DiscreteLookupList`, lub kodowania `ISO-8859-1`, `Windows-1252`, `UTF-16*`, `UTF-32*` | **Tylko Interpreter** (Refused w Codegen) | `lower.rs:956–964`, `1059–1071`, `2278–2287` | `decoder.rs:558–564`, `621–628` (`crates/xtce-decode/src/charset.rs`) | **Refused:** `plan.rs:738–744` (brak wyrównania), `plan.rs:1226–1229` (`DiscreteLookup`), `plan.rs:1284–1290` (transkodowanie) | `L60`, `L73`, `L172–173` |
| `BinaryParameterType` (wyrównane do bajtu, `Fixed` lub `DynamicValue` + `LinearAdjustment`) | **Interpreter + Codegen** | `lower.rs:677`, `929–931`, `1014–1057` | `decoder.rs:523–532`, `631–693` | `plan.rs:730–748`, `1161–1169`, `1307–1311` | `L61`, `L171`, `L174` |
| `BinaryParameterType` — niewyrównane do granicy bajtu lub rozmiar z `DiscreteLookupList` | **Tylko Interpreter** (Refused w Codegen) | `lower.rs:1059–1071` | `decoder.rs:523–532`, `679`, `695–716` | **Refused:** `plan.rs:738–744`, `plan.rs:1226–1229` (w runtime dla dynamicznej szerokości: `DecodeError::Unaligned`, `emit.rs:133–139`) | `L61`, `L76`, `L172`, `L176` |
| `AbsoluteTimeParameterType` (`Encoding` z `offset`/`scale`, `ReferenceTime`/`Epoch`/`OffsetFrom`) | **Partial (Interpreter + Codegen)** — `offset` i `scale` przeliczane jako kalibrator wielomianowy; `Epoch` i `OffsetFrom` zamodelowane w IR, ale nieprzeliczane na datę | `lower.rs:666`, `689–704`, `2192–2226` (`apply_time_unit_scaler`) | `decoder.rs:375` (przez wygenerowany kalibrator wielomianowy) | `plan.rs:1117` | `L62` |
| `RelativeTimeParameterType` | **Represented (Partial)** — zamodelowany w IR, odrzucany w Codegen | `lower.rs:705–707` | `decoder.rs:342` (brak arytmetyki epoki) | **Refused:** `plan.rs:1176–1181` | `L63` |
| `ArrayParameterType` (stałe `StartingIndex` / `EndingIndex`, rozwijane do liści `ARR[i][j]` w porządku row-major do 4096 pól) | **Interpreter + Codegen** | `lower.rs:708–710`, `761–814`, `1454–1654`, `2258` | `decoder.rs:244–246` (widzi rozwinięte parametry skalarne) | `plan.rs:684–697` (odrzuca nierozwiniętą tablicę: `plan.rs:1123–1128`) | `L64`, `L177–180`, `L217–226` |
| `ArrayParameterType` z wymiarem odczytywanym z pakietu (`DynamicValue` / `DiscreteLookupList` w `Dimension`) | **Represented / Rejected** (`TypeKind::Unsupported` na typie, `XtceError::ArrayNotExpanded` na subsettingu wpisu) | `lower.rs:788–796` (na typie), `lower.rs:1486–1496` (na wpisie) | `decoder.rs:315–320` (`DecodeError::Unsupported`) | **Refused:** `plan.rs:1123–1128`, `1170–1175` | `L64`, `L178` |
| `AggregateParameterType` (`MemberList`, `Member`, rozwijane do `P.member`, zagnieżdżenia z tablicami) | **Interpreter + Codegen** | `lower.rs:711–713`, `817–858`, `1454–1654` | `decoder.rs:244–246` | `plan.rs:684–697` | `L65`, `L177`, `L217–226` |

---

### 3.4. Kodowania Danych (`<DataEncoding>`) i Rozmiary (`<SizeInBits>`)

| Konstrukcja XTCE 1.2 | Status pokrycia | `xtce-model` (`lower.rs`) | `xtce-decode` (`decoder.rs`) | `xtce-codegen` (`plan.rs`) | `SUPPORTED.md` |
|---|---|---|---|---|---|
| `IntegerDataEncoding` / `FloatDataEncoding` — `byteOrder="mostSignificantByteFirst"` oraz `"leastSignificantByteFirst"` | **Interpreter + Codegen** | `lower.rs:912–925`, `2271–2276` | `decoder.rs:461–479`, `496–498` (`swap_byte_order`) | `plan.rs:199–205`, `1240–1278` (`emit.rs:658–663`) | `L71–72`, `L154–155`, `L243–255` |
| `StringDataEncoding` (`Fixed`, `Variable`/`DynamicValue`, `TerminationChar`, `LeadingSize`) | **Interpreter + Codegen** (Codegen: tylko UTF-8 i US-ASCII wyrównane do bajtu) | `lower.rs:951–1012` | `decoder.rs:543–629` | `plan.rs:1280–1306` | `L73`, `L170–174` |
| `BinaryDataEncoding` (`SizeInBits/Fixed`, `DynamicValue`, `DiscreteLookupList`) | **Interpreter + Codegen** (Codegen: bez `DiscreteLookupList` i tylko wyrównane do bajtu) | `lower.rs:929–931`, `1014–1076` | `decoder.rs:523–532`, `631–716` | `plan.rs:1187–1232`, `1307–1311` | `L74–76`, `L171–176` |
| `SizeInBits/DynamicValue` + `LinearAdjustment` (`slope`, `intercept`) | **Interpreter + Codegen** (w Codegen tylko dla pól tekstowych i binarnych) | `lower.rs:1038–1057`, `2304–2315` | `decoder.rs:640–677` | `plan.rs:751–758` (odrzuca zmienną szerokość pola liczbowego), `1195–1225` | `L75`, `L174–175` |
| `SizeInBits/DiscreteLookupList` (`DiscreteLookup`) | **Tylko Interpreter** (Refused w Codegen) | `lower.rs:1059–1071` | `decoder.rs:679`, `695–716` | **Refused:** `plan.rs:1226–1229` | `L76` |
| `ErrorDetectCorrect` | **Rejected (Ignored)** | Ignorowane podczas obniżania kodowania (`lower.rs:899–934`) | — | — | `L77` |

---

### 3.5. Kontenery (`<ContainerSet>`) i Kryteria Wyboru (`<RestrictionCriteria>`)

| Konstrukcja XTCE 1.2 | Status pokrycia | `xtce-model` (`lower.rs`) | `xtce-decode` (`decoder.rs`) | `xtce-codegen` (`plan.rs`) | `SUPPORTED.md` |
|---|---|---|---|---|---|
| `SequenceContainer`, `EntryList`, `ParameterRefEntry` | **Interpreter + Codegen** | `lower.rs:1214–1299`, `1358–1416` | `decoder.rs:141–192`, `204–275` | `plan.rs:555–699` | `L82–83` |
| `ContainerRefEntry` (rozwijane inline, limit głębokości 64) | **Interpreter + Codegen** | `lower.rs:1418–1434` | `decoder.rs:211–219`, `247–249` | `plan.rs:629–635`, `649–653` | `L84`, `L124`, `L153` |
| `BaseContainer` + `RestrictionCriteria` (wykrywanie cykli przy ładowaniu) | **Interpreter + Codegen** | `lower.rs:1227–1243`, `2343–2413` | `decoder.rs:149–187`, `720–738` | `plan.rs:603–610`, `1330–1362` | `L85`, `L152` |
| `Comparison`, `ComparisonList` (`==`, `!=`, `<`, `<=`, `>`, `>=`) | **Interpreter + Codegen** (w Codegen: kryteria na liczbach całkowitych oraz etykietach `Enumerated`; odrzucane kryteria na `useCalibratedValue` dla kalibrowanych floatów i `Boolean`) | `lower.rs:1679–1686`, `1798–1820` | `decoder.rs:764–806`, `1054–1075` | `plan.rs:510–529`, `1339–1350`, `1435–1508` (odrzuca `useCalibratedValue` na kalibrowanym parametrze i `Bool`: `plan.rs:1478–1491`) | `L86`, `L152`, `L158–161` |
| `BooleanExpression` (`Condition`, `ANDedConditions`, `ORedConditions`) — parametr vs literał | **Interpreter + Codegen** | `lower.rs:1687–1692`, `1822–1909` | `decoder.rs:808–861` | `plan.rs:1351`, `1365–1429` | `L87`, `L187`, `L257–265` |
| `BooleanExpression` (`Condition`) — parametr vs parametr lub literał po lewej stronie | **Tylko Interpreter** (Refused w Codegen) | `lower.rs:1871–1909` | `decoder.rs:834–892`, `1078–1104` | **Refused:** `plan.rs:1391–1414` | `L87`, `L122`, `L188–189` |
| `LocationInContainerInBits` z `referenceLocation="previousEntry"` lub `"containerStart"` (na wpisach skalarnych) | **Tylko Interpreter** (Refused w Codegen; na wpisach tablicowych/agregatach oznaczane jako `Unsupported`) | `lower.rs:1347`, `1400–1411`, `2048–2061`, `2289–2296` | `decoder.rs:223–240` (`cursor.seek`) | **Refused:** `plan.rs:639–645` | `L88`, `L112`, `L186` |
| `LocationInContainerInBits` z `referenceLocation="containerEnd"` lub `"nextEntry"` | **Represented (Partial)** — ładowane do IR, zgłaszane przy dekodowaniu | `lower.rs:2048–2061`, `2289–2296` | `decoder.rs:227–236` (`DecodeError::Unsupported`) | **Refused:** `plan.rs:639–645` | `L89` |
| `RepeatEntry` ze stałym `Count/FixedValue` (na wpisach skalarnych i `ContainerRefEntry`) | **Tylko Interpreter** (w Codegen wspierane dla `ContainerRefEntry`/`FixedValueEntry`, odrzucane dla `ParameterRefEntry`; na tablicach/agregatach `Unsupported`) | `lower.rs:1348`, `1400–1411`, `2069–2076` | `decoder.rs:242` (`for _ in 0..entry.repeat.unwrap_or(1)`) | **Refused dla parametrów:** `plan.rs:685–693` (wspierane dla `Container`/`FixedValue`: `plan.rs:650`, `659`) | `L90`, `L113`, `L186` |
| `RepeatEntry` z dynamicznym `Count` (`DynamicValue`) | **Represented** (`EntryKind::Unsupported`) | `lower.rs:1353–1356`, `2091–2096` | `decoder.rs:266–271` (`DecodeError::Unsupported`) | **Refused:** `plan.rs:677–683` | `L91` |
| `IncludeCondition` | **Represented** (`EntryKind::Unsupported`) | `lower.rs:1353–1356`, `2085–2090` | `decoder.rs:266–271` (`DecodeError::Unsupported`) | **Refused:** `plan.rs:677–683` | `L92` |
| `IndirectParameterRefEntry` | **Represented** (`EntryKind::Unsupported`) | `lower.rs:1435–1441` | `decoder.rs:266–271` (`DecodeError::Unsupported`) | **Refused:** `plan.rs:677–683` | `L93` |
| `ArrayParameterRefEntry` (w tym subsetting przez `<DimensionList>` ze stałymi indeksami) | **Interpreter + Codegen** | `lower.rs:1359–1414`, `1481–1500`, `1569–1595` | `decoder.rs:244–246` | `plan.rs:684–697` | `L94`, `L177` |
| `CustomAlgorithm` w `RestrictionCriteria` lub `ContextMatch` | **Represented** (`MatchCriteria::Unsupported`) | `lower.rs:1693–1695`, `1911–1921` | `decoder.rs:757–760` (`DecodeError::Unsupported`) | **Refused:** `plan.rs:992–995`, `1352–1358` | `L95`, `L169` |

---

### 3.6. Kalibratory (`<DefaultCalibrator>`, `<ContextCalibratorList>`)

| Konstrukcja XTCE 1.2 | Status pokrycia | `xtce-model` (`lower.rs`) | `xtce-decode` (`decoder.rs` / `calibrate.rs`) | `xtce-codegen` (`plan.rs` / `emit.rs`) | `SUPPORTED.md` |
|---|---|---|---|---|---|
| `PolynomialCalibrator` (`Term` z `coefficient` i `exponent`) | **Interpreter + Codegen** | `lower.rs:1111–1125` | `decoder.rs:379–443` (`crates/xtce-decode/src/calibrate.rs:41–73`) | `plan.rs:870`, `940` (`emit.rs:769–793`: osobna ścieżka `i128` i `powi`) | `L101`, `L125`, `L156`, `L168`, `L207–215` |
| `SplineCalibrator` (`SplinePoint`, `order="0"` i `order="1"`, `extrapolate="true"\|"false"`) | **Interpreter + Codegen** | `lower.rs:1127–1149` (sortowanie punktów po `raw`: `lower.rs:1138`) | `decoder.rs:379–443` (`calibrate.rs:75–155`) | `plan.rs:871–890`, `941–949` (`emit.rs:794–818`) | `L102`, `L123`, `L157`, `L167` |
| `SplineCalibrator` rzędu `order > 1` lub bez punktów | **Represented (Partial)** — ładowane do IR, odrzucane przy dekodowaniu i planowaniu Codegen | `lower.rs:1127–1149` | `calibrate.rs:80–91` (`DecodeError::Calibration`) | **Refused:** `plan.rs:876–887`, `942–947` | `L167` |
| `ContextCalibratorList` / `ContextCalibrator` (`ContextMatch` z `Comparison` / `ComparisonList` oraz obecnym `DefaultCalibrator`) | **Interpreter + Codegen** | `lower.rs:1083–1106` | `decoder.rs:396–411`, `782–798` | `plan.rs:789–821`, `904–1100` (`emit.rs:747–759`) | `L103`, `L163`, `L228–235` |
| `ContextCalibratorList` bez `DefaultCalibrator`, lub z `BooleanExpression`, lub z `useCalibratedValue="true"` na aktualnie kalibrowanym polu | **Tylko Interpreter** (Refused w Codegen) | `lower.rs:1083–1106` | `decoder.rs:396–425`, `785–790` | **Refused:** `plan.rs:922–929` (brak `DefaultCalibrator`), `plan.rs:987–991` (`BooleanExpression`), `plan.rs:1027–1036` (`useCalibratedValue` na bieżącym polu) | `L164–166` |
| `MathOperationCalibrator` oraz `CustomAlgorithm` jako kalibrator | **Represented** (`Calibrator::Unsupported`) | `lower.rs:1150–1156` | `decoder.rs:433–438` (`DecodeError::Unsupported`) | **Refused:** `plan.rs:891–894`, `950–955` | `L104`, `L169` |

---

## 4. Uzupełnienie ze strategii `RustSpaceLab` (XTCE Compiler, Telemetry Studio, Interoperacyjność i Rozpoznawalność)

Poniższa sekcja domyka elementy wizji strategicznej `RustSpaceLab`, które zostały zidentyfikowane w analizie ekosystemowej, a zostały skrócone w pierwotnym dokumencie PDF.

### 4.1. Wielocelowy kompilator misji (`xtce compile --target <TARGET>`)

Zgodnie z koncepcją *„Jeden ekosystem. Jeden model danych. Wiele zastosowań”*, pojedynczy plik definicji XTCE 1.2 stanowi źródło prawdy kompilowane z poziomu `xtce-cli` (`crates/xtce-cli/src/compile.rs`) do siedmiu artefaktów inżynieryjnych:

```bash
xtce compile mission.xml --target rust-ground   -o decoder.rs
xtce compile mission.xml --target wireshark     -o mission.lua
xtce compile mission.xml --target json-schema   -o mission.schema.json
xtce compile mission.xml --target docs          -o MISSION_DICTIONARY.md
xtce compile mission.xml --target dashboard     -o telemetry_studio.json
xtce compile mission.xml --target c-header      -o mission_telemetry.h
xtce compile mission.xml --target python-ctypes -o mission_telemetry.py
```

*Dla kompilacji pokładowych koderów `#![no_std]` używany jest komplementarny kompilator `xtce-flight` z repozytorium `RustSpaceLab/xtce-flight`, a dla wiązań Python — pakiet `xtce-py`.*

### 4.2. Rozszerzony Symulator Misji (`xtce sim`)

Symulator `xtce sim` (`crates/xtce-cli/src/sim.rs`) obsługuje pełen zestaw 7 deterministycznych profili orbitalnych i awaryjnych zasilanych 64-bitowym generatorem SplitMix64 (`--seed`):
1. `nominal` — nominalny przelot orbitalny LEO (28,2 V, 22,5 °C, telemetria `TM[3,25]` i `TM[17,2]`).
2. `voltage-drop` — degradacja / spadek napięcia baterii w cieniu Ziemi poniżej 24,0 V z raportem `TM[5,2]` (`0x1201`) i przejściem do `SAFE_MODE`.
3. `overheat` — przegrzanie komputera pokładowego OBC powyżej +68,0 °C z alarmem `TM[5,2]` (`0x1202`).
4. `comm-loss` — utrata łączności radiowej (skok licznika sekwencji CCSDS o 17 utraconych ramek i raport `0x0502`).
5. `reboot` — reset komputera pokładowego OBC (watchdog reset, wyzerowanie `OBC_UPTIME_S` i raport startowy `0x0503`).
6. `attitude-loss` — utrata orientacji ADCS (tumble / star-tracker fault, raport `0x0504` i natychmiastowe przejście do `SAFE_MODE`).
7. `sensor-glitch` — przekłamanie przetwornika ADC / błędne wartości telemetryczne (pik 35,9 V / 85,0 °C i raport anomalii `0x0505`).

### 4.3. Interoperacyjność w ekosystemie Rust (`sat-rs`, `spacepackets-rs`, `cfdp-rs`)

```text
             RustSpaceLab
                  |
        +---------+---------+
        |                   |
     xtce-rs             xtce-flight
        |                   |
        +---------+---------+
                  |
        CCSDS / ECSS PUS Layer (xtce-pus #![no_std])
                  |
        +---------+---------+
        |                   |
     spacepackets-rs      sat-rs / cfdp-rs
        |
      xtce-gs
        |
   Telemetry Studio / OrbitTrack Live Mission Demo
```

Zamiast duplikować całe frameworki oprogramowania pokładowego lub protokoły transferu plików:
* `xtce-decode::SpacePacketBytes` oraz `xtce-pus::PusPacket` operują bezpośrednio na surowych wycinkach `&[u8]` CCSDS 133.0-B-2, co pozwala na bezkopiową wymianę ramek z `spacepackets-rs`, `sat-rs` oraz `cfdp-rs`.

### 4.4. Trzy filary rozpoznawalności i adopcji `RustSpaceLab`

1. **RustSpaceLab Mission Demo (`OrbitTrack / Telemetry Studio Live`):**
   * Publicznie dostępny, interaktywny demonstrator online (wdrożony na żywo pod adresem **`https://altanix.dev/mission-demo`**) połączony z prawdziwym silnikiem Rust (`xtce` + `#![no_std]` `xtce-pus` HIL OBC responder), wizualizujący w czasie rzeczywistym konstelację polskich i europejskich satelitów LEO (`PIAST-M`, `CAMILA-1`, `EagleEye-2`, `OPS-SAT-2`, `PW-Sat3`) na mapie orbitalnej oraz globusie 3D nad stacją naziemną w Warszawie, z żywymi wykresami telemetrii, wstrzykiwaniem awarii, wysyłaniem podpisanych kryptograficznie telekomend ECSS PUS-C (SipHash-2-4 MAC) i inspektorem ramek CCSDS.
2. **Public Performance Lab:**
   * Powtarzalne benchmarki (`cargo run -p xtask --release -- diff` oraz `xtce bench`) porównujące przepustowość i czas ładowania definicji (do **103× szybciej przy ładowaniu** i **124× szybciej przy dekodowaniu** niż referencyjny `space_packet_parser` w Pythonie, przy **0 alokacjach na pakiet** w ścieżce `decode_into` oraz `xtce-codegen`).
3. **Space Software Engineering Blog (Seria artykułów technicznych):**
   * *Why Rust is interesting for spacecraft software*
   * *How to build a zero-allocation XTCE decoder*
   * *From XTCE XML to `#![no_std]` machine code without a single panic path*
   * *How CCSDS and ECSS PUS-C telemetry decoding works*
   * *Testing satellite software without a satellite (Deterministic HIL & Fault Injection)*
   * *Deterministic Rust in embedded systems*

