# XTCE-RS — specyfikacja projektu

**Cel:** biblioteka w Ruście do dekodowania telemetrii CCSDS na podstawie opisu XTCE, z generatorem statycznego dekodera i bindingami do Pythona.

**Teza wartości:** referencyjna implementacja (`lasp/space_packet_parser`, Python) ma zgłoszony problem wydajnościowy — wczytanie pliku XTCE trwa dłużej niż samo parsowanie pakietów (issue #112). Rust rozwiązuje to dwoma warstwami: szybkim parserem XML→IR oraz kompilacją IR do statycznego kodu dekodera. To jest mierzalna przewaga, nie „bo Rust".

---

## 1. Zakres — czytaj to najpierw

XTCE jest ogromny. Cztery poprzednie próby w Ruście umarły, bo autorzy celowali w pełną zgodność. **Ten projekt celowo implementuje podzbiór i traktuje to jako feature, nie wstyd.** Yamcs robi dokładnie to samo.

### W zakresie MVP

**Sekcja:** wyłącznie `TelemetryMetaData`.

| Element | Zakres |
|---|---|
| `IntegerParameterType` | `unsigned`, `twosComplement`, `signMagnitude`; 1–64 bitów |
| `FloatParameterType` | IEEE754_1985, 32 i 64 bity |
| `EnumeratedParameterType` | pełny `EnumerationList`, w tym zakresy |
| `BooleanParameterType` | z `zeroStringValue` / `oneStringValue` |
| `StringParameterType` | fixed-size oraz terminated (null-terminated) |
| `BinaryParameterType` | fixed-size |
| `AbsoluteTimeParameterType` | tylko `Encoding` z offsetem/skalą do epoki |
| `SequenceContainer` | `EntryList` z `ParameterRefEntry` i `ContainerRefEntry` |
| `BaseContainer` | dziedziczenie + `RestrictionCriteria` (`Comparison`, `ComparisonList`) |
| `LocationInContainerInBits` | `previousEntry`, `containerStart` |
| Kalibratory | `PolynomialCalibrator`, `SplineCalibrator` (interpolacja liniowa) |
| Kolejność bitów | MSB-first (domyślna dla CCSDS), big-endian |

### Poza zakresem — jawnie odrzucone

`CommandMetaData` · `MathAlgorithm` / `CustomAlgorithm` · `ArrayParameterType` · `AggregateParameterType` · `RepeatEntry` z `DynamicValue` · `StreamSet` · alarmy i limity · `ContextCalibrator` · `ErrorDetectCorrect` · little-endian bit fields · `IndirectParameterRefEntry`

**Reguła dla agenta:** napotkanie elementu spoza zakresu → zwróć błąd `XtceError::Unsupported { element, path }` z nazwą elementu i ścieżką w drzewie. **Nigdy nie implementuj go ad hoc.** Nieznane atrybuty w obsługiwanych elementach → ignoruj cicho (jak Yamcs), ale zaloguj na poziomie `debug`.

Plik `SUPPORTED.md` w repo utrzymuje tabelę pokrycia i jest aktualizowany przy każdym milestone.

---

## 2. Architektura

Workspace Cargo, pięć crate'ów:

```
xtce-rs/
├── crates/
│   ├── xtce-model/     # XML → IR, rozwiązywanie referencji, walidacja
│   ├── xtce-decode/    # runtime: IR + &[u8] → wartości parametrów
│   ├── xtce-codegen/   # IR → wygenerowany kod Rust (build.rs)
│   ├── xtce-cli/       # xtce info / xtce decode — smoke testy i demo
│   └── xtce-py/        # bindingi PyO3 (ostatni milestone)
├── testdata/           # pliki XTCE + binarki pakietów
├── benches/
├── SUPPORTED.md
├── PROGRESS.md
└── BLOCKERS.md
```

### `xtce-model`

- Parser oparty o `quick-xml` w trybie strumieniowym (**nie** serde-xml — potrzebna kontrola nad namespace'ami i kolejnością).
- Dwa przebiegi: (1) zbierz definicje, (2) rozwiąż referencje `parameterTypeRef` / `containerRef` / `baseContainer`. Referencje w XTCE są ścieżkami w drzewie SpaceSystem (`/Root/Sub/Param`), obsłuż zarówno absolutne, jak i względne.
- IR trzyma parametry i typy w `Vec` z indeksami (`ParamId(u32)`), nie w `HashMap<String, Rc<...>>`. Nazwy w osobnym interning tablicy. To warunek szybkiego ładowania i późniejszego codegenu.
- Wykrywanie cykli w dziedziczeniu kontenerów → błąd, nie stack overflow.

### `xtce-decode`

- Własny `BitCursor<'a>` nad `&'a [u8]`, MSB-first, bez `bitvec` (zależność nie jest warta narzutu; napisz i przetestuj property-testami).
- API strumieniowe: `Decoder::decode(&self, packet: &[u8]) -> Result<DecodedPacket<'_>>`, gdzie wartości binarne i stringowe są `&[u8]` / `&str` bez alokacji.
- Rozróżnij `RawValue` i `EngValue` — XTCE traktuje je jako osobne pojęcia i testy różnicowe to wychwycą.
- Dopasowanie kontenera: dla MVP liniowy skan po dzieciach z ewaluacją `RestrictionCriteria`, ale API zaprojektuj tak, by dało się podmienić na drzewo decyzyjne bez zmiany sygnatur.
- Zero `panic!` i zero `unwrap()` w kodzie biblioteki. Złośliwy/uszkodzony pakiet → `Err`, nigdy crash.

### `xtce-codegen`

To jest różnica względem wszystkich istniejących implementacji. Wejście: IR. Wyjście: plik `.rs` ze strukturami i rozwiniętymi funkcjami dekodującymi — przesunięcia bitowe policzone w czasie kompilacji, brak interpretacji drzewa w runtime. Używany z `build.rs`. Generuj przez `quote` + `proc-macro2`, formatuj `prettyplease`.

Zacznij od podzbioru: kontenery o stałym rozmiarze i typach całkowitych. Rozszerzaj dopiero, gdy testy różnicowe przechodzą.

---

## 3. Dane testowe i strategia weryfikacji

**To jest najważniejsza część specyfikacji.** Bez tego nocna sesja wyprodukuje kod, którego nikt nie zweryfikuje.

### Skąd wziąć pliki

1. `git clone https://github.com/lasp/space_packet_parser` — katalog z danymi testowymi zawiera realne pliki XTCE i binarki pakietów (JPSS, CLARREO, SUDA). To jest złoto.
2. `git clone https://github.com/yamcs/yamcs` — pliki XTCE w zasobach testowych.
3. Schemat XSD XTCE 1.2 oraz przykład z Annex A dokumentu CCSDS 660.2-G-2.

Skopiuj do `testdata/` z plikiem `testdata/SOURCES.md` opisującym pochodzenie i licencję każdego pliku.

### Testy różnicowe — rdzeń weryfikacji

```
pip install space_packet_parser
```

Napisz `xtask/diff_test.rs` (lub skrypt) który:
1. Uruchamia pythonową referencję na pliku XTCE + strumieniu pakietów, zrzuca wynik do JSON (nazwa parametru → lista wartości raw i eng).
2. Uruchamia implementację Rust na tym samym wejściu, zrzuca ten sam format.
3. Porównuje. Różnica → nazwa parametru, indeks pakietu, obie wartości.

Zapisz golden files w `testdata/golden/`, żeby test działał też bez Pythona w CI.

Dla floatów: porównanie z tolerancją, ale wartości raw muszą zgadzać się bit w bit.

### Testy jednostkowe

Każda zmiana w parserze → test z minimalnym snippetem XML wklejonym inline w teście (nie plik). Docelowo `proptest` na `BitCursor`: losowe offsety i szerokości, porównanie z naiwną implementacją referencyjną.

---

## 4. Milestone'y

Warunek wyjścia każdego milestone jest sprawdzalny automatycznie — agent ma go weryfikować, zanim przejdzie dalej.

| # | Zakres | Warunek wyjścia |
|---|---|---|
| **M0** | Workspace, CI (fmt + clippy + test), `testdata/` pobrane i opisane, `SUPPORTED.md` z tabelą z sekcji 1 | `cargo test` przechodzi na pustym projekcie, dane testowe w repo |
| **M1** | `xtce-model`: parser XML → IR dla podzbioru, rozwiązywanie referencji | `xtce info testdata/*.xml` wypisuje drzewo SpaceSystem, liczbę parametrów i kontenerów dla **wszystkich** plików testowych bez błędu |
| **M2** | `BitCursor` + dekoder dla Integer/Float/Enum/Boolean, dziedziczenie kontenerów, `RestrictionCriteria` | `xtce decode` zwraca wartości dla realnego strumienia pakietów; testy proptest na BitCursor zielone |
| **M3** | Harness testów różnicowych vs Python | Zerowa liczba rozbieżności na co najmniej jednym pełnym pliku testowym; golden files zapisane |
| **M4** | Kalibratory (polynomial, spline), String/Binary/AbsoluteTime | Testy różnicowe zielone na wszystkich plikach testowych |
| **M5** | `xtce-codegen` dla podzbioru | Wygenerowany dekoder daje identyczny wynik co interpretowany na golden files |
| **M6** | Benchmarki criterion | Raport: czas ładowania XTCE i przepustowość dekodowania, Rust interpretowany vs codegen vs Python |
| **M7** | `xtce-py` (PyO3 + maturin) | `import xtce` w Pythonie dekoduje ten sam plik |

**Realistyczny cel na jedną noc: M0–M3.** Nie próbuj domykać M5 w pierwszej sesji.

---

## 5. Guardrails dla sesji autonomicznej

Wklej to do `CONTRIBUTING.md` w repo:

```markdown
## Zasady pracy w tym repo

1. ZAKRES: implementuj wyłącznie elementy z tabeli w SUPPORTED.md.
   Element spoza zakresu → XtceError::Unsupported, NIGDY implementacja ad hoc.
   Nie rozszerzaj SUPPORTED.md bez wyraźnego polecenia.

2. MILESTONE'Y: pracuj sekwencyjnie M0→M1→M2→...
   Nie przechodź dalej, dopóki warunek wyjścia nie jest spełniony i zweryfikowany
   uruchomieniem komendy. Nie zakładaj, że działa — sprawdź.

3. COMMITY: po każdym milestone i po każdej samodzielnej jednostce pracy.
   Format: conventional commits. Nigdy nie commituj kodu, który się nie kompiluje.

4. BLOKADY: jeśli po 2 próbach nie umiesz czegoś rozwiązać — dopisz wpis do
   BLOCKERS.md (co, dlaczego, co próbowałeś) i przejdź do następnego zadania.
   Nie kręć się w pętli.

5. JAKOŚĆ: zero unwrap()/expect()/panic! w kodzie bibliotecznym (testy mogą).
   cargo clippy -- -D warnings musi przechodzić.
   Każda zmiana w parserze → test z minimalnym snippetem XML.

6. LOG: dopisuj do PROGRESS.md po każdym milestone — co zrobione, co działa,
   co następne. Pisz zwięźle, to ma być czytelne rano.

7. NIE: nie publikuj na crates.io. Nie dodawaj zależności spoza listy:
   quick-xml, thiserror, clap, criterion, proptest, quote, proc-macro2,
   prettyplease, pyo3, serde_json (tylko w testach/CLI).
   Każda inna zależność wymaga wpisu uzasadniającego w PROGRESS.md.
```

---

## 6. Prompt startowy

```
Przeczytaj SPEC.md w tym katalogu — to pełna specyfikacja projektu.
Przeczytaj CONTRIBUTING.md — to zasady pracy, obowiązują bezwzględnie.

Zadanie na tę sesję: zrealizuj milestone'y M0, M1, M2 i M3 ze specyfikacji,
sekwencyjnie, weryfikując warunek wyjścia każdego przed przejściem dalej.

Zacznij od M0. Zanim napiszesz kod, wypisz plan dla M0 i sprawdź go
względem sekcji 2 i 3 specyfikacji.

Krytyczne: M3 (testy różnicowe wobec pythonowego space_packet_parser)
jest ważniejszy niż M4-M7. Bez działającej weryfikacji reszta jest bezwartościowa.
Jeśli zabraknie czasu, lepiej mieć M0-M3 zielone niż M0-M5 niesprawdzone.
```

---

## 7. Uwagi strategiczne

**Nazwa.** Na crates.io nie ma ani jednego crate'a zaczynającego się od `xtce`. Nazwy `xtce`, `xtce-model`, `xtce-decode` są wolne. Warto zarezerwować `xtce` wczesnym placeholderem — to najbardziej oczywista nazwa w tej niszy i nie chcesz jej stracić.

**Konkurencja.** `greglucas/space-data-toolkit` (3 ⭐, aktywne) idzie w podobnym kierunku. Greg Lucas jest współautorem pythonowej referencji, więc zna temat lepiej niż ktokolwiek. Rozsądny ruch po M3: napisz do niego z benchmarkiem w ręku i zapytaj o połączenie sił albo o podział zakresu. Lepiej mieć jeden żywy projekt niż dwa martwe — a to jest dokładnie ta branża, w której relacje znaczą więcej niż gwiazdki.

**Sygnał ostrzegawczy.** `xpromache/xtce-rs` porzucone przez głównego developera Yamcs. Warto przeczytać ten kod przed startem — nie po to, by go kopiować, tylko żeby zobaczyć, gdzie autor się zatrzymał. To najtańsza lekcja w całym projekcie.
