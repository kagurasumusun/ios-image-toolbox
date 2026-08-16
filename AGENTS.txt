# AGENTS.md

# Disk Image Analyzer — Autonomous Development Constitution

## 1. 最重要方針

このプロジェクトは、iOS向けの汎用・高性能・高機能なディスクイメージ解析・抽出・検査アプリを開発する。

対象は特定のOS、機種、ファームウェア、ファイルシステムに限定しない。

対応対象は必要に応じて拡張可能な設計とし、最終的には以下を含む広範なディスクイメージ・ストレージ・バイナリ解析を目指す。

- RAW / IMG
- ISO
- QCOW / QCOW2
- MBR / GPT
- 各種ファイルシステム
- バイナリ
- ファームウェアイメージ
- その他の実在するイメージ形式

---

## 2. AI_Constitution

リポジトリ内に存在するAI_Constitution配下の内容を必ず事前に読み、完全に理解したうえで作業すること。

AI_Constitutionの内容を無視して実装を開始してはならない。

AI_Constitutionに定められた規則・原則・制約を、以後のすべての調査、設計、実装、テスト、Git操作、問題解決に適用する。

---

## 3. 基本アーキテクチャ

解析・抽出・フォーマット処理のコアはRustで実装する。

Rust CoreはiOSから独立した汎用ライブラリとして設計し、Linux上で単独ビルド・テスト・実行可能にする。

iOS向けの実装はSwiftで行う。

Swift側は原則として、

- SwiftUI
- iOS UI
- ファイル選択
- ファイルアクセス
- エクスポート
- iOS固有API
- Rust Coreとの連携

を担当する。

ディスクイメージ解析、ファイルシステム解析、検索、抽出、バイナリ解析等の本体ロジックをSwiftへ重複実装してはならない。

ディレクトリ構造やモジュール構成は、実装内容・依存関係・保守性・性能を考慮して最適なものを自律的に設計する。

---

## 4. 自律開発

このプロジェクトでは、ユーザーから細かな指示を受け続けることを前提としない。

ユーザーへの質問によって作業を停止してはならない。

不明点がある場合は、自律的に、

1. リポジトリを調査する
2. 実装を調査する
3. テストを調査する
4. 仕様・一次資料を調査する
5. 実データを調査する
6. 仮説を立てる
7. 実験する
8. 結果を検証する
9. 最適な実装を選択する
10. 実装する
11. テストする
12. 問題があれば修正する
13. 再検証する

という手順で解決する。

質問待ちで停止しない。

不確実な事項は事実として扱わず、

- FACT
- INFERENCE
- HYPOTHESIS
- UNKNOWN

を明確に区別する。

---

## 5. 長時間・高密度・自律開発

短時間で最低限の実装を作って終了することを目的としてはならない。

以下のループを可能な限り長く繰り返す。

調査
↓
設計
↓
実装
↓
Build
↓
Test
↓
実行
↓
結果解析
↓
Bug Fix
↓
再Build
↓
再Test
↓
性能測定
↓
品質改善
↓
追加テスト
↓
問題発見
↓
修正
↓
再検証
↓
次の課題
↓
継続

一つの機能を実装しただけで終了してはならない。

実装後には必ず、

- 正常系
- 異常系
- 境界条件
- 破損データ
- 大容量データ
- 性能
- メモリ
- 安全性
- 統合動作
- 回帰

まで可能な限り確認する。

---

## 6. 作業を勝手に終了しない

以下だけを理由として作業を終了してはならない。

- コードを書いた
- コンパイルできた
- UIが表示された
- 単一テストが通った
- 基本機能が動いた
- READMEを書いた
- TODOを作った
- 「実装可能」と判断した

現在の目的に対して重要な改善・検証・修正が残っているなら、自律的に継続する。

Julesのタスク境界や実行環境上の制約によって停止せざるを得ない場合を除き、可能な限り作業を継続する。

外部制約によって中断された場合も、未完了なのに完成扱いしてはならない。

---

## 7. Rust Core

Rust Coreはプロジェクトの中心である。

以下をRustで実装する。

- Image Container
- Block Device
- Partition Parser
- Filesystem Parser
- File Access
- Extraction
- Search
- Hex Analysis
- Strings
- Entropy
- Checksums
- Binary Detection
- Diagnostics
- その他の解析機能

Rust CoreはLinux上で独立して動作できること。

可能な限りiOS環境に依存しないテストをRust側で大量に実施する。

---

## 8. Block Device Abstraction

すべての上位解析機能の基盤として、ランダムアクセス可能なBlock Device abstractionを設計する。

概念的には、

Image Container
      ↓
Block Device
      ↓
Partition
      ↓
Filesystem
      ↓
Directory / File

というレイヤー構造を維持する。

RAW、IMG、ISO、QCOW2等の入力形式を上位のfilesystem parserへ直接漏らさない。

必要なデータだけを読み込む。

巨大イメージ全体をRAMへロードする設計は禁止する。

---

## 9. Image Container

最低限、

- RAW
- IMG
- ISO
- QCOW
- QCOW2

を対象とする。

将来的な追加を前提に、拡張可能な形式検出・解析構造を設計する。

形式判定は可能な限り構造検証も行う。

破損したイメージを入力しても、

- クラッシュしない
- 無制限にメモリを消費しない
- 無限ループしない
- 範囲外アクセスしない

ことを重視する。

---

## 10. QCOW2

QCOW2は仮想Block Deviceとして実装する。

概念的には、

QCOW2
↓
Header
↓
L1 Table
↓
L2 Table
↓
Cluster
↓
Virtual Block Device

として扱う。

可能な限り仕様に準拠して、

- virtual disk size
- cluster size
- L1
- L2
- refcount
- sparse allocation
- compressed cluster
- backing file
- unallocated cluster
- malformed metadata

等を正確に処理する。

整数オーバーフロー、範囲外アクセス、不正テーブル等を厳密に検証する。

---

## 11. Partition

最低限、

- MBR
- GPT

を実装する。

必要に応じてその他のpartition tableも追加する。

可能な限り、

- offset
- size
- type
- GUID
- attributes
- bootable
- filesystem候補

等を構造化して提供する。

破損したpartition tableも安全に解析できるようにする。

---

## 12. Filesystem

段階的に主要filesystemへ対応する。

優先候補:

1. FAT12
2. FAT16
3. FAT32
4. ISO9660
5. exFAT
6. NTFS
7. ext2
8. ext3
9. ext4
10. UDF

ただし実際の実装優先順位は、依存関係、利用価値、仕様の確実性、テスト可能性、実装難度等を評価して自律的に決定する。

filesystem APIは可能な限り共通化し、

- probe
- metadata
- directory listing
- file metadata
- random read
- streaming read
- extraction

等を統一的に扱えるようにする。

---

## 13. Extraction

ファイル抽出はストリーミング方式を基本とする。

巨大ファイルをRAMへ一括ロードしない。

以下を安全に処理する。

- Unicode filename
- invalid filename
- duplicate filename
- path traversal
- large file
- sparse file
- filesystem metadata error

---

## 14. Hex Analysis

高性能なHex解析機能をRust Coreに実装する。

必要機能:

- arbitrary offset read
- hexadecimal view
- ASCII
- UTF-8
- UTF-16LE
- endian interpretation
- byte selection
- hex search
- text search
- offset jump

巨大データを一括ロードせず、必要な範囲だけ取得する。

---

## 15. Search

検索エンジンはRust Coreで実装する。

対象:

- raw bytes
- hexadecimal pattern
- ASCII
- UTF-8
- UTF-16LE
- filenames
- paths
- metadata

大容量データではchunked / streaming方式を利用する。

---

## 16. Binary Analysis

必要に応じて、

- magic detection
- strings
- entropy
- checksum
- binary signatures
- offset analysis
- integer interpretation

等を実装する。

将来的に、

- ELF
- PE
- Mach-O
- firmware
- boot image
- executable
- archive
- その他のバイナリ形式

へ拡張可能な設計にする。

---

## 17. Swift / iOS

Swift側はiOS専用層として設計する。

担当範囲は、

- SwiftUI
- UI/UX
- iOS File Provider
- Document Picker
- Import / Export
- Share
- iOS lifecycle
- Rust Coreとの連携

等。

解析アルゴリズムをSwiftへ複製しない。

UIはRust Coreの解析結果を表示する役割を中心とする。

---

## 18. Rust ↔ Swift

RustとSwiftの境界は明確かつ最小限にする。

Rust内部の複雑な型を無秩序にSwiftへ公開しない。

大容量データについては不要なコピーを避け、

- streaming
- range-based read
- handles
- opaque objects
- bounded buffers

等を適切に利用する。

---

## 19. iOS Performance

Main Threadをブロックしてはならない。

長時間処理はバックグラウンドで実行する。

Swift Concurrency等を適切に利用し、

- progress
- cancellation
- error reporting
- background execution

を考慮する。

巨大なファイル一覧やHexデータを一括でSwiftUIへ渡さない。

---

## 20. Memory

数GB～数十GB以上のイメージを想定する。

以下の設計は禁止する。

entire image → RAM
entire filesystem → RAM
entire directory tree → RAM

基本原則:

Random Access
+
Streaming
+
Lazy Parsing
+
Bounded Cache

iOSの限られたメモリ環境でも安定して動作できるようにする。

---

## 21. Security

入力イメージは完全にuntrusted dataとして扱う。

特に以下を重点的に検証する。

- integer overflow
- signed/unsigned conversion
- allocation overflow
- out-of-bounds
- malformed metadata
- infinite loop
- recursion explosion
- decompression bomb
- path traversal
- malformed Unicode
- corrupted filesystem
- malicious QCOW2
- malicious partition table

不正入力によってアプリ全体がクラッシュしない設計を優先する。

---

## 22. Error Model

エラーを明確に分類する。

例:

- InvalidHeader
- UnsupportedFormat
- CorruptMetadata
- OutOfBounds
- UnexpectedEOF
- ChecksumMismatch
- UnsupportedFeature
- PermissionDenied
- Cancelled
- IOError

解析失敗の原因を可能な限り具体的に特定できるようにする。

---

## 23. Testing

Rust Coreを中心として大量のテストを作成する。

最低限、

- Unit Tests
- Integration Tests
- Golden Tests
- Malformed Input Tests
- Boundary Tests
- Regression Tests
- Performance Tests

を整備する。

実データとsynthetic fixtureを併用する。

破損データ、境界値、不正metadataを積極的にテストする。

---

## 24. Fuzzing

可能な範囲でparserへfuzz testingを導入する。

重点対象:

- Image Headers
- QCOW2 Metadata
- MBR
- GPT
- Filesystem Metadata
- Directory Entries

目標は、不正入力を与えてもクラッシュせず、安全にエラーとして処理できること。

---

## 25. Performance Engineering

性能改善は測定してから行う。

Measure
↓
Profile
↓
Identify Bottleneck
↓
Optimize
↓
Benchmark
↓
Regression Check

評価対象:

- parsing speed
- extraction throughput
- search throughput
- memory usage
- allocation
- cache efficiency
- I/O operations

推測だけで複雑な最適化を行わない。

---

## 26. UI/UX

アプリは単なるファイルブラウザではなく、専門的な解析ツールとして設計する。

概念的には、

Image
├── Overview
├── Partitions
├── Filesystems
├── Files
├── Hex
├── Strings
├── Search
├── Metadata
└── Export

等を提供する。

解析中は、

- 進捗
- 現在の処理
- キャンセル
- エラー
- 警告

を適切に表示する。

UIの見た目だけを優先せず、解析性能・操作性・情報密度・視認性を重視する。

---

## 27. End-to-End Validation

個別テストだけでなく、実際の利用経路を通して検証する。

Open Image
↓
Detect Container
↓
Parse Partition
↓
Detect Filesystem
↓
Browse Directory
↓
Open File
↓
Read File
↓
Search
↓
Extract File

この一連の処理が実際に動作することを確認する。

---

## 28. Git

安全な論理単位でこまめにコミットする。

長時間の変更を最後まで未保存状態にしない。

破壊的操作を行う前に現在状態を確認する。

ユーザーの変更を勝手に削除・上書きしない。

データ損失を絶対に避ける。

---

## 29. CI

利用可能なCIを積極的に利用する。

Rustについては可能な限り、

- cargo check
- cargo test
- cargo clippy
- cargo fmt --check

等を実行する。

iOS側についても利用可能な環境でbuild/testを実施する。

CI failureは放置せず、原因を調査し修正する。

---

## 30. 自律的問題発見

作業中に現在の目的へ関連する問題を発見した場合は、自律的に修正する。

対象:

- crash
- bug
- race condition
- memory問題
- performance regression
- parser error
- test failure
- architecture flaw
- security issue
- missing regression test

ただし無関係な領域への過度な脱線は避ける。

---

## 31. リファクタリング

同じ処理の重複を放置しない。

一方で、不要な抽象化や過剰設計も行わない。

判断基準:

- correctness
- performance
- maintainability
- extensibility
- testability
- complexity

必要な抽象化だけを導入する。

---

## 32. 完成判断

以下だけでは完成とみなさない。

- コードを書いた
- コンパイルできた
- UIが表示された
- TODOを追加した
- 単一テストが通った

完成度を判断する際は、

Implementation
+
Build
+
Test
+
Runtime Validation
+
Error Handling
+
Performance Validation
+
Regression Validation

を確認する。

---

## 33. 長時間自律実装プロトコル

常に現在の状態を評価し、次に最も価値の高い作業を自律的に選択する。

Current State
↓
Missing Capability / Problem
↓
Research
↓
Implementation
↓
Build
↓
Test
↓
Debug
↓
Optimization
↓
Regression Test
↓
Next Highest-Value Work
↓
Continue

ユーザーから次の指示が来ることを前提として停止しない。

質問待ちで停止しない。

実装した機能についても、さらに改善可能なら継続する。

---

## 34. 作業中断時

Julesの実行時間、環境、CI、ツール等の外部制約によって作業継続が不可能になった場合は、可能な限り、

- 現在の実装状態を保存
- ビルド可能状態を維持
- テスト結果を保存
- 問題を特定
- 次の作業を明確化

して、次回の実行から即座に継続できる状態にする。

中断を完成扱いしない。

---

## 35. 最終目標

最終的に、

Linux上で独立して動作する強力なRustディスクイメージ解析エンジン

と、

そのRust Coreを利用する高性能なiOSアプリ

を完成させる。

Rust Core
↓
正確な解析
↓
安全な処理
↓
高速な処理
↓
大量テスト
↓
継続的改善
↓
Swift Integration
↓
iOS実機検証

という構造を維持する。

調査、設計、実装、ビルド、テスト、デバッグ、性能改善、セキュリティ検証、リファクタリングを一体化した長時間自律開発ループを維持する。

最小限の実装で早期終了することではなく、実用的な完成度を最大化することを優先する。
