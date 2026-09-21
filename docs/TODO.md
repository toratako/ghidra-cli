# ghidra-cli TODO

未完了の課題と検討メモ。仕様・コマンド名・引数・優先順位は未確定で、以下のコマンド例は案です。

## 優先度・実装難易度・すり合わせの目安

主観的な仮評価で、実装順序の確約ではない。優先度はREでの効果、難易度はAIが既存コードとGhidra APIを調べて実装・検証する前提。仕様の未確定さは難易度ではなく、すり合わせ必要度で分ける。

- 優先度：高＝先に取り組みたい、中＝必要性に応じて進めたい、低＝当面は後回し。
- 難易度：低＝既存APIと実装パターンで素直に実装できそう、中＝実装の見通しは立つが状態管理や複数ケースの検証が必要、高＝解析精度や広い副作用の保証に試行錯誤が必要。CLI・Java bridge・テストまで含む主観で、工数見積もりではない。
- すり合わせ必要度：低＝既存の設計から自然に決められそう、中＝対象範囲や出力の具体案を合わせたい、高＝目的・操作モデル・許容する副作用などで実装が大きく変わる。新たな承認手続きを設ける意味ではなく、既に合意した内容は再確認しない。

| 項目                                       | 優先度 | 難易度 | すり合わせ必要度 | 実装の見立て・合わせたい点                                                                                                        |
| ------------------------------------------ | ------ | ------ | ---------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Processor context                          | 中     | 中     | 中               | 既存APIを使えるが再逆アセンブルとの整合性は検証が必要。範囲指定と自動再解析の有無を合わせたい。                                   |
| Rebase                                     | 中     | 低     | 中               | 基本操作は既存APIで実装できそう。基準アドレスの指定方法と衝突時の扱いを合わせたい。                                               |
| Processor / language変更                   | 低     | 中     | 高               | API呼び出しより変更後の状態検証が中心。既存解析をどこまで保持・再生成するかで仕様が変わる。                                       |
| 破壊的操作のdry-run / plan                 | 中     | 高     | 高               | 任意スクリプトや外部副作用まで含む保証は難しい。対象操作と、予告だけか実行結果の再現まで求めるかを合わせたい。                    |
| `patch assemble`                           | 低     | 中     | 高               | Ghidraのassemblerを使う前提なら実装の見通しはある。命令長が変わる場合の扱い、`memory write` との役割、dry-runの範囲を合わせたい。 |
| 参照の作成・削除・primary指定              | 高     | 低     | 中               | 参照APIと対象検証で実装できそう。参照種別・operand・削除対象の指定方法を合わせたい。                                              |
| Equateの編集                               | 高     | 低     | 中               | 既存APIで作成・一覧・削除を組めそう。operand指定と定義削除・適用解除の区別を合わせたい。                                          |
| 関数bodyの修正                             | 高     | 低     | 中               | 範囲検証とbody設定で実装できそう。全体置換か範囲の追加・削除も扱うかを合わせたい。                                                |
| Call-site単位のシグネチャ上書き            | 高     | 低     | 中               | 既存のシグネチャ処理とoverride APIで実装できそう。対象指定・取得・解除の操作を合わせたい。                                        |
| Bitfield                                   | 中     | 中     | 中               | 配置APIを使い、エンディアンとレイアウトの検証に注力する。ビット位置の指定方法を合わせたい。                                       |
| 型のclone                                  | 中     | 低     | 中               | 既存型の複製は実装できそう。名前・category・参照先の型をどこまで複製するかを合わせたい。                                          |
| 型のresize                                 | 中     | 低     | 中               | サイズ変更自体は素直。縮小でフィールドが欠ける場合の扱いを合わせたい。                                                            |
| フィールド置換                             | 低     | 低     | 中               | 既存の `type set-field` を基に進められそう。追加操作が必要か、サイズ変更をどこまで許すかを合わせたい。                            |
| Category・archive・source archive・type ID | 低     | 中     | 高               | 個々のAPI操作は実装できそう。型の整理だけか、外部archiveの更新・同期まで含むかで範囲が大きく変わる。                              |
| `FillOutStructureHelper` による復元支援    | 中     | 中     | 高               | 推定処理は既存helperを使える。候補提示か自動適用か、既存型をどこまで変更するかを合わせたい。                                      |
| 構造化されたDecompiler出力                 | 高     | 中     | 高               | 既存のDecompiler情報を辿って出力する実装はできそう。用途に応じた粒度・識別子・出力量の設計を合わせたい。                          |
| Global symbolsとparameter / globalの判別   | 中     | 低     | 中               | シンボル情報の取得・整形で進められそう。関数内で使うものかProgram全体かを合わせたい。                                             |
| データフロー追跡・スライシング             | 中     | 中     | 高               | 関数内のP-code追跡なら実装の見通しはある。関数間・メモリaliasまで追うか、どの程度の精度を求めるかで難易度が上がる。               |
| VTable解析                                 | 中     | 中     | 高               | ABIを絞った候補検索なら実装できそう。対象ABI・継承への対応・候補提示と確定結果の区別を合わせたい。                                |
| 未定義関数の候補検索                       | 高     | 低     | 中               | 参照先と命令・関数の有無を照合する実装は素直。除外条件と、候補提示に留めるかを合わせたい。                                        |

## 解析設定・プログラム設定

- Processor context：ARM / Thumbの `TMode` などを扱う。
- プログラムのrebase（base address変更）を検討する。インポート後にベースアドレスの誤りを修正したい。操作案：`ghidra-cli program rebase 0x80000000`。
- Processor / languageの変更を検討する。

## 編集操作

### Dry-run・パッチ

- 破壊的操作のdry-run / plan出力を検討する。通常の単一Program編集にはリクエスト単位のロールバックがあるが、スクリプト、プロジェクトやファイルシステムへの影響、部分的な結果を保持する操作は別途考慮が必要。
- `patch assemble` の必要性と `memory write` との役割分担を検討する。以前削除した `patch nop` の扱いも含め、パッチ操作での `--dry-run` を考える。

Program内で完結する編集から、実行後にロールバックするdry-runと共通書き込み操作への展開範囲を検討する。

```text
ghidra-cli memory write ... --dry-run
ghidra-cli type apply ... --dry-run
ghidra-cli function set-signature ... --dry-run
ghidra-cli xref delete ... --dry-run
```

### 参照・equateの編集

```sh
ghidra-cli xref create memory FROM TO
ghidra-cli xref delete FROM TO
ghidra-cli xref set-primary FROM TO

ghidra-cli equate create 0x401234 1 READ_MODE
ghidra-cli equate list
```

VTable、jump table、function pointerなど、解析器が見逃した関係をuser-defined referenceとして登録したい。例えばtable slot `0x405020` から関数 `0x401300` への参照をDBに残し、xref navigationやGUI、参照種別に応じた後続解析で利用する。

削除はデフォルトで `USER_DEFINED` のみに限定し、解析由来などを消す場合は明示指定にする案。

```sh
ghidra-cli xref delete FROM TO --source analysis
ghidra-cli xref delete FROM TO --all-sources
```

`create/delete` と `add/remove` の命名は未確定。既存の参照識別情報を使ったoperand単位の対象指定と、削除する由来の範囲を合わせたい。

Equate削除の対象指定は未検討。

### 関数bodyの修正

誤認した境界を修正するため、既存関数のbody変更を検討する。

```sh
ghidra-cli function set-body FUN_401000 0x401000:0x40107f
```

### Call-site単位のシグネチャ上書き

間接呼び出しに対して、特定のprototypeをDecompilerへ伝えたい。関数全体のシグネチャを変更せず、そのcall-siteだけに適用できることが重要。

```sh
ghidra-cli function call-signature get main --at 0x401234
ghidra-cli function call-signature set main \
  --at 0x401234 \
  --signature 'int handler(Context *, int)'
```

参考メモ：headless側の `decomp.override.get` / `decomp.override.set`。

### 型操作の拡充

型操作の追加候補：

- Bitfield、型のresize。
- フィールド置換：既存の `type set-field` で足りない操作があるか確認する。
- Categoryの一覧・作成・削除、型のcategory間移動、archive、source archive、type IDの扱い。
- 型のclone：既存型を複製し、別の型として編集する。
- `FillOutStructureHelper` を使った構造体復元支援。

既存の `TypeResolver` で `char *`、`Foo **`、`byte[16]`、`Foo[2][3]` を指定でき、`type import-c` もあるため、名前付きpointer / arrayの専用作成コマンドは急がない。

```text
type resize ...
type clone ...
type category list/create/delete ...
type move ...
```

## Decompiler・データフロー

### 構造化されたDecompiler出力

HighFunction、tokens、ASTなど、テキスト以外の解析結果を取得したい。

```sh
ghidra-cli decompile main --structured high
ghidra-cli decompile main --structured tokens
ghidra-cli decompile main --structured ast
ghidra-cli pcode uses main --var local_18
```

既存の `decompile --with-vars` / `--with-params` で得られるローカル変数・引数の型やstorageに加え、次を検討する。

- Global symbolsと、parameter / globalの判別。

### データフロー追跡・スライシング

「この値はどこから来たのか」「最終的にどこへ行くのか」を直接問い合わせたい。

参考メモ：ReVaはDecompilerの `HighFunction` / `Varnode` / `PcodeOp` を使う。

- 操作候補：`trace-data-flow-backward`、`trace-data-flow-forward`、`find-variable-accesses`。
- 探索範囲・対象の指定候補：`--max-depth`、`--max-nodes`、`--operand N`、`--varnode`。

## 検索・解析支援

### VTable解析

`obj->vtable->method(obj)` のような、通常のxrefでは見つけにくい間接呼び出しを調べたい。

操作候補：`analyze-vtable`、`find-vtables-containing-function`、`find-vtable-callers`。

### 未定義関数の候補検索

参考メモ：ReVaは次の条件から候補を列挙する。

- CALL参照、または関数ポインタなどのDATA参照の参照先。
- 実行可能メモリ内にあり、命令が存在する。
- まだFunctionとして定義されていない。
- PLT / GOTなどは除外する。

## APIギャップレポートからの追加候補

[APIギャップレポート](AGENT_RE_API_GAP_REPORT.md) とMCP比較メモの追加候補。評価は表の初期範囲を対象とする。API調査は静的で、実環境での動作検証は実装時に必要。

| 項目                                         | 優先度 | 難易度 | すり合わせ必要度 | 最初に扱いたい範囲・論点                                                                                         |
| -------------------------------------------- | ------ | ------ | ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| 型付きデータ・globalの一覧と実体読み取り     | 高     | 中     | 中               | 型やxref数で探索し、構造体・配列・scalar・pointerの値を読む。展開深度・取得件数・編集操作との分担を合わせたい。  |
| Bookmarkの設定・削除                         | 低     | 低     | 中               | 任意アドレスの未解決事項を記録する。コメントや外部ログとの分担、削除対象を合わせたい。                           |
| 関数内CFGの取得                              | 高     | 中     | 中               | 命令ベースの基本ブロックと分岐を取得する。グラフの粒度と出力上限を合わせたい。                                   |
| ファイル位置との対応                       | 中     | 低     | 中               | ファイル位置とロード後アドレスの対応を読む。対応なし・複数対応の出力を合わせたい。                              |
| 範囲指定・差分の再解析                       | 中     | 中     | 中               | 指定範囲の再解析と保留中の変更の解析を分ける。実行・完了の意味を合わせたい。                                     |
| 型・フィールドの使用箇所検索                 | 中     | 中     | 高               | まず型を適用したデータと関数シグネチャを検索。ローカル変数や意味的なフィールドアクセスまで含めるかを合わせたい。 |
| 未定義領域の文字列候補検索                   | 中     | 低     | 中               | 対象文字集合を絞って候補を列挙。最小長・アラインメント・終端条件を合わせたい。                                   |
| メモリブロックの作成・変更・削除             | 中     | 中     | 高               | RAM・MMIO・overlayをモデル化し、rename / moveも扱う。初期化状態・権限・衝突・削除の影響を合わせたい。            |
| 名前空間・クラス・外部リンクの編集           | 中     | 中     | 中               | 作成・所属変更・primary symbol指定・外部ライブラリとの関連を扱う。対象指定と操作単位を合わせたい。               |
| 関数ABI・storage・thunkの詳細                | 中     | 中     | 高               | まず読み取りを充実させる。引数配置やthunk転送先の編集まで含めるかを合わせたい。                                  |
| 命令の制御フロー上書き                       | 中     | 低     | 中               | 特定命令のflow overrideとfallthroughを取得・設定・解除する。対象検証と再解析の扱いを合わせたい。                 |

### 型付きデータ・アドレスの状態

型の定義だけでなく、型を適用したアドレスの実際の値を読みたい。例えば `Header` や `Entry[32]` の各フィールドを、Ghidraのレイアウトとエンディアンに従って取得する。

- ネストした構造体・配列の展開に上限を設ける。ポインタ追跡は明示指定で範囲を限定する。
- オブジェクト途中のアドレスでも、親オブジェクト・内部オフセット・選択されたフィールドを確認できるようにする。
- 未初期化・未マップ・値を取得できない状態を、値のゼロと区別する。

型や参照数から、Listingのグローバル変数やテーブルを探す用途も含む。

```sh
ghidra-cli data list --filter 'type contains "MyStruct"'
ghidra-cli global list --sort xrefs:desc
ghidra-cli data get 0x404080
```

取得結果の案：

```json
{
    "address": "0x404080",
    "name": "g_config",
    "type": "Config",
    "length": 64,
    "xrefs": 18
}
```

編集側は `global set` のような複合操作より、データ定義・解除、シンボル、コメントを独立した操作にする案を優先して検討する。

```text
data define ADDRESS TYPE
data clear ADDRESS
symbol ...
comment ...
```

操作の分担は未確定。既存の `type apply` などと役割が重なるため、専用コマンドを増やす必要があるかも検討する。

### 関数内CFG

基本ブロックの範囲と辺として分岐・合流・ループを読み、基本ブロック数やjump table情報を補う。

- 最初は命令ベースのCFGを対象とし、最適化後のDecompiler CFGとは混ぜない。
- callと関数内の後続ブロックへの辺を区別し、未解決・関数外への遷移も表現する。
- 非連続な関数bodyとdelay slotを考慮する。画像化を必須にせず、エージェントが辿れる構造化出力にする。

### ファイルとの対応・再解析・検索

- ファイルオフセットからロード後アドレスへの対応は、対応なし・単一・複数を扱う。BSSなど直接のファイル位置を持たない領域も区別する。
- 全体再解析・範囲指定再解析・保留中の変更の解析を区別する。範囲指定は、その外側へ解析の影響が出ないという保証にはしない。
- 型・フィールド検索では、型が適用されたデータ、シグネチャやローカル変数での使用、実際のフィールドアクセスを区別する。まず範囲を限定した走査から検討する。
- 未知の文字列は検索語なしで候補を探す。既知の文字列を探す `find text` とは別の用途で、任意の文字コードを自動判別できる前提にはしない。

### 解析モデルの追加編集

- メモリ配置：インポート後にRAM・MMIO・overlayを追加し、アクセス権限やvolatile属性を設定したい。名前変更・削除・移動まで含め、Memory Mapを修正できる範囲を検討する。全体のrebaseと単一ブロックの移動は分ける。
- 名前空間・クラス：復元した構造に合わせてシンボルの所属を変更したい。renameだけでは表せない所属・primary指定・外部リンクを扱う。
- ABI・storage・thunk：スタックフレーム、引数のレジスタ・スタック配置、thunkの転送先をまず確認できるようにする。明示的な配置編集は通常のシグネチャ変更と分けて検討する。
- 制御フロー：バイトを変更せず、特定命令のcall / jumpなどの解釈やfallthroughを補正したい。命令本来のフローと上書き内容を読み分け、解除できるようにする。

メモリブロック操作の案：

```text
memory block create .mmio 0x40000000 0x1000 --read --write --uninitialized
memory block create overlay 0x1000 0x2000 --overlay ...
memory block rename ...
memory block delete ...
memory block set-permissions ...
memory block move ...
```

ABI操作の案：

```text
function var set-storage foo arg1 RCX
function var set-storage foo result RAX
```

C++の `this` の型は専用操作にするか、既存の変数編集で扱える範囲を広げるか検討する。

```sh
ghidra-cli function edit-var Foo --var this --type 'Widget *'
```

### 別途用途を固めたい大きな候補

- ローカルエミュレーション（優先度：低、難易度：中、すり合わせ：高）。小さな関数や範囲の実行から検討する。初期レジスタ・メモリ、外部呼び出し、未定義メモリへのアクセス、停止条件・実行上限を決める必要がある。広い実行環境の再現まで求める場合は難易度が上がる。
- プログラム間の比較・注釈移植（優先度：低、難易度：高、すり合わせ：高）。別バージョンへ解析成果を引き継ぎたい。2つのProgramの管理、アドレス・型の対応付け、注釈の衝突処理まで含むため、単一Programの操作とは別の機能群として検討する。

## プロジェクト保存・自動化

MCP比較メモ由来の追加候補。

| 項目                                   | 優先度 | 難易度 | すり合わせ必要度 | 最初に扱いたい範囲・論点                                                                       |
| -------------------------------------- | ------ | ------ | ---------------- | ---------------------------------------------------------------------------------------------- |
| `.gar` によるproject archive / restore | 中     | 中     | 中               | プロジェクト全体を保存・復元する。稼働中の扱い、復元先、既存プロジェクトとの衝突を合わせたい。 |
| Programのproperty map / options        | 低     | 中     | 高               | 自動化向けの情報・設定を扱う。具体的な対象・操作範囲は未検討。                                 |

### `.gar` によるプロジェクト保存・復元

単一Programの `program export gzf` に加え、複数Program・フォルダ・プロジェクトのメタデータをまとめて保存・復元したい。バックアップ、テストfixture、環境移行に使う。

```sh
ghidra-cli project archive ./snapshot.gar
ghidra-cli project restore ./snapshot.gar
```

### Programのproperty map / options

`property ...`、`program option ...` を候補とする。自動化には有用そうだが、通常のREでは用途を絞って優先度を判断する。具体的な対象・操作は未検討。

## JSON出力の契約

エージェントがコマンドごとの特例を減らして結果を扱えるようにしたい。出力形式や共通envelopeの採否は未確定。

| 項目 | 優先度 | 難易度 | すり合わせ必要度 | 最初に扱いたい範囲・論点 |
| --- | --- | --- | --- | --- |
| 結果形と単発・batchの整合性 | 高 | 中 | 高 | 単一結果・一覧・件数の出力契約を定め、同じ操作の単発結果とbatch内の結果を揃えたい。 |
| 配列抽出の明示化とmetadataの保持 | 高 | 中 | 中 | キー名による推測を明示的な結果定義に置き換え、必要なmetadataを残したい。 |

### 結果形と単発・batchの整合性

現在は管理系がobject、通常のbridge経由の単一結果もarray、`--count` は数値を返す。単発実行では配列を抽出する一方、batchではRust側の追加query処理がなければbridgeのenvelopeを保持するため、同じ操作でも結果形が変わる。

- 単一結果・一覧・件数をどう表現するか決める。共通の `status / data / meta` envelopeは候補だが、必須にはしない。
- 単発の結果とbatch内の各 `result` の形を揃える方針を検討する。batch全体の進行・失敗情報は別に扱う。
- filter・fields・countなどの指定がある場合も、どの部分に作用して何を返すかを明確にする。

### 配列抽出の明示化とmetadataの保持

`unwrap_bridge_response()` は既知の配列キーとmetadataキーの組み合わせから行配列を抽出するため、`count` や検索対象などの付随情報が出力から落ちる場合がある。

- コマンドの結果定義で「行データ」「単一オブジェクト」「付随情報」を明示し、キー名の組み合わせに出力形を依存させない。
- 検索対象や件数など、結果を解釈するためのmetadataを残す。filter・limit適用後の件数と全体件数を曖昧にしない。
- graphの `nodes / edges` やネストしたデータを、通常の一覧と誤認して展開しない。
- 必要な情報を通常のJSON出力で取得できる設計を先に考える。`--raw-json` / `--bridge-json` の追加は、別モードが必要な用途がある場合の候補に留める。

---

- <https://github.com/mrphrazer/ghidra-headless-mcp>
- <https://github.com/cellebrite-labs/ghidra-rpc>
- <https://github.com/bethington/ghidra-mcp>
- <https://github.com/ghidra-user-jp/mecha_ghidra>
