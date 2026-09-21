# Audit 0.4.0

## 0.4.0

### 1. 並列実行で、明示したプログラムとは別のプログラムを更新する

Owner Note: 難しい
`--program` の選択と操作が別リクエストのため、間に別クライアントが選択を変えると、別プログラムへ編集・保存されます。ジョブの直列実行だけでは防げません。

**対策:** 各操作に対象ファイルの識別子を付け、選択・検証・操作を一つのジョブで実行する。\
根拠: [`execute_bridge_command`](../src/app/mod.rs)、[`ProgramSession.program`](../src/ghidra/scripts/ghidracli/ProgramSession.java)

### 4. localhost IPCに利用者認証がない

Owner Note: 今のところ必要ない
接続した要求を認証せず、プログラム操作やスクリプト実行へ渡します。信頼しない別OSユーザーがいるホストでは、ブリッジ所有者の権限で処理を実行できます。

**対策:** 所有者だけが読める接続秘密、または利用者資格情報を検証できるローカルIPCを使う。\
根拠: [`BridgeServer.serveClient`](../src/ghidra/scripts/ghidracli/BridgeServer.java)

### 7. カテゴリ指定のC型importが、既存型を移動・上書きする

Owner Note: そんなに急ぎでなくともよさそう
パーサーが既存の同等型を返すと、その型自体を指定カテゴリへ移動します。ROOTに同名・異定義の型がある場合は、移動前の解析で既存定義を上書きします。

**対策:** 独立した型管理領域で解析・検証してから、指定カテゴリへ登録する。\
根拠: [`TypeImportCommands`](../src/ghidra/scripts/ghidracli/TypeImportCommands.java)。[既存のカテゴリ分離テスト](../tests/type_tests.rs)の成功は、ROOT衝突・同等型再利用の安全性を保証しません。

## Hardening

- **要求サイズと処理時間の上限。** [`BridgeServer`](../src/ghidra/scripts/ghidracli/BridgeServer.java)は無制限の行読込と期限のない応答書込を行います。30秒のsocket read timeoutとキュー件数制限だけでは、メモリ・接続ワーカーを保護できません。要求サイズと処理全体の期限が必要です。
- **memory readの検証・分割。** [`handleReadMemory`](../src/ghidra/scripts/ghidracli/MemoryCommands.java)はサイズを`int`へ縮小し、上限なしで配列を確保します。値域検証と分割読込で、誤変換とJVMのメモリ枯渇を防ぐ必要があります。
- **一時scriptの資源回収。** [`ScriptCommands`](../src/ghidra/scripts/ghidracli/ScriptCommands.java)はソースだけを削除し、登録したOSGi bundleや別ディレクトリのコンパイル成果物を回収しません。所有・回収方法を定める必要があります。累積量は未計測です。
- **ログ量と記録内容の制御。** [debugログが常時有効](../src/main.rs)で、[要求・応答全文](../src/ipc/client/transport.rs)を保存します。長さ制限、保持期限、機微な内容の省略が必要です。
- **batchの循環・深さ検査。** [`execute_bridge_command`](../src/app/mod.rs)の入れ子再帰に制限がありません。循環参照と過剰な深さを拒否し、設定ミスで再帰が続かないようにする必要があります。
