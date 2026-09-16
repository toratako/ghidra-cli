## query系はJSON以外もかなりある

`OutputFormat` は、

```text
full
compact
minimal
json
json-compact
json-stream
ndjson
csv
tsv
table
ids
count
tree
hex
asm
c
```

があります。

特に

```bash
-o json
-o json-compact
-o json-stream
-o ndjson
```

対応。

大量結果ならNDJSONを選べます。

ただし `tree / hex / asm / c` は現時点ではコード上、

> Currently rendered as JSON

なので、名前ほど完成してはいません。

優先順位もちゃんとしていて、

```text
明示的 --format
    >
--pretty
    >
--json
    >
TTY auto detection
```

です。

なので例えば、

```bash
ghidra-cli --json function list -o table
```

なら **tableが勝つ**。

エラー側もそれに合わせます。

---

# ただし弱点：JSONのtop-level schemaは統一されてない

ここはかなり重要です。

例えばmanagement系は、

```json
{
    "state": "running",
    "pid": 1234,
    "port": 12345
}
```

のような**object**。

一方、bridge経由の普通のsingle-result commandは内部のformatterの都合で、

```json
[
    {
        "status": "created",
        "name": "foo"
    }
]
```

と、**1件でもarray**になることが多いです。

実際tag mutationテストも、

```rust
let rows: Vec<Value> = result.json();
assert_eq!(rows[0]["status"], "created");
```

となっています。

さらに、

```bash
function list --count
```

は

```json
7
```

みたいな**scalar**。

つまり成功stdoutのtop-level型は、

```text
object
array
number
```

の全部があり得ます。

ここはagent APIとしては惜しい。

自分なら理想は全部、

```json
{
  "status": "success",
  "data": ...,
  "meta": {...}
}
```

に統一してほしいです。

### もう一つ：bridge envelopeを剥がすheuristic

`unwrap_bridge_response()` が、

```json
{
  "count": 20,
  "functions": [...]
}
```

みたいなbridge responseを見て、

```json
[
  ...functions...
]
```

に変換します。

人間には便利ですが、場合によっては**元のmetadataを捨てる**ことになります。

machine APIとして「bridge生JSONをそのまま欲しい」というモードはありません。

`--raw-json` / `--bridge-json` みたいなのがあればさらに強い。

---
