# Shani Replay Attack Test Suite

`tests/replay/` は Shani のリプレイ攻撃対策機能を検証する conformance test suite です。  
実装が仕様（SPEC §5.3、§5.4）を満たすかどうかを MUST FAIL / MUST PASS の形式で確認します。

## テスト概要

| # | テスト ID | カテゴリ | 仕様参照 | 説明 |
|---|-----------|----------|----------|------|
| 1 | `nonce_replay` | MUST FAIL | SPEC §5.4 | 同一 ADO nonce の 2 回目使用がブロックされること |
| 2 | `expired_ado_resubmission` | MUST FAIL | SPEC §5.3 | 期限切れ ADO の再提示が拒否されること |
| 3 | `time_window_replay` | MUST FAIL | SPEC §5.3 | タイムウィンドウ外の ADO が拒否されること |
| 4 | `valid_sig_consumed_nonce` | MUST FAIL | SPEC §5.4 | 署名が有効でも nonce 消費済みなら拒否されること |
| 5 | `cross_session_replay` | MUST FAIL | SPEC §5.4 | 別セッション間のリプレイが共有ストアでブロックされること |

## テスト分類

### MUST FAIL
実装が**正しく拒否**しなければならない操作を検証します。  
`condition = True` → 実装が正しく拒否した（PASS）  
`condition = False` → 実装が拒否しなかった（FAIL — セキュリティギャップ）

### MUST PASS
有効な初回 ADO の操作が**正しく受理**されることを検証します（ベースライン確認）。  
`condition = True` → 実装が正しく受理した（PASS）  
`condition = False` → 実装が誤って拒否した（FAIL — 過剰ブロック）

## テストケース詳細

### 1. Nonce Replay（SPEC §5.4）

同一 ADO nonce を 2 回使用しようとした場合の拒否を検証します。

- 初回 `register_executed()` は成功する（MUST PASS）
- 2 回目の `register_executed()` は `NonceAlreadyConsumed` を送出する（MUST FAIL）
- nonce 消費後の `verify_binding()` は `False` を返す（MUST FAIL）
- `_nonce_store.is_consumed(nonce)` は `True` を返す（MUST FAIL）
- 例外メッセージには監査のためのコンテキストが含まれる（MUST FAIL）

### 2. Expired ADO Resubmission（SPEC §5.3）

期限切れ ADO を再提示した場合の拒否を検証します。

- 有効な ADO は `is_expired() == False`（MUST PASS）
- 有効な ADO は `verify_binding() == True`（MUST PASS）
- 期限切れ ADO は `is_expired() == True`（MUST FAIL）
- 期限切れ ADO は `verify_binding() == False`（MUST FAIL）
- 期限切れ ADO は `time_remaining_seconds() == 0.0`（MUST FAIL）

### 3. Time Window Replay（SPEC §5.3）

ADO の有効期間外でのリプレイを検証します。

- 有効期間内の ADO は `time_remaining_seconds() > 0`（MUST PASS）
- 1 時間前に発行・失効した ADO は `is_expired() == True`（MUST FAIL）
- 1 秒前に失効した ADO も `is_expired() == True`（MUST FAIL）

### 4. Valid Signature but Consumed Nonce（SPEC §5.4）

署名が有効でも nonce が消費済みなら拒否されることを検証します。  
リプレイ防止ガードは暗号署名の有効性より優先されます。

- nonce 消費前は `verify_binding() == True`（MUST PASS）
- nonce 消費後は `verify_binding() == False`（MUST FAIL）
- 消費済み nonce はストアに永続的に記録される（MUST FAIL）
- `get_record()` で監査証跡（`decision_id`, `consumed_at`）が取得できる（MUST FAIL）

### 5. Cross-Session Replay（SPEC §5.4）

複数セッション間でのリプレイ攻撃の防止を検証します。

**5a. 共有 InMemoryNonceStore**
- セッション 1 での実行は成功する（MUST PASS）
- セッション 2（同じストア）でのリプレイは `NonceAlreadyConsumed`（MUST FAIL）
- セッション 2 での `verify_binding()` は `False`（MUST FAIL）

**5b. FileNonceStore のリロード（プロセス再起動シミュレーション）**
- プロセス 1 での実行は成功する（MUST PASS）
- プロセス 2 がストアをリロードすると nonce が永続している（MUST FAIL）
- プロセス 2 でのリプレイはブロックされる（MUST FAIL）

## 実行方法

```bash
# スタンドアロン実行（推奨）
python tests/replay/runner.py

# JSON レポート出力
python tests/replay/runner.py --json report.json

# テストファイル直接実行
python tests/replay/test_replay.py

# pytest から実行（CI 統合）
pytest tests/replay/

# 全テストスイートと合わせて実行
pytest
```

## CI 統合

`pyproject.toml` の `testpaths = ["tests"]` 設定により、`pytest` は `tests/replay/test_replay.py` 内の `test_*()` 関数を自動検出して実行します。  
GitHub Actions の CI ワークフロー（`.github/workflows/ci.yml`）は `pytest` を実行するため、このスイートは自動的に CI に統合されます。

## ファイル構成

```
tests/replay/
├── __init__.py        # パッケージ説明
├── test_replay.py     # テストケース（pytest + スタンドアロン両対応）
├── runner.py          # スタンドアロンランナー
└── README.md          # このファイル
```

`tests/conformance/framework.py` および `tests/conformance/fixtures.py` をそのまま再利用しています（コピーなし）。

## 設計原則

- **append-only nonce store**: nonce は一度消費されたら削除されない
- **replay guard > signature**: リプレイ防止チェックは署名検証と独立して動作する
- **persistent state**: `FileNonceStore` はプロセス再起動を跨いで nonce を保持する
- **MUST FAIL / MUST PASS 区別**: セキュリティギャップと過剰ブロックを明確に区別する

## 参照

- [SPEC §5.3](../spec/shani-v0.4.md) — ADO Expiry
- [SPEC §5.4](../spec/shani-v0.4.md) — Replay Prevention
- [`shani/security/replay_store.py`](../shani/security/replay_store.py) — 実装
- [`tests/conformance/test_must_fail.py`](../conformance/test_must_fail.py) — 関連 conformance テスト
