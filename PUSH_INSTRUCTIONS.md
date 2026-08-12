# Push instructions

## 1. Create an empty public repo on GitHub

**Name:** `adom-action-guard`

**Description** (paste this — it's what shows on your profile and in Google):

> Taint-tracking guard that stops an agent exfiltrating a secret it read. Deterministic, no model in the detection path. 6/6, zero dependencies.

Do **not** initialize with a README, .gitignore, or license — this folder already has them.

## 2. Push from this folder

```bash
cd adom-action-guard
git init
git add .
git commit -m "Action Guard: exfiltration-by-value detection for tool-using agents"
git branch -M main
git remote add origin https://github.com/SilkForgeAi/adom-action-guard.git
git push -u origin main
```

## 3. Before you push — verify

Run `git status` and confirm **only these five files** are staged:

- `action_guard.py`
- `test_action_guard.py`
- `README.md`
- `LICENSE`
- `.gitignore`

`__pycache__/` is gitignored and will not be included.

**Do not copy anything else in from the ADOM directory.** That directory contains a `.env` file, several `.db` files, a data room, and your business plan. None of that belongs in a public repo.

## 4. After pushing

Add these repo topics so it's findable: `ai-safety`, `llm-security`, `agent-security`, `prompt-injection`, `taint-analysis`, `data-exfiltration`

Then **pin it** on your profile, first position.

## 5. Sanity check

Clone it fresh somewhere else and run it. If it doesn't pass 6/6 from a clean clone, something didn't get committed:

```bash
cd /tmp && git clone https://github.com/SilkForgeAi/adom-action-guard.git
cd adom-action-guard && python3 test_action_guard.py
```
