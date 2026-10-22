# seal-dataset

Record a dataset snapshot in [LEGION SEAL](https://github.com/Legion33shadow/legion-seal): the tool computes a
deterministic manifest of a folder (one line per file: SHA-256, size, relative path, sorted), sends **only the SHA-256 of
that manifest** to the public log, and writes the manifest, the receipt and a badge snippet for a dataset card.
No file, no file hash and no file name leaves your machine. Python 3 standard library only; no account, no token.

> **What a seal proves.** This snapshot (these file hashes) existed at this date (registry clock).
> **What it does not prove.** The dataset's quality, licence, ownership or origin.
> Single operator, no independent witness yet, no qualified timestamp.

## Use

```
python3 seal_dataset.py seal path/to/dataset --name owner/dataset --git        # label "dataset owner/dataset@<commit7>"
python3 seal_dataset.py seal path/to/dataset --mask-names --no-label          # hide file names, send no label
```

Output in `seal-dataset/`: `manifest.txt` (or `manifest.masked.txt` + `manifest.salt`), `dataset.seal-N.json`,
`DATASET_CARD_SNIPPET.md` (badge, claim boundary, verification steps).

- `--git` requires a clean working tree and uses `HEAD` as the revision. Files ignored by git are still part of the folder,
  so they are in the manifest.
- A Hugging Face clone without `git lfs pull` contains pointer files: the tool warns, because the manifest would then cover
  the pointers, not the data.
- `--mask-names`: each path becomes `HMAC-SHA256(salt, path)`. File count, sizes and file hashes stay visible in the
  manifest if you publish it. Keep `manifest.salt`: without it, nobody (you included) can recompute the masked manifest.
- `--test` sends `X-Legion-Test`: the seal is real but excluded from the registry's counters and feed.

## Verify offline

```
python3 seal_dataset.py manifest path/to/dataset [--salt-file manifest.salt] --out manifest.txt
python3 verify_seal.py dataset.seal-N.json --file manifest.txt                  # RESULTAT: VALIDE or INVALID
# or both steps at once:
python3 seal_dataset.py check path/to/dataset dataset.seal-N.json [--salt-file manifest.salt]
```

`verify_seal.py` is the registry's verifier, byte-identical to
`https://seal.legion-api.com/seal/v1/verify_seal.py`, with the registry key pinned; it needs Python `cryptography`.
The manifest function is the verifier's own `dataset_manifest` (generated from legion-core), so there is one definition.

## GitHub Action

```yaml
- uses: Legion33shadow/seal-dataset@v0      # not published yet
  with:
    dir: data/
- uses: actions/upload-artifact@v4
  with: { name: seal-dataset, path: seal-dataset/ }
```

## Limits

- 6 submissions per minute and 100 per day per IP (registry rules); shared runners share IPs.
- One seal per distinct manifest: sealing an unchanged folder again returns the first entry.
- The date is the registry's clock. The registry is run by one operator, with no independent witness cosigning yet.

MIT licence.
