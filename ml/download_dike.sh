#!/bin/bash
# Downloads a sample of DikeDataset PE files for ML training.
set -e
cd "$(dirname "$0")"
mkdir -p data/dike_benign data/dike_malware

if [ ! -s dike-pe.tsv ]; then
    gh api -X GET "repos/iosifache/DikeDataset/git/trees/main" -f recursive=1 \
        --jq '.tree[] | select(.path | test("^files/(benign|malware)/.+\\.exe$")) | [.path, .size] | @tsv' > dike-pe.tsv
fi

python - <<'EOF'
import random

rows = []
with open('dike-pe.tsv', newline='') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) != 2:
            continue
        path, size = parts[0], int(parts[1])
        if 4096 <= size <= 32 * 1024 * 1024:
            rows.append((path, size))

benign = [r for r in rows if '/benign/' in r[0]]
malware = [r for r in rows if '/malware/' in r[0]]
random.seed(20261113)
benign = random.sample(benign, min(350, len(benign)))
malware = random.sample(malware, min(450, len(malware)))
with open('download-list.tsv', 'w') as f:
    for p, s in benign:
        f.write(f'benign\t{p}\t{s}\n')
    for p, s in malware:
        f.write(f'malware\t{p}\t{s}\n')
print(f'selected benign={len(benign)} malware={len(malware)}')
EOF

download_one() {
    local cls="$1" path="$2"
    local name dir
    name=$(basename "$path")
    dir="data/dike_$cls"
    [ -s "$dir/$name" ] && return 0
    if gh api "repos/iosifache/DikeDataset/contents/$path" \
        -H "Accept: application/vnd.github.raw" > "$dir/$name.tmp" 2>/dev/null; then
        mv "$dir/$name.tmp" "$dir/$name"
    else
        rm -f "$dir/$name.tmp"
        echo "FAILED $path" >&2
    fi
}

export -f download_one
awk -F'\t' '{print $1 "\t" $2}' download-list.tsv |
    tr '\t' '\n' |
    xargs -n 2 -P 6 bash -c 'download_one "$0" "$1"'

echo "benign files: $(ls data/dike_benign | wc -l)"
echo "malware files: $(ls data/dike_malware | wc -l)"
