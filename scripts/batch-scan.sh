#!/usr/bin/env bash
# bbharden batch scan - run bbharden over many repos and build a review sheet.
# Works on Termux (Android) and any Linux/macOS with bash, git and python3.
#
#   Termux setup (once):   pkg install -y git python
#
#   ./scripts/batch-scan.sh repos.txt                 # offline scan
#   ./scripts/batch-scan.sh --osv repos.txt           # + live CVE matching (needs network)
#   ./scripts/batch-scan.sh -o ~/results repos.txt
#
# repos.txt: one entry per line, either a GitHub URL or a local directory.
# Lines starting with '#' and blank lines are ignored.
#
# Output (default ~/bbharden-reports/batch-<date>/, outside any repo):
#   summary.md    per-repo severity counts + most frequent rules
#   review.tsv    one row per finding; fill the 'verdict' column with TP or FP
#   json/<repo>.json   raw bbharden output
#   repos/<repo>/      shallow clones (URLs only)
set -u

OUT=""
OSV=0
LIST=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out) OUT="${2:-}"; shift 2 ;;
    --osv)    OSV=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *)  LIST="$1"; shift ;;
  esac
done
[ -n "$LIST" ] && [ -f "$LIST" ] || { echo "usage: $0 [-o DIR] [--osv] repos.txt" >&2; exit 2; }
OUT="${OUT:-${HOME:-.}/bbharden-reports/batch-$(date +%Y%m%d-%H%M%S)}"   # outside any repo, so later scans do not re-scan old output

command -v python3 >/dev/null 2>&1 || { echo "python3 not found (Termux: pkg install python)" >&2; exit 2; }

# Locate bbharden: installed command, else the checkout this script lives in.
HERE="$(cd "$(dirname "$0")/.." && pwd)"
if command -v bbharden >/dev/null 2>&1; then
  BB=(bbharden)
elif [ -f "$HERE/bbharden/cli.py" ]; then
  BB=(env "PYTHONPATH=$HERE" python3 -m bbharden.cli)
else
  echo "bbharden not found: install it or run this script from a clone" >&2; exit 2
fi

# Safe file-name slug: anything outside [A-Za-z0-9._-] becomes '_'.
slug() { printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }

mkdir -p "$OUT/json" "$OUT/repos"
: > "$OUT/errors.log"
n_ok=0; n_fail=0

while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"                                 # strip comments
  line="$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -z "$line" ] && continue

  case "$line" in
    https://github.com/*|http://github.com/*|git@github.com:*)
      name="$(slug "$(printf '%s' "$line" | sed 's#\.git$##; s#.*github.com[/:]##; s#/#__#g')")"
      dir="$OUT/repos/$name"
      if [ ! -d "$dir" ]; then
        echo "clone  $line"
        # Untrusted repo: no hooks, no tags, shallow, never prompt for credentials.
        if ! GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone -q --depth 1 --no-tags \
              "$line" "$dir" 2>>"$OUT/errors.log"; then
          echo "  FAILED to clone (private repo or no network?)"
          echo "clone failed: $line" >> "$OUT/errors.log"
          n_fail=$((n_fail+1)); continue
        fi
      fi ;;
    *)
      dir="$line"
      [ -d "$dir" ] || { echo "skip   $line (not a directory)"; n_fail=$((n_fail+1)); continue; }
      name="$(slug "$(basename "$(cd "$dir" && pwd)")")" ;;
  esac

  args=(scan "$dir" --format json --output "$OUT/json/$name.json")
  [ "$OSV" = 1 ] && args+=(--osv)
  echo "scan   $name"
  "${BB[@]}" "${args[@]}" --no-config >/dev/null 2>>"$OUT/errors.log"
  rc=$?
  # 0 = clean, 1 = findings at --fail-on (not used here), 2 = tool error
  if [ "$rc" -ge 2 ] || [ ! -s "$OUT/json/$name.json" ]; then
    echo "  FAILED (exit $rc) - see $OUT/errors.log"
    n_fail=$((n_fail+1)); rm -f "$OUT/json/$name.json"
  else
    n_ok=$((n_ok+1))
  fi
done < "$LIST"

python3 - "$OUT" <<'PY'
import collections, csv, glob, json, os, sys

out = sys.argv[1]
rows, per_repo, rules = [], {}, collections.Counter()
order = ["critical", "high", "medium", "low", "info"]
for path in sorted(glob.glob(os.path.join(out, "json", "*.json"))):
    repo = os.path.basename(path)[:-5]
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        continue
    per_repo[repo] = data.get("summary", {})
    for f in data.get("findings", []):
        rules[(f["rule_id"], f["severity"])] += 1
        clean = lambda s: str(s).replace("\t", " ").replace("\n", " ")[:160]
        rows.append([repo, f["rule_id"], f["severity"],
                     f"{clean(f['file'])}:{f['line']}", clean(f.get("evidence", "")), "", ""])

with open(os.path.join(out, "review.tsv"), "w", encoding="utf-8", newline="") as fh:
    w = csv.writer(fh, delimiter="\t")
    w.writerow(["repo", "rule", "severity", "location", "evidence", "verdict(TP/FP)", "notes"])
    w.writerows(rows)

lines = ["# bbharden batch summary", "",
         f"Repos scanned: {len(per_repo)}   Findings: {len(rows)}", "",
         "| repo | " + " | ".join(order) + " |", "|---|" + "---|" * len(order)]
for repo, s in per_repo.items():
    lines.append(f"| {repo} | " + " | ".join(str(s.get(k, 0)) for k in order) + " |")
lines += ["", "## Most frequent rules (candidates to check for false positives)", "",
          "| rule | severity | count |", "|---|---|---|"]
for (rule, sev), n in rules.most_common(15):
    lines.append(f"| {rule} | {sev} | {n} |")
lines += ["", "Next: open review.tsv, mark each row TP or FP, then count FP/(TP+FP) per rule.",
          "A rule with many FPs needs fixing before you sell reports that include it."]
open(os.path.join(out, "summary.md"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
PY

echo
echo "done: $n_ok scanned, $n_fail failed"
echo "  $OUT/summary.md"
echo "  $OUT/review.tsv   <- mark TP / FP here"
[ -s "$OUT/errors.log" ] && echo "  $OUT/errors.log   (warnings/errors)"
exit 0
