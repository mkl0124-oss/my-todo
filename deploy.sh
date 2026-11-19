#!/bin/bash
# 배포: 암호화 번들을 새로 만들고, 캐시 버스팅 버전을 찍은 뒤 main 으로 밀어 GitHub Pages 를 갱신합니다.
# 최초 1회는 저장소(mkl0124-oss/my-todo)와 Pages 활성화가 먼저 필요합니다.
set -euo pipefail
cd "$(dirname "$0")"

REPO="mkl0124-oss/my-todo"
URL="https://mkl0124-oss.github.io/my-todo/"

echo "--- 1) 암호화 번들 생성"
python3 build_encrypted.py

echo "--- 2) 캐시 버스팅 버전 찍기"
# styles.css / data-enc.js / app.js 를 부를 때 붙는 ?v= 값과 version.json 을 같은 값으로 맞춥니다.
# index.html 자체도 브라우저·중계 서버에 10분간 캐시되므로, version.json 을 보고 스스로 새 주소로
# 다시 여는 스크립트가 index.html 안에 들어 있습니다.
VER=$(date +%Y%m%d%H%M%S)
python3 - "$VER" <<'PY'
import json, pathlib, re, sys

ver = sys.argv[1]
idx = pathlib.Path("index.html")
s = idx.read_text(encoding="utf-8")

# 1) asset 주소에 붙은 ?v=... 를 새 버전으로
s = re.sub(r'(?P<name>styles\.css|data-enc\.js|app\.js)(?:\?v=[^"\']*)?',
           lambda m: m.group("name") + "?v=" + ver, s)
# 2) <meta name="board-version" content="...">
s = re.sub(r'(<meta name="board-version" content=")[^"]*(")',
           lambda m: m.group(1) + ver + m.group(2), s)
idx.write_text(s, encoding="utf-8")

app = pathlib.Path("app.js")
a = app.read_text(encoding="utf-8")
a2 = re.sub(r'(board-version:\s*)\S+', lambda m: m.group(1) + ver, a, count=1)
if a2 != a:
    app.write_text(a2, encoding="utf-8")

pathlib.Path("version.json").write_text(
    json.dumps({"version": ver}, ensure_ascii=False) + "\n", encoding="utf-8")

leftover = re.findall(r'"(?:styles\.css|data-enc\.js|app\.js)(?!\?v=)', s)
if leftover:
    sys.exit("캐시 버스팅이 빠진 참조가 있습니다: %s" % leftover)
print("  version = " + ver)
PY

echo "--- 3) 평문이 실수로 올라가지 않는지 확인"
if git ls-files --error-unmatch data.json >/dev/null 2>&1; then
  echo "평문 data.json 이 Git 추적 중입니다. git rm --cached data.json 후 다시 실행하세요." >&2
  exit 1
fi
for f in data.enc.json data-enc.js index.html app.js styles.css version.json; do
  [ -s "$f" ] || { echo "$f 가 없습니다." >&2; exit 1; }
done
if grep -q '"dueDate"' index.html app.js styles.css data-enc.js 2>/dev/null; then
  echo "평문 데이터 구조가 소스에 들어 있습니다. 배포를 멈춥니다." >&2
  exit 1
fi

echo "--- 4) 커밋 & 푸시"
git add -A
if ! git diff --cached --quiet; then
  git commit -m "할 일 보드 갱신 ($(date +%F)) v$VER"
else
  echo "(커밋할 변경 없음)"
fi
git push origin main

echo "--- 5) 사이트 확인"
for i in $(seq 1 30); do
  page=$(curl -s "$URL?cachecheck=$RANDOM")
  if printf '%s' "$page" | grep -q "board-version\" content=\"$VER\""; then
    echo "  index.html 새 버전 확인 (v$VER)"
    break
  fi
  echo "  index.html 아직 이전 버전… ($i)"
  sleep 10
done
for asset in "app.js" "styles.css" "data-enc.js" "version.json"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$URL$asset?v=$VER")
  echo "  $asset?v=$VER HTTP $code"
done
if curl -s "$URL/app.js?v=$VER" | grep -q "board-version: $VER"; then
  echo "  app.js 안의 버전 표식 일치"
else
  echo "  경고: app.js 버전 표식이 아직 이전 값입니다. 1~2분 뒤 다시 확인하세요." >&2
fi
plain=$(curl -s -o /dev/null -w "%{http_code}" "${URL}data.json")
echo "  data.json HTTP $plain (404 여야 정상)"
echo "  새 주소(캐시 없이 바로 열기): ${URL}?v=$VER"
