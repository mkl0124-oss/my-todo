#!/bin/bash
# 배포: 암호화 번들을 새로 만들고 main 으로 밀어 GitHub Pages 를 갱신합니다.
# 최초 1회는 저장소(mkl0124-oss/my-todo)와 Pages 활성화가 먼저 필요합니다.
set -euo pipefail
cd "$(dirname "$0")"

REPO="mkl0124-oss/my-todo"
URL="https://mkl0124-oss.github.io/my-todo/"

echo "--- 1) 암호화 번들 생성"
python3 build_encrypted.py

echo "--- 2) 평문이 실수로 올라가지 않는지 확인"
if git ls-files --error-unmatch data.json >/dev/null 2>&1; then
  echo "평문 data.json 이 Git 추적 중입니다. git rm --cached data.json 후 다시 실행하세요." >&2
  exit 1
fi
for f in data.enc.json data-enc.js index.html app.js; do
  [ -s "$f" ] || { echo "$f 가 없습니다." >&2; exit 1; }
done
if grep -q '"dueDate"' index.html app.js styles.css data-enc.js 2>/dev/null; then
  echo "평문 데이터 구조가 소스에 들어 있습니다. 배포를 멈춥니다." >&2
  exit 1
fi

echo "--- 3) 커밋 & 푸시"
git add -A
if ! git diff --cached --quiet; then
  git commit -m "할 일 보드 갱신 ($(date +%F))"
else
  echo "(커밋할 변경 없음)"
fi
git push origin main

echo "--- 4) 사이트 확인"
for i in $(seq 1 18); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
  echo "  index.html HTTP $code"
  [ "$code" = "200" ] && break
  sleep 10
done
plain=$(curl -s -o /dev/null -w "%{http_code}" "${URL}data.json")
echo "  data.json HTTP $plain (404 여야 정상)"
