/* ✨ 오늘의 할 일 — 이미경님 전용 보드
   board-version: 20261119172020
   데이터: data-enc.js 의 암호문(window.MY_TODO_ENC)을 비밀번호로 풀어서 씁니다.
   평문 할 일 내용은 저장소에 올리지 않습니다. */
(function () {
  'use strict';

  var DONE_KEY = 'mytodo.done.v1';     /* id -> { at, purged } */
  var EXTRA_KEY = 'mytodo.extra.v1';    /* 내가 추가한 항목 */
  var KEY_STORE = 'mytodo.key.v1';      /* 이 기기 잠금 해제 키 */
  var DAY_KO = ['일', '월', '화', '수', '목', '금', '토'];
  var MINE_CAT = '내가 추가';           /* 카테고리를 비우고 추가한 항목의 묶음 이름 */

  var ENC = null;      /* window.MY_TODO_ENC */
  var DATA = null;     /* 복호화된 보드 데이터 */
  var DONE = {};       /* 완료 상태 */
  var EXTRAS = [];     /* 로컬 추가 항목 */
  var TODAY = '';
  var dayTimer = null;

  var el = {};

  /* ---------- 날짜 도우미 (Asia/Seoul 기준) ---------- */

  function pad(n) { return (n < 10 ? '0' : '') + n; }

  function seoulIsoOf(d) {
    var f = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit'
    });
    var p = {};
    f.formatToParts(d).forEach(function (x) { p[x.type] = x.value; });
    return p.year + '-' + p.month + '-' + p.day;
  }

  function seoulToday() { return seoulIsoOf(new Date()); }

  function parseISO(s) {
    var a = String(s).split('-');
    return new Date(+a[0], +a[1] - 1, +a[2]);
  }

  function isoOf(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }

  function shiftISO(iso, n) {
    var d = parseISO(iso);
    d.setDate(d.getDate() + n);
    return isoOf(d);
  }

  function md(iso) {
    var d = parseISO(iso);
    return (d.getMonth() + 1) + '/' + d.getDate();
  }

  function mdKo(iso) {
    var d = parseISO(iso);
    return (d.getMonth() + 1) + '월 ' + d.getDate() + '일 ' + DAY_KO[d.getDay()] + '요일';
  }

  function shortKo(iso) {
    var d = parseISO(iso);
    if (!d || isNaN(d.getTime())) return '';
    return md(iso) + ' ' + DAY_KO[d.getDay()];
  }

  function nowHM() {
    var f = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Seoul', hour: '2-digit', minute: '2-digit', hour12: false
    });
    return f.format(new Date());
  }

  function diffDays(fromIso, toIso) {
    return Math.round((parseISO(toIso) - parseISO(fromIso)) / 86400000);
  }

  function norm(s) { return String(s || '').replace(/\s+/g, '').toLowerCase(); }

  /* 우선순위 묶음(p1·p2 …)인지 — 이런 묶음보다 날짜 묶음(📌 내일까지)에 먼저 합칩니다. */
  function isPriorityKind(kind) { return /^p\d+$/.test(String(kind || '')); }

  function groupKind(g) {
    return String((g && g.kind) || (g && g.priority ? 'p' + g.priority : ''));
  }

  /* 같은 마감일의 날짜 묶음을 찾습니다. (📌 내일까지 처럼 마감일로 묶인 섹션) */
  function groupForDue(due) {
    var pick = null;
    (DATA && DATA.groups ? DATA.groups : []).forEach(function (g) {
      if (pick || !g || !g.dueDate || g.dueDate !== due) return;
      if (isPriorityKind(groupKind(g))) return;
      pick = g;
    });
    return pick;
  }

  /* 마감일만 있는 항목을 담을 섹션 이름 */
  function dueSectionLabel(due) {
    var away = diffDays(TODAY || seoulToday(), due);
    if (away === 0) return '📅 오늘까지';
    if (away === 1) return '📌 내일까지';
    var d = parseISO(due);
    return '🗓️ ' + md(due) + '(' + DAY_KO[d.getDay()] + ')까지';
  }

  function $(id) { return document.getElementById(id); }

  /* ---------- 암호문 불러오기 (PBKDF2-HMAC-SHA256 + AES-256-GCM) ---------- */

  var AES_KEY = null;

  function b64ToBytes(b64) {
    var s = String(b64).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    var u = new Uint8Array(bytes), s = '';
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s);
  }

  function cryptoReady() {
    return !!(window.crypto && window.crypto.subtle && window.TextDecoder && window.TextEncoder);
  }

  function deriveKey(password) {
    var pw = new TextEncoder().encode(password);
    return crypto.subtle.importKey('raw', pw, { name: 'PBKDF2' }, false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: b64ToBytes(ENC.salt),
            iterations: (ENC && ENC.iterations) || 310000,
            hash: 'SHA-256'
          },
          base,
          { name: 'AES-GCM', length: 256 },
          true,
          ['decrypt']
        );
      });
  }

  function decryptWith(key) {
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(ENC.iv) },
      key,
      b64ToBytes(ENC.ciphertext)
    ).then(function (buf) {
      return JSON.parse(new TextDecoder('utf-8').decode(buf));
    });
  }

  function loadStoredKey() {
    try {
      var raw = localStorage.getItem(KEY_STORE);
      if (!raw) return null;
      var bytes = b64ToBytes(raw);
      return bytes.length === 32 ? bytes : null;
    } catch (e) { return null; }
  }

  function storeKey(key) {
    return crypto.subtle.exportKey('raw', key).then(function (raw) {
      try { localStorage.setItem(KEY_STORE, bytesToB64(raw)); } catch (e) {}
    }).catch(function () {});
  }

  function forgetKey() {
    try { localStorage.removeItem(KEY_STORE); } catch (e) {}
  }

  /* 저장된 날짜값을 YYYY-MM-DD 로 다듬습니다. (예전 형식·날짜시간 문자열 대비) */
  function normDue(v) {
    var s = String(v || '').trim();
    if (!s) return '';
    var m = s.match(/^(\d{4})[-.\/](\d{1,2})[-.\/](\d{1,2})/);
    if (m) {
      var iso = m[1] + '-' + pad(+m[2]) + '-' + pad(+m[3]);
      return isNaN(parseISO(iso).getTime()) ? '' : iso;
    }
    var d = new Date(s);
    return isNaN(d.getTime()) ? '' : seoulIsoOf(d);
  }

  function newId() { return 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

  /* ---------- 저장소 ---------- */

  function loadDone() {
    DONE = {};
    try {
      var raw = localStorage.getItem(DONE_KEY);
      var obj = raw ? JSON.parse(raw) : {};
      Object.keys(obj || {}).forEach(function (k) {
        var v = obj[k];
        DONE[k] = (typeof v === 'string')
          ? { at: v, purged: false }
          : { at: (v && v.at) || '', purged: !!(v && v.purged) };
      });
    } catch (e) { DONE = {}; }
  }

  function saveDone() {
    try { localStorage.setItem(DONE_KEY, JSON.stringify(DONE)); } catch (e) {}
  }

  function loadExtras() {
    EXTRAS = [];
    try {
      var raw = localStorage.getItem(EXTRA_KEY);
      var arr = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(arr)) return;
      EXTRAS = arr.filter(function (x) { return x && x.text; }).map(function (x) {
        /* 마감일이 비어 있는 예전 항목은 '오늘'로 밀지 않고, 추가한 날을 마감일로 되살립니다. */
        var created = '';
        if (x.created) {
          var c = new Date(x.created);
          if (!isNaN(c.getTime())) created = seoulIsoOf(c);
        }
        return {
          id: x.id || newId(),
          text: String(x.text),
          category: x.category || MINE_CAT,
          dueDate: normDue(x.dueDate) || normDue(x.due) || created || seoulToday(),
          created: x.created || ''
        };
      });
    } catch (e) { EXTRAS = []; }
  }

  function saveExtras() {
    try { localStorage.setItem(EXTRA_KEY, JSON.stringify(EXTRAS)); } catch (e) {}
  }

  /* ---------- 보드 데이터 합치기 ---------- */

  function collect() {
    var out = [], seen = {};
    (DATA.groups || []).forEach(function (g) {
      (g.items || []).forEach(function (it) {
        seen[norm(it.text)] = true;
        out.push({
          id: it.id,
          text: it.text,
          hint: it.hint || '',
          category: it.category || g.category || '',
          due: it.dueDate || g.dueDate || '',
          badge: it.badge || g.badge || '',
          kind: g.kind || ('p' + (g.priority || 0)),
          sectionId: g.id,
          sectionLabel: g.label || '',
          sectionNote: g.note || '',
          sectionDue: g.dueDate || '',
          order: typeof g.order === 'number' ? g.order : (g.priority || 0),
          extra: false
        });
      });
    });

    EXTRAS.forEach(function (x) {
      if (seen[norm(x.text)]) return;   /* data.json 에 같은 항목이 생기면 로컬 중복은 숨김 */
      out.push({
        id: x.id,
        text: x.text,
        hint: '',
        category: x.category || MINE_CAT,
        due: x.dueDate || seoulToday(),
        badge: '',
        kind: 'add',
        sectionId: '',            /* 렌더할 때 마감일에 맞는 섹션으로 합칩니다 */
        sectionLabel: '',
        sectionNote: '',
        sectionDue: '',
        order: 90,
        extra: true
      });
    });

    return out;
  }

  function isDone(id) { return !!DONE[id]; }

  /* ---------- 렌더링 ---------- */

  function renderHeader(remaining, total) {
    el.todayLabel.textContent = mdKo(TODAY);
    if (!el.remainCount) return;
    if (remaining === 0) {
      el.remainCount.textContent = '다 했어요';
      el.remainCount.classList.add('is-empty');
    } else {
      el.remainCount.textContent = remaining + '개 남음';
      el.remainCount.classList.remove('is-empty');
    }
  }

  function makeItem(entry, isOverdue) {
    var li = document.createElement('li');
    li.className = 'item' + (isOverdue ? ' is-overdue' : '');
    li.dataset.id = entry.id;

    var check = document.createElement('button');
    check.type = 'button';
    check.className = 'check';
    check.setAttribute('role', 'checkbox');
    check.setAttribute('aria-checked', 'false');
    check.setAttribute('aria-label', '완료: ' + entry.text);
    check.addEventListener('click', function () { completeItem(li, entry); });

    var body = document.createElement('div');
    body.className = 'item-body';

    var title = document.createElement('p');
    title.className = 'item-title';
    title.textContent = entry.text;
    body.appendChild(title);

    var hints = [];
    if (entry.hint) hints.push(entry.hint);
    if (hints.length) {
      var h = document.createElement('p');
      h.className = 'item-hint';
      h.textContent = hints.join(' · ');
      body.appendChild(h);
    }

    li.appendChild(check);
    li.appendChild(body);

    var badgeText = isOverdue ? '긴급' : (entry.badge || '');
    if (badgeText) {
      var box = document.createElement('div');
      box.className = 'item-badges';
      var b = document.createElement('span');
      b.className = 'badge ' + (isOverdue ? 'badge-urgent' : ('badge-' + entry.kind));
      b.textContent = badgeText;
      box.appendChild(b);
      if (isOverdue && entry.due) {
        var sub = document.createElement('span');
        sub.className = 'badge-sub';
        sub.textContent = md(entry.due) + ' 이월';
        box.appendChild(sub);
      }
      li.appendChild(box);
    }

    return li;
  }

  function makeSection(opts) {
    var section = document.createElement('section');
    section.className = 'section' + (opts.urgent ? ' is-urgent' : '');

    var head = document.createElement('div');
    head.className = 'section-head';
    var h2 = document.createElement('h2');
    h2.className = 'section-title';
    h2.textContent = opts.label;
    head.appendChild(h2);
    if (opts.dueText) {
      var due = document.createElement('span');
      due.className = 'section-due';
      due.textContent = opts.dueText;
      head.appendChild(due);
    }
    section.appendChild(head);

    if (opts.note) {
      var note = document.createElement('p');
      note.className = 'section-note';
      note.textContent = opts.note;
      section.appendChild(note);
    }

    /* 카테고리별로 묶기 (나온 순서 유지) */
    var order = [], buckets = {};
    opts.items.forEach(function (entry) {
      var cat = entry.category || '기타';
      if (!buckets[cat]) { buckets[cat] = []; order.push(cat); }
      buckets[cat].push(entry);
    });

    order.forEach(function (cat) {
      var wrap = document.createElement('div');
      wrap.className = 'cat';

      var catHead = document.createElement('div');
      catHead.className = 'cat-head';
      var tag = document.createElement('span');
      tag.className = 'cat-tag';
      tag.textContent = cat;
      catHead.appendChild(tag);
      if (buckets[cat].length > 1) {
        var cnt = document.createElement('span');
        cnt.className = 'cat-count';
        cnt.textContent = buckets[cat].length + '개';
        catHead.appendChild(cnt);
      }
      wrap.appendChild(catHead);

      var ul = document.createElement('ul');
      ul.className = 'items';
      buckets[cat].forEach(function (entry) { ul.appendChild(makeItem(entry, !!opts.urgent)); });
      wrap.appendChild(ul);

      section.appendChild(wrap);
    });

    return section;
  }

  function render() {
    TODAY = seoulToday();

    var all = collect();
    var active = all.filter(function (it) { return !isDone(it.id); });

    var groups = (DATA && DATA.groups) || [];
    var groupMeta = {}, groupIndex = {};
    groups.forEach(function (g, i) { groupMeta[g.id] = g; groupIndex[g.id] = i; });

    function groupOrder(g) {
      if (!g) return 900;
      if (typeof g.priority === 'number' && g.priority > 0) return g.priority * 10;
      if (typeof g.order === 'number' && g.order > 0) return g.order * 10;
      return ((groupIndex[g.id] || 0) + 1) * 10;
    }

    var lastOrder = 0;
    groups.forEach(function (g) { lastOrder = Math.max(lastOrder, groupOrder(g)); });

    /* 날짜만 있는 섹션은 data.json 묶음들 사이의 제자리에 놓습니다. */
    function dueSectionOrder(due) {
      var next = null;
      groups.forEach(function (g) {
        if (!g || !g.dueDate || g.dueDate <= due) return;
        var o = groupOrder(g);
        if (next === null || o < next) next = o;
      });
      if (next !== null) return next - 5;
      return lastOrder + 10;
    }

    function sectionDef(key, due) {
      if (key.indexOf('g:') === 0) {
        var g = groupMeta[key.slice(2)];
        return {
          label: g ? (g.label || '') : '',
          note: g ? (g.note || '') : '',
          dueDate: g ? (g.dueDate || '') : '',
          order: groupOrder(g)
        };
      }
      return { label: dueSectionLabel(due), note: '', dueDate: due, order: dueSectionOrder(due) };
    }

    var overdue = [];
    var bySection = {}, sectionOrder = [];
    active.forEach(function (it) {
      if (it.due && it.due < TODAY) { overdue.push(it); return; }

      /* 직접 추가한 항목은 마감일이 같은 날짜 묶음(예: 📌 내일까지)에 합칩니다. */
      var key = it.sectionId ? ('g:' + it.sectionId) : null;
      if (!key) {
        var due = it.due || TODAY;
        var g = groupForDue(due);
        key = g ? ('g:' + g.id) : ('due:' + due);
      }

      if (!bySection[key]) { bySection[key] = []; sectionOrder.push(key); }
      bySection[key].push(it);
    });

    /* 이월 항목은 마감이 오래된 것부터 */
    overdue.sort(function (a, b) { return String(a.due).localeCompare(String(b.due)); });

    var board = el.board;
    board.innerHTML = '';

    if (overdue.length) {
      board.appendChild(makeSection({
        label: '🚨 긴급 (이월)',
        dueText: overdue.length + '개',
        note: '못한 일이 오늘로 넘어왔어요. 이것부터 비워 주세요.',
        urgent: true,
        items: overdue
      }));
    }

    sectionOrder.sort(function (a, b) {
      var A = sectionDef(a, bySection[a][0].due || TODAY);
      var B = sectionDef(b, bySection[b][0].due || TODAY);
      if (A.order !== B.order) return A.order - B.order;
      return String(A.dueDate).localeCompare(String(B.dueDate));
    });

    sectionOrder.forEach(function (key) {
      var items = bySection[key];
      var meta = sectionDef(key, items[0].due || TODAY);
      board.appendChild(makeSection({
        label: meta.label,
        dueText: meta.dueDate ? shortKo(meta.dueDate) : '',
        note: meta.note,
        urgent: false,
        items: items
      }));
    });

    el.empty.hidden = active.length !== 0;

    renderDone(all);
    renderHeader(active.length, all.length);
  }

  function renderDone(all) {
    var list = all.filter(function (it) {
      var d = DONE[it.id];
      return d && !d.purged;
    });
    list.sort(function (a, b) {
      return String((DONE[b.id] || {}).at).localeCompare(String((DONE[a.id] || {}).at));
    });

    el.doneCount.textContent = list.length;
    el.doneList.innerHTML = '';
    el.doneEmpty.hidden = list.length !== 0;
    el.clearDone.hidden = list.length === 0;

    list.forEach(function (it) {
      var li = document.createElement('li');
      li.className = 'done-item';

      var text = document.createElement('span');
      text.className = 'done-text';
      text.textContent = it.text;

      var at = document.createElement('span');
      at.className = 'done-at';
      at.textContent = hmOf(DONE[it.id].at);

      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'restore';
      btn.textContent = '되돌리기';
      btn.addEventListener('click', function () {
        delete DONE[it.id];
        saveDone();
        render();
      });

      li.appendChild(text);
      li.appendChild(at);
      li.appendChild(btn);
      el.doneList.appendChild(li);
    });
  }

  function hmOf(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Seoul', hour: '2-digit', minute: '2-digit', hour12: false
    }).format(d);
  }

  /* ---------- 체크하면 스르륵 사라짐 ---------- */

  function completeItem(li, entry) {
    if (li.classList.contains('is-leaving') || li.classList.contains('is-submitted')) return;
    li.classList.add('is-submitted');

    var check = li.querySelector('.check');
    if (check) { check.classList.add('is-on'); check.setAttribute('aria-checked', 'true'); }

    li.style.height = li.offsetHeight + 'px';
    li.getBoundingClientRect();  /* reflow */
    requestAnimationFrame(function () { li.classList.add('is-leaving'); });

    setTimeout(function () {
      DONE[entry.id] = { at: new Date().toISOString(), purged: false };
      saveDone();
      render();
    }, 320);
  }

  /* ---------- 추가 입력 ---------- */

  function refreshDueOptions(select) {
    if (!select) return;
    var t = seoulToday();
    if (select.options[0]) select.options[0].textContent = '오늘 (' + md(t) + ')';
    if (select.options[1]) select.options[1].textContent = '내일 (' + md(shiftISO(t, 1)) + ')';
    if (select.options[2]) select.options[2].textContent = '날짜';
  }

  function bindAddForm(ids) {
    var form = $(ids.form), text = $(ids.text), cat = $(ids.cat),
        due = $(ids.due), date = $(ids.date);
    if (!form || !text) return;

    refreshDueOptions(due);

    if (due && date) {
      due.addEventListener('change', function () {
        if (due.value === 'pick') {
          date.hidden = false;
          if (!date.value) date.value = shiftISO(seoulToday(), 2);
          date.min = seoulToday();
        } else {
          date.hidden = true;
        }
      });
    }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var value = (text.value || '').trim();
      if (!value) { text.focus(); return; }

      var dueDate = seoulToday();
      if (due) {
        if (due.value === 'tomorrow') dueDate = shiftISO(seoulToday(), 1);
        else if (due.value === 'pick') {
          /* 날짜를 고르지 않았으면 오늘로 넣지 말고 날짜 칸을 열어 줍니다. */
          if (!(date && date.value)) {
            if (date) {
              date.hidden = false;
              date.min = seoulToday();
              if (!date.value) date.value = shiftISO(seoulToday(), 2);
              try { date.focus(); } catch (e2) {}
            }
            return;
          }
          dueDate = normDue(date.value) || seoulToday();
        }
      }

      EXTRAS.push({
        id: newId(),
        text: value,
        category: ((cat && cat.value) || '').trim() || MINE_CAT,
        dueDate: dueDate,
        created: new Date().toISOString()
      });
      saveExtras();

      text.value = '';
      if (cat) cat.value = '';
      if (due) { due.value = 'today'; refreshDueOptions(due); }
      if (date) { date.hidden = true; date.value = ''; }

      render();
      text.focus();
    });
  }

  function fillCatList(all) {
    var list = $('catList');
    if (!list) return;
    var names = [], seen = {};
    (DATA.groups || []).forEach(function (g) { if (g.category && !seen[g.category]) { seen[g.category] = 1; names.push(g.category); } });
    all.forEach(function (it) {
      if (!it.category || it.category === MINE_CAT || seen[it.category]) return;
      seen[it.category] = 1; names.push(it.category);
    });
    list.innerHTML = '';
    names.forEach(function (n) {
      var o = document.createElement('option');
      o.value = n;
      list.appendChild(o);
    });
  }

  /* ---------- 잠금 화면 ---------- */

  var lockEl = null, lockForm = null, lockInput = null, lockErrorEl = null,
      rememberEl = null, submitEl = null;

  function setLockMessage(text, info) {
    if (!lockErrorEl) return;
    lockErrorEl.textContent = text || '';
    lockErrorEl.classList.toggle('show', !!text);
    lockErrorEl.classList.toggle('is-info', !!info);
  }

  function lockBusy(busy) {
    if (submitEl) { submitEl.disabled = busy; submitEl.textContent = busy ? '여는 중…' : '열기'; }
    if (lockInput) lockInput.disabled = busy;
  }

  function showLock(message, info) {
    DATA = null;
    AES_KEY = null;
    document.body.classList.add('locked');
    if (el.app) el.app.hidden = true;
    if (lockEl) lockEl.hidden = false;
    setLockMessage(message || '', info);
    if (lockInput) {
      lockInput.value = '';
      lockInput.disabled = false;
      try { lockInput.focus(); } catch (e) {}
    }
    if (submitEl) { submitEl.disabled = false; submitEl.textContent = '열기'; }
  }

  function showBoard(data) {
    DATA = data;
    document.body.classList.remove('locked');
    if (lockEl) lockEl.hidden = true;
    if (el.app) el.app.hidden = false;
    setLockMessage('');

    TODAY = seoulToday();
    loadDone();
    loadExtras();
    fillCatList(collect());
    render();

    if (!dayTimer) {
      dayTimer = setInterval(function () {
        if (seoulToday() !== TODAY) render();
      }, 60000);
    }
    try { window.scrollTo({ top: 0, behavior: 'auto' }); } catch (e) {}
  }

  function tryUnlock(password) {
    return deriveKey(password).then(function (key) {
      return decryptWith(key).then(function (data) { return { key: key, data: data }; });
    });
  }

  function bindLock() {
    lockEl = $('lockScreen');
    lockForm = $('lockForm');
    lockInput = $('lockInput');
    lockErrorEl = $('lockError');
    rememberEl = $('rememberDevice');
    submitEl = $('lockSubmit');

    if (lockForm) {
      lockForm.addEventListener('submit', function (e) {
        e.preventDefault();
        var pw = ((lockInput && lockInput.value) || '').trim();
        if (!pw) { setLockMessage('비밀번호를 입력해 주세요'); return; }
        setLockMessage('');
        lockBusy(true);
        tryUnlock(pw).then(function (res) {
          lockBusy(false);
          AES_KEY = res.key;
          if (rememberEl && rememberEl.checked) storeKey(res.key);
          else forgetKey();
          showBoard(res.data);
        }).catch(function (err) {
          console.error(err);
          lockBusy(false);
          forgetKey();
          setLockMessage('비밀번호가 맞지 않아요');
          if (lockInput) {
            lockInput.value = '';
            try { lockInput.focus(); } catch (e2) {}
          }
        });
      });
    }

    var lockNow = $('lockNow');
    if (lockNow) {
      lockNow.addEventListener('click', function () {
        forgetKey();
        showLock('잠갔어요. 다시 열려면 비밀번호를 입력해 주세요.', true);
      });
    }
  }

  function bindDone() {
    el.doneToggle = $('doneToggle');
    el.doneBody = $('doneBody');
    el.doneList = $('doneList');
    el.doneCount = $('doneCount');
    el.doneEmpty = $('doneEmpty');
    el.clearDone = $('clearDone');

    if (el.doneToggle) {
      el.doneToggle.addEventListener('click', function () {
        var open = el.doneToggle.getAttribute('aria-expanded') === 'true';
        el.doneToggle.setAttribute('aria-expanded', open ? 'false' : 'true');
        el.doneBody.hidden = open;
      });
    }

    if (el.clearDone) {
      el.clearDone.addEventListener('click', function () {
        var all = collect().filter(function (it) { return DONE[it.id] && !DONE[it.id].purged; });
        if (!all.length) return;
        if (!window.confirm('완료한 ' + all.length + '개를 완료함에서 지울까요? (되돌릴 수 없어요)')) return;
        all.forEach(function (it) { DONE[it.id].purged = true; });
        saveDone();
        render();
      });
    }
  }

  /* ---------- 시작 ---------- */

  function boot() {
    TODAY = seoulToday();
    el.app = $('app');
    el.board = $('board');
    el.empty = $('empty');
    el.todayLabel = $('todayLabel');
    el.remainCount = $('remainCount');

    bindDone();
    bindLock();
    bindAddForm({ form: 'addBottom', text: 'addBottomText', cat: 'addBottomCat', due: 'addBottomDue', date: 'addBottomDate' });

    document.addEventListener('visibilitychange', function () {
      if (!document.hidden && DATA && seoulToday() !== TODAY) render();
    });

    ENC = (window.MY_TODO_ENC && window.MY_TODO_ENC.ciphertext) ? window.MY_TODO_ENC : null;
    if (!ENC) { showLock('보드 데이터를 찾지 못했어요. 잠시 뒤 다시 열어 주세요.'); return; }
    if (!cryptoReady()) {
      showLock('이 환경에서는 잠금을 열 수 없어요. 인터넷 주소로 열어 주세요.', true);
      return;
    }

    var stored = loadStoredKey();
    if (!stored) { showLock(''); return; }

    crypto.subtle.importKey('raw', stored, { name: 'AES-GCM' }, true, ['decrypt'])
      .then(function (key) { return decryptWith(key).then(function (data) { return { key: key, data: data }; }); })
      .then(function (res) { AES_KEY = res.key; showBoard(res.data); })
      .catch(function () { forgetKey(); showLock(''); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
