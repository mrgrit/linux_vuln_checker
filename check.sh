#!/usr/bin/env bash
# 2장 리눅스 보안 점검기 (로컬 설치형, SPEC.md 1-4 / 2절 구현)
# 읽기 전용 도구: sudo·시스템 파일 수정 없음. 산출물은 --out 디렉터리(기본 ./out)에만 쓴다.
#
# 사용법: ./check.sh [--root DIR] [--out DIR] [--host NAME]
#   --root DIR  점검 대상 루트(기본 /). 이 값이 / 가 아니면 테스트 루트로 동작하며
#               ps -ef / 포트 결과는 DIR/ps.txt, DIR/ports.txt(ss -tuln 형식)에서 읽는다(SPEC 1-9).

export LC_ALL=C
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=/
OUT="$SCRIPT_DIR/out"
HOST=$(hostname 2>/dev/null || echo unknown)

while [ $# -gt 0 ]; do
  case $1 in
    --root) ROOT=$2; shift 2 ;;
    --out)  OUT=$2; shift 2 ;;
    --host) HOST=$2; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
  esac
done

R=${ROOT%/}                       # --root / 이면 빈 문자열
mkdir -p "$OUT" || { echo "출력 디렉터리를 만들 수 없음: $OUT" >&2; exit 1; }
RES="$OUT/.results.tsv"; : > "$RES"

if [ -z "$R" ]; then OWNER_UID=0; else OWNER_UID=$(stat -c %u "$ROOT" 2>/dev/null || echo 0); fi

# ---------------------------------------------------------------- 공통 함수
EV=
ev()   { EV="${EV:+$EV | }$*"; }
emit() { # emit ID 판정  (근거는 $EV)
  printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$EV" | tr '\n\t' '  ')" >> "$RES"; EV=
}
rel()  { printf '%s' "${1#"$R"}"; }

fstate() { # ok | unreadable | noaccess | absent
  local f=$1 d
  if [ -e "$f" ]; then [ -r "$f" ] && echo ok || echo unreadable; return; fi
  d=$(dirname "$f")
  while [ "$d" != "/" ] && [ "$d" != "." ]; do
    if [ -e "$d" ]; then [ -x "$d" ] || { echo noaccess; return; }; break; fi
    d=$(dirname "$d")
  done
  echo absent
}
nread() { [ "$1" = unreadable ] || [ "$1" = noaccess ]; }   # 읽지 못함

# key value / key=value 설정에서 유효 줄 조회(2-0a). 결과: KV_NR KV_VAL KV_LINE
kv_get() { # file key first|last
  KV_NR=; KV_VAL=; KV_LINE=
  local out
  out=$(awk -v k="$2" -v m="$3" '
    { l=$0; sub(/^[ \t]+/,"",l); if (l=="" || l ~ /^#/) next
      n=split(l,a,/[ \t=]+/)
      if (m=="first" && tolower(a[1])=="match") exit
      if (tolower(a[1])==tolower(k)) { r=NR "\t" a[2] "\t" l; if (m=="first") { print r; exit } last=r } }
    END { if (m!="first" && last!="") print last }' "$1" 2>/dev/null)
  if [ -n "$out" ]; then IFS=$'\t' read -r KV_NR KV_VAL KV_LINE <<<"$out"; fi
  return 0
}
# 유효(주석 아닌) 줄 중 정규식에 맞는 첫 줄: "줄번호: 내용"
vgrep() { # file regex
  awk -v re="$2" '{ l=$0; sub(/^[ \t]+/,"",l); if (l=="" || l ~ /^#/) next
                    if (l ~ re) { print NR ": " l; exit } }' "$1" 2>/dev/null
}
argval() { # "줄" key → 값 (key=값)
  if [[ $1 =~ (^|[[:space:]])$2=(-?[0-9]+) ]]; then printf '%s' "${BASH_REMATCH[2]}"; fi
}

# 서비스 확인 3요소(1-9): 프로세스, 포트
if [ -z "$R" ]; then
  PS_TXT=$(ps -ef 2>/dev/null); PS_CMD="ps -ef"
  PORT_TXT=$(ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null); PORT_CMD="ss -tuln"
else
  PS_TXT=$(cat "$R/ps.txt" 2>/dev/null); PS_CMD="$(rel "$R/ps.txt")"
  PORT_TXT=$(cat "$R/ports.txt" 2>/dev/null); PORT_CMD="$(rel "$R/ports.txt")"
fi
ps_find() { grep -E "$1" <<<"$PS_TXT" | grep -v -E 'grep|check\.sh' | head -1; }
port_open() { # 포트 [tcp]
  awk -v p="$1" -v pr="${2:-}" '
    pr != "" && $1 !~ ("^" pr) { next }
    $4 ~ ("[:.]" p "$") || $5 ~ ("[:.]" p "$") { f=1 }
    END { exit f ? 0 : 1 }' <<<"$PORT_TXT"
}
ev_proc() { # 설명 정규식
  local l; l=$(ps_find "$2")
  if [ -n "$l" ]; then ev "$PS_CMD | grep $1: 실행 중 → $(echo "$l" | tr -s ' ' | cut -c1-90)"; return 0
  else ev "$PS_CMD | grep $1: 결과 없음"; return 1; fi
}
ev_port() { # 포트 [tcp]
  if port_open "$1" "${2:-}"; then ev "$PORT_CMD | grep :$1: 열림"; return 0
  else ev "$PORT_CMD | grep :$1: 닫힘"; return 1; fi
}
# xinetd 서비스 파일 상태: XS = absent|unread|enabled|disabled
xinetd_state() {
  local f=$1 st; st=$(fstate "$f"); XS=absent
  case $st in
    absent) ;;
    ok) kv_get "$f" disable last
        if [ "$KV_VAL" = yes ]; then XS=disabled; ev "$(rel "$f"):$KV_NR: $KV_LINE"
        elif [ -n "$KV_NR" ]; then XS=enabled; ev "$(rel "$f"):$KV_NR: $KV_LINE (활성)"
        else XS=enabled; ev "$(rel "$f"): disable 줄 없음 → xinetd 기본값 no(활성)"; fi ;;
    *) XS=unread; ev "$(rel "$f"): 읽기 불가" ;;
  esac
}
inetd_state() { # 정규식 → INET = absent|unread|found|none
  local f="$R/etc/inetd.conf" st l; st=$(fstate "$f"); INET=absent
  case $st in
    absent) ;;
    ok) l=$(vgrep "$f" "$1")
        if [ -n "$l" ]; then INET=found; ev "inetd.conf:$l"; else INET=none; fi ;;
    *) INET=unread; ev "/etc/inetd.conf: 읽기 불가" ;;
  esac
}

# ---------------------------------------------------------------- 계정 관리
chk_u01() {
  local f="$R/etc/ssh/sshd_config" st; st=$(fstate "$f")
  case $st in
    absent) ev "/etc/ssh/sshd_config 없음(sshd 미설치)"; emit U-01 "해당 없음"; return ;;
    unreadable|noaccess) ev "/etc/ssh/sshd_config 읽기 불가"; emit U-01 "확인 불가"; return ;;
  esac
  local found= val= file nr line
  while IFS=$'\t' read -r file nr line; do
    if [[ $line =~ ^[Mm][Aa][Tt][Cc][Hh][[:space:]] ]]; then break; fi
    if [[ $line =~ ^[Pp][Ee][Rr][Mm][Ii][Tt][Rr][Oo][Oo][Tt][Ll][Oo][Gg][Ii][Nn][[:space:]=]+([^[:space:]]+) ]]; then
      val=${BASH_REMATCH[1]}; found="$(rel "$file"):$nr: $line"; break
    fi
  done < <(sshd_flat "$f" 0)
  local cmt; cmt=$(grep -nE '^[[:space:]]*#[[:space:]]*PermitRootLogin' "$f" | head -1)
  if [ -z "$found" ]; then
    [ -n "$cmt" ] && ev "sshd_config:$cmt → 주석 처리됨(설정 아님)"
    ev "유효한 PermitRootLogin 줄 없음 → OpenSSH 기본값 prohibit-password 적용(no 아님)"
    emit U-01 "취약"
  elif [ "${val,,}" = no ]; then ev "$found"; emit U-01 "양호"
  else ev "$found (no 아님)"; emit U-01 "취약"; fi
}
sshd_flat() { # sshd 가 읽는 순서(Include 포함)로 "파일\t줄번호\t내용"
  local f=$1 depth=$2 nr=0 line l pat g
  [ "$depth" -gt 5 ] && return
  while IFS= read -r line || [ -n "$line" ]; do
    nr=$((nr+1)); l=${line#"${line%%[![:space:]]*}"}
    case $l in ''|'#'*) continue ;; esac
    if [[ $l =~ ^[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]+(.*)$ ]]; then
      for pat in ${BASH_REMATCH[1]}; do
        if [[ $pat = /* ]]; then pat="$R$pat"; else pat="$R/etc/ssh/$pat"; fi
        for g in $pat; do [ -r "$g" ] && sshd_flat "$g" $((depth+1)); done
      done
    else
      printf '%s\t%s\t%s\n' "$f" "$nr" "$l"
    fi
  done < "$f"
}

chk_u02() {
  local unread=0 p st l f
  local conf="$R/etc/security/pwquality.conf" c_len= c_cls= a_len= a_cls= have=0
  EV=
  st=$(fstate "$conf")
  if [ "$st" = ok ]; then
    kv_get "$conf" minlen last;   c_len=$KV_VAL; [ -n "$KV_NR" ] && ev "pwquality.conf:$KV_NR: $KV_LINE"
    kv_get "$conf" minclass last; c_cls=$KV_VAL; [ -n "$KV_NR" ] && ev "pwquality.conf:$KV_NR: $KV_LINE"
  elif nread "$st"; then unread=1; ev "pwquality.conf 읽기 불가"; fi
  for f in common-password system-auth password-auth; do
    p="$R/etc/pam.d/$f"; st=$(fstate "$p")
    if [ "$st" = ok ]; then
      l=$(vgrep "$p" 'pam_(pwquality|cracklib)\.so')
      if [ -n "$l" ] && [ $have = 0 ]; then
        have=1; ev "pam.d/$f:$l"
        a_len=$(argval "$l" minlen); a_cls=$(argval "$l" minclass)
      fi
    elif nread "$st"; then unread=1; ev "pam.d/$f 읽기 불가"; fi
  done
  local minlen minclass
  if [ $have = 1 ]; then
    minlen=${a_len:-${c_len:-8}}; minclass=${a_cls:-${c_cls:-0}}
  else
    local ld="$R/etc/login.defs"; st=$(fstate "$ld"); minlen=0; minclass=0
    if [ "$st" = ok ]; then kv_get "$ld" PASS_MIN_LEN last
      if [ -n "$KV_NR" ]; then minlen=$KV_VAL; ev "login.defs:$KV_NR: $KV_LINE"; fi
      ev "pam_pwquality 적용 없음 → minclass 제한 없음"
    elif nread "$st"; then unread=1; ev "login.defs 읽기 불가"; fi
  fi
  ev "유효값 minlen=$minlen minclass=$minclass"
  if { [ "$minlen" -ge 8 ] && [ "$minclass" -ge 3 ]; } || { [ "$minlen" -ge 10 ] && [ "$minclass" -ge 2 ]; }; then
    emit U-02 "양호"
  elif [ $unread = 1 ] && { [ -z "$a_len" ] || [ -z "$a_cls" ]; }; then
    emit U-02 "확인 불가"
  else emit U-02 "취약"; fi
}

chk_u03() {
  local d="$R/etc/pam.d" fc="$R/etc/security/faillock.conf" f p st l unread=0 found=0 deny=
  local sd sf; sd=$(fstate "$d"); sf=$(fstate "$fc")
  if [ "$sd" = absent ] && [ "$sf" = absent ]; then ev "/etc/pam.d, faillock.conf 없음(PAM 미사용)"; emit U-03 "해당 없음"; return; fi
  nread "$sd" && { unread=1; ev "/etc/pam.d 읽기 불가"; }
  for f in common-auth system-auth password-auth login sshd; do
    p="$d/$f"; st=$(fstate "$p")
    if [ "$st" = ok ]; then
      l=$(vgrep "$p" 'pam_(faillock|tally2|tally)\.so')
      if [ -n "$l" ]; then found=1; ev "pam.d/$f:$l"; [ -z "$deny" ] && deny=$(argval "$l" deny); fi
    elif nread "$st"; then unread=1; ev "pam.d/$f 읽기 불가"; fi
  done
  if [ $found = 1 ]; then
    if [ -z "$deny" ] && [ "$sf" = ok ]; then kv_get "$fc" deny last
      if [ -n "$KV_NR" ]; then deny=$KV_VAL; ev "faillock.conf:$KV_NR: $KV_LINE"; fi; fi
    if [ -z "$deny" ]; then deny=3; ev "deny 설정 없음 → 기본값 3"; fi
    if [[ $deny =~ ^[0-9]+$ ]] && [ "$deny" -ge 1 ] && [ "$deny" -le 10 ]; then ev "deny=$deny"; emit U-03 "양호"
    else ev "deny=$deny (1~10 아님)"; emit U-03 "취약"; fi
  else
    if [ $unread = 1 ]; then emit U-03 "확인 불가"
    else ev "PAM 에 pam_faillock/pam_tally2 줄 없음"; [ "$sf" = ok ] && ev "faillock.conf 만 있으면 적용되지 않음"; emit U-03 "취약"; fi
  fi
}

chk_u04() {
  local f="$R/etc/passwd" st; st=$(fstate "$f")
  if [ "$st" != ok ]; then ev "/etc/passwd 없음 또는 읽기 불가($st)"; emit U-04 "확인 불가"; return; fi
  local zero; zero=$(awk -F: '$3=="0"{print $1}' "$f" | tr '\n' ' ')
  local n; n=$(wc -w <<<"$zero")
  ev "/etc/passwd UID 0 계정: ${zero:-없음}"
  if [ "$n" -le 1 ]; then emit U-04 "양호"; else emit U-04 "취약"; fi
}

chk_u05() {
  local f="$R/etc/passwd" st; st=$(fstate "$f")
  if [ "$st" != ok ]; then ev "/etc/passwd 없음 또는 읽기 불가($st)"; emit U-05 "확인 불가"; return; fi
  local bad; bad=$(awk -F: '$1 ~ /^(lp|uucp|nuucp|games|news|gopher)$/ {
      s=$7; sub(/.*\//,"",s); if (s !~ /^(nologin|false|sync|halt|shutdown)$/) print $1 "(" ($7==""?"셸 없음":$7) ")" }' "$f" | tr '\n' ' ')
  local all; all=$(awk -F: '$1 ~ /^(lp|uucp|nuucp|games|news|gopher)$/ {print $1}' "$f" | tr '\n' ' ')
  ev "대상 계정 존재: ${all:-없음}"
  if [ -z "$bad" ]; then emit U-05 "양호"; else ev "로그인 셸 보유: $bad"; emit U-05 "취약"; fi
}

chk_u06() {
  local f="$R/etc/login.defs" st; st=$(fstate "$f")
  if [ "$st" != ok ]; then ev "/etc/login.defs 없음 또는 읽기 불가($st)"; emit U-06 "확인 불가"; return; fi
  kv_get "$f" PASS_MAX_DAYS last
  if [ -z "$KV_NR" ]; then ev "PASS_MAX_DAYS 설정 없음 → 기본값 99999"; emit U-06 "취약"; return; fi
  ev "login.defs:$KV_NR: $KV_LINE"
  if [[ $KV_VAL =~ ^[0-9]+$ ]] && [ "$KV_VAL" -ge 1 ] && [ "$KV_VAL" -le 90 ]; then emit U-06 "양호"; else emit U-06 "취약"; fi
}

chk_u07() {
  local f="$R/etc/shadow" st; st=$(fstate "$f")
  if [ "$st" = absent ]; then
    local p="$R/etc/passwd" h=
    if [ -r "$p" ]; then h=$(awk -F: '$2!="" && $2!="x" && $2!="*" && $2 !~ /^!/ {n++} END{print n+0}' "$p"); fi
    if [ "${h:-0}" -gt 0 ]; then ev "/etc/shadow 없음, passwd 에 해시 $h개 → shadow 미사용"; emit U-07 "취약"
    else ev "/etc/shadow 없음"; emit U-07 "확인 불가"; fi
    return
  fi
  if [ "$st" != ok ]; then ev "/etc/shadow 읽기 불가(권한 부족) → 판단 근거 없음"; emit U-07 "확인 불가"; return; fi
  local res; res=$(awk -F: '
    { h=$2
      if (h=="") { empty=empty $1 " "; next }
      if (h ~ /^[*!]/) next
      if (h ~ /^\$(6|5|7|y|gy|2[abxy]?)\$/) { ok++; next }
      if (h ~ /^\$1\$/) { weak=weak $1 "(MD5) "; next }
      if (h !~ /\$/ && length(h)==13) { weak=weak $1 "(DES) "; next }
      weak=weak $1 "(알 수 없는 알고리즘) " }
    END { printf "%d|%s|%s", ok, empty, weak }' "$f")
  local ok empty weak; IFS='|' read -r ok empty weak <<<"$res"
  ev "강한 해시 계정 ${ok}개"
  [ -n "$empty" ] && ev "빈 비밀번호 계정: $empty"
  [ -n "$weak" ]  && ev "약한 해시 계정: $weak"
  if [ -z "$empty" ] && [ -z "$weak" ]; then emit U-07 "양호"; else emit U-07 "취약"; fi
}

# ---------------------------------------------------------------- 서비스 관리
chk_s01() {
  local f="$R/etc/xinetd.d/finger" vuln=0 svc
  svc=$(grep -E '^finger[[:space:]]' "$R/etc/services" 2>/dev/null | head -1)
  ev "/etc/services | grep finger: ${svc:-결과 없음}"
  ev_proc finger '[ /](in\.)?fingerd?([[:space:]]|$)' && vuln=1
  ev_port 79 && vuln=1
  xinetd_state "$f"
  inetd_state '^finger[[:space:]]'
  [ "$XS" = enabled ] && vuln=1
  [ "$INET" = found ] && vuln=1
  if [ $vuln = 1 ]; then emit S-01 "취약"
  elif [ "$XS" = unread ] || [ "$INET" = unread ]; then emit S-01 "확인 불가"
  elif [ "$XS" = absent ] && [ "$INET" != found ]; then ev "xinetd finger 설정 없음(미설치)"; emit S-01 "해당 없음"
  else emit S-01 "양호"; fi
}

chk_s02() {
  local f c st
  for c in "$R/etc/vsftpd.conf" "$R/etc/vsftpd/vsftpd.conf"; do
    st=$(fstate "$c"); [ "$st" != absent ] && { f=$c; break; }
  done
  if [ -z "$f" ]; then
    if ev_port 21 tcp; then ev "vsftpd 설정 파일 없음, 21 포트는 열림 → FTP 서버 종류 확인 불가"; emit S-02 "확인 불가"
    else ev "vsftpd 설정 없음, FTP 미설치"; emit S-02 "해당 없음"; fi
    return
  fi
  if [ "$st" != ok ]; then ev "$(rel "$f") 읽기 불가"; emit S-02 "확인 불가"; return; fi
  kv_get "$f" anonymous_enable last
  if [ -z "$KV_NR" ]; then ev "$(rel "$f"): anonymous_enable 줄 없음 → vsftpd 기본값 YES"; emit S-02 "취약"; return; fi
  ev "$(rel "$f"):$KV_NR: $KV_LINE"
  if [ "${KV_VAL^^}" = NO ]; then emit S-02 "양호"; else emit S-02 "취약"; fi
}

chk_s03() {
  local s vuln=0 sign=0 unread=0 any_enabled=0 rf st
  for s in rsh rlogin rexec; do
    xinetd_state "$R/etc/xinetd.d/$s"
    case $XS in enabled) vuln=1; sign=1 ;; disabled) sign=1 ;; unread) unread=1 ;; esac
  done
  inetd_state '^(shell|login|exec)[[:space:]]'
  [ "$INET" = found ] && { vuln=1; sign=1; }
  [ "$INET" = unread ] && unread=1
  ev_proc "r계열" '[ /](in\.)?r(sh|login|exec)d([[:space:]]|$)' && { vuln=1; sign=1; }
  local p
  for p in 512 513 514; do ev_port $p tcp && { vuln=1; sign=1; }; done
  if [ $sign = 0 ] && [ $unread = 0 ]; then ev "r 계열 서비스 설치 징후 없음"; emit S-03 "해당 없음"; return; fi
  # hosts.equiv / .rhosts 의 '+' 검사
  local list="$R/etc/hosts.equiv $R/root/.rhosts" hu=0
  for p in "$R"/home/*/.rhosts; do [ -e "$p" ] && list="$list $p"; done
  if nread "$(fstate "$R/home")" || nread "$(fstate "$R/root/.rhosts")"; then hu=1; fi
  for rf in $list; do
    st=$(fstate "$rf")
    if [ "$st" = ok ]; then
      if grep -vE '^[[:space:]]*#' "$rf" | grep -qE '(^|[[:space:]])\+([[:space:]]|$)'; then
        ev "$(rel "$rf"): '+' 포함"; vuln=1; else ev "$(rel "$rf"): '+' 없음"; fi
    elif nread "$st"; then hu=1; fi
  done
  if [ $vuln = 1 ]; then emit S-03 "취약"
  elif [ $unread = 1 ] || [ $hu = 1 ]; then ev ".rhosts 또는 설정 파일 읽기 불가"; emit S-03 "확인 불가"
  else emit S-03 "양호"; fi
}

chk_s04() {
  local f="$R/etc/exports" st; st=$(fstate "$f")
  local run=0
  ev_proc nfsd '(\[nfsd\]|rpc\.mountd|rpc\.nfsd)' && run=1
  ev_port 2049 && run=1
  case $st in
    absent) if [ $run = 1 ]; then ev "/etc/exports 없음 → 공유 항목 없음"; emit S-04 "양호"
            else ev "/etc/exports 없음, NFS 미사용"; emit S-04 "해당 없음"; fi; return ;;
    ok) ;;
    *) ev "/etc/exports 읽기 불가"; emit S-04 "확인 불가"; return ;;
  esac
  local bad; bad=$(awk '
    { l=$0; sub(/^[ \t]+/,"",l); if (l=="" || l ~ /^#/) next
      n=split(l,a,/[ \t]+/)
      if (n<2) { print NR ": " l " (클라이언트 제한 없음)"; next }
      for (i=2;i<=n;i++) {
        if (a[i] ~ /^\*/ || a[i] ~ /^\(/) { print NR ": " l " (무제한 호스트)"; break }
        if (a[i] ~ /no_root_squash/) { print NR ": " l " (no_root_squash)"; break } } }' "$f" | tr '\n' ';')
  if [ -n "$bad" ]; then ev "exports:$bad"; emit S-04 "취약"
  else ev "/etc/exports 의 모든 유효 줄이 호스트를 제한하고 no_root_squash 없음"; emit S-04 "양호"; fi
}

chk_s05() {
  local n f vuln=0 sign=0 unread=0 p
  for n in echo discard daytime chargen; do
    for f in "$R/etc/xinetd.d/$n" "$R"/etc/xinetd.d/$n-*; do
      [ -e "$f" ] || [ -L "$f" ] || continue
      xinetd_state "$f"
      case $XS in enabled) vuln=1; sign=1 ;; disabled) sign=1 ;; unread) unread=1 ;; esac
    done
  done
  inetd_state '^(echo|discard|daytime|chargen)[[:space:]]'
  [ "$INET" = found ] && { vuln=1; sign=1; }
  [ "$INET" = unread ] && unread=1
  for p in 7 9 13 19; do port_open $p && { ev "$PORT_CMD: 포트 $p 열림"; vuln=1; sign=1; }; done
  if [ $vuln = 1 ]; then emit S-05 "취약"
  elif [ $unread = 1 ]; then emit S-05 "확인 불가"
  elif [ $sign = 0 ]; then ev "echo/discard/daytime/chargen 설정 없음, 7·9·13·19 포트 닫힘"; emit S-05 "해당 없음"
  else ev "7·9·13·19 포트 닫힘"; emit S-05 "양호"; fi
}

# ---------------------------------------------------------------- 파일 시스템
perm_le() { (( (8#$1 & ~8#$2) == 0 )); }   # 권한 $1 이 $2 이하(비트 포함)
chk_perm() { # ID 파일 최대권한 [mode]
  local id=$1 f="$R$2" max=$3 info perm owner uid grp
  if [ ! -e "$f" ]; then
    if [ "$(fstate "$f")" = noaccess ]; then ev "$2 접근 불가"; else ev "$2 없음"; fi
    emit "$id" "확인 불가"; return
  fi
  info=$(stat -c '%a %u %U %G' "$f" 2>/dev/null) || { ev "$2 stat 실패"; emit "$id" "확인 불가"; return; }
  read -r perm uid owner grp <<<"$info"
  ev "$2 소유자 $owner 그룹 $grp 권한 $perm (기준: root, $max 이하)"
  if [ "$uid" = "$OWNER_UID" ] && perm_le "$perm" "$max"; then emit "$id" "양호"; else emit "$id" "취약"; fi
}
chk_f01() { chk_perm F-01 /etc/passwd 644; }
chk_f02() { chk_perm F-02 /etc/shadow 600; }
chk_f03() { chk_perm F-03 /etc/hosts 644; }

chk_f04() {
  local al="$SCRIPT_DIR/src/suid_allowlist.txt" dirs= d errf
  if [ ! -r "$al" ]; then ev "허용 목록 src/suid_allowlist.txt 없음"; emit F-04 "확인 불가"; return; fi
  if [ -z "$R" ]; then for d in /bin /sbin /lib /lib64 /usr /opt; do [ -e "$d" ] && dirs="$dirs $d"; done
  else dirs=$ROOT; fi
  errf="$OUT/.find.err"
  local found; found=$(find -H $dirs -xdev -type f -perm /6000 -printf '%i\t%m\t%p\n' 2>"$errf" | sort -u -k1,1n)
  local denied; denied=$(grep -c 'Permission denied' "$errf" 2>/dev/null); rm -f "$errf"
  local bad= nbad=0 nall=0 ino mode path base
  while IFS=$'\t' read -r ino mode path; do
    [ -z "$path" ] && continue
    nall=$((nall+1)); base=${path##*/}
    if ! grep -qxF "$base" <(sed 's/#.*//; s/[[:space:]]*$//' "$al"); then
      nbad=$((nbad+1)); [ $nbad -le 8 ] && bad="$bad ${path#"$R"}($mode)"
    fi
  done <<<"$found"
  ev "SUID/SGID 파일 ${nall}개 중 허용 목록 밖 ${nbad}개"
  if [ $nbad -gt 0 ]; then ev "목록 밖:$bad"; emit F-04 "취약"
  elif [ "${denied:-0}" -gt 0 ]; then ev "접근 불가 디렉터리 ${denied}곳 있음"; emit F-04 "확인 불가"
  else emit F-04 "양호"; fi
}

chk_f05() {
  local weak= found=0 unread=0 f st l v
  local ld="$R/etc/login.defs"; st=$(fstate "$ld")
  if [ "$st" = ok ]; then
    kv_get "$ld" UMASK last
    if [ -n "$KV_NR" ]; then found=1; ev "login.defs:$KV_NR: $KV_LINE"
      [[ $KV_VAL =~ ^[0-7]+$ ]] && (( (8#$KV_VAL & 8#022) != 8#022 )) && weak="$weak login.defs($KV_VAL)"; fi
  elif nread "$st"; then unread=1; ev "login.defs 읽기 불가"; fi
  for f in "$R/etc/profile" "$R/etc/bash.bashrc" "$R"/etc/profile.d/*.sh "$R/etc/csh.cshrc" "$R/etc/csh.login"; do
    st=$(fstate "$f")
    if [ "$st" = ok ]; then
      while IFS= read -r l; do
        v=${l#*: }; v=$(sed -E 's/^[[:space:]]*umask[[:space:]]+([0-7]+).*/\1/' <<<"$v")
        found=1; ev "$(rel "$f"):${l%%: *}: umask $v"
        (( (8#$v & 8#022) != 8#022 )) && weak="$weak $(rel "$f")($v)"
      done < <(awk '{ l=$0; sub(/^[ \t]+/,"",l); if (l ~ /^umask[ \t]+[0-7]+/) print NR ": " l }' "$f")
    fi
  done
  if [ -n "$weak" ]; then ev "약한 UMASK:$weak"; emit F-05 "취약"
  elif [ $found = 0 ]; then
    if [ $unread = 1 ]; then emit F-05 "확인 불가"; else ev "UMASK 설정을 찾지 못함"; emit F-05 "취약"; fi
  else emit F-05 "양호"; fi
}

chk_f06() {
  local vuln=0 unread=0 f st l v e
  if nread "$(fstate "$R/root")" || [ ! -x "$R/root" ]; then
    [ -e "$R/root" ] && { unread=1; ev "/root 에 들어갈 수 없음(비root 실행)"; }
  fi
  for f in "$R/root/.bashrc" "$R/root/.profile" "$R/root/.bash_profile" "$R/root/.cshrc" \
           "$R/etc/profile" "$R/etc/bash.bashrc" "$R/etc/environment"; do
    st=$(fstate "$f")
    if [ "$st" = ok ]; then
      while IFS= read -r l; do
        v=$(sed -E 's/^[[:space:]]*(export[[:space:]]+)?PATH=//; s/[[:space:]]+#.*$//; s/^["'"'"']//; s/["'"'"']$//' <<<"${l#*: }")
        local bad=0 IFS_OLD=$IFS; IFS=':'; local arr=($v:x); IFS=$IFS_OLD
        # 끝에 붙인 :x 로 마지막 빈 요소를 감지하고 마지막 요소는 제외
        local i n=$(( ${#arr[@]} - 1 ))
        for (( i=0; i<n; i++ )); do e=${arr[$i]}; [ "$e" = "." ] || [ -z "$e" ] && bad=1; done
        if [ $bad = 1 ]; then vuln=1; ev "$(rel "$f"):${l%%: *}: PATH 에 '.' 또는 빈 요소 → $v"; else ev "$(rel "$f"):${l%%: *}: PATH 양호"; fi
      done < <(awk '{ l=$0; sub(/^[ \t]+/,"",l); if (l ~ /^(export[ \t]+)?PATH=/) print NR ": " l }' "$f")
    elif nread "$st"; then unread=1; ev "$(rel "$f") 읽기 불가"; fi
  done
  if [ $vuln = 1 ]; then emit F-06 "취약"
  elif [ $unread = 1 ]; then emit F-06 "확인 불가"
  else emit F-06 "양호"; fi
}

# ---------------------------------------------------------------- 실행
for fn in chk_u01 chk_u02 chk_u03 chk_u04 chk_u05 chk_u06 chk_u07 \
          chk_s01 chk_s02 chk_s03 chk_s04 chk_s05 \
          chk_f01 chk_f02 chk_f03 chk_f04 chk_f05 chk_f06; do
  EV=; "$fn"
done

# ---------------------------------------------------------------- 결과 출력(JSON + HTML)
python3 -I - "$RES" "$OUT" "$HOST" "$SCRIPT_DIR" <<'PY'
import sys, json, html, datetime, shutil, os
res_path, out, host, script_dir = sys.argv[1:5]

META = [  # SPEC 1-4
 ("U-01","계정 관리","root 원격 접속 제한","상"),("U-02","계정 관리","패스워드 복잡성 설정","상"),
 ("U-03","계정 관리","계정 잠금 임계값 설정","상"),("U-04","계정 관리","root 이외 UID 0 금지","중"),
 ("U-05","계정 관리","불필요 계정 제거","하"),("U-06","계정 관리","패스워드 최대 사용기간","중"),
 ("U-07","계정 관리","패스워드 파일 보호(shadow 내용)","상"),
 ("S-01","서비스 관리","Finger 서비스 비활성화","상"),("S-02","서비스 관리","Anonymous FTP 비활성화","상"),
 ("S-03","서비스 관리","r 계열 서비스 비활성화","상"),("S-04","서비스 관리","NFS 접근 통제","상"),
 ("S-05","서비스 관리","DoS 공격에 취약한 서비스 비활성화","상"),
 ("F-01","파일 시스템","/etc/passwd 파일 소유자 및 권한","상"),("F-02","파일 시스템","/etc/shadow 파일 소유자 및 권한","상"),
 ("F-03","파일 시스템","/etc/hosts 파일 소유자 및 권한","상"),("F-04","파일 시스템","불필요한 SUID·SGID 파일","상"),
 ("F-05","파일 시스템","UMASK 설정","중"),("F-06","파일 시스템","root 홈·PATH 에 \".\" 금지","상"),
]
REMEDY = {  # 취약 항목 조치 방법(안내만 한다. 이 도구는 시스템을 수정하지 않는다)
 "U-01": ("/etc/ssh/sshd_config 에 PermitRootLogin no 를 설정한다. 주석(#)을 풀고 값을 no 로 바꾼다.",
          "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\nsudo sshd -t && sudo systemctl reload ssh"),
 "U-02": ("pwquality 로 8자 이상 3종 이상(또는 10자 이상 2종 이상)을 강제한다.",
          "sudo apt install libpam-pwquality\n# /etc/security/pwquality.conf\nminlen = 8\nminclass = 3"),
 "U-03": ("PAM 에 pam_faillock 을 적용하고 deny 를 1~10 으로 둔다.",
          "# /etc/security/faillock.conf\ndeny = 5\nunlock_time = 600\n# /etc/pam.d/common-auth 에 pam_faillock.so preauth / authfail 줄 추가\n# (설정 전 다른 로그인 세션을 열어 둬 잠기는 사고를 막는다)"),
 "U-04": ("root 외 UID 0 계정은 삭제하거나 UID 를 바꾼다.",
          "sudo usermod -u <새 UID> <계정>   # 또는 sudo userdel <계정>"),
 "U-05": ("불필요 계정(lp·uucp·nuucp·games·news·gopher)의 셸을 nologin 으로 바꾸거나 삭제한다.",
          "sudo usermod -s /usr/sbin/nologin <계정>   # 또는 sudo userdel <계정>"),
 "U-06": ("/etc/login.defs 의 PASS_MAX_DAYS 를 90 이하로 설정한다(기존 계정은 chage 로 적용).",
          "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs\nsudo chage -M 90 <계정>"),
 "U-07": ("빈 비밀번호 계정은 비밀번호를 설정하거나 잠그고, 약한 해시 계정은 비밀번호를 다시 설정해 SHA-512/yescrypt 로 바꾼다.",
          "sudo passwd -l <계정>   # 잠금\nsudo passwd <계정>      # 재설정(현재 해시 알고리즘으로 저장됨)"),
 "S-01": ("finger 서비스를 끈다.",
          "# /etc/xinetd.d/finger 에 disable = yes\nsudo systemctl restart xinetd\n# 또는 패키지 제거: sudo apt remove finger fingerd"),
 "S-02": ("vsftpd 설정에서 익명 접속을 끈다.",
          "# /etc/vsftpd.conf\nanonymous_enable=NO\nsudo systemctl restart vsftpd"),
 "S-03": ("r 계열 서비스를 끄고 hosts.equiv·.rhosts 의 '+' 를 제거한다. 가능하면 패키지를 제거하고 SSH 를 쓴다.",
          "# /etc/xinetd.d/{rsh,rlogin,rexec} 에 disable = yes\nsudo apt remove rsh-server\n# /etc/hosts.equiv, ~/.rhosts 에서 '+' 줄 삭제"),
 "S-04": ("/etc/exports 에서 '*' 와 no_root_squash 를 없애고 허용 호스트를 지정한다.",
          "# /etc/exports\n/share 192.168.0.0/24(ro,root_squash)\nsudo exportfs -ra"),
 "S-05": ("echo·discard·daytime·chargen 을 끈다.",
          "# /etc/xinetd.d/ 의 해당 파일에 disable = yes\nsudo systemctl restart xinetd"),
 "F-01": ("/etc/passwd 를 root 소유, 644 이하로 맞춘다.",
          "sudo chown root:root /etc/passwd\nsudo chmod 644 /etc/passwd"),
 "F-02": ("/etc/shadow 를 root 소유, 600(또는 400)으로 맞춘다. Ubuntu 기본 640 root:shadow 도 교재 기준은 취약이다. shadow 그룹이 읽어야 하는 프로그램이 없는지 확인한 뒤 적용한다.",
          "sudo chown root:root /etc/shadow\nsudo chmod 600 /etc/shadow"),
 "F-03": ("/etc/hosts 를 root 소유, 644 이하로 맞춘다.",
          "sudo chown root:root /etc/hosts\nsudo chmod 644 /etc/hosts"),
 "F-04": ("목록 밖 SUID/SGID 파일은 필요 여부를 확인하고, 불필요하면 특수 권한을 제거한다. 필요하면 src/suid_allowlist.txt 에 근거와 함께 추가한다.",
          "ls -l <파일>\nsudo chmod u-s,g-s <파일>"),
 "F-05": ("UMASK 를 022 이상으로 설정한다.",
          "# /etc/login.defs\nUMASK 022\n# /etc/profile 등에 umask 가 있으면 022 이상으로"),
 "F-06": ("root 의 PATH 에서 '.' 과 빈 요소(::, 앞뒤 :)를 제거한다.",
          "# 해당 파일(.bashrc, /etc/profile 등)의 PATH= 줄을 고친다\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
}
results = {}
for line in open(res_path, encoding="utf-8"):
    p = line.rstrip("\n").split("\t", 2)
    if len(p) == 3: results[p[0]] = (p[1], p[2])

items = []
for id_, cat, name, grade in META:
    r, e = results.get(id_, ("확인 불가", "점검 결과 없음"))
    it = {"id": id_, "category": cat, "name": name, "grade": grade, "result": r, "evidence": e}
    if r == "취약":
        it["remediation"] = {"summary": REMEDY[id_][0], "commands": REMEDY[id_][1]}
    items.append(it)

def tally(sub):
    c = {k: sum(1 for i in sub if i["result"] == k) for k in ("양호","취약","확인 불가","해당 없음")}
    total = c["양호"] + c["취약"] + c["확인 불가"]          # SPEC 1-8: 해당 없음 제외
    return {"total": total, "vuln": c["취약"], "rate": (c["취약"]/total if total else 0.0),
            "good": c["양호"], "unknown": c["확인 불가"], "na": c["해당 없음"]}
cats = ["계정 관리", "서비스 관리", "파일 시스템"]
summary = {c: tally([i for i in items if i["category"] == c]) for c in cats}
totals = tally(items)
generated = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
report = {"host": host, "generated": generated, "tool": "check.sh (로컬 설치형)",
          "items": items, "summary": summary, "totals": totals}
with open(os.path.join(out, "report.json"), "w", encoding="utf-8") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)

E = html.escape
def pct(x): return f"{x*100:.1f}%"
cls = {"양호":"ok","취약":"bad","확인 불가":"unk","해당 없음":"na"}
rows = "".join(
  f'<tr><td>{E(i["id"])}</td><td>{E(i["category"])}</td><td>{E(i["name"])}</td><td>{E(i["grade"])}</td>'
  f'<td class="{cls[i["result"]]}">{E(i["result"])}</td><td class="ev">{E(i["evidence"])}</td></tr>' for i in items)
srows = "".join(
  f'<tr><td>{E(c)}</td><td>{s["total"]}</td><td>{s["vuln"]}</td><td>{s["unknown"]}</td><td>{s["na"]}</td>'
  f'<td><b>{pct(s["rate"])}</b></td></tr>' for c, s in summary.items())
srows += (f'<tr class="tot"><td>전체</td><td>{totals["total"]}</td><td>{totals["vuln"]}</td>'
          f'<td>{totals["unknown"]}</td><td>{totals["na"]}</td><td><b>{pct(totals["rate"])}</b></td></tr>')
rem = "".join(
  f'<div class="rem"><h3>{E(i["id"])} {E(i["name"])} <span class="bad">[{E(i["grade"])}]</span></h3>'
  f'<p>{E(i["remediation"]["summary"])}</p><pre>{E(i["remediation"]["commands"])}</pre></div>'
  for i in items if i["result"] == "취약") or '<p class="meta">취약 항목이 없습니다.</p>'
tech_state = "미이행(취약 항목 존재)" if totals["vuln"] else ("부분 확인(확인 불가 존재)" if totals["unknown"] else "이행")
vuln_ids = ", ".join(i["id"] for i in items if i["result"] == "취약") or "없음"
unk_ids = ", ".join(i["id"] for i in items if i["result"] == "확인 불가") or "없음"
comment = (f"취약 {totals['vuln']}건({vuln_ids}), 확인 불가 {totals['unknown']}건({unk_ids}). "
           "확인 불가는 양호가 아니며, 많으면 취약률이 낮아 보일 뿐 안전한 것이 아니다. 취약 항목은 근거를 보고 설정을 조치한 뒤 재점검한다.")
doc = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>리눅스 보안 점검 결과서</title>
<style>
:root{{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#d8d8d8;--ok:#1a7f37;--bad:#c62828;--unk:#b26a00;--na:#777;--head:#f2f4f7}}
@media(prefers-color-scheme:dark){{:root{{--bg:#16181d;--fg:#e8e8e8;--mut:#9aa0a6;--line:#343942;--ok:#4cc26b;--bad:#ff6b6b;--unk:#f0b45a;--na:#9aa0a6;--head:#20242b}}}}
body{{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px;max-width:1100px;margin-inline:auto}}
h1{{font-size:22px;margin:0 0 4px}}h2{{font-size:17px;margin:28px 0 8px}}.meta{{color:var(--mut)}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:var(--head)}}.ev{{font-size:12px;color:var(--mut);word-break:break-word}}
.ok{{color:var(--ok);font-weight:600}}.bad{{color:var(--bad);font-weight:600}}.unk{{color:var(--unk);font-weight:600}}.na{{color:var(--na)}}
tr.tot td{{background:var(--head)}}
h3{{font-size:14px;margin:0 0 4px}}.rem{{border:1px solid var(--line);border-radius:6px;padding:10px 12px;margin:10px 0}}
.rem p{{margin:4px 0}}pre{{background:var(--head);padding:8px;border-radius:4px;overflow-x:auto;margin:6px 0 0;font-size:12px}}.scroll{{overflow-x:auto}}
</style></head><body>
<h1>리눅스 보안 점검 결과서</h1>
<div class="meta">호스트 {E(host)} · 점검 일시 {E(generated)} · 도구 check.sh (로컬 설치형, 읽기 전용) · <a href="assets.html">자산 관리 대장</a> · <a href="report.json">report.json</a></div>
<h2>1. 점검 항목표</h2><div class="scroll"><table><tr><th>ID</th><th>분류</th><th>항목</th><th>등급</th><th>판정</th><th>근거</th></tr>{rows}</table></div>
<h2>2. 분야별 취약률</h2>
<div class="scroll"><table><tr><th>분야</th><th>점검 항목 수</th><th>취약</th><th>확인 불가</th><th>해당 없음</th><th>취약률</th></tr>{srows}</table></div>
<p class="meta">취약률 = 취약 ÷ (양호+취약+확인 불가). 해당 없음은 분모에서 제외, 확인 불가는 분모에만 포함.</p>
<h2>3. 결과표</h2>
<div class="scroll"><table><tr><th>관점</th><th>이행 여부</th><th>총평</th></tr>
<tr><td>관리적 관점</td><td>인터뷰 필요</td><td>정보보호 정책·절차는 스크립트로 확인할 수 없어 담당자 인터뷰(SPEC 1-6)로 별도 점검한다.</td></tr>
<tr><td>기술적 관점</td><td>{E(tech_state)}</td><td>{E(comment)}</td></tr></table></div>
<h2>4. 취약 항목 조치 방법</h2>
<p class="meta">안내용이다. 이 도구는 시스템을 수정하지 않으므로 관리자가 영향을 확인한 뒤 직접 적용하고 재점검한다.</p>
{rem}
</body></html>"""
with open(os.path.join(out, "report.html"), "w", encoding="utf-8") as f: f.write(doc)

src = os.path.join(script_dir, "assets.html")
if os.path.exists(src): shutil.copy(src, os.path.join(out, "assets.html"))
with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as f:
    f.write('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>리눅스 보안 점검기</title><body style="font:16px system-ui;max-width:600px;margin:40px auto;padding:0 16px">'
            '<h1>리눅스 보안 점검기</h1><ul><li><a href="assets.html">자산 관리 대장</a></li>'
            '<li><a href="report.html">점검 결과서</a></li></ul></body>')
PY
rc=$?
rm -f "$RES"
if [ $rc -eq 0 ]; then echo "완료: $OUT/report.html, report.json"; fi
exit $rc
