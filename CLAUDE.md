# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

이 프로젝트는 읽기 전용 점검 도구다. sudo 와 시스템 파일 수정은 하지 않는다.

Repo: https://github.com/mrgrit/linux_vuln_checker (로컬 작업 디렉터리 `/home/att/ch02`)

## 현재 상태

아직 `SPEC.md` 만 있다(코드 없음). **SPEC.md 가 유일한 요구사항 원본이다.** 코드는 SPEC.md 에 있는 규칙만 구현하고, 규칙을 바꾸려면 코드보다 SPEC.md 를 먼저 고친다. 빌드·린트 설정은 아직 없으므로 명령을 지어내지 말고 실제로 추가된 것만 이 파일에 기록한다.

## 구조 (SPEC.md 기준, 2장 리눅스 보안 점검기)

- `check.sh` — 로컬 설치형 점검 스크립트(SPEC 1-6). 18개 항목(계정 U-01~07, 서비스 S-01~05, 파일 F-01~06)을 점검해 `out/report.json`·`out/report.html` 을 만든다.
- `assets.html` / `out/assets.json` — 자산 관리 대장(SPEC 1-1 의 8개 항목, C·I·A 합산 → 상/중/하).
- `src/suid_allowlist.txt` — F-04 허용 목록(파일 이름 기준).
- `tests/` — 함정 테스트 3종(`test_trap1_permitrootlogin.py`, `test_trap2_finger.py`, `test_trap3_shadow.py`)과 `test_docker.py`(비root 검증).
- 출력 JSON 스키마는 SPEC 4절이며, 다른 장(9장이 `assets.json` 을 읽음)과 교환하는 형식이므로 키 이름을 바꾸지 않는다.

## 구현 시 반드시 지킬 점 (여러 절을 읽어야 보이는 것)

- `--root <dir>` 옵션: `/` 가 아니면 테스트 루트(픽스처)로 동작한다. 모든 경로를 이 루트 기준으로 읽고, 서비스 확인은 명령을 실행하지 않고 `<root>/ps.txt`, `<root>/ports.txt` 를 쓴다(1-9). 소유자 검사의 root 도 루트 디렉터리 소유자로 대체한다(2-0c).
- 판정은 4가지: 양호 / 취약 / 확인 불가 / 해당 없음(1-7). 읽기 권한 없음 → 반드시 확인 불가, 절대 양호 아님. 서비스·패키지 설정 파일 없음 → 해당 없음, passwd·shadow·hosts·login.defs 없음 → 확인 불가.
- 취약률 = 취약 ÷ (양호+취약+확인 불가). 해당 없음은 분모 제외, 확인 불가는 분모에만 포함하고 결과서에 따로 표기(1-8). rate 는 0.0~1.0 소수.
- `#` 주석 줄은 설정이 아니다. 중복 키는 sshd 는 첫 유효 줄, key=value 설정 파일은 마지막 유효 줄(2-0a). `#PermitRootLogin no` 만 있으면 기본값 적용 → 취약이며 근거에 "주석 처리됨"·"기본값" 을 쓴다.
- 권한 "N 이하" 는 8진수 비트 포함 관계다(640 은 644 이하지만 600 이하 아님, 2-0d).
- evidence 에는 읽은 파일 경로·줄 번호·줄 내용 또는 실행 명령과 결과를 적는다. shadow 해시 값은 절대 적지 않는다(계정 이름·알고리즘·개수만).
- 비root 로 실행하면 U-07(shadow 내용), F-06(/root 접근) 등이 확인 불가가 되는 것이 정상 동작이다.

## 안전 규칙

- 점검은 읽기 전용: 파일을 읽고 `stat`·`find`·`ps`·`ss` 같은 조회 명령만 쓴다. sudo 사용, 시스템 파일 수정, 서비스 시작·중지, 설정 변경 금지.
- 산출물은 프로젝트 안의 `out/` 에만 쓴다.
