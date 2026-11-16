# 설치·검증·복구

대상 환경은 Ubuntu 26.04 / Xfce / Egis USB `1c7a:05a1`입니다. 실제 장치 검증 전의 개발 버전입니다.

## 출처와 변경

GitHub 원본 포크 위에 공식 libfprint SDCP v2 제안의 소스 트리를 가져왔습니다.

- 공식 제안: https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/547
- 기반 커밋: `2d7c5277de08c6b29b3fac7447f17a516fbc4d1c`
- 기반 트리: `630ee1f1ee1da45895891a027a7812d7886e4db1`
- 기존 저작권 표시와 LGPL 라이선스를 유지합니다.

로컬 변경은 실제 ECDSA 최종 검증, 올바른 서명 및 바이너리 접두부, 매 인증 새 키 생성, 입력 길이 검사, 오류·취소 상태 정리, 비밀값 로그 제거입니다. 장치가 매번 새로운 연결을 받아들이지 않으면 이전 키로 우회하지 않고 인증을 중단합니다.

## 빌드

필요한 공식 Ubuntu 패키지:

```sh
sudo apt-get install --no-install-recommends meson ninja-build pkg-config libglib2.0-dev libgusb-dev libssl-dev
sh local-setup/build.sh
```

빌드 스크립트 마지막에 나온 SHA-256을 확인한 뒤, 라이브러리 경로와 그 값을 설치 스크립트에 넘깁니다.

```sh
sudo sh local-setup/install-driver.sh /absolute/path/to/build/libfprint/libfprint-2.so.2.0.0 SHA256_FROM_BUILD
```

설치 스크립트는 Ubuntu 패키지 파일을 덮어쓰지 않습니다. `/usr/local/lib/fprint-egismoc-sdcp`에 라이브러리와 복구 정보를 두고 `fprintd` 서비스에만 그 라이브러리를 지정합니다. 이미 설치된 경로는 덮어쓰지 않습니다.

## 실제 장치 확인

자신의 사용자 계정에서 실행합니다. 센서를 초기화하거나 지문을 일괄 삭제할 필요는 없습니다.

```sh
fprintd-enroll -f right-thumb
fprintd-verify -f right-thumb
sudo systemctl restart fprintd
fprintd-verify -f right-thumb
```

등록과 반복 검증이 모두 성공한 뒤에만 화면 잠금에 연결합니다.

```sh
sudo sh local-setup/enable-xfce-lock.sh
```

잠금 해제를 시험할 때는 지문 인식 성공과 비밀번호 대체 경로를 모두 확인합니다. 잠금 설정의 원본은 설치 디렉터리에 보관됩니다. 설치된 라이브러리, 설정, 복구 정보가 남아 있으면 빌드한 소스 폴더는 지워도 됩니다. 지문 원본이나 개인 로그는 이 저장소에 업로드하지 않습니다.

## 복구

```sh
sudo sh /usr/local/lib/fprint-egismoc-sdcp/rollback.sh
```

이 명령은 원래 잠금 인증 설정과 Ubuntu의 기본 지문 드라이버로 돌아갑니다.

## 검사 및 한계

기존 유닛 시험 세 묶음과 새 보안 회귀시험 여섯 개가 통과했습니다. ASan/UBSan으로 암호 시험 여섯 개 및 보안 회귀시험 여섯 개도 통과했습니다. 실행환경 제약으로 누수 검사는 제외했습니다. 공개된 실제 Egis 통신 기록으로 제조사 인증서 체인·모델 서명·장치 서명 검증을 확인했습니다. 기본 공개 암호 벡터의 모델 인증서와 모델 서명이 불일치하는 점은 거부 시험으로 명시했습니다.

실제 `05a1` 장치의 등록, 반복 인식, 절전 후 동작, 화면 잠금 해제는 아직 확인하지 않았습니다. USB 비동기 경로 전체를 시험한 것은 아닙니다. 공식 제안과 마찬가지로 장기 사용 센서의 모델 인증서 날짜 검사는 생략하지만 신뢰 체인과 서명은 검사합니다. 펌웨어 해시의 허용·폐기 정책과 Windows Hello 전체 보안 체계까지 제공하지는 않습니다.
