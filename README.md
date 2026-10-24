# gpu-lock

컴퓨터 없이 아이폰 안에서 Xcode의 **기기 조건(Device Conditions) → GPU 성능 상태**를 켜는 앱입니다.

- iOS 27의 기기 내 페어링(설정 › 개인정보 보호 및 보안 › 개발자 모드 › Pair with GPU Lock)으로 페어링 파일을 만들고
- LocalDevVPN의 루프백(10.7.0.1)으로 자기 기기의 개발자 서비스에 접속해
- 개발자 디스크 이미지를 설치한 뒤 Instruments의 Condition Inducer로 조건을 켭니다.

조건은 앱이 연결을 유지하는 동안만 켜져 있습니다. 앱은 무음 오디오로 백그라운드에서 연결을 유지합니다.

## 빌드

`main`에 푸시하면 GitHub Actions(macOS)가 `GPULock.ipa`를 만들어 **Releases › latest**에 올립니다. Actions 탭에서 직접 실행할 수도 있습니다.

## 구성

- `core/` Rust 라이브러리 ([idevice](https://github.com/jkcoxson/idevice), MIT): 페어링, 터널, 디스크 이미지, Condition Inducer
- `app/` SwiftUI 앱
- `.github/workflows/build.yml` IPA 빌드

개발자 디스크 이미지는 빌드할 때 [doronz88/DeveloperDiskImage](https://github.com/doronz88/DeveloperDiskImage)에서 받아 앱에 넣습니다.
