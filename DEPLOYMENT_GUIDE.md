# SSHift Homebrew 배포 가이드

이 문서는 SSHift를 Homebrew를 통해 배포하는 방법을 설명합니다.

## 📋 사전 준비사항

### 1. GitHub Personal Access Token 생성

1. GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. "Generate new token (classic)" 클릭
3. 권한 설정:
   - `repo` (전체 선택)
   - `workflow` (전체 선택)
4. 토큰 생성 후 안전한 곳에 저장

### 2. Homebrew Tap Repository 생성

1. GitHub에서 새 저장소 생성

   - Repository name: `homebrew-sshift`
   - Public repository로 설정
   - README 파일 생성

2. 저장소에 Formula 파일 추가:

   ```bash
   git clone https://github.com/takealook97/homebrew-sshift.git
   cd homebrew-sshift
   ```

3. `sshift.rb` 파일 생성:

   ```ruby
   class Sshift < Formula
     desc "SSH server management tool with jump server support"
     homepage "https://github.com/takealook97/sshift"
     version "1.0.0"
     license "MIT"

     url "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.0.tar.gz"
     sha256 "your-sha256-here"

     depends_on "go" => :build

     def install
       ldflags = %W[
         -s -w
         -X main.Version=#{version}
       ]

       system "go", "build", *std_go_args(ldflags: ldflags), "-o", bin/"sshift", "main.go"
     end

     test do
       assert_match "SSHift v#{version}", shell_output("#{bin}/sshift version")
       assert_match "Usage:", shell_output("#{bin}/sshift help")
     end
   end
   ```

4. 커밋 및 푸시:
   ```bash
   git add sshift.rb
   git commit -m "Initial sshift formula"
   git push origin main
   ```

## 🚀 배포 과정

### 1단계: GitHub Secrets 설정

메인 저장소 (`sshift`)에서:

1. Settings → Secrets and variables → Actions
2. "New repository secret" 클릭
3. Name: `HOMEBREW_TAP_TOKEN`
4. Value: 위에서 생성한 Personal Access Token
5. "Add secret" 클릭

### 2단계: 릴리즈 준비

```bash
# 로컬에서 태그 생성
git tag v1.0.0
git push origin v1.0.0

# 또는 GitHub에서 직접 태그 생성
```

### 3단계: GitHub Release 생성

1. GitHub 저장소 → Releases → "Create a new release"
2. Tag: `v1.0.0` 선택
3. Title: `SSHift v1.0.0`
4. Description: 릴리즈 노트 작성
5. "Publish release" 클릭

### 4단계: 자동 배포 확인

GitHub Actions가 자동으로 실행됩니다:

1. Actions 탭에서 `Update Homebrew Tap` 워크플로우 확인
2. 성공적으로 완료되면 `homebrew-sshift` 저장소가 업데이트됨

### 5단계: 설치 테스트

```bash
# Tap 추가
brew tap takealook97/sshift

# 설치
brew install sshift

# 테스트
sshift version
sshift help
```

## 🔧 수동 배포 (필요시)

### SHA256 계산

```bash
VERSION="v1.0.0"
SOURCE_URL="https://github.com/takealook97/sshift/archive/refs/tags/${VERSION}.tar.gz"
SHA256=$(curl -sL "$SOURCE_URL" | shasum -a 256 | cut -d' ' -f1)
echo "SHA256: $SHA256"
```

### Formula 수동 업데이트

`homebrew-sshift` 저장소의 `sshift.rb` 파일을 수동으로 업데이트:

```ruby
version "1.0.0"
sha256 "계산된_SHA256_해시"
url "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.0.tar.gz"
```

## 🧪 테스트

### 로컬 Formula 테스트

```bash
# Formula 다운로드
git clone https://github.com/takealook97/homebrew-sshift.git
cd homebrew-sshift

# 로컬에서 설치 테스트
brew install --build-from-source ./sshift.rb

# 설치 확인
sshift version
```

### Homebrew 검증

```bash
# Formula 검증
brew audit --strict sshift

# 설치 테스트
brew install sshift
brew test sshift
```

## 🔍 문제 해결

### 일반적인 문제들

1. **SHA256 불일치**

   ```bash
   # SHA256 재계산
   curl -sL "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.0.tar.gz" | shasum -a 256
   ```

2. **권한 오류**

   - Personal Access Token 권한 확인
   - `repo` 및 `workflow` 권한 필요

3. **빌드 실패**

   ```bash
   # Go 버전 확인
   go version

   # 의존성 설치
   brew install go
   ```

### 디버깅

```bash
# 상세 설치 로그
brew install -v sshift

# Formula 정보 확인
brew info sshift

# 설치된 파일 확인
brew list sshift
```

## 📝 체크리스트

- [ ] GitHub Personal Access Token 생성
- [ ] `homebrew-sshift` 저장소 생성
- [ ] 초기 Formula 파일 추가
- [ ] GitHub Secrets 설정
- [ ] GitHub Actions 워크플로우 확인
- [ ] 릴리즈 태그 생성
- [ ] GitHub Release 생성
- [ ] 자동 배포 확인
- [ ] 설치 테스트
- [ ] 문서 업데이트

## 🔗 유용한 링크

- [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Homebrew Tap](https://docs.brew.sh/Taps)
- [GitHub Actions](https://docs.github.com/en/actions)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github)

---

이제 사용자들이 `brew install takealook97/sshift/sshift` 명령으로 SSHift를 쉽게 설치할 수 있습니다! 🎉
