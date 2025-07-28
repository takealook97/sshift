class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "2.0.0"
  license "MIT"

  url "https://github.com/takealook97/sshift/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "c31f9eae7c0cf7dd82155630b20515db90134ad7f2251e0201d31e043e9fd44e"

  depends_on "go" => :build

  def install
    # Set version from git tag
    ldflags = %W[
      -s -w
      -X main.Version=#{version}
    ]
    
    system "go", "build", *std_go_args(ldflags: ldflags), "-o", bin/"sshift", "main.go"
  end

  test do
    # Test version command
    assert_match "SSHift v#{version}", shell_output("#{bin}/sshift version")
    
    # Test help command
    assert_match "Usage:", shell_output("#{bin}/sshift help")
  end
end
