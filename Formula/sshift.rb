class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "1.3.4"
  license "MIT"

  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.3.4.tar.gz"
  sha256 "b2f0ab58b95af62b4a493b0f5c6ef9cc3876ad0aa5aea34114fcdc9325fdb835"

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
