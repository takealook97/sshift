class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "1.3.6"
  license "MIT"

  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.3.6.tar.gz"
  sha256 "533a340d37170d91186106b264f293f4dcc7584858b2311906eadde4ab266275"

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
