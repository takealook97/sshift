class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "1.3.2"
  license "MIT"
  
  # Go source code
  url "https://github.com/takealook97/sshift/archive/refs/tags/v#{version}.tar.gz"
  sha256 "8230ddfef1bf93161599605f650392badb0013cb22570f2bf807679daf3391e1"
  
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