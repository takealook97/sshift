class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "1.0.1"
  license "MIT"
  
  # Go source code
  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.1.tar.gz"
  sha256 "08f4abc7c449d079a8715d5a3289c6077935ffa17c29ad2bc8e267672d5cf631"
  
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