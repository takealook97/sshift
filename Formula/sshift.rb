class Sshift < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  version "1.0.1"
  license "MIT"
  
  # Go source code
  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.0.1.tar.gz"
  sha256 "0019dfc4b32d63c1392aa264aed2253c1e0c2fb09216f8e2cc269bbfb8bb49b5"
  
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