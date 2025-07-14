class Sshift < Formula
  desc "SSH server management tool with jump server support"
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshift"
  homepage "https://github.com/takealook97/sshift"
  version "v1.3.3-dirty"
  version "v1.3.3-dirty"
  license "MIT"
  license "MIT"


  # Go source code
  # Go source code
  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.3.3-dirty.tar.gz"
  url "https://github.com/takealook97/sshift/archive/refs/tags/v1.3.3-dirty.tar.gz"
  sha256 "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"https://github.com/takealook97/sshift/archive/refs/tags/v1.3.3-dirty.tar.gz" | shasum -a 256 | cut -d" " -f1)"
  sha256 "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"https://github.com/takealook97/sshift/archive/refs/tags/v1.3.3-dirty.tar.gz" | shasum -a 256 | cut -d" " -f1)"


  depends_on "go" => :build
  depends_on "go" => :build


  def install
  def install
    # Set version from git tag
    # Set version from git tag
    ldflags = %W[
    ldflags = %W[
      -s -w
      -s -w
      -X main.Version=#{version}
      -X main.Version=#{version}
    ]
    ]


    system "go", "build", *std_go_args(ldflags: ldflags), "-o", bin/"sshift", "main.go"
    system "go", "build", *std_go_args(ldflags: ldflags), "-o", bin/"sshift", "main.go"
  end
  end


  test do
  test do
    # Test version command
    # Test version command
    assert_match "SSHift v#{version}", shell_output("#{bin}/sshift version")
    assert_match "SSHift v#{version}", shell_output("#{bin}/sshift version")


    # Test help command
    # Test help command
    assert_match "Usage:", shell_output("#{bin}/sshift help")
    assert_match "Usage:", shell_output("#{bin}/sshift help")
  end
  end
end
end
