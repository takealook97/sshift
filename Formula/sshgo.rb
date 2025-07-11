class Sshgo < Formula
  desc "SSH server management tool with jump server support"
  homepage "https://github.com/takealook97/sshgo"
  version "1.0.0"
  
  # Replace with actual release URL when available
  url "https://github.com/takealook97/sshgo/releases/download/v1.0.0/sshgo-darwin-arm64"
  sha256 "your-sha256-hash-here"
  
  # Add other platforms as needed
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/takealook97/sshgo/releases/download/v1.0.0/sshgo-darwin-arm64"
      sha256 "your-sha256-hash-here"
    else
      url "https://github.com/takealook97/sshgo/releases/download/v1.0.0/sshgo-darwin-amd64"
      sha256 "your-sha256-hash-here"
    end
  end
  
  on_linux do
    url "https://github.com/takealook97/sshgo/releases/download/v1.0.0/sshgo-linux-amd64"
    sha256 "your-sha256-hash-here"
  end

  def install
    bin.install "sshgo"
  end

  test do
    system "#{bin}/sshgo", "version"
  end
end 