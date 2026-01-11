class Grincel < Formula
  desc "Solana vanity address grinder with Metal/Vulkan GPU acceleration"
  homepage "https://github.com/binoculars/grincel.gpu"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v0.1.0/grincel-macos-arm64-v0.1.0.tar.gz"
      sha256 "PLACEHOLDER_MACOS_ARM64" # macos-arm64
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v0.1.0/grincel-linux-arm64-v0.1.0.tar.gz"
      sha256 "PLACEHOLDER_LINUX_ARM64" # linux-arm64
    end
    on_intel do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v0.1.0/grincel-linux-amd64-v0.1.0.tar.gz"
      sha256 "PLACEHOLDER_LINUX_AMD64" # linux-amd64
    end
  end

  depends_on "molten-vk" if OS.mac?

  def install
    bin.install "grincel"
  end

  test do
    assert_match "Solana vanity address grinder", shell_output("#{bin}/grincel --help")
  end
end
