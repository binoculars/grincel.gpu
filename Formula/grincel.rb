class Grincel < Formula
  desc "Solana vanity address grinder with Metal/Vulkan GPU acceleration"
  homepage "https://github.com/binoculars/grincel.gpu"
  version "1.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.4.0/grincel-macos-arm64-v1.4.0.tar.gz"
      sha256 "09bbefcd03459ba07ae2693918ac5104a37c7bc7692978d2c274d6881e513983" # macos-arm64
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.4.0/grincel-linux-arm64-v1.4.0.tar.gz"
      sha256 "60b2acb6665842c32ce8d63fde8356c1a32f64ae00b1ae405bc9dc635be49053" # linux-arm64
    end
    on_intel do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.4.0/grincel-linux-amd64-v1.4.0.tar.gz"
      sha256 "7ca650418b73f919792e1dae3cc4067cc825a37ffd4c90a1343a7efe420679e3" # linux-amd64
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
