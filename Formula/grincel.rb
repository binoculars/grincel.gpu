class Grincel < Formula
  desc "Solana vanity address grinder with Metal/Vulkan GPU acceleration"
  homepage "https://github.com/binoculars/grincel.gpu"
  version "1.4.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.4.1/grincel-macos-arm64-v1.4.1.tar.gz"
      sha256 "a3e58bc05798b1aed5da8c4ced2be0fe0e8f2570b2ccedb530ed95868c6b9297" # macos-arm64
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.4.1/grincel-linux-arm64-v1.4.1.tar.gz"
      sha256 "153760ac1a86cbf38ba3af363daed0b6f04a678dd55216930209ee1032681de0" # linux-arm64
    end
    on_intel do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.4.1/grincel-linux-amd64-v1.4.1.tar.gz"
      sha256 "8e11637362d6bdcfac90a1515af86f27659de83b467fa07ec581abef7de2b53f" # linux-amd64
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
