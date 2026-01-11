class Grincel < Formula
  desc "Solana vanity address grinder with Metal/Vulkan GPU acceleration"
  homepage "https://github.com/binoculars/grincel.gpu"
  version "1.2.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.2.1/grincel-macos-arm64-v1.2.1.tar.gz"
      sha256 "8ec7a7f2ba9f6e176fe2ef880858e312fac76f342a8decbffed198963586f576" # macos-arm64
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.2.1/grincel-linux-arm64-v1.2.1.tar.gz"
      sha256 "51f2de765774d5f2b2b50200df397fc2a2c203b5b3348659e8b5845e38b65209" # linux-arm64
    end
    on_intel do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.2.1/grincel-linux-amd64-v1.2.1.tar.gz"
      sha256 "29217d851d3d27e6f6dc4c3bc5de57e505f5865f4885f722e8bc22781cf4ce5f" # linux-amd64
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
