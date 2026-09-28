class Grincel < Formula
  desc "Solana vanity address grinder with Metal/Vulkan GPU acceleration"
  homepage "https://github.com/binoculars/grincel.gpu"
  version "1.3.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.3.1/grincel-macos-arm64-v1.3.1.tar.gz"
      sha256 "19ff34461ece190d3453a743fd817eca22d535ecffddce9df537d050affde64a" # macos-arm64
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.3.1/grincel-linux-arm64-v1.3.1.tar.gz"
      sha256 "9793c261831c13334b053cd0f619e8057810a13ce33edae070f662fc0c3c4317" # linux-arm64
    end
    on_intel do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.3.1/grincel-linux-amd64-v1.3.1.tar.gz"
      sha256 "d79e278020d9c7fbefa736521cc459db117cfae1d419a8b74f9166d4619bb751" # linux-amd64
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
