class Grincel < Formula
  desc "Solana vanity address grinder with Metal/Vulkan GPU acceleration"
  homepage "https://github.com/binoculars/grincel.gpu"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v0.2.0/grincel-macos-arm64-v0.2.0.tar.gz"
      sha256 "0dfed4b3e0a319f0ee506c3d568bf4571726e8ade23492c02051068d1e964ca6" # macos-arm64
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v0.2.0/grincel-linux-arm64-v0.2.0.tar.gz"
      sha256 "f829d2ab427bf7772e21196c4d2d22a15c5d3a887dfa181cc0052dedda944c2e" # linux-arm64
    end
    on_intel do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v0.2.0/grincel-linux-amd64-v0.2.0.tar.gz"
      sha256 "158389cd1fb40fe9ec67f1a6515238c7ec0bc9a4ec6c81f0593076700f002bbd" # linux-amd64
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
