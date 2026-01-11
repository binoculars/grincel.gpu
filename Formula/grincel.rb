class Grincel < Formula
  desc "Solana vanity address grinder with Metal/Vulkan GPU acceleration"
  homepage "https://github.com/binoculars/grincel.gpu"
  version "1.2.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.2.2/grincel-macos-arm64-v1.2.2.tar.gz"
      sha256 "bcda37d24813d705b6b064206e3edb37410e53a5166c0ddd47fd97925d7ea6b6" # macos-arm64
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.2.2/grincel-linux-arm64-v1.2.2.tar.gz"
      sha256 "6c4fa9c61eabb1c56256933a2e4e9f061f6eaf2df75110469e15608ef54d5e6d" # linux-arm64
    end
    on_intel do
      url "https://github.com/binoculars/grincel.gpu/releases/download/v1.2.2/grincel-linux-amd64-v1.2.2.tar.gz"
      sha256 "d13784be9b136ba2e665dcbb978ff80a001600c4870ad50b0bab6eadf40cc720" # linux-amd64
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
