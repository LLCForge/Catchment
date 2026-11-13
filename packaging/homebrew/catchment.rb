# Homebrew formula for Catchment.
# Rendered by sync.py; @VERSION@ and the @SHA256_*@ values are filled in by the
# release workflow (job "publish", step "Render package-manager manifests") and
# shipped in catchment-<version>-package-manifests.tar.gz. Copy the rendered file
# into the tap repository (LLCForge/homebrew-tap, Formula/catchment.rb).
class Catchment < Formula
  desc "Anycast catchment prober: maps which PoP each vantage point lands in and detects shifts"
  homepage "https://github.com/LLCForge/Catchment"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/LLCForge/Catchment/releases/download/v@VERSION@/catchment-@VERSION@-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/LLCForge/Catchment/releases/download/v@VERSION@/catchment-@VERSION@-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/LLCForge/Catchment/releases/download/v@VERSION@/catchment-@VERSION@-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/LLCForge/Catchment/releases/download/v@VERSION@/catchment-@VERSION@-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_LINUX_MUSL@"
    end
  end

  def install
    bin.install "catchment"
    pkgetc.install "catchment.example.toml" if File.exist?("catchment.example.toml")
    doc.install Dir["README*.md"]
  end

  service do
    run [opt_bin/"catchment", "run", "--config", etc/"catchment/catchment.toml"]
    environment_variables STATE_DIRECTORY: var/"lib/catchment"
    keep_alive successful_exit: false
    log_path var/"log/catchment.log"
    error_log_path var/"log/catchment.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/catchment --version")
  end
end
