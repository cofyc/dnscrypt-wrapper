require 'formula'

class DnscryptProxy < Formula
  homepage 'http://dnscrypt.org'
  url 'https://github.com/downloads/opendns/dnscrypt-proxy/dnscrypt-proxy-1.2.0.tar.gz'
  head 'https://github.com/opendns/dnscrypt-proxy.git', :branch => 'master'
  sha256 '02ae6360887995d73d4c02ea7fa0cc8cad4a4de61f89c2fd68674a65f427b333'

  if build.head?
    depends_on :automake
    depends_on :libtool
  end

  option "plugins", "Support plugins and install example plugins."

  def install
    system "autoreconf", "-if" if build.head?

    configure_args = [ "--prefix=#{prefix}", "--disable-dependency-tracking" ]
    if build.include? "plugins"
      configure_args << "--enable-plugins"
      configure_args << "--enable-plugins-root"
      configure_args << "--enable-relaxed-plugins-permissions"
    end
    system "./configure", *configure_args
    system "make install"
  end
end
