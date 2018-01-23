DNSCW = '../dnscrypt-wrapper'
ESVERSION = {"xsalsa20" => "\0\1", "xchacha20" => "\0\2"}

def cleanup()
  %w{secret.key public.key 1.key 1.cert}.each do |f|
    begin
      File.delete(f)
    rescue
    end
  end
end

Before do
  cleanup
end

After do
  cleanup
end


Given /^a provider keypair$/ do
  str = DNSCW + " --gen-provider-keypair --provider-name=2.dnscrypt-cert.example.org --ext-address=127.0.0.1"
  `#{str}`
end

And /^a time limited secret key$/ do
  str = DNSCW + " --gen-crypt-keypair --crypt-secretkey-file=1.key"
  `#{str}`
end

When /^a (\w+) cert is generated$/ do |type|
  arg = if type == "xchacha20" then "-x" else "" end
  str = DNSCW + " --gen-cert-file --crypt-secretkey-file=1.key " +
    "--provider-cert-file=1.cert --provider-publickey-file=public.key " +
    "--provider-secretkey-file=secret.key --cert-file-expire-days=365 " + arg
  `#{str}`
end

Then /^it is a (\w+) cert$/ do |type|
  cert = open("1.cert").read()
  expect(cert[4..5]).to eq(ESVERSION[type])
end
