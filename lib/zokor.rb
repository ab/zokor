require 'openssl'

require_relative 'zokor/version'
require_relative 'zokor/logger'

require_relative 'zokor/config'
require_relative 'zokor/proxy_connection'
require_relative 'zokor/proxy_magic'

module Zokor
  unless defined?(self::SafeOpenSSLSettings)
    SafeOpenSSLSettings = true
    OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] |= OpenSSL::SSL::OP_NO_COMPRESSION
    OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] |= OpenSSL::SSL::OP_NO_SSLv2
    OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] |= OpenSSL::SSL::OP_NO_SSLv3
    OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers] = 'HIGH:!TLSv1:!SSLv3:!aNULL:!eNULL'
  end
end
