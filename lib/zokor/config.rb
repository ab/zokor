require 'etc'
require 'openssl'
require 'socket'
require 'yaml'

module Zokor
  class Config
    DEFAULT_CONFIG_DIR = File.join(File.expand_path('~'), '.config', 'zokor')

    attr_reader :config_dir

    # @param config_dir [String] (DEFAULT_CONFIG_DIR)
    def initialize(config_dir=nil)
      @config_dir = config_dir || DEFAULT_CONFIG_DIR
    end

    def load_config(filename=nil)
      filename ||= config_yaml_file
      YAML.load_file(filename)
    end

    def config_yaml_file
      config_file('zokor.yaml')
    end

    def config_file(name)
      File.join(config_dir, name)
    end

    def init_config(remote_host, remote_port, local_port=8080)
      FileUtils.mkdir_p(config_dir)

      path = config_yaml_file

      if File.exist?(path)
        warn('Config file already exists: ' + path)
        return false
      end

      data = {
        use_ssl: true,
        ca_file: :builtin,
        cert: config_file('client.crt'),
        key: config_file('client.key'),
        local_host: '127.0.0.1',
        local_port: local_port,
        remote_host: remote_host,
        remote_port: remote_port,
      }

      File.write(path, YAML.dump(data))
    end

    def create_client_keypair
      key = generate_rsa_key
      File.open(config_file('client.key'), 'w', 0600) do |f|
        f.write(key.to_s)
      end

      csr = generate_csr(key, subject)
      csr.to_s

      File.write(config_file('client.csr'), csr.to_s)

      puts csr.to_s
      puts "Send the above certificate request"

      return true
    end

    private

    def generate_rsa_key(bits=2048)
      OpenSSL::PKey::RSA.generate(bits)
    end

    def generate_csr(key, common_name)
      request = OpenSSL::X509::Request.new
      request.version = 0


      # don't bother including much of anything in the subject
      request.subject = OpenSSL::X509::Name.new([
        # ['C',  options[:country],         OpenSSL::ASN1::PRINTABLESTRING],
        # ['ST', options[:state],           OpenSSL::ASN1::UTF8STRING],
        # ['L',  options[:city],            OpenSSL::ASN1::UTF8STRING],
        # ['O',  options[:organization],    OpenSSL::ASN1::UTF8STRING],
        # ['OU', options[:department],      OpenSSL::ASN1::UTF8STRING],
        ['CN', user_address,              OpenSSL::ASN1::UTF8STRING],
        # ['emailAddress', options[:email], OpenSSL::ASN1::UTF8STRING]
      ])

      request.public_key = key.public_key
      request.sign(key, OpenSSL::Digest::SHA256.new)

      request
    end

    def user_address
      "#{Etc.getlogin}@#{Socket.gethostname}"
    end
  end
end
