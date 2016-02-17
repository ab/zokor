require 'etc'
require 'fileutils'
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
      ret = YAML.load_file(filename)
      log.info("Read config from #{filename.inspect}")
      ret
    end

    def config_yaml_file
      config_file('zokor.yaml')
    end

    def config_file(name)
      File.join(config_dir, name)
    end

    def interactive_install_cert(filename='client.crt')
      path = config_file(filename)
      log.debug('Will install certificate to ' + path.inspect)
      puts 'Please paste your certificate now from -----BEGIN CERTIFICATE-----'

      cert_data = ''

      in_cert = false
      while line = STDIN.gets
        next if line.strip.empty?

        # check for begin marker
        if !in_cert
          if line.strip == '-----BEGIN CERTIFICATE-----'
            in_cert = true
          else
            log.warn "Certificate should start with: -----BEGIN CERTIFICATE-----"
            return false
          end
        end

        cert_data << line

        # end
        break if line.strip == '-----END CERTIFICATE-----'
      end

      File.open(path, File::WRONLY|File::CREAT|File::EXCL, 0644) do |f|
        f.write(cert_data)
      end

      log.info("Saved certificate to #{path.inspect}")

      path
    end

    def interactive_init(opts)
      unless opts[:remote_host]
        log.error('Please pass --ext-host')
        return false
      end
      unless opts[:remote_port]
        log.error('Please pass --ext-port')
        return false
      end

      init_config(opts.fetch(:remote_host), opts.fetch(:remote_port))
    end

    def init_config(remote_host, remote_port,
                    local_host: '127.0.0.1', local_port: 8080)
      unless Dir.exist?(config_dir)
        log.info("mkdir #{config_dir}")
        FileUtils.mkdir_p(config_dir)
      end

      path = config_yaml_file

      if File.exist?(path)
        log.warn('Config file already exists: ' + path)
        return false
      end

      data = {
        use_ssl: true,
        ssl_opts: {
          ca_file: :builtin,
          cert_file: config_file('client.crt'),
          key_file: config_file('client.key'),
        },
        local_host: local_host,
        local_port: local_port,
        remote_host: remote_host,
        remote_port: remote_port,
      }

      log.info('Initializing config: ' + YAML.dump(data))

      File.write(path, YAML.dump(data))

      create_client_keypair(config_file('client.key'),
                            config_file('client.csr'))
    end

    # @param key_file [String] Key filename
    # @param csr_file [String] CSR filename
    def create_client_keypair(key_file, csr_file)
      log.info('Generating SSL/TLS key and certificate request')

      key = generate_rsa_key
      File.open(key_file, File::WRONLY|File::CREAT|File::EXCL, 0600) do |f|
        f.write(key.to_s)
      end

      log.info("Wrote key to #{key_file.inspect}")

      csr = generate_csr(key, user_address)
      csr.to_s

      File.write(csr_file, csr.to_s)

      log.info("Wrote request to #{csr_file.inspect}")

      log.warn('Certificate request follows:')

      puts csr.to_s

      log.warn('Please send the above certificate request.')

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
        ['CN', common_name,               OpenSSL::ASN1::UTF8STRING],
        # ['emailAddress', options[:email], OpenSSL::ASN1::UTF8STRING]
      ])

      request.public_key = key.public_key
      request.sign(key, OpenSSL::Digest::SHA256.new)

      request
    end

    def user_address
      "#{Etc.getlogin}@#{Socket.gethostname}"
    end

    def log
      @log ||= Zokor::ProgLogger.new('config')
    end
  end
end
