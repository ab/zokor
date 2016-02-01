#!/usr/bin/env ruby
$VERBOSE = true # enable warnings

require 'openssl'
require 'socket'
require 'uri'

require 'proxifier'

# TODO: not sure if this is desirable
# Thread.abort_on_exception = true

unless defined?(SafeOpenSSLSettings)
  SafeOpenSSLSettings = true
  OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] |= OpenSSL::SSL::OP_NO_COMPRESSION
  OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] |= OpenSSL::SSL::OP_NO_SSLv2
  OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:options] |= OpenSSL::SSL::OP_NO_SSLv3
  OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers] = 'HIGH:!TLSv1:!SSLv3:!aNULL:!eNULL'
end

class ProxyMagic; end

class ProxyMagic::Connection
  BlockSize = 1024 * 4

  LOG_LEVEL = 1
  LOG_CHUNDER = false

  def initialize(local_socket, remote_host, remote_port, opts={})
    @proxy_url = opts[:proxy_url]
    @use_ssl = opts[:use_ssl]

    @local_socket = local_socket
    @remote_host = remote_host
    @remote_port = remote_port

    log('new local connection')
  end

  def connect

    local = @local_socket

    # open connection to remote server
    remote = create_outbound_tcp_socket

    # SSL remote main loop
    loop do
      log_debug('IO.select()')
      read_set = [local, remote]
      if remote.is_a?(OpenSSL::SSL::SSLSocket)
        # TODO: determine whether this is needed
        read_set << remote.io
      end

      rd_ready, _, _ = IO.select(read_set, nil, nil, 2)

      if rd_ready.nil?
        # log_DEBUG('TIMEOUT')
        # require 'pry'; binding.pry # XXX
        next
      end

      # log_DEBUG('read ready: ' + rd_ready.inspect)
      # require 'pry'; binding.pry

      if rd_ready.include?(local)
        data = local.recv(BlockSize)
        if data.empty?
          log('Local end closed connection')
          return
        end
        log_debug("=> #{data.length} bytes to remote")
        socket_write(remote, data)
        log_DEBUG('writen')
      end
      if rd_ready.include?(remote)
        while true
          data = socket_read(remote, BlockSize)
          if data.empty?
            log('Remote end closed connection')
            return
          end
          log_debug("<= #{data.length} bytes from remote")
          local.write(data)
          log_DEBUG('written')

          if data.length < BlockSize
            log_DEBUG("data.length < blocksize, done")
            break
          else
            log_DEBUG("data.length >= blocksize, continuing")
          end
        end
      end
    end

  rescue Errno::ECONNRESET, Errno::ENETUNREACH, Errno::EPIPE, EOFError => err
    log(err.inspect)

  ensure
    local.close if local && !local.closed?
    remote.close if remote && !remote.closed?

    log('Connection closed')
  end

  def to_s
    "<#{self.class.name} to #{label}>"
  end

  private

  # Initiate a TCP connection to our configured remote host.
  #
  # If @proxy_url is set, create a fake connection object that goes
  # through the proxy.
  #
  # If @use_ssl is set, open an SSL socket on this connection.
  #
  # @return [TCPSocket, OpenSSL::SSL::SSLSocket]
  #
  def create_outbound_tcp_socket
    label = "#{@remote_host}:#{@remote_port}"
    if @proxy_url
      log("Connecting to #{label} through proxy #{@proxy_url}")
      @proxy = Proxifier::Proxy(@proxy_url)
      tcp_socket = @proxy.open(@remote_host, @remote_port)
    else
      log("Connecting to #{label}")
      tcp_socket = TCPSocket.new(@remote_host, @remote_port)
    end

    if @use_ssl
      create_ssl_socket(tcp_socket)
    else
      tcp_socket
    end
  end

  def create_ssl_socket(tcp_socket)
    log('Beginning SSL handshake')
    ssl_context = OpenSSL::SSL::SSLContext.new()
    # ssl_context.cert = OpenSSL::X509::Certificate.new(File.open("client.crt"))
    # ssl_context.key = OpenSSL::PKey::RSA.new(File.open("client.key"))
    ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
    ssl_context.ca_file = '/home/andy/gov/dhs/proxy/tls.crt' # TODO XXX DEBUG
    ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
    ssl_socket.sync_close = true
    ssl_socket.connect
    log('Connected!')

    ssl_socket
  end

  # Abstract over SSL and TCP socket read().
  #
  # @param [TCPSocket, OpenSSL::SSL::SSLSocket] socket
  # @param [Integer] bytes
  #
  # @return [String] data
  #
  def socket_read(socket, bytes, until_blocked=false)
    case socket
    when TCPSocket
      socket.recv(bytes)
    when OpenSSL::SSL::SSLSocket
      ssl_socket_read(socket, bytes)
    else
      raise ArgumentError.new("Unexpected socket type: #{socket.inspect}")
    end
  end

  # Abstract over SSL ant TCP socket write().
  #
  # @param [TCPSocket, OpenSSL::SSL::SSLSocket] socket
  # @param [String] data
  #
  # @return [Integer] bytes written
  #
  def socket_write(socket, data)
    case socket
    when TCPSocket
      socket.write(data)
    when OpenSSL::SSL::SSLSocket
      ssl_socket_write(socket, data)
    else
      raise ArgumentError.new("Unexpected socket type: #{socket.inspect}")
    end
  end

  # Write in a blocking fashion to the given SSLSocket.
  # This handles the appropriate subtleties of waiting for necessary
  # reads/writes with the underlying IO, which makes a simple IO.select and
  # normal blocking write impossible.
  # https://bugs.ruby-lang.org/issues/8875
  #
  # @param [OpenSSL::SSL::SSLSocket] ssl_socket
  # @param [String] data
  #
  # @return [Integer] number of bytes written
  #
  # @see [OpenSSL::Buffering#write_nonblock]
  #
  def ssl_socket_write(ssl_socket, data)
    log_DEBUG('ssl_socket_write')

    begin
      return ssl_socket.write_nonblock(data)
    rescue IO::WaitReadable
      log_DEBUG('WaitReadable') # XXX
      IO.select([ssl_socket.io])
      log_DEBUG('WaitReadable retry') # XXX
      retry
    rescue IO::WaitWritable
      log_DEBUG('WaitWritable') # XXX
      IO.select(nil, [ssl_socket.io])
      log_DEBUG('WaitWritable retry') # XXX
      retry
    end
  ensure
    log_DEBUG('done ssl_socket_write')
  end
  #
  # Read in a blocking fashion from the given SSLSocket.
  # This handles the appropriate subtleties of waiting for necessary
  # reads/writes with the underlying IO, which makes a simple IO.select and
  # normal blocking read impossible.
  # https://bugs.ruby-lang.org/issues/8875
  #
  # @param [OpenSSL::SSL::SSLSocket] ssl_socket
  # @param [Integer] bytes Maximum number of bytes to read
  #
  # @return [String] data read
  #
  # @see [OpenSSL::Buffering#write_nonblock]
  #
  def ssl_socket_read(ssl_socket, bytes)
    log_DEBUG('ssl_socket_read')

    begin
      return ssl_socket.read_nonblock(bytes)
    rescue IO::WaitReadable
      log_DEBUG('WaitReadable') # XXX
      IO.select([ssl_socket.io])
      log_DEBUG('WaitReadable retry') # XXX
      retry
    rescue IO::WaitWritable
      log_DEBUG('WaitWritable') # XXX
      IO.select(nil, [ssl_socket.io])
      log_DEBUG('WaitWritable retry') # XXX
      retry
    end

  ensure
    log_DEBUG('done ssl_socket_read')
  end

  def default_cert_store
    store = OpenSSL::X509::Store.new
    store.set_default_paths

    # TODO: handle windows

  end

  def label
    @label ||= label!
  end
  def label!
    port, name = @local_socket.peeraddr[1..2]
    "#{name}:#{port}"
  end

  def log(text)
    puts "*** [#{label}] #{text}"
  end

  def log_debug(text)
    log("DEBUG " + text) if LOG_LEVEL <= 0
  end

  def log_DEBUG(text)
    log_debug(text) if LOG_CHUNDER
  end
end

class ProxyMagic
  VERSION = '0.0.2'

  def self.usage
    STDERR.puts <<-EOM
usage: #{File.basename($0)} LOCAL_PORT TARGET_HOST TARGET_PORT [PROXY_URL]

Version: #{VERSION}
    EOM
  end

  attr_reader :server, :remote_host, :remote_port, :opts

  def initialize(local_host, local_port, remote_host, remote_port, opts={})
    @remote_host = remote_host
    @remote_port = remote_port

    @opts = opts

    @server = serve(local_host, local_port)

    if @opts[:proxy_url]
      puts "*** Will proxy through #{@opts.fetch(:proxy_url)}"
    end
  end

  def serve(local_host, local_port)
    server = TCPServer.open(local_host, local_port)

    port = server.addr[1]
    addrs = server.addr[2..-1].uniq
    puts "*** Listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"

    server
  end

  def run_loop
    puts "*** Starting main loop"

    # Add thread to process Ctrl-C on Windows
    _sleep_thread = Thread.new { loop { sleep 1 } }

    @threads = []

    while true
      @threads.select!(&:alive?)
      puts "*** #{@threads.length} open connections" unless @threads.empty?
      @threads << Thread.start(server.accept) {|sock|
        c = ProxyMagic::Connection.new(sock, remote_host, remote_port, opts)
        c.connect
      }
    end
  end
end

def parse_args(args)
  # TODO: use optparse
  options = {}
  if args.delete('--ssl')
    options[:use_ssl] = true
  end

  if args.length < 3
    ProxyMagic.usage
    exit 1
  end

  begin
    local_host = '127.0.0.1'
    local_port = Integer(args.fetch(0))
    remote_host = args.fetch(1)
    remote_port = Integer(args.fetch(2))
    options[:proxy_url] = args[3] if args[3]
  rescue IndexError, ArgumentError
    ProxyMagic.usage
    exit 1
  end

  pm = ProxyMagic.new(local_host, local_port, remote_host, remote_port,
                      options)
  pm.run_loop
end

if $0 == __FILE__
  parse_args(ARGV.dup)
end
