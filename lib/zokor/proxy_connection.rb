require 'openssl'
require 'socket'

require 'proxifier'

module Zokor
  class ProxyConnection
    BlockSize = 1024 * 4

    def initialize(local_socket, remote_host, remote_port, opts={})
      @proxy_url = opts[:proxy_url]
      @use_ssl = opts[:use_ssl]

      @local_socket = local_socket
      @remote_host = remote_host
      @remote_port = remote_port

      log.info('new local connection')
    end

    def connect

      local = @local_socket

      # open connection to remote server
      remote = create_outbound_tcp_socket

      # SSL remote main loop
      loop do
        log.debug('IO.select()')
        read_set = [local, remote]
        if remote.is_a?(OpenSSL::SSL::SSLSocket)
          # TODO: determine whether this is needed
          read_set << remote.io
        end

        rd_ready, _, _ = IO.select(read_set, nil, nil, 2)

        if rd_ready.nil?
          # log.chunder('TIMEOUT')
          # require 'pry'; binding.pry # XXX
          next
        end

        # log.chunder('read ready: ' + rd_ready.inspect)
        # require 'pry'; binding.pry

        if rd_ready.include?(local)
          data = local.recv(BlockSize)
          if data.empty?
            log.info('Local end closed connection')
            return
          end
          log.debug("=> #{data.length} bytes to remote")
          socket_write(remote, data)
          log.chunder('writen')
        end
        if rd_ready.include?(remote)
          while true
            data = socket_read(remote, BlockSize)
            if data.empty?
              log.info('Remote end closed connection')
              return
            end
            log.debug("<= #{data.length} bytes from remote")
            local.write(data)
            log.chunder('written')

            if data.length < BlockSize
              log.chunder("data.length < blocksize, done")
              break
            else
              log.chunder("data.length >= blocksize, continuing")
            end
          end
        end
      end

    rescue Errno::ECONNRESET, Errno::ENETUNREACH, Errno::EPIPE, EOFError => err
      log.warn(err.inspect)

    ensure
      local.close if local && !local.closed?
      remote.close if remote && !remote.closed?

      log.info('Connection closed')
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
        log.info("Connecting to #{label} through proxy #{@proxy_url}")
        @proxy = Proxifier::Proxy(@proxy_url)
        tcp_socket = @proxy.open(@remote_host, @remote_port)
      else
        log.info("Connecting to #{label}")
        tcp_socket = TCPSocket.new(@remote_host, @remote_port)
      end

      if @use_ssl
        create_ssl_socket(tcp_socket)
      else
        tcp_socket
      end
    end

    def create_ssl_socket(tcp_socket)
      log.info('Beginning SSL handshake')
      ssl_context = OpenSSL::SSL::SSLContext.new()
      # ssl_context.cert = OpenSSL::X509::Certificate.new(File.open("client.crt"))
      # ssl_context.key = OpenSSL::PKey::RSA.new(File.open("client.key"))
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      ssl_context.ca_file = '/home/andy/gov/dhs/proxy/tls.crt' # TODO XXX DEBUG
      ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
      ssl_socket.sync_close = true

      begin
        ssl_socket.connect
      rescue StandardError => err
        log.warn(err.message)
        raise
      end

      log.info('Connected!')

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
      log.chunder('ssl_socket_write')

      begin
        return ssl_socket.write_nonblock(data)
      rescue IO::WaitReadable
        log.chunder('WaitReadable') # XXX
        IO.select([ssl_socket.io])
        log.chunder('WaitReadable retry') # XXX
        retry
      rescue IO::WaitWritable
        log.chunder('WaitWritable') # XXX
        IO.select(nil, [ssl_socket.io])
        log.chunder('WaitWritable retry') # XXX
        retry
      end
    ensure
      log.chunder('done ssl_socket_write')
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
      log.chunder('ssl_socket_read')

      begin
        return ssl_socket.read_nonblock(bytes)
      rescue IO::WaitReadable
        log.chunder('WaitReadable') # XXX
        IO.select([ssl_socket.io])
        log.chunder('WaitReadable retry') # XXX
        retry
      rescue IO::WaitWritable
        log.chunder('WaitWritable') # XXX
        IO.select(nil, [ssl_socket.io])
        log.chunder('WaitWritable retry') # XXX
        retry
      end

    ensure
      log.chunder('done ssl_socket_read')
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

    def log
      @log ||= Zokor::ProgLogger.new("<#{label}>")
    end
  end
end
