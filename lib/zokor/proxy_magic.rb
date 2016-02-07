require 'socket'

# TODO: not sure if this is desirable
Thread.abort_on_exception = true

module Zokor
  class ProxyMagic
    attr_reader :server, :remote_host, :remote_port, :opts

    def initialize(local_host, local_port, remote_host, remote_port, opts={})
      @remote_host = remote_host
      @remote_port = remote_port

      @opts = opts

      @server = serve(local_host, local_port)

      if @opts[:proxy_url]
        log.info "Intermediate proxy: #{@opts.fetch(:proxy_url)}"
      else
        log.info "Intermediate proxy: none"
      end

      if @opts[:use_ssl]
        ssl_msg = '[SSL]'
      else
        ssl_msg = '[no SSL]'
      end

      log.info "External proxy: #{ssl_msg} #{remote_host}:#{remote_port}"
    end

    def serve(local_host, local_port)
      server = TCPServer.open(local_host, local_port)

      port = server.addr[1]
      addrs = server.addr[2..-1].uniq
      log.info "Listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"
      server
    end

    def run_loop
      log.info "Starting main loop..."

      # Add thread to process Ctrl-C on Windows
      _sleep_thread = Thread.new { loop { sleep 1 } }

      @threads = []

      while true
        @threads.select!(&:alive?)
        log.debug "#{@threads.length} open connections" unless @threads.empty?
        @threads << Thread.start(server.accept) {|sock|
          c = Zokor::ProxyConnection.new(sock, remote_host, remote_port, opts)
          c.connect
        }
      end
    end

    def log
      @log ||= Zokor::ProgLogger.new('zokor')
    end
  end
end

