#!/usr/bin/env ruby
require 'uri'
require 'webrick'
require 'webrick/httpproxy'

def usage
  STDERR.puts <<-EOM
usage: #{File.basename($0)} PORT [PROXY_URL]
  EOM
end

def serve(port, proxy_url=nil)
  puts 'Starting up double proxy server!'

  puts "Listening on port #{port.inspect}"
  opts = {Port: port}

  if proxy_url
    puts "Forwarding through proxy #{proxy_url.inspect}"
    opts[:ProxyURI] = URI.parse(proxy_url)
  end

  proxy = WEBrick::HTTPProxyServer.new(opts)

  Signal.trap('INT') { proxy.shutdown }
  Signal.trap('QUIT') { proxy.shutdown }
  Signal.trap('TERM') { proxy.shutdown }

  proxy.start
end

def main(args)
  begin
    port = args.fetch(0)
  rescue IndexError
    usage
    exit 1
  end

  begin
    port = Integer(port)
  rescue ArgumentError => err
    usage
    STDERR.puts err
    exit 1
  end

  proxy_url = args[1]
  if proxy_url && proxy_url.empty?
    proxy_url = nil
  end

  serve(port, proxy_url)
end

if $0 == __FILE__
  main(ARGV)
end
