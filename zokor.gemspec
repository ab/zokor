# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'zokor/version'

Gem::Specification.new do |spec|
  spec.name          = 'zokor'
  spec.version       = Zokor::VERSION
  spec.authors       = ['Andy Brody']
  spec.email         = ['git@abrody.com']
  spec.summary       = 'Nested HTTP proxy tunnel tool'
  spec.description   = <<-EOM
    Zokor is an HTTP proxy tunnelling tool that collapses multiple HTTP proxies
    into one. It's useful when you want to send traffic through a chain of two
    HTTP proxies where the first supports the CONNECT verb.

    Zokor presents a local server that transparently tunnels packets through
    the first proxy as though clients were directly connected to the second
    proxy. It optionally uses TLS to connect to the second proxy.
  EOM
  spec.homepage      = 'https://github.com/ab/zokor'
  spec.license       = 'GPL-3'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'proxifier', '~> 1.0'
  spec.add_dependency 'subprocess', '~> 1.2'

  spec.add_development_dependency 'bundler', '~> 1.3'
  spec.add_development_dependency 'pry'
  spec.add_development_dependency 'rake'
  # spec.add_development_dependency 'rspec', '~> 3.0'
  # spec.add_development_dependency 'rubocop', '~> 0'
  spec.add_development_dependency 'yard'

  spec.required_ruby_version = '>= 2.0'
end
