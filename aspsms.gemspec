# vim: set et ts=2 sw=2 ft=ruby:
spec = Gem::Specification.new do |s|
  s.name = 'aspsms'
  s.version = '0.99'
  s.date = '2015-01-18'
  s.homepage = 'http://www.roe.ch/ASPSMS'
  s.authors = [ 'Daniel Roethlisberger' ]
  s.email = 'daniel@roe.ch'
  s.summary = 'aspsms.com SMS gateway library and client'
  s.description = 'aspsms.com SMS gateway library and client'
  s.files = [
    'README',
    'LICENSE',
    'lib/aspsms.rb',
    'bin/aspsms',
  ]
  s.executables = [ 'aspsms' ]
  s.required_ruby_version = '>= 1.9'
end
