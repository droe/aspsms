#!/usr/bin/env ruby
# vim: set et ts=2 sw=2:
#
# Ruby ASPSMS -- aspsms.com short message service gateway library and client
# http://www.roe.ch/ASPSMS
#
# Copyright (C) 2005-2011, Daniel Roethlisberger <daniel@roe.ch>
# All rights reserved.
#
# Redistribution and use, with or without modification, are permitted
# provided that the following conditions are met:
# 1. Redistributions must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 2. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This is both a ruby library and a command line client for painfree,
# UNIX-style interaction with the aspsms.com short message gateways.
#
# Written to conform with the ASPSMS XML Interface Specs 1.91, 2007-12-05.
# -   Support for text SMS, show credits, and originator unlocking/testing.
# -   Conforms to ASPSMS failure safety recommendations.
# -   Delivery status notification is supported by the low-level library
#     but not exposed in the easy API nor the command line client.
#
# Configuration is read from ~/.aspsms or [/usr/local]/etc/aspsms by default:
#   # ASPSMS configuration
#   # mandatory options:
#   userkey XYZXYZXYZXYZ
#   password y0UrPasSw0rD
#   # optional default originator:
#   originator +41XXXXXXXXX
#   # optional gateway override:
#   gateway othergateway:port
# Make sure to set sensible permissions (0600 is a good start).

require 'rexml/document'
require 'net/http'
require 'uri'
require 'iconv'

class String
  def is_phone_number?
    self.match(/^\+[0-9]{2,20}$/)
  end
end

module ASPSMS
  REVISION = '96'
  FILES = [ "#{ENV['HOME']}/.aspsms", '/etc/aspsms', '/usr/local/etc/aspsms' ]
  CHARSET = 'latin1'

  # Represents a configuration, file based or hash based.
  class Config
    def self.charset_from_environment
      ['LC_ALL', 'LC_CTYPE', 'LANG'].each do |key|
        if ENV.has_key?(key)
          return ENV[key].match(/\./) ? ENV[key].sub(/^.*\./, '') : CHARSET
        end
      end
      return CHARSET
    end

    @password, @userkey, @originator, @gateway, @charset = nil,nil,nil,nil,nil
    def initialize(confdata)
      if confdata.kind_of?(Hash)
        set(confdata)
      elsif confdata.kind_of?(String)
        load(confdata)
      else
        autoload
      end
      @charset = ASPSMS::Config.charset_from_environment
      if ENV.has_key?('http_proxy')
        uri = URI.parse(ENV['http_proxy'])
        user, pass = uri.userinfo.split(/:/) if uri.userinfo
        @http_class = Net::HTTP::Proxy(uri.host, uri.port, user, pass)
      else
        @http_class = Net::HTTP
      end
    end
    def autoload
      FILES.each do |fn|
        begin
          load(fn)
          return
        rescue Errno::ENOENT
          # ignore if not found
        end
        raise "No configuration file found (#{FILES.join(' ')})"
      end
    end
    def load(fn)
      conf = {}
      File.open(fn).each do |line|
        line.chomp.scan(/^\s*([a-zA-Z0-9]+)\s+([^\s#]+)/) do |k,v|
          case k.downcase
          when 'password'
            conf[:password] = v
          when 'userkey'
            conf[:userkey] = v
          when 'sender' # backwards compat
            conf[:originator] = v
          when 'originator'
            conf[:originator] = v
          when 'gateway'
            conf[:gateway] = v
          end
        end
      end
      set(conf)
    end
    def set(conf)
      @password   = conf[:password]   if conf.has_key?(:password)
      @userkey    = conf[:userkey]    if conf.has_key?(:userkey)
      @originator = conf[:originator] if conf.has_key?(:originator)
      @gateway    = conf[:gateway]    if conf.has_key?(:gateway)

      raise "#{fn}: 'userkey' missing!" if @userkey.nil?
      raise "#{fn}: 'password' missing!" if @password.nil?
      if !@gateway.nil? && !@gateway.match(/^[a-zA-Z0-9\[\]:._-]+:[0-9]{1,5}$/)
        raise "#{fn}: 'gateway' not in format 'host:port'!"
      end
    end
    def userkey
      @userkey
    end
    def password
      @password
    end
    def originator
      @originator.nil? ? 'aspsms' : @originator
    end
    def gateways
      if @gateway.nil?
        return [ 'xml1.aspsms.com:5061', 'xml2.aspsms.com:5098',
                 'xml1.aspsms.com:5098', 'xml2.aspsms.com:5061' ]
      else
        return [ @gateway ]
      end
    end
    def useragent
      "ASPSMS::Gateway/#{REVISION} (http://www.roe.ch/ASPSMS)"
    end
    def http_class
      @http_class
    end
    def utf8(str)
      unless @charset.match(/utf-?8/i)
        return Iconv::iconv('utf-8', @charset, str)[0]
      else
        return str
      end
    end
  end

  # Represents a request of specific types.
  # Handles construction of the request XML document.
  class Request
    class Abstract
      include REXML
      attr_accessor :userkey, :password
      def initialize(cfg)
        @cfg = cfg
        @userkey = @cfg.userkey
        @password = @cfg.password
      end
      def to_s
        doc = Document.new
        doc << REXML::XMLDecl.new('1.0', 'ISO-8859-1')
        root = Element.new('aspsms')
        root.elements.add(Element.new('Userkey').
                          add_text(@cfg.utf8(userkey)))
        root.elements.add(Element.new('Password').
                          add_text(@cfg.utf8(password)))
        each_element do |element|
          root.elements.add(element)
        end
        root.elements.add(Element.new('Action').
                          add_text(self.class.name.gsub(/^.*::/, '')))
        doc << root
        doc.to_s
      end
    end
    class SendTextSMS < Abstract
      attr_accessor :originator, :recipients, :text, :flashing, :blinking,
                    :tx_refs, :url_buffered, :url_nondelivery, :url_delivery
      def initialize(cfg)
        super(cfg)
        @originator = @cfg.originator
        @recipients = []
        @text = ''
        @flashing = false
        @blinking = false
        @tx_refs = []
        @url_buffered = ''
        @url_delivery = ''
        @url_nondelivery = ''
      end
      def each_element
        yield REXML::Element.new('Originator').add_text(@cfg.utf8(originator))
        @recipients = [ @recipients ] unless @recipients.kind_of?(Array)
        txr = @tx_refs.dup
        recipients.each do |recipient|
          rcpt = REXML::Element.new('Recipient')
          rcpt.elements.add(Element.new('PhoneNumber').
                            add_text(@cfg.utf8(recipient)))
          rcpt.elements.add(Element.new('TransRefNumber').
                            add_text(txr.shift)) unless txr.empty?
          yield rcpt
        end
        yield REXML::Element.new('MessageData').add_text(@cfg.utf8(text))
        yield REXML::Element.new('UsedCredits').add_text('1')
        yield REXML::Element.new('FlashingSMS').add_text('1') if flashing
        yield REXML::Element.new('BlinkingSMS').add_text('1') if blinking
        yield REXML::Element.new('URLBufferedMessageNotification').
            add_text(@cfg.utf8(url_buffered)) unless url_buffered.empty?
        yield REXML::Element.new('URLDeliveryNotification').
            add_text(@cfg.utf8(url_delivery)) unless url_delivery.empty?
        yield REXML::Element.new('URLNonDeliveryNotification').
            add_text(@cfg.utf8(url_nondelivery)) unless url_nondelivery.empty?
      end
    end
    class SendOriginatorUnlockCode < Abstract
      attr_accessor :originator
      def initialize(cfg)
        super(cfg)
        @originator = @cfg.originator
      end
      def each_element
        yield REXML::Element.new('Originator').add_text(@cfg.utf8(originator))
      end
    end
    class UnlockOriginator < Abstract
      attr_accessor :originator, :code
      def initialize(cfg)
        super(cfg)
        @originator = @cfg.originator
        @code = ''
      end
      def each_element
        yield REXML::Element.new('Originator').
          add_text(@cfg.utf8(originator))
        yield REXML::Element.new('OriginatorUnlockCode').
          add_text(@cfg.utf8(code))
      end
    end
    class CheckOriginatorAuthorization < Abstract
      attr_accessor :originator
      def initialize(cfg)
        super(cfg)
        @originator = @cfg.originator
      end
      def each_element
        yield REXML::Element.new('Originator').add_text(@cfg.utf8(originator))
      end
    end
    class ShowCredits < Abstract
      def initialize(cfg)
        super(cfg)
      end
      def each_element
        # no additional elements
      end
    end
  end

  # Represents a response to a request of any type.
  # Handles parsing of the response XML document and
  # provides easy access to data fields therein.
  class Response
    def self.parse(cfg, xmlstr)
      args = {}
      doc = REXML::Document.new(xmlstr)
      doc.root.each_element('*') do |element|
        args[element.name] = element.text.chomp
      end
      raise "'ErrorCode' missing!" if args['ErrorCode'].nil?
      raise "'ErrorDescription' missing!" if args['ErrorDescription'].nil?
      Response.new(cfg, args)
    end
    def initialize(cfg, args)
      @cfg = cfg
      @args = args
    end
    #  1 Ok
    # 30 Originator not Authorized
    # 31 Originator already Authorized
    def success?
      ['1', '30', '31'].include?(errno)
    end
    def authorized?
      errno == '31'
    end
    def errno
      @args['ErrorCode']
    end
    def errdesc
      @args['ErrorDescription']
    end
    def credits
      @args['Credits']
    end
    def credits_used
      @args['CreditsUsed']
    end
    def to_s
      "#{@args['ErrorCode']}: #{@args['ErrorDescription']} #{@args.inspect}"
    end
  end

  # Handles network communication with the ASPSMS gateways.
  class Gateway
    attr_reader :host, :port
    def self.send(cfg, req)
      cfg.gateways.each do |spec|
        begin
          resp = Gateway.new(cfg, spec).send(req)
          return resp
        rescue
          # continue with next gateway in list
          # XXX collect exception objects and add to raise below
        end
      end
      raise 'Failed to send request to gateways!'
    end
    def initialize(cfg, gw)
      @cfg = cfg
      if gw.match(/^(.*):([0-9]{1,5})$/)
        @host, @port = $1, $2
      end
      @http = @cfg.http_class.new(host, port)
    end
    def send(req)
      headers = { 'User-Agent' => @cfg.useragent,
                  'Content-Type' => 'text/xml' }
      resp = @http.post('/xmlsvr.asp', req.to_s, headers)
      ASPSMS::Response.parse(@cfg, resp.body)
    end
  end

  # Easy straightforward API class; for most use cases,
  # this should be all that is needed.
  class Easy
    def initialize(conf = nil)
      @cfg = ASPSMS::Config.new(conf)
    end
    def show_credits
      request = ASPSMS::Request::ShowCredits.new(@cfg)
      response = ASPSMS::Gateway.send(@cfg, request)
      raise 'Error status from server!' unless response.success?
      response.credits
    end
    def send_text_sms(text, recipients, opts = {})
      request = ASPSMS::Request::SendTextSMS.new(@cfg)
      request.text       = text
      request.recipients = recipients
      request.originator = opts[:originator] if opts.has_key?(:originator)
      request.flashing   = opts[:flashing]   if opts.has_key?(:flashing)
      request.blinking   = opts[:blinking]   if opts.has_key?(:blinking)
      response = ASPSMS::Gateway.send(@cfg, request)
      raise 'Error status from server!' unless response.success?
      response.credits_used
    end
    def send_originator_unlock_code(opts = {})
      request = ASPSMS::Request::SendOriginatorUnlockCode.new(@cfg)
      request.originator = opts[:originator] if opts.has_key?(:originator)
      response = ASPSMS::Gateway.send(@cfg, request)
      raise 'Error status from server!' unless response.success?
      response
    end
    def unlock_originator(code, opts = {})
      request = ASPSMS::Request::UnlockOriginator.new(@cfg)
      request.code       = code
      request.originator = opts[:originator] if opts.has_key?(:originator)
      response = ASPSMS::Gateway.send(@cfg, request)
      raise 'Error status from server!' unless response.success?
      response
    end
    def check_originator_authorization(opts = {})
      request = ASPSMS::Request::CheckOriginatorAuthorization.new(@cfg)
      request.originator = opts[:originator] if opts.has_key?(:originator)
      response = ASPSMS::Gateway.send(@cfg, request)
      raise 'Error status from server!' unless response.success?
      response.authorized?
    end
  end
end

if $0 == __FILE__
  require 'getoptlong'

  $bn = File.basename($0)
  def usage
    puts <<EOF
Usage:
  #{$bn} [-M] [-v] [-c file] [-o orig] [-t [n]] [-f] [-b] rcpt [...]
  #{$bn}  -C  [-v] [-c file]
  #{$bn}  -O  [-v] [-c file] [-o orig]
  #{$bn}  -U  [-v] [-c file] [-o orig] [-u code]
Actions:
  -M    send text message read from stdin (implied if recipients are given)
  -C    retrieve credit balance
  -O    check originator authorization
  -U    send originator unlock code; unlock if used with -u
Parameters:
  -o    specify originator (phone number or up to 11 characters)
  -t    truncate message to n bytes, or 160 if used without argument
  -f/-b flashing/blinking text SMS
  -u    specify unlock code
  -c    specify config file (default: ~/.aspsms, [/usr/local]/etc/aspsms)
  -v    verbose
  -h/-V show help/version and exit
Recipient phone number format: international format, e.g. +41XXXXXXXXX
EOF
  end
  def die(reason, detail = nil)
    STDERR.print "#{$0}: #{reason}"
    STDERR.puts detail.nil? ? '' : " -- #{detail}"
    exit 1
  end

  actions = []
  truncate = -1
  code = nil
  cf = nil
  verbose = false
  opts = {}
  begin
    GetoptLong.new(
      [ "-M", GetoptLong::NO_ARGUMENT ],
      [ "-C", GetoptLong::NO_ARGUMENT ],
      [ "-O", GetoptLong::NO_ARGUMENT ],
      [ "-U", GetoptLong::NO_ARGUMENT ],
      [ "-o", GetoptLong::REQUIRED_ARGUMENT ],
      [ "-t", GetoptLong::OPTIONAL_ARGUMENT ],
      [ "-f", GetoptLong::NO_ARGUMENT ],
      [ "-b", GetoptLong::NO_ARGUMENT ],
      [ "-u", GetoptLong::REQUIRED_ARGUMENT ],
      [ "-c", GetoptLong::REQUIRED_ARGUMENT ],
      [ "-v", GetoptLong::NO_ARGUMENT ],
      [ "-h", GetoptLong::NO_ARGUMENT ],
      [ "-V", GetoptLong::NO_ARGUMENT ]
    ).each do |opt, arg|
      case opt
      when '-h'
        usage
        exit 0
      when '-V'
        puts "#{$bn}: Ruby ASPSMS r#{ASPSMS::REVISION}"
        puts "Copyright (C) 2005-2011, Daniel Roethlisberger <daniel@roe.ch>"
        puts "http://www.roe.ch/ASPSMS"
        exit 0
      when '-M'
        actions << :textsms
      when '-C'
        actions << :credits
      when '-O'
        actions << :auth
      when '-U'
        actions << :unlock
      when '-o'
        opts[:originator] = arg
      when '-t'
        unless arg.empty? || arg.to_i > 0
          die('invalid option argument', '-t expects positive integer')
        end
        truncate = arg.empty? ? 160 : arg.to_i
      when '-f'
        opts[:flashing] = true
      when '-b'
        opts[:blinking] = true
      when '-u'
        code = arg
      when '-c'
        cf = arg
      when '-v'
        verbose = true
      end
    end
  rescue GetoptLong::MissingArgument, GetoptLong::InvalidOption
    exit 1
  end
  actions << :textsms unless ARGV.empty? || actions.include?(:textsms)

  if actions.length > 1
    die('incompatible options', '-M, -C, -O and -U mutually exclusive')
  end
  if actions[0] != :textsms && (truncate > 0 ||
                                opts.has_key?(:flashing) ||
                                opts.has_key?(:blinking))
    die('incompatible options', '-t, -f and -b require -M')
  end
  if actions[0] != :unlock && !code.nil?
    die('incompatible options', '-c requires -U')
  end
  if actions.include?(:credits) && opts.has_key?(:originator)
    die('incompatible options', '-o requires -M, -O or -U')
  end

  # XXX catch exceptions and print more sensible error messages;
  #     add custom exception classes to the ASPSMS:: namespace.
  aspsms = ASPSMS::Easy.new(cf)
  actions.each do |action|
    case action
    when :credits
      credits = aspsms.show_credits
      print credits
      puts verbose ? ' credits' : ''
      exit credits.to_i > 0 ? 0 : 1
    when :auth
      res = aspsms.check_originator_authorization(opts)
      puts res ? 'authorized' : 'not authorized' if verbose
      exit res ? 0 : 1
    when :unlock
      if code.nil?
        res = aspsms.send_originator_unlock_code(opts)
        puts 'sent unlock code' if verbose
      else
        res = aspsms.unlock_originator(code, opts)
        puts 'unlocked originator' if verbose
      end
      exit 0
    when :textsms
      rcpt = ARGV.dup
      rcpt.each do |rcpt|
        unless rcpt.is_phone_number?
          die('invalid phone number', rcpt)
        end
      end
      text = STDIN.read.gsub(/\s+/, ' ').gsub(/^\s+|\s+$/, '')
      text = text[0..(truncate - 1)] if truncate > 0
      credits_used = aspsms.send_text_sms(text, rcpt, opts)
      puts "message delivered (#{credits_used} credits used)" if verbose
      exit 0
    end
  end
  usage
  exit 1
end

