#!/usr/bin/env ruby
# vim: set et ts=2 sw=2:
#
# Ruby ASPSMS -- aspsms.com short message service gateway library and client
# http://www.roe.ch/ASPSMS
#
# Copyright (C) 2005-2012, Daniel Roethlisberger <daniel@roe.ch>
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

require 'rexml/document'
require 'net/http'
require 'uri'
require 'iconv'

module ASPSMS
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
      end
      raise "No configuration file found (#{FILES.join(' ')})"
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
      "ASPSMS::Gateway (http://www.roe.ch/ASPSMS)"
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

