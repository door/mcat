#!/usr/bin/env ruby
# coding: utf-8

require 'optparse'
require 'socket'
require 'uri'
require 'digest'
require 'webrick'


DEFAULT_PAYLOAD_SIZE = 1000 # bytes


$file_hash = nil


def main
  options = get_cli_opts
  p options

  blocksize = options[:blocksize] || DEFAULT_PAYLOAD_SIZE

  Thread.abort_on_exception = true

  make_file_reader = lambda do
    FileReader.new options[:file], blocksize
  end

  pusher_thread = Thread.start do
    pusher = UdpPusher.new options[:udp_uri], options[:speed], make_file_reader.call
    pusher.run
  end

  Thread.start do
    puts options[:file]
    $file_hash = Digest::SHA1.file options[:file]
    puts "$file_hash: #{$file_hash}\n\n"
  end

  WebApp.start(options[:control_url], blocksize, make_file_reader.call)
end



def get_cli_opts
  options = {}

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} -a ADDRESS -c URL -f FILE -r SPEED [-s SIZE]"

    opts.on("-a", "--address UDP_GROUP_ADDRESS", "Multicast group IP:PORT") do |address|
      unless address =~ /^udp:\/\//
        address = "udp://#{address}"
      end
      options[:udp_uri] = URI.parse(address)
    end

    opts.on("-c", "--control-url URL", "Control URL") do |url|
      options[:control_url] = url
    end

    opts.on("-f", "--file FILE", "Data file to send") do |file|
      options[:file] = file
    end

    opts.on("-r", "--bitrate SPEED[km]", "Sending speed, bits per second") do |speed|
      speed = speed . gsub(/([km])$/, '')
      m = case $1
          when "k"; 1024
          when "m"; 1024*1024
          when nil; 1
          end
      options[:speed] = speed . to_i
      raise unless options[:speed] > 0
      options[:speed] *= m
    end

    opts.on("-s", "--payload-size BYTES", "Packet payload size, bytes") do |n|
      options[:blocksize] = n . to_i
      raise unless options[:blocksize] > 0
    end

  end

  parser.parse!

  unless [:file, :control_url, :speed, :udp_uri].all? {|k| options[k]}
    puts parser
    exit 1
  end

  options
end



class UdpPusher
  def initialize udp_uri, speed, file_reader
    @addr = Addrinfo.udp(udp_uri.host, udp_uri.port)
    @socket = UDPSocket.new
    pktsize = file_reader . blocksize + 4 # Packet number + payload
    @interval = 1.0 / (speed . to_f / 8.0 / pktsize)
    @file_reader = file_reader
  end
  #
  #
  def run
    iter = 0
    loop do
      iter += 1
      puts "Iter #{iter}"
      send_file
    end
  end
  #
  #
  def send_file
    blockno = 0

    loop do
      t1 = Time.now

      s = @file_reader . read_block
      return unless s
      pkt = [blockno, s].pack("Na*")

      @socket.send pkt, 0, @addr

      blockno += 1

      t2 = Time.now
      d = t2 - t1
      if d < @interval
        sleep(@interval - d)
      end
    end
  end
end



class FileReader
  attr_reader :blocksize, :size, :name
  #
  #
  def initialize filename, blocksize
    @name = File.basename(filename)
    @size = File.size(filename)
    @file = File.open(filename, "rb")
    @blocksize = blocksize
    @blocks = @size / @blocksize
    if @size % @blocksize > 0
      @blocks += 1
    end
  end
  #
  #
  def read_block blockno = nil
    if blockno
      if blockno >= @blocks
        return false
      end
      @file . sysseek(@blocksize * blockno)
    end
    @file . sysread(@blocksize)
  rescue EOFError
    @file . rewind
    nil
  end
end



class WebApp
  def initialize file_reader, blocksize
    @file_reader = file_reader
    @blocksize = blocksize
  end
  #
  #
  def serve req, resp
    p req.path_info
    case req.path_info
    when "/info"
      info(resp)
    when "/hash"
      hash(resp)
    when /^\/block\/(\d+)$/
      block $1.to_i, resp
    else
      resp.status = 404
    end
  end
  #
  #
  def info resp
    reply resp, 200, "text/plain", "#{@blocksize} #{@file_reader.size} #{@file_reader.name}"
  end
  #
  #
  def hash resp
    unless $file_hash
      reply resp, 424 # Failed Dependency
      return
    end
    reply resp, 200, "text/plain", $file_hash.to_s
  end
  #
  #
  def block blockno, resp
    puts "sending block #{blockno}"
    s = @file_reader.read_block blockno
    if s == false
      reply resp, 404
      return
    end
    reply resp, 200, "application/octet-stream", s
  end
  #
  #
  def reply resp, code, content_type = nil, body = nil
    resp.status = code
    resp.content_type = content_type if content_type
    resp.body = body if body
  end
  #
  #
  def self.start control_url_, blocksize, file_reader
    control_url = URI.parse(control_url_)

    web_server = WEBrick::HTTPServer.new(:Port => control_url.port)
    web_app = WebApp.new(file_reader, blocksize)
    web_server.mount_proc control_url.path do |req, resp|
      web_app.serve(req, resp)
    end
    web_server.start
  end
end



main
