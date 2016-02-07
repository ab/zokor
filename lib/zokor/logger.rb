require 'logger'

module Zokor
  def self.log_level
    @log_level ||= log_level!
  end
  def self.log_level=(level)
    @log_level = Integer(level)
  end
  def self.log_level!
    level = ENV['LOG_LEVEL']
    return Integer(level) if level && !level.empty?

    Logger::INFO
  end

  module TermColors
    NOTHING      = '0;0'
    BLACK        = '0;30'
    RED          = '0;31'
    GREEN        = '0;32'
    BROWN        = '0;33'
    BLUE         = '0;34'
    PURPLE       = '0;35'
    CYAN         = '0;36'
    LIGHT_GRAY   = '0;37'
    DARK_GRAY    = '1;30'
    LIGHT_RED    = '1;31'
    LIGHT_GREEN  = '1;32'
    YELLOW       = '1;33'
    LIGHT_BLUE   = '1;34'
    LIGHT_PURPLE = '1;35'
    LIGHT_CYAN   = '1;36'
    WHITE        = '1;37'
    BG_BLACK     = '1;40'
    BG_RED       = '1;41'
    BG_GREEN     = '1;42'
    BG_YELLOW    = '1;43'
    BG_BLUE      = '1;44'
    BG_PURPLE    = '1;45'
    BG_CYAN      = '1;46'
    BG_WHITE     = '1;47'
    RED_ON_WHITE = '1;31;47'

    SCHEMA = {
      STDOUT => %w[nothing green brown red purple cyan],
      STDERR => %w[dark_gray nothing yellow light_red bg_red light_cyan],
    }
  end

  class ColoredLogger < Logger
    def format_message(level, *args)
      if TermColors::SCHEMA[@logdev.dev] && @logdev.dev.tty?
        begin
          index = self.class.const_get(level.sub('ANY', 'UNKNOWN'))
          color_name = TermColors::SCHEMA[@logdev.dev][index]
          color = TermColors.const_get(color_name.to_s.upcase)
        rescue NameError
          color = '0;0'
        end
        message = super(level, *args)
        if message.end_with?("\n")
          # make sure color is turned off before any trailing newline
          "\e[#{color}m#{message[0...-1]}\e[0;0m\n"
        else
          "\e[#{color}m#{message}\e[0;0m"
        end
      else
        super(level, *args)
      end
    end

    def rainbow(*args)
      SEV_LABEL.each_with_index do |level, i|
        add(i, *args)
      end
    end
  end

  class ProgLogger < ColoredLogger
    def initialize(name, opts={})
      opts[:stream] ||= STDERR

      @chunder = !!ENV['LOG_CHUNDER']

      super(opts.fetch(:stream))
      self.level = Zokor.log_level
      self.progname = name
    end

    def chunder(*args, &blk)
      return unless @chunder
      debug(*args, &blk)
    end
  end
end

