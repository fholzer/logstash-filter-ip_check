# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"

class LogStash::Filters::IpCheck < LogStash::Filters::Base
  config_name "ip_check"

  # Name of the field that contains the IP address to validate.
  # If field is an array, all items of the array must be valid IP addresses
  # for the filter to succeed.
  config :match, :validate => :string, :default => ""

  # If true, doesn't fail if the match field is absent.
  config :ignore_absent, :validate => :boolean, :default => true

  # In case the specified field doesn't contain a valid IP address,
  # these tags will be set.
  config :tags_on_invalid_ip, :validate => :array, :default => ["_ip_check_invalid"]

  # In case an error ocurrs while checking the IP address,
  # these tags will be set.
  config :tags_on_failure, :validate => :array, :default => ["_ip_check_failure"]

  public
  def register
    if @match.length < 1
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "ip_check",
        :error => "The configuration option 'match' must be a non-zero length string"
      )
    end
  end # def register

  private
  def match(address)
    begin
      IPAddr.new(address)
    rescue ArgumentError => e
      return false
    end
    return true
  end # def match

  public
  def filter(event)
    field = event.get(@match);

    # return if field is absent
    if field == nil
      # tag with failure tag, if needed
      if not @ignore_absent
        @tags_on_failure.each {|tag| event.tag(tag)}
      end
      return
    end

    res = true
    if field.kind_of?(Array)
      res = nil == field.find {|o| !match(o)}
    elsif field.kind_of?(String)
      res = match(field)
    else
      @tags_on_failure.each {|tag| event.tag(tag)}
      return
    end

    if res == false
      @tags_on_invalid_ip.each {|tag| event.tag(tag)}
      return
    end
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::IpCheck
