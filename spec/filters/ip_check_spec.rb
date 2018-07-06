# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ip_check"

describe LogStash::Filters::IpCheck do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        ip_check {
          match => "ip"
        }
      }
    CONFIG
    end

    sample("dummy") do
      expect(subject).not_to include("tags")
    end

    sample("ip" => 1) do
      expect(subject).to include("tags")
      expect(subject.get('tags')).to include("_ip_check_failure")
    end

    sample("ip" => "some text") do
      expect(subject).to include("tags")
      expect(subject.get('tags')).to include("_ip_check_invalid")
    end

    sample("ip" => "1.2.3.4") do
      expect(subject).not_to include("tags")
    end

    sample("ip" => ["1.2.3.4", "6.7.8.9"]) do
      expect(subject).not_to include("tags")
    end

    sample("ip" => ["1.2.3.4", "abc"]) do
      expect(subject).to include("tags")
      expect(subject.get('tags')).to include("_ip_check_invalid")
    end
  end

  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        ip_check {
          match => "ip"
          ignore_absent => false
        }
      }
    CONFIG
    end

    sample("dummy") do
      expect(subject).to include("tags")
      expect(subject.get('tags')).to include("_ip_check_failure")
    end

    sample("ip" => "1.2.3.4") do
      expect(subject).not_to include("tags")
    end
  end
end
