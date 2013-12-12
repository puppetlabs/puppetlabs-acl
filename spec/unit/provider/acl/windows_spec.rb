#! /usr/bin/env ruby
require 'spec_helper'
require 'puppet/type'
require 'puppet/provider/acl/windows'

describe Puppet::Type.type(:acl).provider(:windows), :if => Puppet.features.microsoft_windows? do
  let(:resource) { Puppet::Type.type(:acl).new(:provider => :windows, :name => "windows_acl") }
  let(:provider) { resource.provider}

  it "should be an instance of Puppet::Type::Acl::ProviderWindows" do
    provider.must be_an_instance_of Puppet::Type::Acl::ProviderWindows
  end

  context "self.instances" do
    it "should return an empty array" do
      provider.class.instances.should == []
    end
  end
end
