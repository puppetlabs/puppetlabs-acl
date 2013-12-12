#! /usr/bin/env ruby
require 'spec_helper'
require 'puppet/type'
require 'puppet/type/acl'

describe Puppet::Type.type(:acl) do
  let(:resource) { Puppet::Type.type(:acl).new(:name => "acl") }
  let(:provider) { Puppet::Provider.new(resource) }

  before :each do
    resource.provider = provider
  end

  it "should be an instance of Puppet::Type::Acl" do
    resource.must be_an_instance_of Puppet::Type::Acl
  end
end
