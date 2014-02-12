#! /usr/bin/env ruby
require 'spec_helper'
require 'puppet/type'
require 'puppet/provider/acl/windows'

if Puppet.features.microsoft_windows?
  class WindowsSecurityTester
    require 'puppet/util/windows/security'
    include Puppet::Util::Windows::Security
  end
end


describe Puppet::Type.type(:acl).provider(:windows), :if => Puppet.features.microsoft_windows? do
  let (:resource) { Puppet::Type.type(:acl).new(:provider => :windows, :name => "windows_acl") }
  let (:provider) { resource.provider}

  let (:top_level_path) do
    Dir.mktmpdir('acl_playground')
  end

  let (:path) { top_level_path }

  def set_path(sub_directory)
    path = File.join(top_level_path, sub_directory)
    Dir.mkdir(path) unless Dir.exists?(path)

    path
  end

  before :each do
    resource.provider = provider
  end

  context ":owner" do
    before :each do
      path = set_path('owner_stuff')
      resource[:target] = path
    end

    it "should not be nil" do
      provider.owner.must_not be_nil
    end

    it "should grab current owner" do
      provider.owner.must == 'S-1-5-32-544'
    end
  end

  context ":inherit_parent_permissions" do
    before :each do
      path = set_path('inheritance_stuff')
      resource[:target] = path
    end

    it "should not be nil" do
      provider.inherit_parent_permissions.must_not be_nil
    end

    it "should be true by default" do
      provider.inherit_parent_permissions.must be_true
    end
  end

  context ":permissions" do
    before :each do
      path = set_path('permissions_stuff')
      resource[:target] = path
    end

    it "should not be nil" do
      provider.permissions.must_not be_nil
    end

    it "should contain at least one ace" do
      provider.permissions.count.must_not == 0
    end

    it "should contain aces that are access allowed" do
       at_least_one = false
       provider.permissions.each do |ace|
         if ace.type == 'allow'
           at_least_one = true
           break
         end
       end

       at_least_one.must be_true
    end

    it "should contain aces that allow inheritance" do
      at_least_one = false
      provider.permissions.each do |ace|
        case ace.child_types
          when 'all','objects','containers'
            at_least_one = true
            break
        end
      end

      at_least_one.must be_true
    end

    it "should contain aces that are inherited" do
      at_least_one = false
      provider.permissions.each do |ace|
        if ace.is_inherited?
          at_least_one = true
          break
        end
      end

      at_least_one.must be_true
    end

    it "should contain aces that propagate inheritance" do
      at_least_one = false
      provider.permissions.each do |ace|
        case ace.affects
          when 'all','children_only','self_and_direct_children_only','direct_children_only'
            at_least_one = true
            break
        end
      end

      at_least_one.must be_true
    end

  end

end
