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

    context ".insync?" do
      it "should return true for Administrators and S-1-5-32-544" do
        provider.is_owner_insync?("S-1-5-32-544","Administrators").must be_true
      end

      it "should return true for Administrators and Administrators" do
        provider.is_owner_insync?("Administrators","Administrators").must be_true
      end

      it "should return false for Administrators and Administrator (user)" do
        provider.is_owner_insync?("Administrators","Administrator").must be_false
      end
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

    context ".insync?" do
      context "when purge=>false (the default)" do
        it "should return true for Administrators and specifying Administrators with same permissions" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], [admins], false).must be_true
        end

        it "should return true for Administrators and specifying Administrators even if one specifies sid and other non-required information" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          admin2 = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'sid'=>"S-1-5-32-544", 'mask'=>::Windows::File::GENERIC_ALL, 'is_inherited'=>false})
          provider.are_permissions_insync?([admins], [admin2], false).must be_true
        end

        it "should return true for Administrators and specifying Administrators when more current permissions exist than are specified" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          admin = Puppet::Type::Acl::Ace.new({'identity'=>'Administrator', 'rights'=>['full']})
          provider.are_permissions_insync?([admin,admins], [admin], false).must be_true
        end

        it "should return false for Administrators and specifying Administrators when more current permissions are specified than exist" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          admin = Puppet::Type::Acl::Ace.new({'identity'=>'Administrator', 'rights'=>['full']})
          provider.are_permissions_insync?([admin], [admin,admins], false).must be_false
        end

        it "should return false for Administrators and specifying Administrators if rights are different" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          admin2 = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['modify']})
          provider.are_permissions_insync?([admins], [admin2], false).must be_false
        end

        it "should return false for Administrators and specifying Administrators if types are different" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'type'=>'allow'})
          admin2 = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'type'=>'deny'})
          provider.are_permissions_insync?([admins], [admin2], false).must be_false
        end

        it "should return false for Administrators and specifying Administrators if child_types are different" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'child_types'=>'all'})
          admin2 = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'child_types'=>'none'})
          provider.are_permissions_insync?([admins], [admin2], false).must be_false
        end

        it "should return false for Administrators and specifying Administrators if affects are different" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'affects'=>'all'})
          admin2 = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'affects'=>'children_only'})
          provider.are_permissions_insync?([admins], [admin2], false).must be_false
        end

        it "should return false for Administrators and specifying Administrators if current is inherited" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'is_inherited'=>'true'})
          admin2 = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], [admin2], false).must be_false
        end

        it "should return true for Administrators and specifying S-1-5-32-544" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          adminSID = Puppet::Type::Acl::Ace.new({'identity'=>'S-1-5-32-544', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], [adminSID], false).must be_true
        end

        it "should return false for nil and specifying Administrators" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?(nil, [admins], false).must be_false
        end

        it "should return true for Administrators and specifying nil" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], nil, false).must be_true
        end

        it "should return true for Administrators and specifying []" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], [], false).must be_true
        end

        it "should return false for [] and specifying Administrators" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([], [admins], false).must be_false
        end
      end

      context "when purge=>true" do
        it "should return true for Administrators and specifying Administrators with same permissions" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], [admins], true).must be_true
        end

        it "should return true for Administrators and specifying Administrators even if one specifies sid and other non-required information" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          admin2 = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full'], 'sid'=>"S-1-5-32-544", 'mask'=>::Windows::File::GENERIC_ALL, 'is_inherited'=>false})
          provider.are_permissions_insync?([admins], [admin2], true).must be_true
        end

        it "should return false for Administrators and specifying Administrators when more current permissions exist than are specified" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          admin = Puppet::Type::Acl::Ace.new({'identity'=>'Administrator', 'rights'=>['full']})
          provider.are_permissions_insync?([admin,admins], [admin], true).must be_false
        end

        it "should return false for Administrators and specifying Administrators when more permissions are specified than exist" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          admin = Puppet::Type::Acl::Ace.new({'identity'=>'Administrator', 'rights'=>['full']})
          provider.are_permissions_insync?([admin], [admin,admins], true).must be_false
        end

        it "should return false for nil and specifying Administrators" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?(nil, [admins], true).must be_false
        end

        it "should return false for Administrators and specifying nil" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], nil, true).must be_false
        end

        it "should return false for Administrators and specifying []" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([admins], [], true).must be_false
        end

        it "should return false for [] and specifying Administrators" do
          admins = Puppet::Type::Acl::Ace.new({'identity'=>'Administrators', 'rights'=>['full']})
          provider.are_permissions_insync?([], [admins], true).must be_false
        end
      end
    end
  end
end
