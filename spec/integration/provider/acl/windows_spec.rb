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
  let (:provider) { resource.provider }
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

  it "should throw an error for an invalid target" do
    resource[:target] = "c:/somwerhaear2132312323123123123123123_does_not_exist"

    expect {
      provider.owner.must_not be_nil
    }.to raise_error(Exception, /Failed to get security descriptor for path/)
  end

  context ":owner" do
    before :each do
      resource[:target] = set_path('owner_stuff')
    end

    it "should not be nil" do
      provider.owner.must_not be_nil
    end

    it "should grab current owner" do
      provider.owner.must == 'S-1-5-32-544'
    end

    context ".flush" do
      before :each do
        resource[:target] = set_path('set_owner')
      end

       it "should update owner to Administrator properly" do
         provider.owner.must == 'S-1-5-32-544'
         provider.owner = 'Administrator'

         resource.provider.flush

         provider.owner.must == provider.get_account_sid('Administrator')
       end

       it "should not update owner to a user that does not exist" do
          expect {
            provider.owner = 'someuser1231235123112312312'
         }.to raise_error(Exception, /User does not exist/)
       end
    end
  end

  context ":group" do
    before :each do
      resource[:target] = set_path('group_stuff')
    end

    it "should not be nil" do
      provider.group.must_not be_nil
    end

    it "should grab current group" do
      # there really isn't a default group, it depends on the primary group of the original CREATOR OWNER of a resource.
      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms676927(v=vs.85).aspx
      provider.group.must_not == Puppet::Type::Acl::Constants::GROUP_UNSPECIFIED
    end

    context ".flush" do
      before :each do
        resource[:target] = set_path('set_group')
      end

       it "should update group to Administrator properly" do
         provider.group.must_not == Puppet::Type::Acl::Constants::GROUP_UNSPECIFIED
         if provider.group == provider.get_account_sid('Administrator')
           provider.group = 'Users'
           resource.provider.flush
         end
         provider.group.must_not == provider.get_account_sid('Administrator')
         provider.group = 'Administrator'

         resource.provider.flush

         provider.group.must == provider.get_account_sid('Administrator')
       end

       it "should not update group to a group that does not exist" do
          expect {
            provider.group = 'somegroup1231235123112312312'
         }.to raise_error(Exception, /Group does not exist/)
       end
    end
  end

  context ":inherit_parent_permissions" do
    before :each do
      resource[:target] = set_path('inheritance_stuff')
    end

    it "should not be nil" do
      provider.inherit_parent_permissions.must_not be_nil
    end

    it "should be true by default" do
      provider.inherit_parent_permissions.must be_true
    end

    context ".flush" do
      before :each do
        resource[:target] = set_path('set_inheritance')
      end

      it "should do nothing if inheritance is set to true (default)" do
        provider.inherit_parent_permissions.must be_true

        # puppet will not make this call if values are in sync
        #provider.inherit_parent_permissions = :true

        resource.provider.expects(:set_security_descriptor).never

        resource.provider.flush
      end

      it "should update inheritance to false when set to :false" do
        provider.inherit_parent_permissions.must be_true
        provider.inherit_parent_permissions = :false

        resource.provider.flush

        provider.inherit_parent_permissions.must be_false
      end
    end
  end

  context ":permissions" do
    before :each do
      resource[:target] = set_path('permissions_stuff')
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
         if ace.type == :allow
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
          when :all, :objects, :containers
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
          when :all, :children_only, :self_and_direct_children_only, :direct_children_only
            at_least_one = true
            break
        end
      end

      at_least_one.must be_true
    end

    context "when setting permissions" do
      before :each do
        resource[:target] = set_path('set_perms')
      end

      def set_perms(permissions, include_inherited = false)
        provider.permissions = permissions
        resource.provider.flush

        if include_inherited
          provider.permissions
        else
          provider.permissions.select { |p| !p.is_inherited? }
        end
      end

      it "should not allow permissions to be set to a user that does not exist" do
        permissions = [Puppet::Type::Acl::Ace.new({'identity' => 'someuser1231235123112312312','rights' => ['full']})]

        expect {
          provider.permissions = permissions
        }.to raise_error(Exception, /User or users do not exist/)
      end


      it "should handle minimally specified permissions" do
        permissions = [Puppet::Type::Acl::Ace.new({'identity' => 'Everyone','rights' => ['full']}, provider)]
        set_perms(permissions).must == permissions
      end

    end
  end

  context ".set_security_descriptor" do
    it "should handle nil security descriptor appropriately" do
      expect {
        provider.set_security_descriptor(nil)
      }.to raise_error(Exception, /Failed to set security descriptor for path/)
    end
  end
end
