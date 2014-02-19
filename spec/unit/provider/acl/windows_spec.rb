#! /usr/bin/env ruby
require 'spec_helper'
require 'puppet/type'
require 'puppet/provider/acl/windows'

describe Puppet::Type.type(:acl).provider(:windows), :if => Puppet.features.microsoft_windows? do

  let (:resource) { Puppet::Type.type(:acl).new(:provider => :windows, :name => "windows_acl") }
  let (:provider) { resource.provider}

  it "should be an instance of Puppet::Type::Acl::ProviderWindows" do
    provider.must be_an_instance_of Puppet::Type::Acl::ProviderWindows
  end

  context "self.instances" do
    it "should return an empty array" do
      provider.class.instances.should == []
    end
  end

  context ":permissions" do
    let (:ace) { Puppet::Util::Windows::AccessControlEntry.new('S-1-5-32-544',0x31)}

    context "get_ace_type" do
      it "should return allow if ace is nil" do
        ace.stubs(:type).returns(1) #ensure no false readings
        ace.expects(:nil?).returns(true)

        Puppet::Provider::Acl::Windows::Base.get_ace_type(ace).must == 'allow'
      end

      it "should return allow when ace.type is 0" do
        ace.expects(:type).returns(0)

        Puppet::Provider::Acl::Windows::Base.get_ace_type(ace).must == 'allow'
      end

      it "should return deny when ace.type is 1" do
        ace.expects(:type).returns(1)

        Puppet::Provider::Acl::Windows::Base.get_ace_type(ace).must == 'deny'
      end
    end

    context "get_ace_child_types" do
      it "should return all if ace is nil" do
        ace.stubs(:container_inherit?).returns(false) #ensure no false readings
        ace.expects(:nil?).returns(true)

        Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace).must == 'all'
      end

      it "should return none when container_inherit and object_inherit are both false" do
        ace.expects(:container_inherit?).returns(false).at_least_once
        ace.expects(:object_inherit?).returns(false).at_least_once

        Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace).must == 'none'
      end

      it "should return objects when container_inherit is false and object_inherit is true" do
        ace.expects(:container_inherit?).returns(false).at_least_once
        ace.expects(:object_inherit?).returns(true).at_least_once

        Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace).must == 'objects'
      end

      it "should return containers when container_inherit is true and object_inherit is false" do
        ace.expects(:container_inherit?).returns(true).at_least_once
        ace.expects(:object_inherit?).returns(false).at_least_once

        Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace).must == 'containers'
      end

      it "should return all when container_inherit and object_inherit are both true" do
        ace.expects(:container_inherit?).returns(true).at_least_once
        ace.expects(:object_inherit?).returns(true).at_least_once

        Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace).must == 'all'
      end
    end

    context "get_ace_propagation" do
      before :each do
        ace.expects(:container_inherit?).returns(true).times(0..1)
        ace.expects(:object_inherit?).returns(true).times(0..1)
        ace.expects(:inherit_only?).returns(false).times(0..2)
      end

      it "should return all if ace is nil" do
        ace.stubs(:inherit_only?).returns(true) #ensure no false readings
        ace.expects(:nil?).returns(true)

        Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'all'
      end

      context "includes self" do
        it "should return all when when ace.inherit_only? is false, ace.object_inherit? is true and ace.container_inherit? is true" do
          Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'all'
        end

        it "should return all when when ace.inherit_only? is false, ace.object_inherit? is false and ace.container_inherit? is true (only one container OR object inherit type is required)" do
          ace.expects(:object_inherit?).returns(false).times(0..1)
          Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'all'
        end

        it "should return all when when ace.inherit_only? is false, ace.object_inherit? is true and ace.container_inherit? is true (only one container OR object inherit type is required)" do
          ace.expects(:container_inherit?).returns(false).times(0..1)
          Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'all'
        end

        it "should return self_only when ace.inherit_only? is false, ace.object_inherit? is false and ace.container_inherit? is false" do
          ace.expects(:container_inherit?).returns(false).times(0..1)
          ace.expects(:object_inherit?).returns(false).times(0..1)
          Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'self_only'
        end

        it "should return self_and_direct_children when ace.inherit_only? is false and no_propagation_flag is set" do
          ace.expects(:flags).returns(0x4) # http://msdn.microsoft.com/en-us/library/windows/desktop/ms692524(v=vs.85).aspx

          Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'self_and_direct_children'
        end
      end

      context "inherit only (IO)" do
        before :each do
          ace.expects(:inherit_only?).returns(true).times(0..2)
        end

        it "should return children_only when ace.inherit_only? is true and no_propagation_flag is not set" do
          ace.expects(:flags).returns(0x10)

          Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'children_only'
        end

        it "should return direct_children_only when ace.inherit_only? is true and no_propagation_flag is set" do
          ace.expects(:flags).returns(0x4) # http://msdn.microsoft.com/en-us/library/windows/desktop/ms692524(v=vs.85).aspx

          Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace).must == 'direct_children_only'
        end
      end
    end

    context "get_ace_rights_from_mask" do
      it "should return [] if ace is nil?" do
        ace.expects(:nil?).returns(true)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == []
      end

      it "should have only full if ace.mask contains GENERIC_ALL" do
        ace.expects(:mask).returns(::Windows::Security::GENERIC_ALL).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['full']
      end

      it "should have only full if ace.mask contains FILE_ALL_ACCESS" do
        ace.expects(:mask).returns( ::Windows::File::FILE_ALL_ACCESS).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['full']
      end

      it "should contain read, write, execute if ace.mask contains GENERIC_WRITE, GENERIC_READ, and GENERIC_EXECUTE" do
        ace.expects(:mask).returns(::Windows::Security::GENERIC_WRITE |
                                   ::Windows::Security::GENERIC_READ |
                                   ::Windows::Security::GENERIC_EXECUTE ).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['write','read','execute']
      end

      it "should contain read, write, execute if ace.mask contains FILE_GENERIC_WRITE, FILE_GENERIC_READ, and FILE_GENERIC_EXECUTE" do
        ace.expects(:mask).returns(::Windows::File::FILE_GENERIC_WRITE |
                                   ::Windows::File::FILE_GENERIC_READ |
                                   ::Windows::File::FILE_GENERIC_EXECUTE ).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['write','read','execute']
      end

      it "should contain modify if ace.mask contains GENERIC_WRITE, GENERIC_READ, GENERIC_EXECUTE and contains DELETE" do
        ace.expects(:mask).returns(::Windows::Security::GENERIC_WRITE |
                                   ::Windows::Security::GENERIC_READ |
                                   ::Windows::Security::GENERIC_EXECUTE |
                                   ::Windows::Security::DELETE ).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['modify']
        end

      it "should contain modify if ace.mask contains FILE_GENERIC_WRITE, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE and contains DELETE" do
        ace.expects(:mask).returns(::Windows::File::FILE_GENERIC_WRITE |
                                   ::Windows::File::FILE_GENERIC_READ |
                                   ::Windows::File::FILE_GENERIC_EXECUTE |
                                   ::Windows::Security::DELETE ).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['modify']
      end

      it "should contain read, execute if ace.mask contains GENERIC_READ and GENERIC_EXECUTE" do
        ace.expects(:mask).returns(::Windows::Security::GENERIC_READ |
                                   ::Windows::Security::GENERIC_EXECUTE).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['read','execute']
      end

      it "should contain read, execute if ace.mask contains FILE_GENERIC_READ and FILE_GENERIC_EXECUTE" do
        ace.expects(:mask).returns(::Windows::File::FILE_GENERIC_READ |
                                   ::Windows::File::FILE_GENERIC_EXECUTE).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['read','execute']
      end

      it "should contain write if ace.mask contains GENERIC_WRITE" do
        ace.expects(:mask).returns(::Windows::Security::GENERIC_WRITE).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['write']
      end

      it "should contain write if ace.mask contains FILE_WRITE_DATA" do
        ace.expects(:mask).returns(::Windows::File::FILE_WRITE_DATA).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['write']
      end

      it "should contain write if ace.mask contains FILE_APPEND_DATA" do
        ace.expects(:mask).returns(::Windows::File::FILE_APPEND_DATA).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['write']
      end

      it "should contain read if ace.mask contains GENERIC_READ" do
        ace.expects(:mask).returns(::Windows::Security::GENERIC_READ).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['read']
      end

      it "should contain read if ace.mask contains FILE_GENERIC_READ" do
        ace.expects(:mask).returns(::Windows::File::FILE_GENERIC_READ).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['read']
      end

      it "should contain read if ace.mask contains FILE_READ_DATA" do
        ace.expects(:mask).returns(::Windows::File::FILE_READ_DATA).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['read']
      end

      it "should contain execute if ace.mask contains GENERIC_EXECUTE" do
        ace.expects(:mask).returns(::Windows::Security::GENERIC_EXECUTE).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['execute']
      end

      it "should contain execute if ace.mask contains FILE_GENERIC_EXECUTE" do
        ace.expects(:mask).returns(::Windows::File::FILE_GENERIC_EXECUTE).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['execute']
      end

      it "should contain execute if ace.mask contains FILE_EXECUTE" do
        ace.expects(:mask).returns(::Windows::File::FILE_EXECUTE).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['execute']
      end

      it "should contain mask_specific if ace.mask contains permissions too specific" do
        ace.expects(:mask).returns(::Windows::File::DELETE).times(0..10)

        Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace).must == ['mask_specific']
      end
    end
  end
end
