# frozen_string_literal: true

require 'spec_helper'
require 'puppet/type'
require 'puppet/provider/acl/windows'

describe Puppet::Type.type(:acl).provider(:windows), if: Puppet.features.microsoft_windows? do
  let(:resource) { Puppet::Type.type(:acl).new(provider: :windows, name: 'windows_acl') }
  let(:provider) { resource.provider }
  let(:catalog) { Puppet::Resource::Catalog.new }
  let(:base) { Puppet::Provider::Acl::Windows::Base }

  before :each do
    resource.provider = provider
  end

  it 'is an instance of Puppet::Type::Acl::ProviderWindows' do
    expect(provider).to be_an_instance_of(Puppet::Type::Acl::ProviderWindows)
  end

  context 'self.instances' do
    it 'returns an empty array' do
      expect(provider.class.instances).to eq([])
    end
  end

  context 'autorequiring resources' do
    context 'users' do
      def test_should_set_autorequired_user(user_name)
        user = Puppet::Type.type(:user).new(name: user_name)
        catalog.add_resource resource
        catalog.add_resource user

        reqs = resource.autorequire
        expect(reqs.count).to eq(1)
        expect(reqs[0].source).to eq(user)
        expect(reqs[0].target).to eq(resource)
      end

      def test_should_not_set_autorequired_user(user_name)
        user = Puppet::Type.type(:user).new(name: user_name)
        catalog.add_resource resource
        catalog.add_resource user

        reqs = resource.autorequire
        expect(reqs).to be_empty
      end

      it 'autorequires identities in permissions' do
        user_name = 'Administrator'
        resource[:permissions] = [{ 'identity' => 'bill', 'rights' => ['modify'] }, { 'identity' => user_name, 'rights' => ['full'] }]
        test_should_set_autorequired_user(user_name)
      end

      it "does not autorequire 'Administrators' if owner is set to the default Administrators SID" do
        # unfortunately we get the full account name 'BUILTIN\Administrators' which doesn't match Administrators
        test_should_not_set_autorequired_user('Administrators')
      end

      it 'autorequires BUILTIN\\Administrators if owner is set to the Administrators SID' do
        resource[:owner] = 'S-1-5-32-544'
        test_should_set_autorequired_user('BUILTIN\Administrators')
      end

      it 'autorequires fully qualified identities in permissions even if identities use SIDS' do
        resource[:owner] = 'Administrator'
        user_name = 'BUILTIN\Administrators'
        user_sid = 'S-1-5-32-544'

        resource[:permissions] = [{ 'identity' => 'bill', 'rights' => ['modify'] }, { 'identity' => user_sid, 'rights' => ['full'] }]
        test_should_set_autorequired_user(user_name)
      end
    end
  end

  context ':owner' do
    it 'is set to the default unspecified value by default' do
      expect(resource[:owner]).to be_nil
    end

    context '.insync?' do
      it 'returns true for Administrators and S-1-5-32-544' do
        expect(provider).to be_owner_insync('S-1-5-32-544', 'Administrators')
      end

      it 'returns true for Administrators and Administrators' do
        expect(provider).to be_owner_insync('Administrators', 'Administrators')
      end

      it 'returns true for BUILTIN\\Administrators and Administrators' do
        expect(provider).to be_owner_insync('BUILTIN\\Administrators', 'Administrators')
      end

      it 'returns false for Administrators and Administrator (user)' do
        expect(provider.owner_insync?('Administrators', 'Administrator')).to be false
      end
    end
  end

  context ':group' do
    it 'is set to the default unspecified value by default' do
      expect(resource[:group]).to be_nil
    end

    context '.insync?' do
      it 'returns true for Administrators and S-1-5-32-544' do
        expect(provider).to be_group_insync('S-1-5-32-544', 'Administrators')
      end

      it 'returns true for Administrators and Administrators' do
        expect(provider).to be_group_insync('Administrators', 'Administrators')
      end

      it 'returns true for BUILTIN\\Administrators and Administrators' do
        expect(provider).to be_group_insync('BUILTIN\\Administrators', 'Administrators')
      end

      it 'returns false for Administrators and Administrator (user)' do
        expect(provider.group_insync?('Administrators', 'Administrator')).to be false
      end
    end
  end

  context ':permissions' do
    let(:ace) { Puppet::Util::Windows::AccessControlEntry.new('S-1-5-32-544', 0x31) }

    context '.get_ace_type' do
      it 'returns allow if ace is nil' do
        allow(ace).to receive(:perm_type).and_return(1) # ensure no false readings
        expect(ace).to receive(:nil?).and_return(true)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_type(ace)).to eq(:allow)
      end

      it 'returns allow when ace.type is 0' do
        expect(ace).to receive(:type).and_return(0)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_type(ace)).to eq :allow
      end

      it 'returns deny when ace.type is 1' do
        expect(ace).to receive(:type).and_return(1)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_type(ace)).to eq :deny
      end
    end

    context '.get_ace_child_types' do
      it 'returns all if ace is nil' do
        allow(ace).to receive(:container_inherit?).and_return(false) # ensure no false readings
        expect(ace).to receive(:nil?).and_return(true)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace)).to eq :all
      end

      it 'returns none when container_inherit and object_inherit are both false' do
        expect(ace).to receive(:container_inherit?).and_return(false).at_least(:once)
        expect(ace).to receive(:object_inherit?).and_return(false).at_least(:once)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace)).to eq :none
      end

      it 'returns objects when container_inherit is false and object_inherit is true' do
        expect(ace).to receive(:container_inherit?).and_return(false).at_least(:once)
        expect(ace).to receive(:object_inherit?).and_return(true).at_least(:once)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace)).to eq :objects
      end

      it 'returns containers when container_inherit is true and object_inherit is false' do
        expect(ace).to receive(:container_inherit?).and_return(true).at_least(:once)
        expect(ace).to receive(:object_inherit?).and_return(false).at_least(:once)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace)).to eq :containers
      end

      it 'returns all when container_inherit and object_inherit are both true' do
        expect(ace).to receive(:container_inherit?).and_return(true).at_least(:once)
        expect(ace).to receive(:object_inherit?).and_return(true).at_least(:once)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_child_types(ace)).to eq :all
      end
    end

    context '.get_ace_propagation' do
      before(:each) do
        allow(ace).to receive(:container_inherit?).and_return(true).at_most(:once)
        allow(ace).to receive(:object_inherit?).and_return(true).at_most(:once)
        allow(ace).to receive(:inherit_only?).and_return(false).at_most(:twice)
      end

      it 'returns all if ace is nil' do
        allow(ace).to receive(:inherit_only?).and_return(true) # ensure no false readings
        expect(ace).to receive(:nil?).and_return(true)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :all
      end

      context 'includes self' do
        it 'returns all when when ace.inherit_only? is false, ace.object_inherit? is true and ace.container_inherit? is true' do
          expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :all
        end

        it 'returns all when when ace.inherit_only? is false, ace.object_inherit? is false and ace.container_inherit? is true (only one container OR object inherit type is required)' do
          expect(ace).to receive(:object_inherit?).and_return(false).at_most(:once)
          expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :all
        end

        it 'returns all when when ace.inherit_only? is false, ace.object_inherit? is true and ace.container_inherit? is true (only one container OR object inherit type is required)' do
          expect(ace).to receive(:container_inherit?).and_return(false).at_most(:once)
          expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :all
        end

        it 'returns self_only when ace.inherit_only? is false, ace.object_inherit? is false and ace.container_inherit? is false' do
          expect(ace).to receive(:container_inherit?).and_return(false).at_most(:once)
          expect(ace).to receive(:object_inherit?).and_return(false).at_most(:once)
          expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :self_only
        end

        it 'returns self_and_direct_children when ace.inherit_only? is false and no_propagation_flag is set' do
          expect(ace).to receive(:flags).and_return(0x4) # http://msdn.microsoft.com/en-us/library/windows/desktop/ms692524(v=vs.85).aspx

          expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :self_and_direct_children_only
        end
      end

      context 'inherit only (IO)' do
        it 'returns children_only when ace.inherit_only? is true and no_propagation_flag is not set' do
          expect(ace).to receive(:container_inherit?).and_return(true).at_most(:once)
          expect(ace).to receive(:object_inherit?).and_return(true).at_most(:once)
          expect(ace).to receive(:inherit_only?).and_return(true).at_most(:twice)
          expect(ace).to receive(:flags).and_return(0x10)

          expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :children_only
        end

        it 'returns direct_children_only when ace.inherit_only? is true and no_propagation_flag is set' do
          expect(ace).to receive(:container_inherit?).and_return(true).at_most(:once)
          expect(ace).to receive(:object_inherit?).and_return(true).at_most(:once)
          expect(ace).to receive(:inherit_only?).and_return(true).at_most(:twice)
          expect(ace).to receive(:flags).and_return(0x4) # http://msdn.microsoft.com/en-us/library/windows/desktop/ms692524(v=vs.85).aspx

          expect(Puppet::Provider::Acl::Windows::Base.get_ace_propagation(ace)).to eq :direct_children_only
        end
      end
    end

    context '.get_ace_rights_from_mask' do
      it 'returns [] if ace is nil?' do
        expect(ace).to receive(:nil?).and_return(true)

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq []
      end

      it 'has only full if ace.mask contains GENERIC_ALL' do
        expect(ace).to receive(:mask).and_return(base::GENERIC_ALL).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:full]
      end

      it 'has only full if ace.mask contains FILE_ALL_ACCESS' do
        expect(ace).to receive(:mask).and_return(base::FILE_ALL_ACCESS).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:full]
      end

      it 'contains read, write, execute if ace.mask contains GENERIC_WRITE, GENERIC_READ, and GENERIC_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::GENERIC_WRITE |
                                   base::GENERIC_READ |
                                   base::GENERIC_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:write, :read, :execute]
      end

      it 'contains read, write, execute if ace.mask contains FILE_GENERIC_WRITE, FILE_GENERIC_READ, and FILE_GENERIC_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_WRITE |
                                   base::FILE_GENERIC_READ |
                                   base::FILE_GENERIC_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:write, :read, :execute]
      end

      it 'contains write, execute if ace.mask contains FILE_GENERIC_WRITE and FILE_GENERIC_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_WRITE |
                                   base::FILE_GENERIC_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:write, :execute]
      end

      it 'contains modify if ace.mask contains GENERIC_WRITE, GENERIC_READ, GENERIC_EXECUTE and contains DELETE' do
        expect(ace).to receive(:mask).and_return(base::GENERIC_WRITE |
                                   base::GENERIC_READ |
                                   base::GENERIC_EXECUTE |
                                   base::DELETE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:modify]
      end

      it 'contains modify if ace.mask contains FILE_GENERIC_WRITE, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE and contains DELETE' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_WRITE |
                                   base::FILE_GENERIC_READ |
                                   base::FILE_GENERIC_EXECUTE |
                                   base::DELETE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:modify]
      end

      it 'contains read, execute if ace.mask contains GENERIC_READ and GENERIC_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::GENERIC_READ |
                                   base::GENERIC_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:read, :execute]
      end

      it 'contains read, execute if ace.mask contains FILE_GENERIC_READ and FILE_GENERIC_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_READ |
                                   base::FILE_GENERIC_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:read, :execute]
      end

      it 'contains write if ace.mask contains GENERIC_WRITE' do
        expect(ace).to receive(:mask).and_return(base::GENERIC_WRITE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:write]
      end

      it 'contains write if ace.mask contains FILE_GENERIC_WRITE' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_WRITE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:write]
      end

      it 'contains mask_specific if ace.mask only contains FILE_WRITE_DATA' do
        expect(ace).to receive(:mask).and_return(base::FILE_WRITE_DATA).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:mask_specific]
      end

      it 'contains mask_specific if ace.mask only contains FILE_APPEND_DATA' do
        expect(ace).to receive(:mask).and_return(base::FILE_APPEND_DATA).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:mask_specific]
      end

      it 'contains read if ace.mask contains GENERIC_READ' do
        expect(ace).to receive(:mask).and_return(base::GENERIC_READ).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:read]
      end

      it 'contains read if ace.mask contains FILE_GENERIC_READ' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_READ).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:read]
      end

      it 'contains mask_specific if ace.mask contains FILE_GENERIC_READ | FILE_WRITE_ATTRIBUTES' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_READ |
                                   base::FILE_WRITE_ATTRIBUTES).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:mask_specific]
      end

      it 'contains mask_specific if ace.mask only contains FILE_READ_DATA' do
        expect(ace).to receive(:mask).and_return(base::FILE_READ_DATA).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:mask_specific]
      end

      it 'contains execute if ace.mask contains GENERIC_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::GENERIC_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:execute]
      end

      it 'contains execute if ace.mask contains FILE_GENERIC_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::FILE_GENERIC_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:execute]
      end

      it 'contains mask_specific if ace.mask only contains FILE_EXECUTE' do
        expect(ace).to receive(:mask).and_return(base::FILE_EXECUTE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:mask_specific]
      end

      it 'contains mask_specific if ace.mask contains permissions too specific' do
        expect(ace).to receive(:mask).and_return(base::DELETE).at_most(10).times

        expect(Puppet::Provider::Acl::Windows::Base.get_ace_rights_from_mask(ace)).to eq [:mask_specific]
      end
    end

    context '.insync?' do
      context 'when purge=>false (the default)' do
        it 'returns true for Administrators and specifying Administrators with same permissions' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], [admins])).to be true
        end

        it 'returns true for Administrators and specifying Administrators even if one specifies sid and other non-required information' do
          admins = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
          admin2 = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'id' => 'S-1-5-32-544', 'mask' => base::GENERIC_ALL, 'is_inherited' => false)
          expect(provider.are_permissions_insync?([admins], [admin2])).to be true
        end

        it 'returns true for Administrators and specifying Administrators when more current permissions exist than are specified' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          admin = Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admin, admins], [admin])).to be true
        end

        it 'returns false for Administrators and specifying Administrators when more current permissions are specified than exist' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          admin = Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admin], [admin, admins])).to be false
        end

        it 'returns false for Administrators and specifying Administrators if rights are different' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          admin2 = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['modify'])
          expect(provider.are_permissions_insync?([admins], [admin2])).to be false
        end

        it 'returns false for Administrators and specifying Administrators if types are different' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'allow')
          admin2 = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'deny')
          expect(provider.are_permissions_insync?([admins], [admin2])).to be false
        end

        it 'returns false for Administrators and specifying Administrators if child_types are different' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'all')
          admin2 = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'none')
          expect(provider.are_permissions_insync?([admins], [admin2])).to be false
        end

        it 'returns false for Administrators and specifying Administrators if affects are different' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all')
          admin2 = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'children_only')
          expect(provider.are_permissions_insync?([admins], [admin2])).to be false
        end

        it 'returns false for Administrators and specifying Administrators if current is inherited' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'is_inherited' => 'true')
          admin2 = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], [admin2])).to be false
        end

        it 'returns true for Administrators and specifying S-1-5-32-544' do
          admins = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
          admin_sid = Puppet::Type::Acl::Ace.new({ 'identity' => 'S-1-5-32-544', 'rights' => ['full'] }, provider)
          expect(provider.are_permissions_insync?([admins], [admin_sid])).to be true
        end

        it 'returns false for nil and specifying Administrators' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?(nil, [admins])).to be false
        end

        it 'returns true for Administrators and specifying nil' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], nil)).to be true
        end

        it 'returns true for Administrators and specifying []' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], [])).to be true
        end

        it 'returns false for [] and specifying Administrators' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([], [admins])).to be false
        end
      end

      context 'when purge=>true' do
        it 'returns true for Administrators and specifying Administrators with same permissions' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], [admins], :true)).to be true
        end

        it 'returns true for Administrators and specifying Administrators even if one specifies sid and other non-required information' do
          admins = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
          admin2 = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'id' => 'S-1-5-32-544', 'mask' => base::GENERIC_ALL, 'is_inherited' => false }, provider)
          expect(provider.are_permissions_insync?([admins], [admin2], :true)).to be true
        end

        it 'returns false for Administrators and specifying Administrators when more current permissions exist than are specified' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          admin = Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admin, admins], [admin], :true)).to be false
        end

        it 'returns false for Administrators and specifying Administrators when more permissions are specified than exist' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          admin = Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admin], [admin, admins], :true)).to be false
        end

        it 'returns false for nil and specifying Administrators' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?(nil, [admins], :true)).to be false
        end

        it 'returns false for Administrators and specifying nil' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], nil, :true)).to be false
        end

        it 'returns false for Administrators and specifying []' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], [], :true)).to be false
        end

        it 'returns false for [] and specifying Administrators' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([], [admins], :true)).to be false
        end
      end

      context 'when purge=>listed_permissions' do
        it 'returns false for Administrators and specifying Administrators with same permissions' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], [admins], :listed_permissions)).to be false
        end

        it 'returns false for Administrators and specifying Administrators even if one specifies sid and other non-required information' do
          admins = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
          admin2 = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'id' => 'S-1-5-32-544', 'mask' => base::GENERIC_ALL, 'is_inherited' => false }, provider)
          expect(provider.are_permissions_insync?([admins], [admin2], :listed_permissions)).to be false
        end

        it 'returns false for Administrators and specifying Administrators when more current permissions exist than are specified' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          admin = Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admin, admins], [admin], :listed_permissions)).to be false
        end

        it 'returns false for Administrators and specifying Administrators when more permissions are specified than exist' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          admin = Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admin], [admin, admins], :listed_permissions)).to be false
        end

        it 'returns true for nil and specifying Administrators' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?(nil, [admins], :listed_permissions)).to be true
        end

        it 'returns true for Administrators and specifying nil' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], nil, :listed_permissions)).to be true
        end

        it 'returns true for Administrators and specifying []' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([admins], [], :listed_permissions)).to be true
        end

        it 'returns true for [] and specifying Administrators' do
          admins = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
          expect(provider.are_permissions_insync?([], [admins], :listed_permissions)).to be true
        end
      end
    end

    context '.get_account_mask' do
      let(:ace) { Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full']) }

      it 'retuns 0 if the ace is nil' do
        expect(Puppet::Provider::Acl::Windows::Base.get_account_mask(nil)).to be 0
      end

      it 'returns ace.mask if the mask has a value' do
        ace.mask = 0x31
        expect(Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)).to be 0x31
      end

      it "returns FILE_ALL_ACCESS if ace.rights includes 'full'" do
        ace.rights = ['full']
        expect(Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)).to be base::FILE_ALL_ACCESS
      end

      it "returns mask including FILE_DELETE if ace.rights includes 'modify'" do
        ace.rights = ['modify']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::DELETE).to be base::DELETE
      end

      it "returns mask including FILE_GENERIC_WRITE if ace.rights includes 'modify'" do
        ace.rights = ['modify']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_WRITE).to be base::FILE_GENERIC_WRITE
      end

      it "returns mask including FILE_GENERIC_READ if ace.rights includes 'modify'" do
        ace.rights = ['modify']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_READ).to be base::FILE_GENERIC_READ
      end

      it "returns mask including FILE_GENERIC_EXECUTE if ace.rights includes 'modify'" do
        ace.rights = ['modify']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_EXECUTE).to be base::FILE_GENERIC_EXECUTE
      end

      it "returns mask that doesn't include FILE_ALL_ACCESS if ace.rights includes 'modify'" do
        ace.rights = ['modify']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_ALL_ACCESS).not_to be base::FILE_ALL_ACCESS
      end

      it "returns mask including FILE_GENERIC_WRITE if ace.rights includes 'write'" do
        ace.rights = ['write']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_WRITE).to be base::FILE_GENERIC_WRITE
      end

      it "returns mask that doesn't include FILE_GENERIC_READ if ace.rights only includes 'write'" do
        ace.rights = ['write']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_READ).not_to be base::FILE_GENERIC_READ
      end

      it "returns mask that doesn't include FILE_GENERIC_EXECUTE if ace.rights only includes 'write'" do
        ace.rights = ['write']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_EXECUTE).not_to be base::FILE_GENERIC_EXECUTE
      end

      it "returns mask including FILE_GENERIC_READ if ace.rights includes 'read'" do
        ace.rights = ['read']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_READ).to be base::FILE_GENERIC_READ
      end

      it "returns mask that doesn't include FILE_GENERIC_WRITE if ace.rights only includes 'read'" do
        ace.rights = ['read']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_WRITE).not_to be base::FILE_GENERIC_WRITE
      end

      it "returns mask that doesn't include FILE_GENERIC_EXECUTE if ace.rights only includes 'read'" do
        ace.rights = ['read']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_EXECUTE).not_to be base::FILE_GENERIC_EXECUTE
      end

      it "returns mask including FILE_GENERIC_EXECUTE if ace.rights only includes 'execute'" do
        ace.rights = ['execute']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_EXECUTE).to be base::FILE_GENERIC_EXECUTE
      end

      it "returns mask that doesn't include FILE_GENERIC_WRITE if ace.rights only includes 'execute'" do
        ace.rights = ['execute']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_WRITE).not_to be base::FILE_GENERIC_WRITE
      end

      it "returns mask that doesn't include FILE_GENERIC_READ if ace.rights only includes 'execute'" do
        ace.rights = ['execute']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_READ).not_to be base::FILE_GENERIC_READ
      end

      it "returns mask that includes FILE_GENERIC_READ if ace.rights == ['read',execute']" do
        ace.rights = ['read', 'execute']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_READ).to be base::FILE_GENERIC_READ
      end

      it "returns mask that includes FILE_GENERIC_EXECUTE if ace.rights == ['read',execute']" do
        ace.rights = ['read', 'execute']
        mask = Puppet::Provider::Acl::Windows::Base.get_account_mask(ace)
        expect(mask & base::FILE_GENERIC_EXECUTE).to be base::FILE_GENERIC_EXECUTE
      end
    end

    context '.get_account_flags' do
      let(:ace) { Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['full']) }

      it "returns (OI)(CI) for child_types => 'all', affects => 'all' (defaults)" do
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        (flags & (Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE)
        ).must be(Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE)
      end

      it "returns 0x0 (no flags) when child_types => 'none'" do
        ace.child_types = 'none'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags).to eq 0x0
      end

      it "returns 0x0 (no flags) when affects => 'self_only'" do
        ace.affects = 'self_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags).to eq 0x0
      end

      it "returns (CI) for child_types => 'containers', affects => 'all'" do
        ace.child_types = 'containers'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE).to be Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE
      end

      it "returns (OI) for child_types => 'objects', affects => 'all'" do
        ace.child_types = 'objects'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE).to be Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE
      end

      it "returns (OI)(CI)(IO) for child_types => 'all', affects => 'children_only'" do
        ace.affects = 'children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)
      end

      it "returns (CI)(IO) for child_types => 'containers', affects => 'children_only'" do
        ace.child_types = 'containers'
        ace.affects = 'children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)
      end

      it "returns (OI)(IO) for child_types => 'objects', affects => 'children_only'" do
        ace.child_types = 'objects'
        ace.affects = 'children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)
      end

      it "returns (OI)(CI)(NP) for child_types => 'all', affects => 'self_and_direct_children_only'" do
        ace.affects = 'self_and_direct_children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE)
      end

      it "returns (CI)(NP) for child_types => 'containers', affects => 'self_and_direct_children_only'" do
        ace.child_types = 'containers'
        ace.affects = 'self_and_direct_children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE)
      end

      it "returns (OI)(NP) for child_types => 'objects', affects => 'self_and_direct_children_only'" do
        ace.child_types = 'objects'
        ace.affects = 'self_and_direct_children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE)
      end

      it "returns (OI)(CI)(IO)(NP) for child_types => 'all', affects => 'direct_children_only'" do
        ace.affects = 'direct_children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)
      end

      it "returns (CI)(IO)(NP) for child_types => 'containers', affects => 'direct_children_only'" do
        ace.child_types = 'containers'
        ace.affects = 'direct_children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)
      end

      it "returns (OI)(IO)(NP) for child_types => 'objects', affects => 'direct_children_only'" do
        ace.child_types = 'objects'
        ace.affects = 'direct_children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags & (Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)).to be(Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                  Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)
      end

      it "returns 0x0 (no flags) when child_types => 'none', affects=> 'children_only' (effectively ignoring affects)" do
        ace.child_types = 'none'
        ace.affects = 'children_only'
        flags = Puppet::Provider::Acl::Windows::Base.get_account_flags(ace)
        expect(flags).to eq 0x0
      end

      it "logs a warning when child_types => 'none' and affects is not 'all' (default) or 'self_only'" do
        expect(Puppet).to receive(:warning) do |arg|
          arg.include?("If child_types => 'none', affects => value")
        end
        ace.child_types = 'none'
        ace.affects = 'children_only'
      end
    end

    context '.sync_aces' do
      let(:current_dacl) { Puppet::Util::Windows::AccessControlList.new }
      let(:should_aces) { [Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']), Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['modify'])] }
      let(:should_purge) { false }

      before :each do
        # explicit (CI)(OI)
        current_dacl.allow(provider.get_account_id('Users'), base::FILE_ALL_ACCESS, Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                                                                                    Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE)
        # explicit (IO) no propagate
        current_dacl.allow(provider.get_account_id('Users'), base::FILE_GENERIC_READ | base::FILE_GENERIC_EXECUTE, Puppet::Util::Windows::AccessControlEntry::NO_PROPAGATE_INHERIT_ACE |
                                                                                                                   Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE)
        # add inherited
        current_dacl.allow(provider.get_account_id('Administrators'), base::FILE_ALL_ACCESS, Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                                                                                             Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                                                                                             Puppet::Util::Windows::AccessControlEntry::INHERITED_ACE)
      end

      it 'ignores the current dacl aces and only return the should aces when purge => true' do
        should_purge = true
        expect(provider.sync_aces(current_dacl, should_aces, should_purge)).to eq should_aces
      end

      it 'does not add inherited to returned aces' do
        current_dacl = Puppet::Util::Windows::AccessControlList.new
        current_dacl.allow(provider.get_account_id('Administrators'), base::FILE_ALL_ACCESS, Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE |
                                                                                             Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
                                                                                             Puppet::Util::Windows::AccessControlEntry::INHERITED_ACE)
        expect(provider.sync_aces(current_dacl, should_aces, should_purge)).to eq should_aces
      end

      it 'adds an unmanaged deny ace to the front of the array' do
        expect(should_aces[0].perm_type).to eq(:allow)
        current_dacl.deny(provider.get_account_id('Administrator'), base::FILE_ALL_ACCESS, 0x0)
        aces = provider.sync_aces(current_dacl, should_aces, should_purge)

        sut_ace = aces[0]
        expect(sut_ace.perm_type).to eq(:deny)
        expect(sut_ace.identity).to eq(provider.get_account_name('Administrator'))
      end

      it 'adds unmanaged deny aces to the front of the array in proper order' do
        expect(should_aces[0].perm_type).to eq(:allow)
        current_dacl.deny(provider.get_account_id('Administrator'), base::FILE_ALL_ACCESS, 0x0)
        current_dacl.deny(provider.get_account_id('Users'), base::FILE_ALL_ACCESS, 0x0)
        aces = provider.sync_aces(current_dacl, should_aces, should_purge)

        sut_ace = aces[0]
        expect(sut_ace.perm_type).to eq(:deny)
        expect(sut_ace.identity).to eq(provider.get_account_name('Administrator'))
      end

      it 'adds unmanaged deny aces after existing managed deny aces' do
        should_aces = [Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'deny'),
                       Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['modify'])]
        current_dacl.deny(provider.get_account_id('Administrator'), base::FILE_ALL_ACCESS, 0x0)
        current_dacl.deny(provider.get_account_id('Users'), base::FILE_ALL_ACCESS, 0x0)
        aces = provider.sync_aces(current_dacl, should_aces, should_purge)

        sut_ace = aces[2]
        expect(sut_ace.perm_type).to eq(:deny)
        expect(sut_ace.identity).to eq(provider.get_account_name('Users'))
      end

      it 'adds unmanaged deny aces after existing managed deny aces when there are no allowed aces' do
        should_aces = [Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'deny')]
        current_dacl = Puppet::Util::Windows::AccessControlList.new
        current_dacl.deny(provider.get_account_id('Administrator'), base::FILE_ALL_ACCESS, 0x0)
        current_dacl.deny(provider.get_account_id('Users'), base::FILE_ALL_ACCESS, 0x0)
        aces = provider.sync_aces(current_dacl, should_aces, should_purge)

        sut_ace = aces[2]
        expect(sut_ace.perm_type).to eq(:deny)
        expect(sut_ace.identity).to eq(provider.get_account_name('Users'))
      end

      it 'adds unmanaged allow aces after existing managed aces' do
        aces = provider.sync_aces(current_dacl, should_aces, should_purge)

        expect(aces.count).to eq(4)
        sut_ace = aces[2]
        expect(sut_ace.identity).to eq(provider.get_account_name('Users'))
      end
    end

    context '.convert_to_dacl' do
      it 'returns properly' do
        resource[:permissions] = { 'identity' => 'Administrator', 'rights' => ['full'] }
        dacl = provider.convert_to_dacl(resource[:permissions])
        dacl.each do |ace|
          expect(ace.sid).to eq(provider.get_account_id('Administrator'))
          expect(ace.mask & base::FILE_ALL_ACCESS).to be(base::FILE_ALL_ACCESS)
        end
      end
    end
  end
end
