require 'spec_helper'
require 'puppet/type'
require 'puppet/provider/acl/windows'

if Puppet.features.microsoft_windows?
  class WindowsSecurityTester
    require 'puppet/util/windows/security'
    include Puppet::Util::Windows::Security
  end
end

describe Puppet::Type.type(:acl).provider(:windows) do
  let(:resource) { Puppet::Type.type(:acl).new(provider: :windows, name: 'windows_acl') }
  let(:provider) { resource.provider }
  let(:top_level_path) do
    Dir.mktmpdir('acl_playground')
  end
  let(:path) { top_level_path }

  def set_path(sub_directory) # rubocop:disable Style/AccessorMethodName
    path = File.join(top_level_path, sub_directory)
    Dir.mkdir(path) unless Dir.exist?(path)

    path
  end

  def set_perms(permissions, include_inherited = false)
    provider.permissions = permissions
    resource.provider.flush

    if include_inherited
      provider.permissions
    else
      provider.permissions.reject { |p| p.inherited? }
    end
  end

  def get_permissions_for_path(path)
    sd = Puppet::Util::Windows::Security.get_security_descriptor(path)

    permissions = []
    sd.dacl.each do |ace|
      permissions << Puppet::Type::Acl::Ace.new(provider.convert_to_permissions_hash(ace), self)
    end

    permissions
  end

  before :each do
    skip 'Not on Windows platform' unless Puppet.features.microsoft_windows?
    resource.provider = provider
  end

  it 'throws an error for an invalid target' do
    resource[:target] = 'c:/somwerhaear2132312323123123123123123_does_not_exist'

    expect {
      provider.owner.not_to be_nil
    }.to raise_error(Exception, %r{Failed to get security descriptor for path})
  end

  context ':target' do
    before :each do
      resource[:target] = set_path('set_target')
    end

    it 'does not allow permissions to be set on directory symlinks (PUP-2338)',
       if: Puppet.features.manages_symlinks? do
      target_path = set_path('symlink_target')
      resource[:target] = File.expand_path('fake', resource[:target])
      Puppet::Util::Windows::File.symlink(target_path, resource[:target])

      expect {
        resource.validate
      }.to raise_error(Puppet::ResourceError, %r{Puppet cannot manage ACLs of symbolic links})
    end

    it 'does not allow permissions to be set on file symlinks (PUP-2338)',
       if: Puppet.features.manages_symlinks? do
      target_path = set_path('symlink_target')
      file_path = File.join(target_path, 'file.txt')
      FileUtils.touch(file_path)
      resource[:target] = File.expand_path('fakefile.txt', resource[:target])
      Puppet::Util::Windows::File.symlink(file_path, resource[:target])

      expect {
        resource.validate
      }.to raise_error(Puppet::ResourceError, %r{Puppet cannot manage ACLs of symbolic links})
    end
  end

  context ':owner' do
    before :each do
      resource[:target] = set_path('owner_stuff')
    end

    it 'is not nil' do
      expect(provider.owner).not_to be_nil
    end

    it 'grabs current owner' do
      expect(provider.owner).to eq('S-1-5-32-544')
    end

    context '.flush' do
      before :each do
        resource[:target] = set_path('set_owner')
      end

      it 'updates owner to Administrator properly' do
        expect(provider.owner).to eq('S-1-5-32-544')
        provider.owner = 'Administrator'

        resource.provider.flush

        expect(provider.owner).to eq(provider.get_account_id('Administrator'))
      end

      it 'does not update owner to a user that does not exist' do
        expect {
          provider.owner = 'someuser1231235123112312312'
        }.to raise_error(Exception, %r{User does not exist})
      end
    end
  end

  context ':group' do
    before :each do
      resource[:target] = set_path('group_stuff')
    end

    it 'is not nil' do # rubocop:disable RSpec/RepeatedExample
      expect(provider.group).not_to be_nil
    end

    it 'grabs current group' do # rubocop:disable RSpec/RepeatedExample
      # there really isn't a default group, it depends on the primary group of the original CREATOR GROUP of a resource.
      # http://msdn.microsoft.com/en-us/library/windows/desktop/ms676927(v=vs.85).aspx
      expect(provider.group).not_to be_nil
    end

    context '.flush' do
      before :each do
        resource[:target] = set_path('set_group')
      end

      it 'updates group to Administrator properly' do
        expect(provider.group).not_to be_nil
        if provider.group == provider.get_account_id('Administrator')
          provider.group = 'Users'
          resource.provider.flush
        end
        expect(provider.group).not_to eq(provider.get_account_id('Administrator'))
        provider.group = 'Administrator'

        resource.provider.flush

        expect(provider.group).to eq(provider.get_account_id('Administrator'))
      end

      it 'does not update group to a group that does not exist' do
        expect {
          provider.group = 'somegroup1231235123112312312'
        }.to raise_error(Exception, %r{Group does not exist})
      end
    end
  end

  context ':inherit_parent_permissions' do
    before :each do
      resource[:target] = set_path('inheritance_stuff')
    end

    it 'is not nil' do
      expect(provider.inherit_parent_permissions).not_to be_nil
    end

    it 'is true by default' do
      expect(provider.inherit_parent_permissions).to be_truthy
    end

    context '.flush' do
      before :each do
        resource[:target] = set_path('set_inheritance')
      end

      it 'does nothing if inheritance is set to true (default)' do
        expect(provider.inherit_parent_permissions).to be_truthy

        # puppet will not make this call if values are in sync
        # provider.inherit_parent_permissions = :true

        expect(resource.provider).to receive(:set_security_descriptor).never

        resource.provider.flush
      end

      it 'updates inheritance to false when set to :false' do
        expect(provider.inherit_parent_permissions).to be_truthy
        provider.inherit_parent_permissions = false

        resource.provider.flush

        expect(provider.inherit_parent_permissions).to be false
      end
    end
  end

  context ':permissions' do
    before :each do
      resource[:target] = set_path('permissions_stuff')
    end

    it 'is not nil' do
      expect(provider.permissions).not_to be_nil
    end

    it 'contains at least one ace' do
      expect(provider.permissions.count).not_to eq 0
    end

    it 'contains aces that are access allowed' do
      at_least_one = false
      provider.permissions.each do |ace|
        if ace.perm_type == :allow
          at_least_one = true
          break
        end
      end

      expect(at_least_one).to be_truthy
    end

    it 'contains aces that allow inheritance' do
      at_least_one = false
      provider.permissions.each do |ace|
        case ace.child_types
        when :all, :objects, :containers
          at_least_one = true
          break
        end
      end

      expect(at_least_one).to be_truthy
    end

    it 'contains aces that are inherited' do
      at_least_one = false
      provider.permissions.each do |ace|
        if ace.inherited?
          at_least_one = true
          break
        end
      end

      expect(at_least_one).to be_truthy
    end

    it 'contains aces that propagate inheritance' do
      at_least_one = false
      provider.permissions.each do |ace|
        case ace.affects
        when :all, :children_only, :self_and_direct_children_only, :direct_children_only
          at_least_one = true
          break
        end
      end

      expect(at_least_one).to be_truthy
    end

    context 'when setting permissions' do
      before :each do
        resource[:target] = set_path('set_perms')
      end

      it 'does not allow permissions to be set to a user that does not exist' do
        permissions = [Puppet::Type::Acl::Ace.new('identity' => 'someuser1231235123112312312', 'rights' => ['full'])]

        expect {
          provider.permissions = permissions
        }.to raise_error(Exception, %r{User or users do not exist})
      end

      it 'handles minimally specified permissions' do
        skip 'Not on Windows platform' unless Puppet.features.microsoft_windows?
        permissions = [Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider)]
        expect(set_perms(permissions)).to eq permissions
      end

      it 'handles fully specified permissions' do
        skip 'Not on Windows platform' unless Puppet.features.microsoft_windows?
        permissions = [Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'], 'perm_type' => 'allow', 'child_types' => 'all', 'affects' => 'all' }, provider)]
        expect(set_perms(permissions)).to eq permissions
      end

      [
        # 2012R2 (kernel 6.3) required for ALL APPLICATION PACKAGES
        { min_kernel: 6.3, identity: 'ALL APPLICATION PACKAGES' },
        { min_kernel: 6.3, identity: 'S-1-15-2-1' },
        # 2016 (kernel 10.0) required for ALL RESTRICTED APPLICATION PACKAGES
        { min_kernel: 10.0, identity: 'ALL RESTRICTED APPLICATION PACKAGES' },
        { min_kernel: 10.0, identity: 'S-1-15-2-2' },
      ].each do |account|
        it "should not error when referencing special account #{account[:identity]}",
           if: (Facter[:kernelmajversion].value.to_f >= account[:min_kernel]) do

          permissions = [Puppet::Type::Acl::Ace.new({ 'identity' => account[:identity], 'rights' => ['full'] }, provider)]
          expect(set_perms(permissions)).to eq permissions
          # permissions = get_permissions_for_path(resource[:target]).select { |p| !p.inherited? }
          # expect(set_perms(removing_perms)).to eq (permissions - removing_perms)
        end
      end

      it 'handles multiple users' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrator', 'rights' => ['modify'] }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['write', 'read', 'execute'] }, provider),
        ]
        expect(set_perms(permissions)).to eq permissions
      end

      it 'handles setting folder protected' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider),
        ]
        provider.inherit_parent_permissions = :false

        expect(set_perms(permissions)).to eq(permissions)

        perms_not_empty = false
        all_perms = get_permissions_for_path(resource[:target])
        all_perms.each do |perm|
          perms_not_empty = true
          expect(perm.inherited?).to eq(false)
        end

        expect(perms_not_empty).to eq(true)
      end

      it 'handles file permissions' do
        file_path = File.join(resource[:target], 'file.txt')
        FileUtils.touch(file_path)
        resource[:target] = file_path
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider),
        ]
        resource[:purge] = true
        provider.inherit_parent_permissions = :false

        expect(set_perms(permissions)).to eq permissions
      end

      it 'handles setting ace inheritance' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'containers' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrator', 'rights' => ['full'], 'child_types' => 'objects' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['full'], 'child_types' => 'none' }, provider),
        ]
        resource[:purge] = :true
        provider.inherit_parent_permissions = :false

        expect(set_perms(permissions)).to eq permissions
      end

      it 'handles extraneous rights' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full', 'modify'] }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrator', 'rights' => ['modify', 'read'] }, provider),
        ]
        resource[:purge] = :true
        provider.inherit_parent_permissions = :false

        actual_perms = set_perms(permissions)

        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrator', 'rights' => ['modify'] }, provider),
        ]

        expect(actual_perms).to eq permissions
      end

      it 'handles deny' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrator', 'rights' => ['full'], 'perm_type' => 'deny' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider),
        ]
        resource[:purge] = :true
        provider.inherit_parent_permissions = :false

        actual = set_perms(permissions)

        expect(actual).to eq permissions
      end

      it "handles deny when affects => 'self_only'" do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrator', 'rights' => ['full'], 'perm_type' => 'deny', 'affects' => 'self_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider),
        ]
        resource[:purge] = :true
        provider.inherit_parent_permissions = :false

        expect(set_perms(permissions)).to eq permissions
      end

      it 'handles the same user with differing permissions appropriately' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['modify'], 'child_types' => 'none' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['modify'], 'child_types' => 'containers' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['modify'], 'child_types' => 'objects' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['full'], 'affects' => 'self_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['read', 'execute'], 'affects' => 'direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['read', 'execute'], 'child_types' => 'containers', 'affects' => 'direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['read', 'execute'], 'child_types' => 'objects', 'affects' => 'direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['full'], 'affects' => 'children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['full'], 'child_types' => 'containers', 'affects' => 'children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['full'], 'child_types' => 'objects', 'affects' => 'children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['read'], 'affects' => 'self_and_direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['read'], 'child_types' => 'containers', 'affects' => 'self_and_direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'SYSTEM', 'rights' => ['read'], 'child_types' => 'objects', 'affects' => 'self_and_direct_children_only' }, provider),
        ]
        resource[:purge] = :true
        provider.inherit_parent_permissions = :false

        expect(set_perms(permissions)).to eq permissions
      end

      it 'handles setting propagation appropriately' do
        # tried to split this one up into multiple assertions but rspec mocks me
        path = set_path('set_perms_propagation')
        resource[:target] = path
        child_path = File.join(path, 'child_folder')
        Dir.mkdir(child_path) unless Dir.exist?(child_path)
        child_file = File.join(path, 'child_file.txt')
        File.new(child_file, 'w').close
        grandchild_file = File.join(child_path, 'grandchild_file.txt')
        File.new(grandchild_file, 'w').close
        grandchild_path = File.join(child_path, 'grandchild_folder')
        Dir.mkdir(grandchild_path) unless Dir.exist?(grandchild_path)

        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['write', 'read'], 'child_types' => 'objects', 'affects' => 'all' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['read'], 'child_types' => 'containers', 'affects' => 'all' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrator', 'rights' => ['modify'], 'affects' => 'self_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['full'], 'affects' => 'direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['modify'], 'child_types' => 'objects', 'affects' => 'direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['read'], 'child_types' => 'containers', 'affects' => 'direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['read'], 'affects' => 'children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['read', 'execute'], 'child_types' => 'objects', 'affects' => 'children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['modify'], 'child_types' => 'containers', 'affects' => 'children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['read'], 'affects' => 'self_and_direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['execute'], 'child_types' => 'objects', 'affects' => 'self_and_direct_children_only' }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['write', 'read'], 'child_types' => 'containers', 'affects' => 'self_and_direct_children_only' }, provider),
        ]
        resource[:purge] = :true
        provider.inherit_parent_permissions = :false

        expect(set_perms(permissions)).to eq(permissions)

        # TODO: None of the following code is an expectation and rspec was not treating as such, however the tests are broken.  Disabling for the moment
        # rubocop:disable Metrics/LineLength
        # # child object
        # permissions = [
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => %w[write read], 'child_types' => 'objects', 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['full'], 'affects' => 'direct_children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['modify'], 'child_types' => 'objects', 'affects' => 'direct_children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['read'], 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => %w[read execute], 'child_types' => 'objects', 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['read'], 'affects' => 'self_and_direct_children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['execute'], 'child_types' => 'objects', 'affects' => 'self_and_direct_children_only', 'is_inherited' => 'true' }, provider),
        # ]
        # get_permissions_for_path(child_file) == permissions

        # # grandchild object
        # permissions = [
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => %w[write read], 'child_types' => 'objects', 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['read'], 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => %w[read execute], 'child_types' => 'objects', 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        # ]
        # get_permissions_for_path(grandchild_file) == permissions

        # # child container
        # permissions = [
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['read'], 'child_types' => 'containers', 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['full'], 'affects' => 'direct_children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Authenticated Users', 'rights' => ['read'], 'child_types' => 'containers', 'affects' => 'direct_children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['read'], 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['modify'], 'child_types' => 'containers', 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['read'], 'affects' => 'self_and_direct_children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => %w[write read], 'child_types' => 'containers', 'affects' => 'self_and_direct_children_only', 'is_inherited' => 'true' }, provider),
        # ]
        # get_permissions_for_path(child_path) == permissions

        # # grandchild container
        # permissions = [
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['read'], 'child_types' => 'containers', 'affects' => 'all', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['read'], 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        #   Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['modify'], 'child_types' => 'containers', 'affects' => 'children_only', 'is_inherited' => 'true' }, provider),
        # ]
        # get_permissions_for_path(grandchild_path) == permissions
        # rubocop:enable Metrics/LineLength
      end
    end
  end

  context ':purge' do
    before :each do
      resource[:target] = set_path('purge_stuff')
    end

    context 'purge => true' do
      it 'removes unspecified explicit permissions' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['full'] }, provider),
        ]
        resource[:purge] = :true

        expect(set_perms(permissions)).to eq(permissions)

        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider),
        ]

        expect(set_perms(permissions)).to eq(permissions)
      end

      it 'with inherit_parent_permissions => false, should remove all but specified permissions' do
        permissions = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider),
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Users', 'rights' => ['full'] }, provider),
        ]
        resource[:purge] = :true
        provider.inherit_parent_permissions = :false

        expect(set_perms(permissions)).to eq(permissions)
        # all permissions including inherited should also be the same
        expect(get_permissions_for_path(resource[:target])).to eq(permissions)
      end

      context 'when purge => true with a pre-existing manifest and inherit parent permissions is then set false (PUP-2036)' do
        let(:permissions_hash) do
          [
            { 'identity' => 'Administrators', 'rights' => ['full'] },
            { 'identity' => 'SYSTEM', 'rights' => ['full'] },
            { 'identity' => 'Administrator', 'rights' => ['modify'] },
          ]
        end

        let(:permissions) do
          [
            Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']),
            Puppet::Type::Acl::Ace.new('identity' => 'SYSTEM', 'rights' => ['full']),
            Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['modify']),
          ]
        end

        before :each do
          resource[:target] = set_path('perms_purge_true_inherit_false_second_sync')
          resource[:purge] = true
          permissions.each do |perm|
            perm.id = provider.get_account_id(perm.identity)
            perm.identity = provider.get_account_name(perm.identity)
          end
          resource[:permissions] = permissions_hash
        end

        it 'removes the permissions successfully' do
          expect(set_perms(permissions)).to eq permissions

          provider.inherit_parent_permissions = false
          resource.provider.flush

          expect(provider.permissions).to eq permissions
        end
      end
    end

    context 'purge => listed_permissions' do
      let(:permissions) do
        [
          Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full']),
          Puppet::Type::Acl::Ace.new('identity' => 'Administrator', 'rights' => ['modify']),
          Puppet::Type::Acl::Ace.new('identity' => 'Authenticated Users', 'rights' => ['write', 'read', 'execute']),
        ]
      end

      before :each do
        resource[:target] = set_path('perms_remove')
        permissions.each do |perm|
          perm.id = provider.get_account_id(perm.identity)
        end
      end

      it 'removes specified permissions' do
        expect(set_perms(permissions)).to eq(permissions)
        resource[:purge] = :listed_permissions
        removing_perms = [
          Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider),
        ]

        expect(set_perms(removing_perms)).to eq(permissions - removing_perms)
      end

      context 'when removing non-existing users' do
        begin
          require 'puppet/util/windows/adsi' if Puppet.features.microsoft_windows?
        rescue LoadError
          require 'puppet/util/adsi'
        end

        let(:adsi) { Puppet::Util::Windows.constants.include?(:ADSI) ? Puppet::Util::Windows::ADSI : Puppet::Util::ADSI }

        it 'allows it to work with SIDs' do
          user_name = 'jimmy123456_randomyo'

          user = adsi::User.create(user_name) unless adsi::User.exists?(user_name)
          user = adsi::User.new(user_name) if adsi::User.exists?(user_name)
          user.commit
          sid = user.sid.to_s

          permissions = [
            Puppet::Type::Acl::Ace.new({ 'identity' => user_name, 'rights' => ['modify'] }, provider),
          ]
          expect(set_perms(permissions)).to eq(permissions)

          adsi::User.delete(user_name)

          resource[:purge] = :listed_permissions
          removing_perms = [
            Puppet::Type::Acl::Ace.new({ 'identity' => sid, 'rights' => ['modify'] }, provider),
          ]

          permissions = get_permissions_for_path(resource[:target]).reject { |p| p.inherited? }
          expect(set_perms(removing_perms)).to eq(permissions - removing_perms)
        end
      end
    end
  end

  context '.set_security_descriptor' do
    it 'handles nil security descriptor appropriately' do
      expect {
        provider.set_security_descriptor(nil)
      }.to raise_error(Exception, %r{Failed to set security descriptor for path})
    end
  end
end
