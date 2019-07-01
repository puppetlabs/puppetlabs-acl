require 'spec_helper'
require 'puppet/type'
require 'puppet/type/acl'

def is_puppet_5?
  Gem::Version.new(Puppet::PUPPETVERSION.dup.freeze) >= Gem::Version.new('5.0.0')
end

describe Puppet::Type.type(:acl) do
  let(:resource) { Puppet::Type.type(:acl).new(name: 'acl') }
  let(:provider) { Puppet::Provider.new(resource) }
  let(:catalog) { Puppet::Resource::Catalog.new }

  before :each do
    resource.provider = provider
  end

  it 'is an instance of Puppet::Type::Acl' do
    resource.must be_an_instance_of Puppet::Type::Acl
  end

  context 'parameter :name' do
    it 'is the name var' do
      resource.parameters[:name].isnamevar?.should be_truthy
    end

    it 'does not allow nil' do
      expect {
        resource[:name] = nil
      }.to raise_error(Puppet::Error, %r{Got nil value for name})
    end

    it 'does not allow empty' do
      expect {
        resource[:name] = ''
      }.to raise_error(Puppet::ResourceError, %r{A non-empty name must})
    end

    it 'accepts any string value' do
      resource[:name] = 'value'
      resource[:name] = 'c:/thisstring-location/value/somefile.txt'
      resource[:name] = 'c:\\thisstring-location\\value\\somefile.txt'
    end
  end

  context 'parameter :target' do
    it 'defaults to name' do
      resource[:target].must == resource[:name]
    end

    it 'does not allow nil' do
      expect {
        resource[:target] = nil
      }.to raise_error(Puppet::Error, %r{Got nil value for target})
    end

    it 'does not allow empty' do
      expect {
        resource[:target] = ''
      }.to raise_error(Puppet::ResourceError, %r{A non-empty target must})
    end

    it 'accepts any string value' do
      resource[:target] = 'value'
      resource[:target] = 'c:/thisstring-location/value/somefile.txt'
      resource[:target] = 'c:\\thisstring-location\\value\\somefile.txt'
    end

    it 'does not override :name' do
      resource[:target] = 'somevalue'
      resource[:target].should_not == resource[:name]
    end
  end

  context 'parameter :target_type' do
    it 'defaults to :file' do
      resource[:target_type].must == :file
    end

    it 'accepts :file' do
      resource[:target_type] = :file
    end

    it 'rejects any other value' do
      expect {
        resource[:target_type] = :whenever
      }.to raise_error(Puppet::ResourceError, %r{Invalid value :whenever. Valid values are file})
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
        reqs.must be_empty
      end

      it 'does not autorequire owner when set to unspecified' do # rubocop:disable RSpec/RepeatedExample
        test_should_not_set_autorequired_user('Administrators')
      end

      it 'autorequires owner when set to Administrators' do
        resource[:owner] = 'Administrators'
        test_should_set_autorequired_user(resource[:owner])
      end

      it 'does not autorequire group when set to unspecified' do # rubocop:disable RSpec/RepeatedExample
        test_should_not_set_autorequired_user('Administrators')
      end

      it 'autorequires group when set to Administrators' do
        resource[:group] = 'Administrators'
        test_should_set_autorequired_user(resource[:group])
      end

      it 'does not autorequire Administrators if owner is set to the default Administrators SID' do # rubocop:disable RSpec/RepeatedExample
        # we have no way at the type level of knowing that Administrators == S-1-5-32-544 - this would require a call to the provider
        # unfortunately even in the provider we get the full account name 'BUILTIN\Administrators' which doesn't match Administrators
        test_should_not_set_autorequired_user('Administrators')
      end

      it 'does not autorequire BUILTIN\\Administrators if owner is set to the default Administrators SID' do
        # we have no way at the type level of knowing that BUILTIN\Administrators == S-1-5-32-544 - this would require a call to the provider
        # check the provider for a similar test that notes the require works
        test_should_not_set_autorequired_user('BUILTIN\Administrators')
      end

      it 'autorequires identities in permissions' do
        user_name = 'bob'
        resource[:permissions] = [{ 'identity' => 'bill', 'rights' => ['modify'] }, { 'identity' => user_name, 'rights' => ['full'] }]
        test_should_set_autorequired_user(user_name)
      end

      it 'autorequires identities in permissions once even when included more than once' do
        user_name = 'bob'
        resource[:permissions] = [{ 'identity' => user_name, 'rights' => ['modify'], 'affects' => 'children_only' }, { 'identity' => user_name, 'rights' => ['full'] }]
        test_should_set_autorequired_user(user_name)
      end

      it 'does not autorequire users that are not part of the owner or permission identities' do
        resource[:permissions] = [{ 'identity' => 'bob', 'rights' => ['modify'] }]
        test_should_not_set_autorequired_user('bill')
      end

      it 'does not autorequire identities/owner if their is not a match to a user in the catalog' do
        resource[:owner] = 'Administrators'
        resource[:permissions] = [{ 'identity' => 'bob', 'rights' => ['modify'] }]
        catalog.add_resource resource

        reqs = resource.autorequire
        reqs.must be_empty
      end
    end

    context 'groups' do
      def test_should_set_autorequired_group(group_name)
        group = Puppet::Type.type(:group).new(name: group_name)
        catalog.add_resource resource
        catalog.add_resource group

        reqs = resource.autorequire
        expect(reqs.count).to eq(1)
        expect(reqs[0].source).to eq(group)
        expect(reqs[0].target).to eq(resource)
      end

      def test_should_not_set_autorequired_group(group_name)
        group = Puppet::Type.type(:group).new(name: group_name)
        catalog.add_resource resource
        catalog.add_resource group

        reqs = resource.autorequire
        reqs.must be_empty
      end

      it 'does not autorequire owner when set to unspecified' do # rubocop:disable RSpec/RepeatedExample
        test_should_not_set_autorequired_group('Administrators')
      end

      it 'autorequires owner when set to Administrators' do
        resource[:owner] = 'Administrators'
        test_should_set_autorequired_group(resource[:owner])
      end

      it 'does not autorequire group when set to unspecified' do # rubocop:disable RSpec/RepeatedExample
        test_should_not_set_autorequired_group('Administrators')
      end

      it 'autorequires group when set to Administrators' do
        resource[:group] = 'Administrators'
        test_should_set_autorequired_group(resource[:group])
      end

      it 'does not autorequire Administrators if owner is set to the default Administrators SID' do # rubocop:disable RSpec/RepeatedExample
        # we have no way at the type level of knowing that Administrators == S-1-5-32-544 - this would require a call to the provider
        # unfortunately even in the provider we get the full account name 'BUILTIN\Administrators' which doesn't match Administrators
        test_should_not_set_autorequired_group('Administrators')
      end

      it 'does not autorequire BUILTIN\\Administrators if owner is set to the default Administrators SID' do
        # we have no way at the type level of knowing that BUILTIN\Administrators == S-1-5-32-544 - this would require a call to the provider
        # check the provider for a similar test that notes the require works
        test_should_not_set_autorequired_group('BUILTIN\Administrators')
      end

      it 'autorequires identities in permissions' do
        user_name = 'bob'
        resource[:permissions] = [{ 'identity' => 'bill', 'rights' => ['modify'] }, { 'identity' => user_name, 'rights' => ['full'] }]
        test_should_set_autorequired_group(user_name)
      end

      it 'autorequires identities in permissions once even when included more than once' do
        user_name = 'bob'
        resource[:permissions] = [{ 'identity' => user_name, 'rights' => ['modify'], 'affects' => 'children_only' }, { 'identity' => user_name, 'rights' => ['full'] }]
        test_should_set_autorequired_group(user_name)
      end

      it 'does not autorequire groups that are not part of the owner or permission identities' do
        resource[:permissions] = [{ 'identity' => 'bob', 'rights' => ['modify'] }]
        test_should_not_set_autorequired_group('bill')
      end

      it 'does not autorequire identities/owner if their is not a match to a group in the catalog' do
        resource[:owner] = 'Administrators'
        resource[:permissions] = [{ 'identity' => 'bob', 'rights' => ['modify'] }]
        catalog.add_resource resource

        reqs = resource.autorequire
        reqs.must be_empty
      end
    end

    # :as_platform => :windows - doesn't exist outside of puppet?
    context 'when :target_type => :file' do
      def test_should_set_autorequired_file(resource_path, file_path)
        resource[:target] = resource_path
        dir = Puppet::Type.type(:file).new(path: file_path)
        catalog.add_resource resource
        catalog.add_resource dir
        reqs = resource.autorequire

        expect(reqs.count).to eq(1)
        expect(reqs[0].source).to eq(dir)
        expect(reqs[0].target).to eq(resource)
      end

      def test_should_not_set_autorequired_file(resource_path, file_path)
        resource[:target] = resource_path
        dir = Puppet::Type.type(:file).new(path: file_path)
        catalog.add_resource resource
        catalog.add_resource dir
        reqs = resource.autorequire

        reqs.must be_empty
      end

      before :each do
        skip 'Not on Windows platform' unless Puppet.features.microsoft_windows?
      end

      it 'autorequires an existing file resource when acl.target matches file.path exactly' do
        test_should_set_autorequired_file('c:/temp', 'c:/temp')
      end

      it 'autorequires an existing file resource when acl.target uses back slashes and file.path uses forward slashes' do
        test_should_set_autorequired_file('c:\temp', 'c:/temp')
      end

      it 'autorequires an existing file resource when acl.target uses forward slashes and file.path uses back slashes' do
        test_should_set_autorequired_file('c:/temp', 'c:\temp')
      end

      it 'autorequires an existing file resource when acl.target volume is uppercase C and file.path is uppercase C' do
        test_should_set_autorequired_file('C:/temp', 'C:/temp')
      end

      it 'does not autorequire an existing file resource when acl.target volume is uppercase C and file.path is lowercase c' do
        test_should_not_set_autorequired_file('C:/temp', 'c:/temp')
      end

      it 'does not autorequire an existing file resource when acl.target volume is lowercase C and file.path is uppercase C' do
        test_should_not_set_autorequired_file('c:/temp', 'C:/temp')
      end

      it 'does not autorequire an existing file resource when it is different than acl.target' do
        resource[:target] = 'c:/temp'
        dir = Puppet::Type.type(:file).new(path: 'c:/temp/something')
        catalog.add_resource resource
        catalog.add_resource dir
        reqs = resource.autorequire

        reqs.must be_empty
      end
    end
  end

  context 'parameter :purge' do
    it 'defaults to nil' do
      resource[:purge].must == :false
    end

    it 'accepts true' do
      resource[:purge] = true
    end

    it 'accepts false' do
      resource[:purge] = false
    end

    it "accepts 'true'" do
      resource[:purge] = 'true'
    end

    it "accepts 'false'" do
      resource[:purge] = 'false'
    end

    it 'accepts :true' do
      resource[:purge] = :true
    end

    it 'accepts :false' do
      resource[:purge] = :false
    end

    it 'accepts :listed_permissions' do
      resource[:purge] = :listed_permissions
    end

    it 'rejects non-boolean values' do
      expect {
        resource[:purge] = :whenever
      }.to raise_error(Puppet::ResourceError, %r{Invalid value :whenever. Valid values are true})
    end
  end

  context 'property :owner' do
    it 'defaults to use the default unspecified group' do
      resource[:owner].must be_nil
    end

    it 'accepts bob' do
      resource[:owner] = 'bob'
    end

    it 'accepts Domain\\Bob' do
      resource[:owner] = 'Domain\Bob'
    end

    it 'accepts SIDs like S-1-5-32-544' do
      resource[:owner] = 'S-1-5-32-544'
    end

    it 'does not allow nil' do
      expect {
        resource[:owner] = nil
      }.to raise_error(Puppet::Error, %r{Got nil value for owner})
    end

    it 'does not allow empty' do
      expect {
        resource[:owner] = ''
      }.to raise_error(Puppet::ResourceError, %r{A non-empty owner must})
    end

    it 'accepts any string value' do
      resource[:owner] = 'value'
      resource[:owner] = 'c:/thisstring-location/value/somefile.txt'
      resource[:owner] = 'c:\\thisstring-location\\value\\somefile.txt'
    end
  end

  context 'property :group' do
    it 'defaults to use the default unspecified group' do
      resource[:group].must be_nil
    end

    it 'accepts bob' do
      resource[:group] = 'bob'
    end

    it 'accepts Domain\\Bob' do
      resource[:group] = 'Domain\Bob'
    end

    it 'accepts SIDs like S-1-5-32-544' do
      resource[:group] = 'S-1-5-32-544'
    end

    it 'does not allow nil' do
      expect {
        resource[:group] = nil
      }.to raise_error(Puppet::Error, %r{Got nil value for group})
    end

    it 'does not allow empty' do
      expect {
        resource[:group] = ''
      }.to raise_error(Puppet::ResourceError, %r{A non-empty group must})
    end

    it 'accepts any string value' do
      resource[:group] = 'value'
      resource[:group] = 'c:/thisstring-location/value/somefile.txt'
      resource[:group] = 'c:\\thisstring-location\\value\\somefile.txt'
    end
  end

  context 'property :inherit_parent_permissions' do
    it 'defaults to true' do
      resource[:inherit_parent_permissions].must == :true
    end

    context 'when the provider has implemented :can_inherit_parent_permissions' do
      before :each do
        resource.provider.class.expects(:satisfies?).with(:can_inherit_parent_permissions).returns(true)
      end

      it 'accepts true' do
        resource[:inherit_parent_permissions] = true
      end

      it 'accepts false' do
        resource[:inherit_parent_permissions] = false
      end

      it 'rejects non-boolean values' do
        expect {
          resource[:inherit_parent_permissions] = :whenever
        }.to raise_error(Puppet::ResourceError, %r{Invalid value :whenever. Valid values are true})
      end
    end
  end

  context 'property :permissions' do
    it 'does not accept empty array' do
      expect {
        Puppet::Type.type(:acl).new(name: 'acl', permissions: [])
      }.to raise_error(Puppet::ResourceError, %r{Value for permissions should be an array with at least one element specified})
    end

    it 'does not allow empty string' do
      expect {
        resource[:permissions] = ''
      }.to raise_error(Puppet::ResourceError, %r{A non-empty permissions must be})
    end

    it 'does not allow nil' do
      expect {
        resource[:permissions] = nil
      }.to raise_error(Puppet::Error, %r{Got nil value for permissions})
    end

    it 'is of type Array' do
      resource[:permissions] = [{ 'identity' => 'bob', 'rights' => ['full'] }]
      resource[:permissions].must be_an_instance_of Array
    end

    it 'is an array that has elements of type Puppet::Type::Acl::Ace' do
      resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }
      resource[:permissions].each do |permission|
        permission.must be_an_instance_of Puppet::Type::Acl::Ace
      end
    end

    it 'does not allow inherited aces in manifests' do
      expect {
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'is_inherited' => 'true' }
      }.to raise_error(Puppet::ResourceError, %r{Puppet can not manage inherited ACEs})
    end

    it "does not log a warning when an ace contains child_types => 'none' and affects => 'self_only'" do
      Puppet.expects(:warning).never
      resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'none', 'affects' => 'self_only' }
    end

    it "does not log a warning when an ace contains child_types => 'none' and affects is set to 'all' (default)" do
      Puppet.expects(:warning).never
      resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'none' }
    end

    it "does not log a warning when an ace contains affects => 'self_only' and child_types is set to 'all' (default)" do
      Puppet.expects(:warning).never
      resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'self_only' }
    end

    it "logs a warning when an ace contains child_types => 'none' and affects is not 'all' (default) or 'self_only'" do
      Puppet.expects(:warning).with do |v|
        %r{If child_types => 'none', affects => value}.match(v)
      end
      resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'none', 'affects' => 'children_only' }
    end

    it "logs a warning when an ace contains affects => 'self_only' and child_types is not 'all' (default) or 'none'" do
      Puppet.expects(:warning).with do |v|
        %r{If affects => 'self_only', child_types => value}.match(v)
      end
      resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'containers', 'affects' => 'self_only' }
    end

    context 'formatting' do
      it 'when called from puppet resource should format like a hash and ASCIIbetical order properties in Puppet 4 when displaying / adhere to desired ordering in Puppet 5' do
        # properties are out of order here
        resource[:permissions] = [{ 'rights' => ['full'], 'child_types' => 'containers', 'identity' => 'bob' }, { 'rights' => ['full'], 'identity' => 'tim' }]

        # ordered asciibetically
        expected = if is_puppet_5?
                     "[
  {'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'containers'},
  {'identity' => 'tim', 'rights' => ['full']}]"
                   else
                     "[{'child_types' => 'containers', 'identity' => 'bob', 'rights' => ['full']}, {'identity' => 'tim', 'rights' => ['full']}]"
                   end

        Puppet::Parameter.format_value_for_display(resource[:permissions]).should == expected
      end

      it 'when called from puppet should format much better when displaying' do
        # properties are out of order here
        resource[:permissions] = [{ 'rights' => ['read', 'write'], 'perm_type' => 'deny', 'child_types' => 'containers', 'identity' => 'bob' }, { 'rights' => ['full'], 'identity' => 'tim' }]

        # and spaced / ordered properly here
        expected = "[
 { identity => 'bob', rights => [\"write\", \"read\"], perm_type => 'deny', child_types => 'containers' },\s
 { identity => 'tim', rights => [\"full\"] }
]"

        resource.parameters[:permissions].class.format_value_for_display(resource[:permissions]).should == expected
      end
    end

    context ':identity' do
      it 'accepts bob' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }
      end

      it 'accepts Domain\\Bob' do
        resource[:permissions] = { 'identity' => 'Domain\Bob', 'rights' => ['full'] }
      end

      it 'accepts SIDs like S-1-5-32-544' do
        resource[:permissions] = { 'identity' => 'S-1-5-32-544', 'rights' => ['full'] }
      end

      it 'uses the SID when the system returns a non-existing user' do
        resource[:permissions] = { 'identity' => '', 'id' => 'S-1-5-32-544', 'rights' => ['full'] }
      end

      it 'rejects empty' do
        expect {
          resource[:permissions] = { 'rights' => ['full'] }
        }.to raise_error(Puppet::ResourceError, %r{A non-empty identity must})
      end

      it 'rejects nil' do
        expect {
          resource[:permissions] = { 'identity' => nil, 'rights' => ['full'] }
        }.to raise_error(Puppet::ResourceError, %r{A non-empty identity must})
      end
    end

    context ':rights' do
      it "accepts ['full']" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }
      end

      it "accepts ['modify']" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['modify'] }
      end

      it "accepts ['write']" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['write'] }
      end

      it "accepts ['read']" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['read'] }
      end

      it "accepts ['execute']" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['execute'] }
      end

      it "accepts ['mask_specific']" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['mask_specific'], 'mask' => '123123' }
      end

      it 'accepts a combination of valid values' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['read', 'execute'] }
      end

      it 'reorders [:execute,:read] to [:read,:execute]' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => [:execute, :read] }
        resource[:permissions][0].rights.should == [:read, :execute]
      end

      it "sets ['read','read'] to [:read]" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['read', 'read'] }
        resource[:permissions][0].rights.should == [:read]
      end

      it "does not allow improperly cased rights like ['READ']" do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['READ'] }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "READ". Valid values are})
      end

      it "logs a warning when rights does not contain 'full' by itself" do
        Puppet.expects(:warning).with do |v|
          %r{In each ace, when specifying rights, if you include 'full'}.match(v)
        end
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full', 'read'] }
      end

      it "removes all but 'full' when rights does not contain 'full' by itself" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full', 'read'] }
        resource[:permissions][0].rights.should == [:full]
      end

      it "logs a warning when rights does not contain 'modify' by itself" do
        Puppet.expects(:warning).with do |v|
          %r{In each ace, when specifying rights, if you include 'modify'}.match(v)
        end
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['modify', 'read'] }
      end

      it "removes all but 'modify' when rights does not contain 'modify' by itself" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['modify', 'read'] }
        resource[:permissions][0].rights.should == [:modify]
      end

      it "does not allow 'mask_specific' to exist with other rights" do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['mask_specific', 'read'] }
        }.to raise_error(Puppet::ResourceError, %r{In each ace, when specifying rights, if you include 'mask_specific'})
      end

      it "does not allow 'mask_specific' without mask" do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['mask_specific'] }
        }.to raise_error(Puppet::ResourceError, %r{If you specify rights => \['mask_specific'\], you must also include mask})
      end

      it "sets ['read',:read] to [:read]" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['read', :read] }
        resource[:permissions][0].rights.should == [:read]
      end

      it 'rejects any other value' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['what'] }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "what". Valid values are})
      end

      it 'rejects a value even if with valid values' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['modify', 'what'] }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "what". Valid values are})
      end

      it 'rejects non-array value' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => 'read' }
        }.to raise_error(Puppet::ResourceError, %r{Value for rights should be an array. Perhaps try \['read'\]\?})
      end

      it 'rejects empty' do
        expect {
          resource[:permissions] = { 'identity' => 'bob' }
        }.to raise_error(Puppet::ResourceError, %r{A non-empty rights must})
      end

      it 'rejects nil' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => nil }
        }.to raise_error(Puppet::ResourceError, %r{A non-empty rights must})
      end

      it 'rejects emtpy array' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => [] }
        }.to raise_error(Puppet::ResourceError, %r{Value for rights should have least one element in the array})
      end
    end

    context ':perm_type' do
      it 'defaults to allow' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }
        resource[:permissions][0].perm_type.should == :allow
      end

      it 'accepts allow' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'perm_type' => 'allow' }
      end

      it 'accepts deny' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'perm_type' => 'deny' }
      end

      it 'rejects any other value' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'perm_type' => 'what' }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "what". Valid values are})
      end

      it 'rejects empty' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'perm_type' => '' }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "". Valid values are})
      end

      it 'sets default value on nil' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'perm_type' => nil }
        resource[:permissions][0].perm_type.should == :allow
      end

      it 'munges `type` to `perm_type`' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'type' => 'deny' }
        resource[:permissions][0].perm_type.should == :deny
      end

      it 'throws a warning when using type' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'type' => 'deny' }
        # rubocop:disable RSpec/InstanceVariable
        expect(@logs[0].level).to equal(:warning)
        @logs[0].message.should match(%r{Permission `type` is deprecated and has been replaced with perm_type for allow or deny})
        # rubocop:enable RSpec/InstanceVariable
      end
      context 'setting both type and permtype' do
        it 'throws error with different values' do
          expect {
            resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'type' => 'deny', 'perm_type' => 'allow' }
          }.to raise_error(Puppet::ResourceError, %r{Can not accept both `type` => deny and `perm_type` => allow})
        end
        it 'does not throw an error if both are the same' do
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'type' => 'deny', 'perm_type' => 'deny' }
        end
      end
    end

    context ':child_types' do
      it "defaults to 'all'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }
        resource[:permissions][0].child_types.should == :all
      end

      it "accepts 'all'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'all' }
      end

      it "accepts 'none'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'none' }
      end

      it "when set to 'none' should update affects to 'self_only'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'none' }
        resource[:permissions][0].affects.should == :self_only
      end

      it "accepts 'objects'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'objects' }
      end

      it "accepts 'containers'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'containers' }
      end

      it 'rejects any other value' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => 'what' }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "what". Valid values are})
      end

      it 'rejects empty' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => '' }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "". Valid values are})
      end

      it 'sets default value on nil' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'child_types' => nil }
        resource[:permissions][0].child_types.should == :all
      end
    end

    context ':affects' do
      it "defaults to 'all'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }
        resource[:permissions][0].affects.should == :all
      end

      it "accepts 'all'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'all' }
      end

      it "accepts 'self_only'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'self_only' }
      end

      it "when set to 'self_only' should update child_types to 'none'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'self_only' }
        resource[:permissions][0].child_types.should == :none
      end

      it "accepts 'children_only'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'children_only' }
      end

      it "accepts 'self_and_direct_children_only'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'self_and_direct_children_only' }
      end

      it "accepts 'direct_children_only'" do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'direct_children_only' }
      end

      it 'rejects any other value' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => 'what' }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "what". Valid values are})
      end

      it 'rejects empty' do
        expect {
          resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => '' }
        }.to raise_error(Puppet::ResourceError, %r{Invalid value "". Valid values are})
      end

      it 'sets default value on nil' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'], 'affects' => nil }
        resource[:permissions][0].affects.should == :all
      end
    end

    context 'when working with a single permission' do
      before :each do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }
      end

      it 'converts the values appropriately' do
        resource[:permissions] = { 'identity' => 'bob', 'rights' => ['full'] }

        expect(resource[:permissions][0].identity).to eq('bob')
        expect(resource[:permissions][0].rights).to eq([:full])
      end

      it 'sets defaults' do
        expect(resource[:permissions][0].perm_type).to eq(:allow)
        expect(resource[:permissions][0].child_types).to eq(:all)
        expect(resource[:permissions][0].affects).to eq(:all)
      end
    end

    context 'when working with multiple permissions' do
      before :each do
        resource[:permissions] = [{ 'identity' => 'bob', 'rights' => ['full'] }, { 'identity' => 'tim', 'rights' => ['full'] }]
      end

      it 'contains the number of items set' do
        expect(resource[:permissions].count).to eq(2)
      end

      it 'is in the exact order set' do
        expect(resource[:permissions][0].identity).to eq('bob')
        expect(resource[:permissions][1].identity).to eq('tim')
      end
    end
  end
end
