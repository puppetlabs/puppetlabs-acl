# frozen_string_literal: true

require 'spec_helper'
require 'puppet/type'
require 'puppet/type/acl'
require 'yaml'

describe 'Ace' do
  describe '.hash' do
    it 'is equal for two like aces' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full']).hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full']).hash

      expect(left).to eq right
    end

    it 'is equal for two like aces even with extra information' do
      sid = 'S-32-12-0'
      provider = double
      expect(provider).to receive(:get_account_id).and_return(sid)
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'id' => sid, 'mask' => '2023422').hash
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider).hash

      expect(left).to eq right
    end

    it 'is equal for two like aces when one has sid' do
      sid = 'S-1-1-0'
      provider = double
      expect(provider).to receive(:get_account_id).and_return(sid)
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'id' => sid, 'rights' => ['full']).hash
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'Everyone', 'rights' => ['full'] }, provider).hash

      expect(left).to eq right
    end

    it 'is equal for two like aces when both have same sid but identities are different' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'id' => 'S-1-1-0', 'rights' => ['full']).hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'BUILT IN\Administrators', 'id' => 'S-1-1-0', 'rights' => ['full']).hash

      expect(left).to eq right
    end

    it 'is equal for two like aces when identities evaluate to the same because provider' do
      provider = double
      expect(provider).to receive(:get_account_name).and_return('same').twice

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider).hash
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'BUILT IN\Administrators', 'rights' => ['full'] }, provider).hash

      expect(left).to eq right
    end

    it 'is not equal for two like aces when identities do not evaluate to the same because provider' do
      provider = double
      allow(provider).to receive(:get_account_name).and_return('one', 'two')

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider).hash
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider).hash

      expect(left).not_to eq right
    end

    it 'is equal for two aces when SIDs evaluate to the same because provider' do
      provider = double
      expect(provider).to receive(:get_account_id).and_return('S-1-1-0').twice

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider).hash
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'NOTAdministrators', 'rights' => ['full'] }, provider).hash

      expect(left).to eq right
    end

    it 'is not equal for two like aces when SIDs evaluate different because provider' do
      provider = double
      allow(provider).to receive(:get_account_id).and_return('S-1-1-0', 'S-1-1-5')

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider).hash
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider).hash

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by identities' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']).hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'Users', 'rights' => ['full']).hash

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by rights' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']).hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['modify']).hash

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by type' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'allow').hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'deny').hash

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by child_types' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'all').hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'objects').hash

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by affects' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all').hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'children_only').hash

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by is_inherited' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'is_inherited' => 'false').hash
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'is_inherited' => 'true').hash

      expect(left).not_to eq right
    end
  end

  describe '.==' do
    it 'is equal for two like aces' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])

      expect(left).to eq right
    end

    it 'is equal for two like aces even with extra information' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'id' => 'S-32-12-0', 'mask' => '2023422')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])

      expect(left).to eq right
    end

    it 'is equal for two like aces when one has sid' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'id' => 'S-1-1-0', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])

      expect(left).to eq right
    end

    it 'is equal for two like aces when both have same sid but identities are different' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'id' => 'S-1-1-0', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'BUILT IN\Administrators', 'id' => 'S-1-1-0', 'rights' => ['full'])

      expect(left).to eq right
    end

    it 'is equal for two like aces when identities evaluate to the same because provider' do
      provider = double
      expect(provider).to receive(:get_account_name).and_return('same').twice

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'BUILT IN\Administrators', 'rights' => ['full'] }, provider)

      expect(left).to eq right
    end

    it 'is not equal for two like aces when identities do not evaluate to the same because provider' do
      provider = double
      allow(provider).to receive(:get_account_name).and_return('one', 'two')

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])

      expect(left).not_to eq right
    end

    it 'is equal for two aces when SIDs evaluate to the same because provider' do
      provider = double
      expect(provider).to receive(:get_account_id).and_return('S-1-1-0').twice

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'NOTAdministrators', 'rights' => ['full'] }, provider)

      expect(left).to eq right
    end

    it 'is not equal for two like aces when SIDs evaluate different because provider' do
      provider = double
      allow(provider).to receive(:get_account_id).and_return('S-1-1-0', 'S-1-1-5')

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by identities' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Users', 'rights' => ['full'])

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by rights' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['modify'])

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by type' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'allow')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'deny')

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by child_types' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'all')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'objects')

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by affects' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'children_only')

      expect(left).not_to eq right
    end

    it 'is not equal if aces are different by is_inherited' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'is_inherited' => 'false')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'is_inherited' => 'true')

      expect(left).not_to eq right
    end
  end

  describe '.same?' do
    it 'is true for two like aces' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])

      expect(left.same?(right)).to be true
    end

    it 'is true for two like aces even with extra information' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'id' => 'S-32-12-0', 'mask' => '2023422')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])

      expect(left.same?(right)).to be true
    end

    it 'is true for two like aces when one has sid' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'id' => 'S-1-1-0', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])

      expect(left.same?(right)).to be true
    end

    it 'is true for two like aces when both have same sid but identities are different' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'id' => 'S-1-1-0', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'BUILT IN\Administrators', 'id' => 'S-1-1-0', 'rights' => ['full'])

      expect(left.same?(right)).to be true
    end

    it 'is true for two like aces when identities evaluate to the same because provider' do
      provider = double
      expect(provider).to receive(:get_account_name).and_return('same').twice

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'BUILT IN\Administrators', 'rights' => ['full'] }, provider)

      expect(left.same?(right)).to be true
    end

    it 'is false for two like aces when identities do not evaluate to the same because provider' do
      provider = double
      allow(provider).to receive(:get_account_name).and_return('one', 'two')

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])

      expect(left.same?(right)).to be false
    end

    it 'is true for two aces when SIDs evaluate to the same because provider' do
      provider = double
      expect(provider).to receive(:get_account_id).and_return('S-1-1-0').twice

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'NOTAdministrators', 'rights' => ['full'] }, provider)

      expect(left.same?(right)).to be true
    end

    it 'is false for two like aces when SIDs evaluate different because provider' do
      provider = double
      allow(provider).to receive(:get_account_id).and_return('S-1-1-0', 'S-1-1-5')

      left = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)
      right = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)

      expect(left.same?(right)).to be false
    end

    it 'is true if aces are different by rights' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['modify'])

      expect(left.same?(right)).to be true
    end

    it 'is false if aces are different by identities' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Users', 'rights' => ['full'])

      expect(left.same?(right)).to be false
    end

    it 'is false if aces are different by type' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'allow')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'perm_type' => 'deny')

      expect(left.same?(right)).to be false
    end

    it 'is false if aces are different by child_types' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'all')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'child_types' => 'objects')

      expect(left.same?(right)).to be false
    end

    it 'is false if aces are different by affects' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'all')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'affects' => 'children_only')

      expect(left.same?(right)).to be false
    end

    it 'is false if aces are different by is_inherited' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'is_inherited' => 'false')
      right = Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'], 'is_inherited' => 'true')

      expect(left.same?(right)).to be false
    end
  end

  context 'with arrays' do
    it 'is equal for two like ace arrays' do
      left = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]
      right = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]

      expect(left).to eq right
    end

    it 'is not equal for two unlike ace arrays' do
      left = [Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full'])]
      right = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]

      expect(left).not_to eq right
    end

    it 'the union of two like ace arrays should return the same as one of the arrays' do
      left = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]
      right = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]

      expect(left | right).to eq left
    end

    it 'the intersect of two like ace arrays should return the same as one of the arrays' do
      left = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]
      right = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]

      expect(left & right).to eq left
    end

    it 'the intersect of two ace arrays with similar elements should return an array with common elements' do
      left = [
        Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full']),
        Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']),
      ]
      right = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]

      expect(left & right).to eq right
    end

    it 'the intersect of two ace arrays with similar elements should return an array with common elements no matter where the common elements occur' do
      left = [
        Puppet::Type::Acl::Ace.new('identity' => 'Users', 'rights' => ['full']),
        Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full']),
        Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']),
      ]
      right = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]

      expect(left & right).to eq right
    end

    it "the intersect of two like ace arrays out of order should return the same as the element on the left of the '&'" do
      left = [
        Puppet::Type::Acl::Ace.new('identity' => 'Users', 'rights' => ['full']),
        Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full']),
        Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']),
      ]
      right = [
        Puppet::Type::Acl::Ace.new('identity' => 'Users', 'rights' => ['full']),
        Puppet::Type::Acl::Ace.new('identity' => 'Administrators', 'rights' => ['full']),
        Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full']),

      ]

      expect(left & right).to eq left
      expect(right & left).to eq right
    end

    it 'the difference of two like ace arrays should return an empty array' do
      left = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]
      right = [Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])]

      expect(left - right).to eq []
    end
  end

  describe '.eql?' do
    it 'is true for two like aces' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])

      expect(left.eql?(right)).to be true
    end

    it 'is an alias of .==' do
      type = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])
      expect(type.method(:==)).to eq type.method(:eql?)
    end
  end

  describe '.equal?' do
    it 'is not equal for two like aces' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])
      right = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])

      expect(left.equal?(right)).to be false
    end

    it 'is equal for two aces that are the same object' do
      left = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])
      right = left

      expect(left.equal?(right)).to be true
    end

    it 'is not an alias of .==' do
      type = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])
      expect(type.method(:==)).not_to eq type.method(:equal?)
    end
  end

  context 'when serializing' do
    it "does not include a key named 'provider'" do
      # non-nil provider instance - doesn't need to do anything but can't be anonymous
      provider = Object.new
      ace = Puppet::Type::Acl::Ace.new({ 'identity' => 'Administrators', 'rights' => ['full'] }, provider)

      round_tripped_ace = YAML.safe_load(YAML.dump(ace))

      expect(round_tripped_ace.instance_variables).not_to include(:@provider)
      expect(round_tripped_ace.keys).not_to include('provider')
    end

    it 'includes the same set of keys as .to_hash' do
      # NOTE: id, mask and affects don't appear in to_hash
      ace = Puppet::Type::Acl::Ace.new('identity' => 'Administrators',
                                       'rights' => ['full'],
                                       'id' => 'S-32-12-0',
                                       'mask' => '2023422',
                                       'perm_type' => 'deny',
                                       'child_types' => 'objects',
                                       'affects' => 'all',
                                       'is_inherited' => 'true')

      ace_hash = ace.to_hash
      ace_from_yaml = YAML.load(YAML.dump(ace)) # rubocop:disable Security/YAMLLoad

      expect(ace_hash.keys).to eq(ace_from_yaml.keys)
      expect(ace_hash.instance_variables).to eq(ace_from_yaml.instance_variables)
    end

    it 'deserializes as a plain Ruby Hash object' do
      ace = Puppet::Type::Acl::Ace.new('identity' => 'Everyone', 'rights' => ['full'])

      ace_from_yaml = YAML.load(YAML.dump(ace)) # rubocop:disable Security/YAMLLoad

      expect(ace_from_yaml.class).to be(Hash)
    end
  end
end
