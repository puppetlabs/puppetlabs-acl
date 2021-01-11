# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Group - Negative' do
  let(:user_type) { '257_char_name' }
  let(:file_content) { 'Organized chaos party.' }

  let(:target_name) { "group_#{user_type}.txt" }

  let(:target) { "#{target_parent}/#{target_name}" }
  let(:group_id) { 'jadsqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg' } # rubocop:disable Layout/LineLength

  let(:expected_error) { %r{Error:.*Group does not exist.} }
  let(:verify_content_path) { "#{target_parent}/#{target_name}" }

  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target}":
        purge           => 'true',
        permissions     => [
          { identity    => 'CREATOR GROUP',
            rights      => ['modify']
          },
          { identity    => '#{user_id}',
            rights      => ['read']
          },
          { identity    => 'Administrators',
            rights      => ['full'],
            affects     => 'all',
            child_types => 'all'
          }
        ],
        group           => '#{group_id}',
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  context 'change group to local group with long name' do
    it 'attempts to apply manifest, raises error' do
      apply_manifest(acl_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{#{expected_error}})
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
