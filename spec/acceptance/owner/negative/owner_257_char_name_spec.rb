require 'spec_helper_acceptance'

describe 'Owner - Negative' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_name}":
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

      acl { "#{target_parent}/#{target_name}":
        permissions  => [
          { identity => '#{user_id}',
            rights   => ['modify']
          },
        ],
        owner        => '#{owner_id}'
      }
    MANIFEST
  end

  let(:verify_content_path) { "#{target_parent}/#{target_name}" }

  context 'Specify 257 Character String for Owner' do
    let(:file_content) { 'I AM TALKING VERY LOUD!' }
    let(:target_name)  { 'owner_257_char_name.txt' }
    let(:owner_id) { 'jasqddsweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg' } # rubocop:disable Metrics/LineLength

    it 'applies manifest, raises error' do
      apply_manifest(acl_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error:.*User does not exist})
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
