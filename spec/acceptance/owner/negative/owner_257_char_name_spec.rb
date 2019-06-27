require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(agent, target_name, file_content, user_id, owner_id)
  context "on #{agent}" do
    expected_error = %r{Error:.*User does not exist}
    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"

    it 'Attempt to Execute ACL Manifest' do
      execute_manifest_on(agent, acl_manifest(target_name, file_content, user_id, owner_id), debug: true) do |result|
        assert_match(expected_error, result.stderr, 'Expected error was not detected!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'Owner - Negative' do
  def acl_manifest(target_name, file_content, user_id, owner_id)
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

  context 'Specify 257 Character String for Owner' do
    file_content = 'I AM TALKING VERY LOUD!'
    target_name = 'owner_257_char_name.txt'
    owner_id = 'jasqddsweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg' # rubocop:disable Metrics/LineLength

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target_name, file_content, user_id, owner_id)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
