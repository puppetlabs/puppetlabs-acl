require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(agent, file_content, group_id, group_regex, user_type)
  context "on #{agent}" do
    it 'Execute ACL Manifest' do
      execute_manifest_on(agent, acl_manifest(user_type, file_content, group_id), debug: true) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_group_command(user_type)) do |result|
        assert_match(group_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command(user_type)) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'Group' do
  def acl_manifest(user_type, file_content, group_id)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/group_#{user_type}.txt":
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

      group { "#{group_id}":
        ensure     => present
      }

      acl { "#{target_parent}/group_#{user_type}.txt":
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

  def verify_group_command(user_type)
    "icacls #{target_parent}/group_#{user_type}.txt"
  end

  def verify_content_command(user_type)
    "cat /cygdrive/c/temp/group_#{user_type}.txt"
  end

  context 'Change Group to Local Group' do
    user_type = 'local_group'
    file_content = 'Hot sand in your eyes!'
    group_id = 'jerks'
    group_regex = %r{.*\\jerks:\(M\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, group_id, group_regex, user_type)
    end
  end

  context 'Change Group to Local Group with Long Name' do
    user_type = 'local_long_group_name'
    file_content = 'Uncontrolled napping.'
    # rubocop:disable Metrics/LineLength
    group_id = 'jasqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg'
    group_regex = %r{.*\\jasqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg:\(M\)}
    # rubocop:enable Metrics/LineLength

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, group_id, group_regex, user_type)
    end
  end

  context 'Change Group to Local User with Long Name' do
    user_type = 'local_long_user_name'
    file_content = 'Dog eat dog world.'
    group_id = 'long_user_name_jerry'
    group_regex = %r{.*\\long_user_name_jerry:\(M\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, group_id, group_regex, user_type)
    end
  end

  context 'Change Group to Local User' do
    user_type = 'local_user'
    file_content = 'cat-man-doo!'
    group_id = generate_random_username
    group_regex = %r{.*\\#{group_id}:\(M\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, file_content, group_id, group_regex, user_type)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
