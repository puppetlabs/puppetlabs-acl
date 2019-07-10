require 'spec_helper_acceptance'

describe 'Group' do
  let(:acl_manifest) do
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

  let(:verify_acl_command) { "icacls #{target_parent}/group_#{user_type}.txt" }

  let(:verify_content_path) { "#{target_parent}/group_#{user_type}.txt" }

  context 'Change Group to Local Group' do
    let(:user_type) {  'local_group' }
    let(:file_content) { 'Hot sand in your eyes!' }
    let(:group_id) { 'jerks' }
    let(:acl_regex) { %r{.*\\jerks:\(M\)} }

    include_examples 'execute manifest and verify file'
  end

  context 'Change Group to Local Group with Long Name' do
    let(:user_type) {  'local_long_group_name' }
    let(:file_content) { 'Uncontrolled napping.' }
    # rubocop:disable Metrics/LineLength
    let(:group_id) { 'jasqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg' }
    let(:acl_regex) { %r{.*\\jasqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg:\(M\)} }

    # rubocop:enable Metrics/LineLength

    include_examples 'execute manifest and verify file'
  end

  context 'Change Group to Local User with Long Name' do
    let(:user_type) {  'local_long_user_name' }
    let(:file_content) { 'Dog eat dog world.' }
    let(:group_id) { 'long_user_name_jerry' }
    let(:acl_regex) { %r{.*\\long_user_name_jerry:\(M\)} }

    include_examples 'execute manifest and verify file'
  end

  context 'Change Group to Local User' do
    random_username = generate_random_username
    let(:user_type) {  'local_user' }
    let(:file_content) { 'cat-man-doo!' }
    let(:group_id) { random_username }
    let(:acl_regex) { %r{.*\\#{group_id}:\(M\)} }

    include_examples 'execute manifest and verify file'
  end
end
