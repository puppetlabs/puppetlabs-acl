require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(agent, target_name, file_content, owner_id, owner_regex)
  context "on #{agent}" do
    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"
    dosify_target = "c:\\temp\\#{target_name}"
    verify_owner_command = "cmd /c \"dir /q #{dosify_target}\""

    it 'Execute ACL Manifest' do
      execute_manifest_on(agent, acl_manifest(target_name, file_content, owner_id), { :debug => true }) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_owner_command) do |result|
        assert_match(owner_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'Owner - Local Group' do
  def acl_manifest(target_name, file_content, owner_id)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_name}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      group { "#{owner_id}":
        ensure     => present
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

  context 'Change Owner to Local Group' do
    file_content = 'Spearhead was a great MOHAA game.'
    target_name = 'owner_local_group.txt'
    owner_id = 'jerks'
    owner_regex = %r{.*\\jerks}

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target_name, file_content, owner_id, owner_regex)
    end
  end

  context 'Change Owner to Local Group with Long Name' do
    file_content = 'Cow are animals with mooing capabilities.'
    target_name = 'owner_local_long_group_name.txt'
    owner_id = 'jasqddweruwqiouroaysfyuasudyfaisoyfqoiuwyefiaysdiyfzixycivzixyvciqywifyiasdiufyasdygfasirfwerqiuwyeriatsdtfastdfqwyitfastdfawerfytasdytfasydgtaisdytfiasydfiosayghiayhidfhygiasftawyegyfhgaysgfuyasgdyugfasuiyfguaqyfgausydgfaywgfuasgdfuaisydgfausasdfuygsadfyg' # rubocop:disable Metrics/LineLength
    owner_regex = %r{.*\\jasq}

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target_name, file_content, owner_id, owner_regex)
    end
  end

  context 'Change Owner to Local Unicode Group' do
    file_content = 'I thought things on a Saturday night.'
    prefix = SecureRandom.uuid.to_s
    target_name = "#{prefix}.txt"
    raw_owner_id = '\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE'
    owner_id =     "\u4388\u542B\u3D3C\u7F4D\uF961\u4381\u53F4\u79C0\u3AB2\u8EDE" # 䎈含㴼罍率䎁叴秀㪲軞
    verify_owner_command = "(Get-ACL '#{target_parent}/#{target_name}' | Where-Object { $_.Owner -match ('.*\\\\' + [regex]::Unescape(\"#{raw_owner_id}\")) } | Measure-Object).Count"

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(target_name, file_content, owner_id), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, powershell(verify_owner_command, 'EncodedCommand' => true)) do |result|
            assert_match(%r{^1$}, result.stdout, 'Expected ACL was not present!')
          end
        end
      end
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
