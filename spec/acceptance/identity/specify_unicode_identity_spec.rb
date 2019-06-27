require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(agent, file_content, target, user_id, verify_acl_command)
  it 'Execute Manifest' do
    execute_manifest_on(agent, acl_manifest_user(target, file_content, user_id), debug: true) do |result|
      assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
    end
  end

  it 'Verify that ACL Rights are Correct' do
    on(agent, powershell(verify_acl_command, 'EncodedCommand' => true)) do |result|
      assert_match(%r{^1$}, result.stdout, 'Expected ACL was not present!')
    end
  end
end

describe 'Identity' do
  def acl_manifest_group(target, file_content, group_id)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target}':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      group { '#{group_id}':
        ensure => present,
      }

      acl { '#{target}':
        permissions  => [
          { identity => '#{group_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def acl_manifest_user(target, file_content, user_id)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target}':
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { '#{target}':
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Specify Group Name Containing Unicode for Identity' do
    prefix = SecureRandom.uuid.to_s
    target = "c:/temp/#{prefix}.txt"
    raw_group_id = 'group_\uB81D\uB534\uC2AB\uC788\uCC98'
    group_id = "group_\uB81D\uB534\uC2AB\uC788\uCC98" # 렝딴슫있처
    file_content = 'Garbage bag full of money.'
    verify_acl_command = "(Get-ACL '#{target}' | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match ('\\\\' + [regex]::Unescape(\"#{raw_group_id}\")) -and $_.FileSystemRights -eq 'FullControl' } | Measure-Object).Count" # rubocop:disable Metrics/LineLength

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute Manifest' do
          execute_manifest_on(agent, acl_manifest_group(target, file_content, group_id), debug: true) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, powershell(verify_acl_command, 'EncodedCommand' => true)) do |result|
            assert_match(%r{^1$}, result.stdout, 'Expected ACL was not present!')
          end
        end
      end
    end
  end

  context 'Windows ACL Module - Specify User Name Containing Unicode for Identity' do
    prefix = SecureRandom.uuid.to_s
    target = "c:/temp/#{prefix}.txt"
    raw_user_id = 'user_\uB81D\uB534\uC2AB\uC788\uCC98'
    user_id = "user_\uB81D\uB534\uC2AB\uC788\uCC98" # 렝딴슫있처
    file_content = 'Flying Spaghetti Monster wants to save your soul.'
    verify_acl_command = "(Get-ACL '#{target}' | ForEach-Object { $_.Access } | Where-Object { $_.IdentityReference -match ('\\\\' + [regex]::Unescape(\"#{raw_user_id}\")) -and $_.FileSystemRights -eq 'FullControl' } | Measure-Object).Count" # rubocop:disable Metrics/LineLength

    windows_agents.each do |agent|
      context "on #{agent}" do
        apply_manifest_and_verify(agent, file_content, target, user_id, verify_acl_command)
      end
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
