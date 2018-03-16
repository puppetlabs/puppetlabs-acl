require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup, RSpec/RepeatedDescription
def apply_manifest_and_verify(agent, target, target8dot3, verify_acl_command, remove = false)
  context "on #{agent}" do
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(F\)}
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(target, target8dot3), { :debug => true }) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command) do |result|
        assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
      end
    end
    if remove
      it 'Execute Remove Manifest' do
        execute_manifest_on(agent, acl_manifest_remove(target8dot3), { :debug => true }) do |result|
          assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, verify_acl_command) do |result|
          assert_no_match(acl_regex, result.stdout, 'Unexpected ACL was present!')
        end
      end
    end
  end
end

describe 'Permissions - Directory - 8.3' do
  def acl_manifest(target, target8dot3)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target8dot3}":
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def acl_manifest_remove(target8dot3)
    <<-MANIFEST
      acl { '#{target8dot3}':
        purge => 'listed_permissions',
        permissions => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Add Permissions to a 8.3 Directory' do
    target = 'c:/temp/dir_short_name'
    target8dot3 = 'c:/temp/DIR_SH~1'
    verify_acl_command = "icacls #{target8dot3}"

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target, target8dot3, verify_acl_command)
    end
  end

  context 'Remove Permissions from a 8.3 Directory' do
    target = 'c:/temp/rem_dir_short_name'
    target8dot3 = 'c:/temp/REM_DI~1'
    verify_acl_command = "icacls #{target8dot3}"

    windows_agents.each do |agent|
      apply_manifest_and_verify(agent, target, target8dot3, verify_acl_command, true)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup, RSpec/RepeatedDescription
