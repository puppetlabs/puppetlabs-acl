require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup, RSpec/RepeatedDescription
def apply_manifest_and_verify(file_name, target8dot3, file_content, agent, remove = nil)
  acl_regex = %r{.*\\bob:\(F\)}
  verify_acl_command = "icacls #{target_parent}/#{file_name}"
  verify_content_command = "cat /cygdrive/c/temp/#{file_name}"
  context "on #{agent}" do
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(file_name, target8dot3, file_content), { :debug => true }) do |result|
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

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'Expected file content is invalid!')
      end
    end
  end
end

describe 'Permissions - File - 8.3' do
  def acl_manifest(file_name, target8dot3, file_content)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{file_name}':
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

      acl { '#{target8dot3}':
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

  context 'Add Permissions to 8.3 File' do
    file_name = 'file_short_name.txt'
    target8dot3 = 'c:/temp/FILE_S~2.TXT'
    file_content = 'short file names are very short'

    windows_agents.each do |agent|
      apply_manifest_and_verify(file_name, target8dot3, file_content, agent)
    end
  end

  context 'Remove Permissions from 8.3 File' do
    file_name = 'rem_file_short_name.txt'
    target8dot3 = 'c:/temp/REM_FI~2.TXT'
    file_content = 'wax candle butler space station zebra glasses'

    windows_agents.each do |agent|
      apply_manifest_and_verify(file_name, target8dot3, file_content, agent, true)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup, RSpec/RepeatedDescription
